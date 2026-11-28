#!/usr/bin/env python3
"""Reference caller: one journaled unit of work, gated by hallpass.

    caller.py pin     JOURNAL PASS ARCHIVE [--require-signature PRINCIPAL --allowed-signers FILE [--signature FILE]]
    caller.py run     JOURNAL PASS REF --to ADDR:PORT/PROTO[@NAME] --charge COUNTER=N
                      [--to ...] [--charge ...] [--duration S] [--outbox FILE] [--rehearsal]
    caller.py handoff JOURNAL PASS [--ref-prefix PREFIX] [--since SEQ] [--all]
    caller.py reconcile-references JOURNAL PASS --reason TEXT [--also JOURNAL ...]
                                     [--accept-shortfall] [--rehearsal]

The hallpass ledger is the authority for debits. The journal is the authority
for what this caller did. Python 3 standard library only. See README.md.
"""
import argparse
import fcntl
import json
import os
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True  # leave no __pycache__ in the checkout
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "conformance"))
import check  # noqa: E402  The reference reply decoder, docs/conformance/check.py.

# Test hook: exit at once at this point, as a crash would.
INTERRUPT = os.environ.get("REFERENCE_CALLER_INTERRUPT")  # after-spend, after-callback


MAX_MANIFEST_ROWS = 1_024  # hallpass reconcile takes at most this many rows in one manifest
MAX_REFERENCES = 10_000  # hallpass records at most this many references in one reconciliation


def fail(message):
    print(f"caller: {message}", file=sys.stderr)
    sys.exit(1)


def hallpass(*args, rehearsal=False):
    """Run hallpass in JSON mode, never through a shell. Return (exit, stdout)."""
    env = dict(os.environ)
    if not rehearsal:
        env.pop("HALLPASS_UNSAFE_TEST_CLOCK", None)  # a live caller never pins the clock
    try:
        done = subprocess.run(["hallpass", "--format", "json", *args], env=env, stdout=subprocess.PIPE)
    except OSError as error:
        print(f"caller: could not run hallpass: {error}", file=sys.stderr)
        return None, b""
    return done.returncode, done.stdout


def decode(stdout):
    """The reply as a dict, or {} when it is not one. Only for reading fields."""
    try:
        reply = json.loads(stdout)
    except ValueError:
        return {}
    return reply if isinstance(reply, dict) else {}


def message(reply):
    return (reply.get("error") or {}).get("message",
                                          "no reply (if hallpass said on stderr that the entry IS recorded, it is: inspect the ledger)")


def append(journal, _unless_ref=None, **record):
    """Append one record and force it to disk before the caller acts on it.

    With _unless_ref, the record is written only if no record of that reference is
    in the journal. The check and the write happen under the one lock, so of
    several runs that start with one reference at once, exactly one gets True."""
    record = {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), **record}
    new = not os.path.exists(journal)
    fd = os.open(journal, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)  # one writer at a time, so the tail check below is true
        drop_torn_tail(fd, journal)
        if _unless_ref is not None:
            for line in os.pread(fd, os.fstat(fd).st_size, 0).split(b"\n"):
                try:
                    seen = json.loads(line)
                except ValueError:
                    continue
                if isinstance(seen, dict) and seen.get("ref") == _unless_ref:
                    return False
        os.write(fd, (json.dumps(record) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)  # closing the descriptor also releases the lock
    if new:  # make the new directory entry durable too
        fd = os.open(os.path.dirname(os.path.abspath(journal)), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return True


def drop_torn_tail(fd, journal):
    """A crash can cut the last record off before its newline. The caller writes a
    record and forces it to disk before it acts on it, so it never acted on a
    record that has no newline: nothing depends on those bytes. Appending after
    them would fuse the next record into one unreadable line, so cut them off
    first, say so, and show what was cut. The file is not kept: the cut bytes
    are in this message, and `handoff` and the ledger hold the facts."""
    size = os.fstat(fd).st_size
    if size == 0 or os.pread(fd, 1, size - 1) == b"\n":
        return
    data = os.pread(fd, size, 0)
    keep = data.rfind(b"\n") + 1  # 0 when the file is only a fragment
    print(f"caller: {journal} ended in an unfinished record ({size - keep} bytes, after a crash while "
          f"writing); the caller never acted on it, so it is removed before the next record: "
          f"{data[keep:].decode(errors='replace')!r}", file=sys.stderr)
    os.ftruncate(fd, keep)
    os.fsync(fd)


def read_journal(journal):
    """Every complete record. A crash can cut off the last line before its
    newline. The caller acts only on records already on disk, so it never
    acted on that one, and it is ignored (the next `append` removes it).
    Any other line that is not a JSON object is damage: refuse, with the line."""
    try:
        data = Path(journal).read_bytes()
    except FileNotFoundError:
        return []
    records = []
    for number, line in enumerate(data.split(b"\n")[:-1], 1):
        try:
            record = json.loads(line)
        except ValueError:
            record = None
        if not isinstance(record, dict):
            fail(f"{journal} line {number} is not a journal record. The journal is damaged "
                 f"and is not read further; keep a copy, then fix or remove that line "
                 f"(each line is one JSON object), and run the command again")
        records.append(record)
    return records


def pass_key(pass_file):
    """The pass path as the journal records it: resolved, so that `e.pass.toml`,
    `./e.pass.toml` and the absolute path read the same. It is for the reader of
    the journal. Records are matched to a pass by its ID, which hallpass reports."""
    return os.path.realpath(pass_file)


def is_pass(record, pass_id):
    return record.get("pass_id") == pass_id


def units(records, pass_id):
    """The records of each caller reference for this pass, in journal order."""
    out = {}
    for record in records:
        if "ref" in record:
            out.setdefault(record["ref"], []).append(record)
    return {ref: rs for ref, rs in out.items() if is_pass(rs[0], pass_id)}


def target(text):
    """ADDR:PORT/PROTO[@NAME] as typed. `canonical` spells it the way hallpass does."""
    literal, _, name = text.partition("@")
    return {"target": literal, "name": name or None}


def canonical(a):
    """Replace each --to by the spelling hallpass itself uses, before any journal write.

    hallpass is the authority on canonical form (lower-case compressed IPv6, lower-case
    name without a trailing dot), so ask it: `permits` normalizes every --to and says so
    in `targets`, whether it allows or refuses. An exit other than 0 or 2 means hallpass
    would not take the input at all; stop before an intent exists."""
    args = ["permits"]
    for t in a.to:
        args += ["--to", t["target"] + ("@" + t["name"] if t["name"] is not None else "")]
    code, out = hallpass(*args, "--", a.pass_file, rehearsal=a.rehearsal)
    reply = decode(out)
    error = reply.get("error")
    if code == 1 and isinstance(error, dict) and error.get("code") != "usage":
        # not about the targets: a missing pass, a damaged ledger, a lock; say hallpass's own words
        fail(f"hallpass error ({error.get('code')}): {error.get('message')}")
    echoed = reply.get("targets")
    if (code not in (0, 2) or reply.get("command") != "permits" or not isinstance(echoed, list)
            or len(echoed) != len(a.to)
            or not all(isinstance(e, dict) and isinstance(e.get("target"), str)
                       and (e.get("name") is None or isinstance(e["name"], str)) for e in echoed)):
        fail(f"hallpass would not take these targets: {message(reply)}")
    clock = reply.get("test_clock")
    if a.rehearsal and clock is not True:
        fail("--rehearsal needs a hallpass that honours HALLPASS_UNSAFE_TEST_CLOCK, and this one "
             "uses the real clock (a release build ignores it), so a spend would be live; nothing "
             "was journaled. Use a debug build or one built with the test-clock feature, set the "
             "variable, or run without --rehearsal")
    if not a.rehearsal and clock is not False:
        fail("hallpass reports a test clock, but this is not a rehearsal; nothing was journaled. "
             "Unset HALLPASS_UNSAFE_TEST_CLOCK in the hallpass environment, or run with --rehearsal")
    if not isinstance(reply.get("pass_id"), str):
        fail(f"hallpass did not say the pass ID: {message(reply)}")
    a.pass_id = reply["pass_id"]
    return [{"target": e["target"], "name": e.get("name")} for e in echoed]


def charge(text):
    counter, _, n = text.partition("=")
    if counter and n.isascii() and n.isdigit() and int(n) > 0:
        return {"counter": counter, "n": int(n)}
    raise argparse.ArgumentTypeError(f"expected COUNTER=N with N > 0, not {text!r}")


def move_aside(a, digest):
    base = f"{a.archive}/{digest}"
    return (f"If the archive keeps a record of another principal, move {base}.sig and {base}.approval "
            "aside (a record is never replaced), then run pin again")


def check_signers_file(path):
    """Refuse a signers file that another user could change, as hallpass does.

    Whoever can write it can add a key for the owner's principal and sign a
    widened pass. So it must be a regular file, not a link, owned by this
    user or root, and writable by neither group nor others. hallpass checks
    this again when it reads the file."""
    try:
        info = os.lstat(path)
    except OSError as error:
        fail(f"cannot read the trusted signers file {path}: {error.strerror}; check --allowed-signers")
    if not stat.S_ISREG(info.st_mode):
        fail(f"the trusted signers file {path} is not a regular file (or is a link); name the file itself")
    if info.st_uid not in (os.geteuid(), 0):
        fail(f"the trusted signers file {path} is owned by UID {info.st_uid}; use one owned by UID "
             f"{os.geteuid()} or root after checking every line in it")
    if info.st_mode & 0o022:
        fail(f"the trusted signers file {path} has mode {stat.S_IMODE(info.st_mode):04o}, so other users can add "
             f"a key for any principal to it; run `chmod 600 {path}`, then check that every line in it names a key "
             "you trust")


def signed_digest(a):
    """Verify the signature itself and return the digest it covers. Stop on anything less.

    The pin must rest on a verified signature, never on a record in the archive:
    anyone who can write the archive can write a record. So this runs
    `verify-approval` with the operator's own signers file and principal, which
    publishes the verified bytes with their signature to the archive, and then
    `archive` on whatever is on disk now. An unsigned edit made between the two
    archives different bytes, so the digests differ and the pin is refused."""
    if not a.allowed_signers:
        fail("--require-signature needs --allowed-signers: the signers file the operator trusts")
    check_signers_file(a.allowed_signers)
    signature = a.signature or a.pass_file + ".sig"
    code, out = hallpass("verify-approval", "--signature", signature, "--allowed-signers", a.allowed_signers,
                         "--principal", a.require_signature, "--archive", a.archive, "--", a.pass_file)
    verified = decode(out)
    if verified.get("provenance") == "signature-not-stored":
        fail(f"the archive has no signature record of {a.require_signature}: it keeps the record of "
             f"{(verified.get('approval') or {}).get('principal')}. {move_aside(a, verified.get('digest'))}")
    if (code != 0 or verified.get("command") != "verify-approval" or verified.get("result") != "verified"
            or verified.get("principal") != a.require_signature
            or verified.get("provenance") != "signature-recorded"
            or not isinstance(verified.get("digest"), str)):
        reason = verified.get("next_step") or verified.get("reason") or message(verified)
        fail(f"{a.pass_file} is not signed by {a.require_signature}: {reason}")
    code, out = hallpass("archive", "--", a.pass_file, a.archive)
    archived = decode(out)
    approval = archived.get("approval")
    if code != 0 or archived.get("result") != "ok":
        fail(f"archive failed: {message(archived)}")
    if archived.get("digest") != verified["digest"]:
        fail("the pass changed after its signature was verified; sign it again and verify it again")
    if (archived.get("provenance") != "signature-recorded" or not isinstance(approval, dict)
            or approval.get("principal") != a.require_signature):
        fail(f"the archive has no signature record of {a.require_signature} for {archived.get('digest')}. "
             + move_aside(a, archived.get("digest")))
    return verified["digest"]


def pin(a):
    """Archive the reviewed bytes and pin their digest for the units that follow.

    Without --require-signature this pins whatever is on disk: the digest rests
    on a review, not on a signature. With it, the digest must be one that
    `verify-approval` verified for the named principal."""
    if a.require_signature is None and (a.allowed_signers or a.signature):
        fail("--allowed-signers and --signature are used only with --require-signature PRINCIPAL")
    signed = signed_digest(a) if a.require_signature is not None else None
    code, out = hallpass("archive", "--", a.pass_file, a.archive)
    archived = decode(out)
    if code != 0 or archived.get("result") != "ok":
        fail(f"archive failed: {message(archived)}")
    if signed is not None and (archived["digest"] != signed or archived.get("provenance") != "signature-recorded"):
        fail("the pass changed after its signature was verified; sign it again and verify it again")
    code, out = hallpass("digest", "--", a.pass_file)
    current = decode(out)
    if code != 0 or current.get("digest") != archived["digest"]:
        fail("the pass changed while it was archived; review it again")
    extra = {"signed_by": a.require_signature} if signed is not None else {}
    append(a.journal, event="pin", **{"pass": pass_key(a.pass_file)}, pass_id=current["pass_id"], digest=current["digest"],
           **extra)
    how = f" signed by {a.require_signature}" if signed is not None else ""
    print(f"pinned {current['pass_id']} {current['digest']}{how}")
    return 0


def production_view(stdout):
    """--rehearsal only. A debug hallpass that honoured HALLPASS_UNSAFE_TEST_CLOCK
    says test_clock = true, which inspect_reply refuses. Accept that one field
    and let inspect_reply judge everything else."""
    try:
        reply = json.loads(stdout, object_pairs_hook=check._unique_members)
    except ValueError:
        return stdout
    if isinstance(reply, dict) and reply.get("test_clock") is True:
        return json.dumps({**reply, "test_clock": False})
    return stdout


def send_unit(outbox, ref, targets, charges):
    """The unit of work. A real caller sends traffic here; this one writes a line."""
    with open(outbox, "a") as f:
        f.write(json.dumps({"ref": ref, "targets": targets, "charges": charges}) + "\n")
        f.flush()
        os.fsync(f.fileno())


def run(a):
    """Journal the intent, spend, and send only after a verified debit."""
    records = read_journal(a.journal)
    if a.ref in {r.get("ref") for r in records}:
        fail(f"{a.ref} is already in {a.journal}; give every unit a new reference")
    a.to = canonical(a)  # one spelling for the intent, the spend, the reply check and the manifest
    pins = [r for r in records if r["event"] == "pin" and is_pass(r, a.pass_id)]
    if not pins:
        fail(f"no pin for {a.pass_file}; review the pass, then run `pin`")
    pinned = pins[-1]
    expected = {
        "file": a.pass_file, "pass_id": pinned["pass_id"], "digest": pinned["digest"],
        "mode": "charges", "charges": a.charge, "targets": a.to,
        "record_targets": True, "caller_ref": a.ref, "note": None,
    }
    # The early check above is only a quick refusal. This one is the real one: it
    # is made under the journal lock, so two runs of one reference cannot both pass.
    if not append(a.journal, _unless_ref=a.ref, ref=a.ref, event="intent", **{"pass": pass_key(a.pass_file)},
                  pass_id=pinned["pass_id"], digest=pinned["digest"], targets=a.to, charges=a.charge,
                  rehearsal=a.rehearsal):
        fail(f"{a.ref} is already in {a.journal} (another run took it first); give every unit a new reference")

    args = ["spend", "--digest", pinned["digest"], "--duration", str(a.duration),
            "--caller-ref", a.ref, "--require-new-ref", "--record-target"]
    for t in a.to:
        args += ["--to", t["target"] + (f"@{t['name']}" if t["name"] else "")]
    for c in a.charge:
        args += ["--charge", f"{c['counter']}={c['n']}"]
    code, out = hallpass(*args, "--", a.pass_file, rehearsal=a.rehearsal)
    if INTERRUPT == "after-spend":
        os._exit(3)  # the reply is lost: the journal holds only the intent
    reply = decode(out)

    live_in_rehearsal = []

    def dispatch():  # inspect_reply calls this only for a verified debit
        append(a.journal, ref=a.ref, event="spend", outcome="debited", seq=reply["seq"])
        if a.rehearsal and reply.get("test_clock") is not True:
            live_in_rehearsal.append(reply["seq"])  # the preflight should have caught this
            return
        append(a.journal, ref=a.ref, event="callback-start")
        send_unit(a.outbox, a.ref, a.to, a.charge)
        if INTERRUPT == "after-callback":
            os._exit(3)  # the unit ran, but its completion was never recorded
        append(a.journal, ref=a.ref, event="callback-done")

    def warn(message):
        print(f"hallpass warning: {message}", file=sys.stderr)

    action = check.inspect_reply(code, production_view(out) if a.rehearsal else out, expected, dispatch, warn)
    if live_in_rehearsal:
        print(f"{a.ref}: refused to send: this is a rehearsal but the debit (seq {live_in_rehearsal[0]}) is "
              f"live, because this hallpass ignores HALLPASS_UNSAFE_TEST_CLOCK (a release build). The "
              f"callback did not run. Run `handoff`; the debit stands and cannot be undone", file=sys.stderr)
        return 1
    if action == "proceed":
        print(f"{a.ref}: debit seq {reply['seq']} verified, unit sent, completion recorded")
        return 0
    refusal = reply.get("refusal")
    if (code == 2 and reply.get("command") == "spend" and reply.get("result") == "refused"
            and reply.get("seq") is None and isinstance(refusal, dict) and isinstance(refusal.get("code"), str)):
        append(a.journal, ref=a.ref, event="spend", outcome="refused", code=refusal["code"])
        print(f"{a.ref}: refused {refusal['code']}, nothing sent")
        print(f"hallpass: {refusal.get('message')}", file=sys.stderr)
        return 2
    # Anything else is unknown until the ledger says otherwise: never retry blindly.
    append(a.journal, ref=a.ref, event="spend", outcome="unknown", exit=code)
    print(f"{a.ref}: spend outcome unknown, nothing sent; run `handoff` before anything else")
    return 1


def spend_record(records):
    """The spend record that matters for one reference: the one that debited, else the first."""
    spends = [r for r in records if r["event"] == "spend"]
    return next((r for r in spends if r.get("outcome") == "debited"), spends[0] if spends else {})


def intent_record(records):
    """The intent of the run that debited (the last intent before its spend record),
    else the first intent."""
    spend = spend_record(records)
    intents = [r for r in records if r["event"] == "intent"]
    if spend.get("outcome") == "debited":
        before = []
        for r in records:
            if r is spend:
                break
            if r["event"] == "intent":
                before.append(r)
        if before:
            return before[-1]
    return intents[0] if intents else records[0]


def caller_record(records):
    """What the journal says this caller did for one reference."""
    events = [r["event"] for r in records]
    spend = spend_record(records)
    if spend.get("outcome") == "refused":
        return f"refused {spend['code']}"
    if "callback-done" in events:
        return "sent"
    if "callback-start" in events:
        return "unconfirmed"
    return "not sent" if spend.get("outcome") == "debited" else "unknown"


VERDICTS = {
    ("sent", "match"): "ok: debited and sent",
    ("sent", "reconciled"): "ok: sent; its debit is missing from the adopted ledger, and the reference is reconciled",
    ("refused", "reconciled"): "ok: refused, nothing debited or sent",
    ("unconfirmed", "reconciled"): "ATTENTION: completion not recorded; check the target, do not repeat",
    ("not sent", "reconciled"): "ATTENTION: debited, never sent; the debit is missing from the adopted ledger",
    ("unknown", "reconciled"): "ATTENTION: maybe debited in lines an adoption lost; nothing was sent",
    ("refused", "absent"): "ok: refused, nothing debited or sent",
    ("unconfirmed", "match"): "ATTENTION: completion not recorded; check the target, do not repeat",
    ("not sent", "match"): "ATTENTION: debited, never sent; the debit stands",
    ("unknown", "match"): "ATTENTION: debited, never sent; the debit stands",
    ("unknown", "absent"): "ATTENTION: not debited, not sent; use a new reference to run it",
    ("refused", "match"): "ATTENTION: another run debited this reference; find its record",
    ("no record", "match"): "ATTENTION: no journal record; find the run record of this debit",
}


def handoff(a):
    """Every unit in this journal by reference: the caller's record beside the ledger's.

    Other debits on a shared ledger are not this caller's to judge. They are counted,
    listed with --all, and never set the exit code, except a debit whose reference
    starts with --ref-prefix: this caller owns that prefix, so one without a journal
    record is an ATTENTION item. --since SEQ looks only at debits from SEQ on."""
    if a.ref_prefix == "":
        fail("--ref-prefix must not be empty: it would claim every reference")
    records = read_journal(a.journal)
    since = ["--since", str(a.since)] if a.since else []
    code, out = hallpass("ledger", *since, "--", a.pass_file)
    ledger = decode(out)
    if code != 0 or ledger.get("verified") is not True:
        fail(f"the ledger could not be verified: {message(ledger)}")
    mine = units(records, ledger["pass_id"])
    pending = ledger.get("unreconciled_adoption")
    rows = {}
    if mine:
        # One manifest takes at most MAX_MANIFEST_ROWS rows: ask in chunks and merge the rows.
        entries = [{"caller_ref": ref, "digest": intent_record(rs)["digest"], "charges": intent_record(rs)["charges"],
                    "targets": intent_record(rs)["targets"]} for ref, rs in mine.items()]
        for start in range(0, len(entries), MAX_MANIFEST_ROWS):
            manifest = {"version": 1, "pass_id": ledger["pass_id"], "units": entries[start:start + MAX_MANIFEST_ROWS]}
            with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
                json.dump(manifest, f)
                f.flush()
                code, out = hallpass("reconcile", "--", a.pass_file, f.name)
            reply = decode(out)
            if code not in (0, 2) or not isinstance(reply.get("rows"), list):
                fail(f"reconcile failed: {message(reply)}")
            for row in reply["rows"]:
                # A debit lost with an adopted ledger is absent, but a reference
                # reconciliation lists it: say so rather than "no debit".
                if row["result"] == "absent" and row.get("reconciled_at"):
                    rows[row["caller_ref"]] = ("reconciled", row["reconciled_at"])
                else:
                    rows[row["caller_ref"]] = (row["result"], row["sequences"])

    table = [(ref, caller_record(rs), *rows[ref]) for ref, rs in mine.items()]
    others = []
    for entry in ledger["entries"]:
        ref = (entry.get("receipt") or {}).get("caller_ref")
        if ref in mine:
            continue
        if a.ref_prefix and ref and ref.startswith(a.ref_prefix):
            table.append((ref, "no record", "match", [entry["seq"]]))
        else:
            others.append((ref or "(no reference)", "not this journal", f"debit seq {entry['seq']}",
                           "other: not judged"))
    print(f"Handoff for {ledger['pass_id']} ({a.pass_file}) from {a.journal}")
    lines = []
    for ref, did, result, seqs in table:
        kind = "debit" if result == "match" else result
        found = "no debit" if result == "absent" else f"{kind} seq {','.join(map(str, seqs))}"
        state = "refused" if did.startswith("refused ") else did
        verdict = VERDICTS.get((state, result), "ATTENTION: journal and ledger disagree; reconcile by hand")
        if pending is not None and result == "absent" and state != "refused":
            # The ledger was adopted and may have lost lines: absent does not mean not debited.
            verdict = (f"ATTENTION: may be in the lines the adoption at seq {pending} lost; "
                       f"run `caller.py reconcile-references` first, then `handoff` again")
        repeats = sum(r["event"] == "intent" for r in mine[ref]) if ref in mine else 0
        if repeats > 1:
            verdict = (f"ATTENTION: {repeats} intent records for this reference, from runs that raced; "
                       f"judged by the one that debited. {verdict}")
        lines.append((ref, did, found, verdict))
    attention = sum(line[3].startswith("ATTENTION") for line in lines)
    if a.all:
        lines += others
    widths = [max(len(line[i]) for line in lines) for i in range(3)] if lines else []
    for line in lines:
        print("  ".join(cell.ljust(w) for cell, w in zip(line, widths)) + "  " + line[3])
    # Records are matched by pass ID, so a moved or respelled path is still judged.
    # Say when they name another file: the pass may have moved, or this may be a second copy.
    elsewhere = sorted({r["pass"] for r in records if is_pass(r, ledger["pass_id"])
                        and isinstance(r.get("pass"), str) and pass_key(r["pass"]) != pass_key(a.pass_file)})
    for path in elsewhere:
        print(f"Note: the journal has records for pass {ledger['pass_id']} written under {path!r}, not "
              f"{pass_key(a.pass_file)!r}. They are judged here by the pass ID. If the pass did not move "
              f"with its ledger, this is a second copy: stop and find out which file is the pass.")
    pins = [r for r in records if r["event"] == "pin" and is_pass(r, ledger["pass_id"])]
    if pins:
        code, out = hallpass("digest", "--", a.pass_file)
        current = decode(out)
        if code != 0 or not isinstance(current.get("digest"), str):
            fail(f"could not read the digest of {a.pass_file}: {message(current)}")
        if current["digest"] != pins[-1]["digest"]:
            attention += 1
            print(f"ATTENTION: the pass on disk ({current['digest']}) is not the last pinned revision "
                  f"({pins[-1]['digest']}). The ceilings below come from the file on disk, not from "
                  f"the pinned revision; review and pin it again, or restore the pinned bytes.")
        signed = [r for r in pins[:-1] if r.get("signed_by")]
        if not pins[-1].get("signed_by") and signed:
            attention += 1
            print(f"ATTENTION: the last pin ({pins[-1]['digest']}) is not signed, but an earlier pin "
                  f"({signed[-1]['digest']}) was signed by {signed[-1]['signed_by']!r}. Units may have been "
                  f"spent on an unsigned revision; have {signed[-1]['signed_by']!r} sign the pass, then pin "
                  f"it again with --require-signature, or restore the signed bytes.")
    spent = ", ".join(f"{t['name']} {t['spent']} of {t['total']}" for t in ledger["totals"])
    shown = ledger.get("shown")
    scope = f"{len(ledger['entries'])} debits" if not shown else (
        f"{len(ledger['entries'])} debits from seq {a.since} (of {shown['of']})")
    print(f"Ledger: {scope}, witness {ledger['witness']}. Spent: {spent}.")
    if pending is not None:
        print(f"Pending: the adoption at seq {pending} may have lost ledger lines, and its references are not "
              f"reconciled. Debits in those lines are not shown. Run `caller.py reconcile-references` with every "
              f"caller's journal before anything is spent.")
    if others:
        print(f"{len(others)} other debits by other callers or without a reference, not judged"
              + ("." if a.all else "; use --all to list them."))
    print(f"{attention} need attention." if attention else "Nothing needs attention.")
    return 2 if attention else 0


def reconcile_references(a):
    """After an adoption that may have lost lines, record in the ledger every
    reference that the journals used on this pass, so that guarded spends resume.

    hallpass then refuses each listed reference as a duplicate and accepts a new
    one. A reference left off the list would be accepted as new, so name the
    journal of every caller that spent on this pass: this one, and each other one
    with --also. The list is every reference in them, whatever its outcome."""
    code, out = hallpass("ledger", "--", a.pass_file)
    ledger = decode(out)
    if code != 0 or ledger.get("verified") is not True:
        fail(f"the ledger could not be verified: {message(ledger)}")
    adoption = ledger.get("unreconciled_adoption")
    if adoption is None:
        print("No adoption that may have lost lines waits for a reference reconciliation: nothing to do.")
        return 0
    references = []
    debited = {}  # counter -> units the journals say they debited
    possible = {}  # counter -> units whose outcome is unknown: they may have been debited
    unknown = 0
    in_ledger = {(e.get("receipt") or {}).get("caller_ref") for e in ledger.get("entries", [])}
    for journal in [a.journal, *a.also]:
        if not os.path.exists(journal):
            fail(f"no journal at {journal}")
        for ref, rs in units(read_journal(journal), ledger["pass_id"]).items():
            if ref not in references:
                references.append(ref)
                # A debit already in the ledger is not one the adoption lost.
                if ref in in_ledger:
                    continue
                spend = spend_record(rs)
                if spend.get("outcome") == "debited":
                    book = debited
                elif spend.get("outcome") == "refused":
                    continue
                else:  # an intent with no reply, or an unknown outcome: perhaps debited
                    book = possible
                    unknown += 1
                for charge in intent_record(rs).get("charges", []):
                    book[charge["counter"]] = book.get(charge["counter"], 0) + charge["n"]
    # The adoption carried the totals the witness knew. If the journals show fewer debited units
    # than that, a journal is missing, and its references would be accepted as new later.
    carried = next((x.get("carried", {}) for x in ledger.get("adoptions", []) if x.get("seq") == adoption), {})
    if unknown:
        print(f"{unknown} units with unknown outcome counted as possibly debited.")
    counted = {c: debited.get(c, 0) + possible.get(c, 0) for c in {*debited, *possible}}
    short = {c: n - counted.get(c, 0) for c, n in carried.items() if n > counted.get(c, 0)}
    if short:
        names = ", ".join(f"{c} {n}" for c, n in sorted(short.items()))
        print(f"warning: the journals show fewer debited units (counting unknown outcomes as debited) than the adoption at seq {adoption} carried: "
              f"short by {names}. A caller's journal may be missing, and its references would be accepted as new "
              f"after this. Name every journal with --also. If the shortfall is expected (a debit by a caller "
              f"with no journal), run again with --accept-shortfall.",
              file=sys.stderr)
        if not a.accept_shortfall:
            fail("nothing was recorded; add the missing journals, or pass --accept-shortfall")
    parts = [references[i:i + MAX_REFERENCES] for i in range(0, len(references), MAX_REFERENCES)] or [[]]
    recorded = 0
    for number, part in enumerate(parts, 1):
        listing = {"version": 1, "pass_id": ledger["pass_id"], "references": part}
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "references.json")
            with open(path, "w") as f:
                json.dump(listing, f)
            code, out = hallpass("reconcile-references", "--adoption", str(adoption), "--references", path,
                                 "--reason", a.reason, "--", a.pass_file, rehearsal=a.rehearsal)
        reply = decode(out)
        if code != 0 or reply.get("result") != "ok" or not isinstance(reply.get("seq"), int):
            left = f" Part {number} of {len(parts)} failed; {recorded} references are recorded and the rest are not. " \
                   f"Spend nothing until the rest are recorded with `hallpass reconcile-references --adoption {adoption}`." \
                if recorded else ""
            fail(f"reconcile-references failed: {message(reply)}.{left}")
        recorded += len(part)
        append(a.journal, event="reconcile-references", **{"pass": pass_key(a.pass_file)},
               pass_id=ledger["pass_id"], adoption=adoption,
               seq=reply["seq"], references=len(part), part=number, parts=len(parts))
        if len(parts) > 1:
            print(f"part {number} of {len(parts)}: {len(part)} references, ledger seq {reply['seq']}")
    print(f"reconciled {len(references)} references for the adoption at seq {adoption}: ledger seq {reply['seq']}")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(required=True)
    pin_command = commands.add_parser("pin", help="archive the reviewed pass and pin its digest")
    run_command = commands.add_parser("run", help="perform one unit of work")
    handoff_command = commands.add_parser("handoff", help="report every unit in the journal by reference")
    reconcile_command = commands.add_parser(
        "reconcile-references", help="after a lossy adoption, record the journals' references so guarded spends resume")
    for command, action in [(pin_command, pin), (run_command, run), (handoff_command, handoff),
                            (reconcile_command, reconcile_references)]:
        command.set_defaults(action=action)
        command.add_argument("journal")
        command.add_argument("pass_file", metavar="pass")
    pin_command.add_argument("archive")
    pin_command.add_argument("--require-signature", default=None, metavar="PRINCIPAL",
                             help="pin only a revision that verify-approval verified for this principal")
    pin_command.add_argument("--allowed-signers", default=None, metavar="FILE",
                             help="the operator's trusted signers file (with --require-signature)")
    pin_command.add_argument("--signature", default=None, metavar="FILE",
                             help="the detached signature; default PASS.sig (with --require-signature)")
    handoff_command.add_argument("--ref-prefix", default=None, metavar="PREFIX",
                                 help="references this caller owns: a debit with it and no journal record needs attention")
    handoff_command.add_argument("--since", type=int, default=0, metavar="SEQ",
                                 help="look at ledger debits from this sequence number on")
    handoff_command.add_argument("--all", action="store_true", help="list the debits that are not this journal's")
    reconcile_command.add_argument("--reason", required=True, help="why the list is complete; recorded in the ledger")
    reconcile_command.add_argument("--also", action="append", default=[], metavar="JOURNAL",
                                   help="the journal of another caller that spent on this pass; repeat for each")
    reconcile_command.add_argument("--accept-shortfall", action="store_true",
                                   help="record even when the journals show fewer debits than the adoption carried")
    reconcile_command.add_argument("--rehearsal", action="store_true",
                                   help="keep HALLPASS_UNSAFE_TEST_CLOCK for a debug hallpass")
    run_command.add_argument("ref")
    run_command.add_argument("--to", action="append", required=True, type=target,
                             metavar="ADDR:PORT/PROTO[@NAME]", help="a literal endpoint; repeat for each")
    run_command.add_argument("--charge", action="append", required=True, type=charge,
                             metavar="COUNTER=N", help="one cost of the unit; repeat for each")
    run_command.add_argument("--duration", type=int, default=0, help="seconds the unit may send")
    run_command.add_argument("--outbox", default="outbox.jsonl", help="where the callback writes")
    run_command.add_argument("--rehearsal", action="store_true",
                             help="accept HALLPASS_UNSAFE_TEST_CLOCK replies from a debug hallpass")
    a = parser.parse_args()
    sys.exit(a.action(a))


if __name__ == "__main__":
    main()
