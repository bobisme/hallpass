#!/usr/bin/env python3
"""Reference caller: one journaled unit of work, gated by hallpass.

    caller.py pin     JOURNAL PASS ARCHIVE
    caller.py run     JOURNAL PASS REF --to ADDR:PORT/PROTO[@NAME] --charge COUNTER=N
                      [--to ...] [--charge ...] [--duration S] [--outbox FILE] [--rehearsal]
    caller.py handoff JOURNAL PASS

The hallpass ledger is the authority for debits. The journal is the authority
for what this caller did. Python 3 standard library only. See README.md.
"""
import argparse
import json
import os
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
    return (reply.get("error") or {}).get("message", "no reply")


def append(journal, **record):
    """Append one record and force it to disk before the caller acts on it."""
    record = {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), **record}
    new = not os.path.exists(journal)
    fd = os.open(journal, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(record) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    if new:  # make the new directory entry durable too
        fd = os.open(os.path.dirname(os.path.abspath(journal)), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def read_journal(journal):
    """Every complete record. A crash can cut off the last line before its
    newline. The caller acts only on records already on disk, so it never
    acted on that one, and it is ignored."""
    try:
        data = Path(journal).read_bytes()
    except FileNotFoundError:
        return []
    return [json.loads(line) for line in data.split(b"\n")[:-1]]


def units(records, pass_file):
    """The records of each caller reference for this pass, in journal order."""
    out = {}
    for record in records:
        if "ref" in record:
            out.setdefault(record["ref"], []).append(record)
    return {ref: rs for ref, rs in out.items() if rs[0]["pass"] == pass_file}


def target(text):
    """ADDR:PORT/PROTO[@NAME] as the decoder expects it: canonical name or None."""
    literal, _, name = text.partition("@")
    return {"target": literal, "name": name.lower().removesuffix(".") or None}


def charge(text):
    counter, _, n = text.partition("=")
    if counter and n.isascii() and n.isdigit() and int(n) > 0:
        return {"counter": counter, "n": int(n)}
    raise argparse.ArgumentTypeError(f"expected COUNTER=N with N > 0, not {text!r}")


def pin(a):
    """Archive the reviewed bytes and pin their digest for the units that follow."""
    code, out = hallpass("archive", "--", a.pass_file, a.archive)
    archived = decode(out)
    if code != 0 or archived.get("result") != "ok":
        fail(f"archive failed: {message(archived)}")
    code, out = hallpass("digest", "--", a.pass_file)
    current = decode(out)
    if code != 0 or current.get("digest") != archived["digest"]:
        fail("the pass changed while it was archived; review it again")
    append(a.journal, event="pin", **{"pass": a.pass_file}, pass_id=current["pass_id"], digest=current["digest"])
    print(f"pinned {current['pass_id']} {current['digest']}")
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
    pins = [r for r in records if r["event"] == "pin" and r["pass"] == a.pass_file]
    if not pins:
        fail(f"no pin for {a.pass_file}; review the pass, then run `pin`")
    pinned = pins[-1]
    expected = {
        "file": a.pass_file, "pass_id": pinned["pass_id"], "digest": pinned["digest"],
        "mode": "charges", "charges": a.charge, "targets": a.to,
        "record_targets": True, "caller_ref": a.ref, "note": None,
    }
    append(a.journal, ref=a.ref, event="intent", **{"pass": a.pass_file}, pass_id=pinned["pass_id"],
           digest=pinned["digest"], targets=a.to, charges=a.charge, rehearsal=a.rehearsal)

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

    def dispatch():  # inspect_reply calls this only for a verified debit
        append(a.journal, ref=a.ref, event="spend", outcome="debited", seq=reply["seq"])
        append(a.journal, ref=a.ref, event="callback-start")
        send_unit(a.outbox, a.ref, a.to, a.charge)
        if INTERRUPT == "after-callback":
            os._exit(3)  # the unit ran, but its completion was never recorded
        append(a.journal, ref=a.ref, event="callback-done")

    def warn(message):
        print(f"hallpass warning: {message}", file=sys.stderr)

    action = check.inspect_reply(code, production_view(out) if a.rehearsal else out, expected, dispatch, warn)
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


def caller_record(records):
    """What the journal says this caller did for one reference."""
    events = [r["event"] for r in records]
    spend = next((r for r in records if r["event"] == "spend"), {})
    if spend.get("outcome") == "refused":
        return f"refused {spend['code']}"
    if "callback-done" in events:
        return "sent"
    if "callback-start" in events:
        return "unconfirmed"
    return "not sent" if spend.get("outcome") == "debited" else "unknown"


VERDICTS = {
    ("sent", "match"): "ok: debited and sent",
    ("refused", "absent"): "ok: refused, nothing debited or sent",
    ("unconfirmed", "match"): "ATTENTION: completion not recorded; check the target, do not repeat",
    ("not sent", "match"): "ATTENTION: debited, never sent; the debit stands",
    ("unknown", "match"): "ATTENTION: debited, never sent; the debit stands",
    ("unknown", "absent"): "ATTENTION: not debited, not sent; use a new reference to run it",
    ("refused", "match"): "ATTENTION: another run debited this reference; find its record",
    ("no record", "match"): "ATTENTION: no journal record; find the run record of this debit",
}


def handoff(a):
    """Every unit of this pass by reference: the caller's record beside the ledger's."""
    mine = units(read_journal(a.journal), a.pass_file)
    code, out = hallpass("ledger", "--", a.pass_file)
    ledger = decode(out)
    if code != 0 or ledger.get("verified") is not True:
        fail(f"the ledger could not be verified: {message(ledger)}")
    rows = {}
    if mine:
        manifest = {"version": 1, "pass_id": ledger["pass_id"], "units": [
            {"caller_ref": ref, "digest": rs[0]["digest"], "charges": rs[0]["charges"],
             "targets": rs[0]["targets"]} for ref, rs in mine.items()]}
        with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
            json.dump(manifest, f)
            f.flush()
            code, out = hallpass("reconcile", "--", a.pass_file, f.name)
        reply = decode(out)
        if code not in (0, 2) or not isinstance(reply.get("rows"), list):
            fail(f"reconcile failed: {message(reply)}")
        rows = {row["caller_ref"]: (row["result"], row["sequences"]) for row in reply["rows"]}

    table = [(ref, caller_record(rs), *rows[ref]) for ref, rs in mine.items()]
    for entry in ledger["entries"]:
        ref = (entry.get("receipt") or {}).get("caller_ref")
        if ref not in mine:
            table.append((ref or "(no reference)", "no record", "match", [entry["seq"]]))
    print(f"Handoff for {ledger['pass_id']} ({a.pass_file}) from {a.journal}")
    lines = []
    for ref, did, result, seqs in table:
        kind = "debit" if result == "match" else result
        found = "no debit" if result == "absent" else f"{kind} seq {','.join(map(str, seqs))}"
        state = "refused" if did.startswith("refused ") else did
        verdict = VERDICTS.get((state, result), "ATTENTION: journal and ledger disagree; reconcile by hand")
        lines.append((ref, did, found, verdict))
    widths = [max(len(line[i]) for line in lines) for i in range(3)] if lines else []
    for line in lines:
        print("  ".join(cell.ljust(w) for cell, w in zip(line, widths)) + "  " + line[3])
    spent = ", ".join(f"{t['name']} {t['spent']} of {t['total']}" for t in ledger["totals"])
    print(f"Ledger: {len(ledger['entries'])} debits, witness {ledger['witness']}. Spent: {spent}.")
    attention = sum(line[3].startswith("ATTENTION") for line in lines)
    print(f"{attention} need attention." if attention else "Nothing needs attention.")
    return 2 if attention else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(required=True)
    pin_command = commands.add_parser("pin", help="archive the reviewed pass and pin its digest")
    run_command = commands.add_parser("run", help="perform one unit of work")
    handoff_command = commands.add_parser("handoff", help="report every unit by reference")
    for command, action in [(pin_command, pin), (run_command, run), (handoff_command, handoff)]:
        command.set_defaults(action=action)
        command.add_argument("journal")
        command.add_argument("pass_file", metavar="pass")
    pin_command.add_argument("archive")
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
