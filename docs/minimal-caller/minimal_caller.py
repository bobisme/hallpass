#!/usr/bin/env python3
"""The smallest correct caller: preflight, spend before the work, strict reply check.

usage: minimal_caller.py [--rehearsal] PASS ADDRESS:PORT/PROTOCOL REF
Exit: 0 the work ran | 2 hallpass refused, no work | 3 reconcile first | 1 stop.
The work is a print. Replace do_work() with the one unit that sends traffic.
--rehearsal is for tests with a debug hallpass and HALLPASS_UNSAFE_TEST_CLOCK.
It stops before the spend if the preflight says test_clock is false (a release
build ignores the variable and would debit live); without it, a test clock stops it.

What the digest pin protects. By default the caller pins the digest that its own
preflight (`permits`) saw, and `spend --digest` refuses if the pass changed
after that. That closes the gap between preflight and spend. It does not say
that the bytes were reviewed or signed: an edit made before the preflight, or
a torn in-place save that the preflight itself read (the settle time is 250 ms),
is pinned as it is. To pin the bytes a person reviewed or verified earlier, set
HALLPASS_REVIEWED_DIGEST to that digest (for example the `digest` that
`verify-approval` printed). Then the preflight asks `permits --digest` too, and
a pass that differs is refused with `pass-changed` before any spend. For a
journaled pin that requires a verified signature, use the reference caller.
"""
import json, os, subprocess, sys
from pathlib import Path

sys.dont_write_bytecode = True  # keep __pycache__ out of the docs tree
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "conformance"))
from check import inspect_reply  # the strict decoder INTEGRATING.md requires

rehearsal = "--rehearsal" in sys.argv
pass_file, to, ref = [a for a in sys.argv[1:] if a != "--rehearsal"]
env = dict(os.environ)
if not rehearsal:
    env.pop("HALLPASS_UNSAFE_TEST_CLOCK", None)  # a live caller never pins the clock


def hallpass(*args):  # no shell; (None, b"") if hallpass did not run
    try:
        done = subprocess.run(["hallpass", "--format", "json", *args], env=env, stdout=subprocess.PIPE)
    except OSError:
        return None, b""
    return done.returncode, done.stdout


def refusal_message(out):
    try:
        return json.loads(out)["refusal"]["message"]
    except (ValueError, KeyError, TypeError):
        return "no message"


def do_work():
    print(f"sent {ref}")  # the traffic goes here, only after an allowed spend


# 1. Preflight: hallpass gives the canonical target spelling, the pass id and the digest.
#    With HALLPASS_REVIEWED_DIGEST set, the digest is the reviewed one, not what is on disk now.
reviewed = os.environ.get("HALLPASS_REVIEWED_DIGEST")
code, out = hallpass("permits", "--to", to, *(["--digest", reviewed] if reviewed else []), "--", pass_file)
if code == 2:  # refused: show the message, do not send
    print("refused:", refusal_message(out), file=sys.stderr)
    sys.exit(2)
try:
    pre = json.loads(out)
    # A rehearsal needs a hallpass that honours the test clock; a live one needs a hallpass that does not.
    if pre.get("test_clock") is not rehearsal:
        sys.exit("stop: " + ("--rehearsal, but this hallpass uses the real clock (a release build ignores "
                 "HALLPASS_UNSAFE_TEST_CLOCK), so a spend would be live; use a debug build"
                 if rehearsal else "this hallpass reports a test clock, but this is not a rehearsal"))
    target = {"target": pre["targets"][0]["target"], "name": pre["targets"][0]["name"]}
    assert code == 0 and pre["command"] == "permits" and len(pre["targets"]) == 1
    assert reviewed is None or pre["digest"] == reviewed  # the pin is the reviewed digest
except (ValueError, KeyError, IndexError, TypeError, AttributeError, AssertionError):
    sys.exit("stop: preflight failed")

# 2. Spend before the work. The reply must match this expected object exactly.
expected = {"file": pass_file, "pass_id": pre["pass_id"], "digest": pre["digest"], "mode": "scalar",
            "charges": [{"counter": "requests", "n": 1}], "targets": [target],
            "record_targets": False, "caller_ref": ref, "note": None}
dest = target["target"] + ("@" + target["name"] if target["name"] else "")
code, out = hallpass("spend", "--digest", pre["digest"], "--caller-ref", ref, "--require-new-ref",
                     "--to", dest, "--n", "1", "--", pass_file, "requests")
if rehearsal and code == 0:  # a debug build says test_clock = true; accept that one field in tests only
    if b'"test_clock":true' not in out:  # the preflight said true, so this is not expected: a debit may exist
        print("reconcile: rehearsal, but the spend reply is not on the test clock; the debit is live. "
              "Do not send; look up this ref with hallpass receipt", file=sys.stderr)
        sys.exit(3)
    out = out.replace(b'"test_clock":true', b'"test_clock":false')

# 3. Strict check, then the work. Only "proceed" may send.
verdict = inspect_reply(code, out, expected, lambda: None, lambda w: print("warning:", w, file=sys.stderr))
if verdict == "proceed":
    do_work()
elif code == 2:  # refused: nothing was recorded, do not send
    print("refused:", refusal_message(out), file=sys.stderr)
    sys.exit(2)
elif verdict == "reconcile":  # a debit may exist: never retry, see EVIDENCE.md
    print("reconcile: the spend may be recorded; look up this ref with hallpass receipt", file=sys.stderr)
    sys.exit(3)
else:  # error, crash, odd reply: unknown outcome, do not send
    sys.exit("stop: unknown outcome, do not send")
