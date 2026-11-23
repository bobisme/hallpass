#!/usr/bin/env python3
"""The smallest correct caller: preflight, spend before the work, strict reply check.

usage: minimal_caller.py [--rehearsal] PASS ADDRESS:PORT/PROTOCOL REF
Exit: 0 the work ran | 2 hallpass refused, no work | 3 reconcile first | 1 stop.
The work is a print. Replace do_work() with the one unit that sends traffic.
--rehearsal is for tests with a debug hallpass and HALLPASS_UNSAFE_TEST_CLOCK.
"""
import json, os, subprocess, sys
from pathlib import Path

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
code, out = hallpass("permits", "--to", to, "--", pass_file)
if code == 2:  # refused: show the message, do not send
    print("refused:", refusal_message(out), file=sys.stderr)
    sys.exit(2)
try:
    pre = json.loads(out)
    target = {"target": pre["targets"][0]["target"], "name": pre["targets"][0]["name"]}
    assert code == 0 and pre["command"] == "permits" and len(pre["targets"]) == 1
except (ValueError, KeyError, IndexError, TypeError, AssertionError):
    sys.exit("stop: preflight failed")

# 2. Spend before the work. The reply must match this expected object exactly.
expected = {"file": pass_file, "pass_id": pre["pass_id"], "digest": pre["digest"], "mode": "scalar",
            "charges": [{"counter": "requests", "n": 1}], "targets": [target],
            "record_targets": False, "caller_ref": ref, "note": None}
dest = target["target"] + ("@" + target["name"] if target["name"] else "")
code, out = hallpass("spend", "--digest", pre["digest"], "--caller-ref", ref, "--require-new-ref",
                     "--to", dest, "--n", "1", "--", pass_file, "requests")
if rehearsal:  # a debug build says test_clock = true; accept that one field in tests only
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
