"""Run with python3 check.py, or adapt inspect_reply to your subprocess wrapper."""
import json
from pathlib import Path


def inspect_reply(code, stdout, expected, on_allowed, show_warning):
    """Check stdout against the pass_id, digest, counter, and n sent to spend."""
    if type(code) is not int:
        return "stop"
    try:
        reply = json.loads(stdout)
    except (ValueError, TypeError, UnicodeError):
        return "stop"
    if not isinstance(reply, dict):
        return "stop"
    if code == 1 and reply.get("command") == "spend" and reply.get("result") == "error":
        error = reply.get("error")
        if isinstance(error, dict) and error.get("recording") in ("recorded", "uncertain"):
            return "reconcile"
    if code != 0 or reply.get("command") != "spend" or reply.get("result") != "allowed":
        return "stop"
    if reply.get("test_clock") is not False or type(reply.get("seq")) is not int or reply["seq"] < 1:
        return "stop"
    if not isinstance(expected, dict):
        return "stop"
    for field, kind in (("pass_id", str), ("digest", str), ("counter", str), ("n", int)):
        wanted = expected.get(field)
        actual = reply.get(field)
        if type(wanted) is not kind or type(actual) is not kind or actual != wanted:
            return "stop"
    if not all(expected[field] for field in ("pass_id", "digest", "counter")) or expected["n"] < 1:
        return "stop"
    warnings = reply.get("warnings")
    if not isinstance(warnings, list) or any(not isinstance(w, str) for w in warnings):
        return "stop"
    for warning in warnings:
        show_warning(warning)
    on_allowed()
    return "proceed"


if __name__ == "__main__":
    import sys
    corpus = json.loads(Path(__file__).with_name("cases.json").read_text())
    assert corpus["version"] == 2
    cases = corpus["cases"]
    default_expected = corpus["expected"]
    # The CLI integration test supplies genuine process output on stdin.
    if sys.argv[1:] == ["--stdin-cases"]:
        cases = json.load(sys.stdin)
        default_expected = None
    for case in cases:
        calls, warnings = [], []
        action = inspect_reply(
            case["exit"], case["stdout"], case.get("expected", default_expected),
            lambda: calls.append(1), warnings.append,
        )
        if (action, len(calls), warnings) != (case["action"], int(case["action"] == "proceed"), case.get("warnings", [])):
            raise SystemExit("unexpected action for " + case["id"])
