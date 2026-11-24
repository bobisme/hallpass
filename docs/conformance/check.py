"""Reference spend-response decoder. Run python3 check.py for the offline corpora."""
import json
from pathlib import Path


def _charge_matches(row, expected):
    if not isinstance(row, dict) or not isinstance(expected, dict):
        return False
    return (isinstance(expected.get("counter"), str) and bool(expected["counter"])
            and row.get("counter") == expected["counter"]
            and type(expected.get("n")) is int and expected["n"] > 0
            and type(row.get("n")) is int and row["n"] == expected["n"])


def _balances_match(row):
    return (all(type(row.get(k)) is int for k in ("total", "spent", "remaining"))
            and row["n"] <= row["spent"] <= row["total"]
            and row["remaining"] == row["total"] - row["spent"])


def _matches_request(reply, expected):
    if not isinstance(expected.get("file"), str) or reply.get("file") != expected["file"]:
        return False
    mode = expected.get("mode")
    charges = expected.get("charges")
    if mode not in ("scalar", "charges") or not isinstance(charges, list) or not charges:
        return False
    # The scalar fields repeat the only charge of a one-counter unit. They are
    # null when the unit charges several counters, and older replies omit them.
    if mode == "scalar" or (len(charges) == 1 and reply.get("counter") is not None):
        if len(charges) != 1 or not _charge_matches(reply, charges[0]) or not _balances_match(reply):
            return False
    elif any(reply.get(key) is not None for key in ("counter", "n", "spent", "total", "remaining")):
        return False

    targets = expected.get("targets")
    rows = reply.get("targets")
    if not isinstance(targets, list) or not isinstance(rows, list) or len(rows) != len(targets):
        return False
    for target, row in zip(targets, rows):
        if not isinstance(target, dict) or not isinstance(row, dict):
            return False
        if not isinstance(target.get("target"), str) or not target["target"]:
            return False
        if "name" not in target or not (target["name"] is None or isinstance(target["name"], str)):
            return False
        if row.get("target") != target["target"] or "name" not in row or row["name"] != target["name"]:
            return False
        if not isinstance(row.get("label"), str) or not row["label"]:
            return False
    for key in ("target", "name", "label"):
        if key not in reply or reply[key] != (rows[0][key] if rows else None):
            return False

    reference = expected.get("caller_ref")
    record = expected.get("record_targets")
    if type(record) is not bool or (record and not targets):
        return False
    if reference is not None and (not isinstance(reference, str) or not reference):
        return False
    receipt = reply.get("receipt")
    if record or reference is not None:
        if not isinstance(receipt, dict) or receipt.get("caller_ref") != reference:
            return False
        retained = receipt.get("targets", [])
        if not isinstance(retained, list) or len(retained) != (len(rows) if record else 0):
            return False
        for item, row in zip(retained, rows):
            if not isinstance(item, dict) or any(item.get(k) != row[k] for k in ("target", "name", "label")):
                return False
    elif receipt is not None:
        return False

    if mode == "charges" or record or reference is not None or "charges" in reply:
        actual = reply.get("charges")
        if not isinstance(actual, list) or len(actual) != len(charges):
            return False
        if not all(_charge_matches(row, cost) and _balances_match(row) for row, cost in zip(actual, charges)):
            return False
        if len({cost["counter"] for cost in charges}) != len(charges):
            return False
        if any(row.get("projected_spent") is not None for row in actual):
            return False
        if reply.get("counter") is not None:
            for key in ("total", "spent", "remaining"):
                if type(reply.get(key)) is not int or type(actual[0].get(key)) is not int or reply[key] != actual[0][key]:
                    return False
    return (reply.get("note") == expected.get("note") and reply.get("projected_spent") is None
            and reply.get("refusal") is None and reply.get("refused_target") is None)


def _unique_members(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate JSON member {name!r}")
        result[name] = value
    return result


def _reject_constant(token):
    raise ValueError(f"invalid JSON number {token}")


def _inspect(code, stdout, expected, on_allowed, show_warning, matches):
    if type(code) is not int:
        return "stop"
    try:
        reply = json.loads(stdout, object_pairs_hook=_unique_members, parse_constant=_reject_constant)
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
    for field in ("pass_id", "digest"):
        if not isinstance(expected.get(field), str) or not expected[field] or reply.get(field) != expected[field]:
            return "stop"
    if not matches(reply, expected):
        return "stop"
    warnings = reply.get("warnings")
    if not isinstance(warnings, list) or any(not isinstance(w, str) for w in warnings):
        return "stop"
    for warning in warnings:
        show_warning(warning)
    on_allowed()
    return "proceed"


def inspect_reply(code, stdout, expected, on_allowed, show_warning):
    """Bind a committed reply to the complete expected unit before advancing."""
    return _inspect(code, stdout, expected, on_allowed, show_warning, _matches_request)


def _legacy_reply(code, stdout, expected, on_allowed, show_warning):
    return _inspect(code, stdout, expected, on_allowed, show_warning, _charge_matches)


def _run(cases, default_expected, inspect):
    """Check every case; return how many passed."""
    for case in cases:
        calls, warnings = [], []
        action = inspect(case["exit"], case["stdout"], case.get("expected", default_expected),
                         lambda: calls.append(1), warnings.append)
        if (action, len(calls), warnings) != (case["action"], int(case["action"] == "proceed"), case.get("warnings", [])):
            raise SystemExit("unexpected action for " + case["id"])
    return len(cases)


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--stdin-cases"]:
        _run(json.load(sys.stdin), None, inspect_reply)
    else:
        passed = 0
        for name, version, matcher in [("cases-v2.json", 2, _legacy_reply), ("cases.json", 3, inspect_reply)]:
            corpus = json.loads(Path(__file__).with_name(name).read_text())
            assert corpus["version"] == version
            passed += _run(corpus["cases"], corpus["expected"], matcher)
        print(f"{passed} cases passed")
