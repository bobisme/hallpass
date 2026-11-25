//! `diff` says what changed when the digests differ and no declared field does.
#![cfg(feature = "cli")]

use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

const BASE: &str = include_str!("../docs/review-approval.toml");

fn write_pass(dir: &Path, file: &str, text: &str) {
    let path = dir.join(file);
    fs::write(&path, text).expect("pass");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    // A pass written less than 250 ms ago is read again; backdate it.
    fs::File::options()
        .write(true)
        .open(&path)
        .and_then(|f| f.set_modified(SystemTime::now() - Duration::from_secs(60)))
        .expect("backdate");
}

/// The text and JSON replies of `diff old new`, which exits 0.
fn diff(old: &str, new: &str) -> (String, Value) {
    let dir = tempfile::tempdir().expect("dir");
    write_pass(dir.path(), "old", old);
    write_pass(dir.path(), "new", new);
    let run = |json: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        if json {
            cmd.arg("--json");
        }
        let out = cmd
            .args(["diff", "old", "new"])
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .output()
            .expect("run");
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        String::from_utf8(out.stdout).expect("utf8")
    };
    let text = run(false);
    let value = serde_json::from_str(&run(true)).expect("json");
    (text, value)
}

const SAME: &str = "The digests differ, but no declared field does: the files differ only in";

fn assert_same_fields(text: &str, value: &Value) {
    assert_ne!(value["old_digest"], value["new_digest"], "{value}");
    assert_eq!(value["same_declared_fields"], true, "{value}");
    assert_eq!(value["changes"], json!([]), "{value}");
    assert_eq!(text.matches(SAME).count(), 1, "{text}");
    assert!(
        text.ends_with("This is a declared-field diff only; it never authorizes a spend.\n"),
        "{text}"
    );
}

#[test]
fn a_comment_only_change_is_named_and_the_comments_are_shown_escaped() {
    let new = BASE
        .replace(
            "# Historical documentation fixture for the offline owner case suite.\n",
            "",
        )
        .replace("revoked = false\n", "revoked = false # owner said \"ok\"\n");
    // A pass refuses hidden characters even in comments (bn-3qp), so a
    // backslash shows the escaping instead.
    let new = format!("{new}# owner also approved port 22 by phone, see C:\\notes\n");
    let (text, value) = diff(BASE, &new);
    assert_same_fields(&text, &value);
    assert_eq!(value["text_changes"], json!(["comments"]), "{value}");
    assert!(
        text.contains(&format!(
            "{SAME} comments (added, removed, changed or moved).\n"
        )),
        "{text}"
    );
    assert_eq!(
        value["comment_changes"],
        json!([
            {"change": "removed", "line": 1, "text": "# Historical documentation fixture for the offline owner case suite."},
            {"change": "added", "line": 10, "text": "# owner said \"ok\""},
            {"change": "added", "line": 17, "text": "# owner also approved port 22 by phone, see C:\\notes"},
        ]),
        "{value}"
    );
    for line in [
        "Comment removed (OLD line 1): \"# Historical documentation fixture for the offline owner case suite.\"\n",
        "Comment added (NEW line 10): \"# owner said \\\"ok\\\"\"\n",
        "Comment added (NEW line 17): \"# owner also approved port 22 by phone, see C:\\\\notes\"\n",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
    assert!(!text.contains("C:\\notes"), "{text}");
}

#[test]
fn an_offset_only_change_is_a_value_written_another_way() {
    let new = BASE.replace(
        "valid_until = 2026-11-20T17:00:00Z",
        "valid_until = 2026-11-20T22:30:00+05:30",
    );
    let (text, value) = diff(BASE, &new);
    assert_same_fields(&text, &value);
    assert_eq!(value["text_changes"], json!(["value-spelling"]), "{value}");
    assert_eq!(value["comment_changes"], json!([]), "{value}");
    assert!(
        text.contains(&format!(
            "{SAME} values written another way (such as a time with another offset, or a list in another order).\n"
        )),
        "{text}"
    );
    assert!(!text.contains("Comment "), "{text}");
}

#[test]
fn a_key_order_only_change_is_layout() {
    let new = BASE.replace(
        "owner = \"Example owner\"\nreference = \"Documentation fixture\"\n",
        "reference = \"Documentation fixture\"\nowner = \"Example owner\"\n",
    );
    assert_ne!(new, BASE);
    let (text, value) = diff(BASE, &new);
    assert_same_fields(&text, &value);
    assert_eq!(value["text_changes"], json!(["layout"]), "{value}");
    assert_eq!(value["comment_changes"], json!([]), "{value}");
    assert!(
        text.contains(&format!(
            "{SAME} whitespace or layout (spacing, line breaks, key order, or the form of a table or list).\n"
        )),
        "{text}"
    );
}

#[test]
fn several_kinds_are_named_together() {
    let new = BASE
        .replace("revoked = false\n", "revoked = false\n\n# checked\n")
        .replace(
            "valid_from = 2026-11-20T08:00:00Z",
            "valid_from = 2026-11-20T09:00:00+01:00",
        );
    let (text, value) = diff(BASE, &new);
    assert_same_fields(&text, &value);
    assert_eq!(
        value["text_changes"],
        json!(["comments", "layout", "value-spelling"]),
        "{value}"
    );
    assert!(
        text.contains("comments (added, removed, changed or moved), whitespace or layout"),
        "{text}"
    );
    assert!(text.contains("layout (spacing, line breaks, key order, or the form of a table or list), and values written another way"), "{text}");
}

#[test]
fn identical_files_and_declared_changes_add_no_line() {
    let (text, value) = diff(BASE, BASE);
    assert_eq!(value["same_declared_fields"], true, "{value}");
    assert_eq!(value["text_changes"], json!([]), "{value}");
    assert!(!text.contains(SAME), "{text}");

    // A declared change hides the comment changes beside it: the field diff is the review.
    let new = format!(
        "{}# and port 444\n",
        BASE.replace("ports = 443", "ports = [443, 444]")
    );
    let (text, value) = diff(BASE, &new);
    assert_eq!(value["same_declared_fields"], false, "{value}");
    assert_eq!(value["text_changes"], json!([]), "{value}");
    assert_eq!(value["comment_changes"], json!([]), "{value}");
    assert!(!text.contains(SAME), "{text}");
    assert!(
        text.contains("destination[web].ports: 443 -> 443-444"),
        "{text}"
    );
}
