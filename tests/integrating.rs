//! Runs the worked example of `docs/INTEGRATING.md`: writes the pass that
//! the document shows, runs every `$ hallpass` line of its `console` blocks
//! in order, and compares the exit code and the JSON fields shown. The
//! document is the test data, so it cannot drift from the tool.
//!
//! Like `tests/cli.rs`, this sets the clock with
//! `HALLPASS_UNSAFE_TEST_CLOCK` (debug builds, or `--features test-clock`)
//! and uses a private `HOME` and `XDG_STATE_HOME`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use serde_json::Value;

const DOC: &str = include_str!("../docs/INTEGRATING.md");
const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";

/// The bodies of the fenced blocks tagged `lang`, in order.
fn blocks(lang: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    let open = format!("```{lang}");
    for line in DOC.lines() {
        match current.as_mut() {
            None if line == open => current = Some(String::new()),
            None => {}
            Some(_) if line == "```" => out.extend(current.take()),
            Some(body) => {
                body.push_str(line);
                body.push('\n');
            }
        }
    }
    assert!(current.is_none(), "an unclosed {lang} block");
    out
}

/// One documented command: its arguments, exit code and the fields shown.
struct Step {
    args: Vec<String>,
    exit: i32,
    shown: Value,
}

fn steps() -> Vec<Step> {
    let mut out = Vec::new();
    for block in blocks("console") {
        let mut lines = block.lines();
        while let Some(line) = lines.next() {
            let command = line
                .strip_prefix("$ hallpass ")
                .unwrap_or_else(|| panic!("expected a `$ hallpass` line, found {line:?}"));
            assert!(
                !command.contains(['"', '\'', '\\', '$', '*']),
                "the example uses plain words only: {command}"
            );
            let exit = lines
                .next()
                .and_then(|l| l.strip_prefix("exit "))
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("an `exit N` line must follow {command:?}"));
            let shown = lines
                .next()
                .and_then(|l| serde_json::from_str(l).ok())
                .unwrap_or_else(|| panic!("one line of JSON must follow {command:?}"));
            out.push(Step {
                args: command.split_whitespace().map(str::to_owned).collect(),
                exit,
                shown,
            });
        }
    }
    out
}

/// Every field of `shown` is in `actual` with the same value; objects are
/// compared field by field, lists element by element.
fn assert_shown(shown: &Value, actual: &Value, at: &str) {
    match (shown, actual) {
        (Value::Object(want), Value::Object(have)) => {
            for (key, value) in want {
                let found = have
                    .get(key)
                    .unwrap_or_else(|| panic!("{at}: the output has no field `{key}`: {actual}"));
                assert_shown(value, found, &format!("{at}.{key}"));
            }
        }
        (Value::Array(want), Value::Array(have)) => {
            assert_eq!(want.len(), have.len(), "{at}: {actual}");
            for (i, (w, h)) in want.iter().zip(have).enumerate() {
                assert_shown(w, h, &format!("{at}[{i}]"));
            }
        }
        _ => assert_eq!(shown, actual, "{at}"),
    }
}

#[test]
fn the_worked_example_runs_as_documented() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    fs::create_dir(&home).expect("home");
    let pass = blocks("toml");
    assert_eq!(pass.len(), 1, "the document shows one pass");
    let file = dir.path().join("engagement.pass.toml");
    fs::write(&file, &pass[0]).expect("write");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("chmod");

    let steps = steps();
    assert!(steps.len() >= 9, "the example lost its commands");
    let mut results = Vec::new();
    for step in &steps {
        let output = Command::new(BIN)
            .args(&step.args)
            .current_dir(dir.path())
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("run hallpass");
        let at = step.args.join(" ");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(step.exit), "{at}: {stdout}");
        let actual: Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{at}: not one JSON object ({e}): {stdout:?}"));
        assert_shown(&step.shown, &actual, &at);
        // The rule the document gives a caller: both or neither.
        assert_eq!(
            step.exit == 0,
            matches!(actual["result"].as_str(), Some("allowed" | "ok")),
            "{at}"
        );
        results.push(actual["result"].as_str().unwrap_or_default().to_owned());
    }
    // The example shows every kind of answer.
    for kind in ["ok", "allowed", "refused", "error"] {
        assert!(
            results.iter().any(|r| r == kind),
            "no `{kind}` in the example"
        );
    }
    // Exactly the two recorded spends are in the ledger.
    let ledger =
        fs::read_to_string(dir.path().join("engagement.pass.toml.ledger")).expect("ledger");
    assert_eq!(ledger.lines().count(), 3, "a header and two entries");
}

#[test]
fn every_code_block_in_the_document_says_what_it_is() {
    // A bare fence would be compiled as Rust by the documentation tests.
    // The Rust example is compiled there and not run: it would spend from
    // a pass in the current directory.
    let mut inside = false;
    for line in DOC.lines() {
        if line.starts_with("```") {
            if !inside {
                assert!(
                    ["```toml", "```console", "```text", "```rust,no_run"].contains(&line),
                    "an untagged or unknown code block: {line:?}"
                );
            }
            inside = !inside;
        }
    }
    assert_eq!(blocks("rust,no_run").len(), 1);
}
