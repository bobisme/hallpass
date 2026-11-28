//! Clap errors use hallpass's usage shape, and a warning two sources report
//! is listed once (polish, round 17).
#![cfg(feature = "cli")]

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

const NEGATIVE: &str = "`--duration` needs a value; a negative value is not allowed";

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .args(args)
        .env("HOME", dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z")
        .output()
        .expect("run hallpass")
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).expect("json reply")
}

/// A pass from the docs template, dated `ahead` from now.
fn pass_dated(dir: &Path, modified: SystemTime) -> std::path::PathBuf {
    let pass = dir.join("approval");
    let body = format!(
        "{}\n[ceilings]\ncalls = 10\n",
        include_str!("../docs/review-approval.toml")
    );
    fs::write(&pass, body).expect("pass");
    fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("private pass");
    File::options()
        .write(true)
        .open(&pass)
        .and_then(|file| file.set_modified(modified))
        .expect("date the pass");
    pass
}

fn count(list: &serde_json::Value, needle: &str) -> usize {
    list.as_array()
        .expect("warnings")
        .iter()
        .filter(|w| w.as_str().is_some_and(|s| s.contains(needle)))
        .count()
}

#[test]
fn a_negative_option_value_gets_one_sentence_in_text_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &[
            "permits",
            "p.toml",
            "--to",
            "192.0.2.10:443/tcp",
            "--duration",
            "-5",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr,
        format!("hallpass permits: error: usage: {NEGATIVE}\nNothing was permitted.\n"),
    );
}

#[test]
fn a_negative_option_value_gets_one_line_headline_in_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &[
            "--json",
            "permits",
            "p.toml",
            "--to",
            "192.0.2.10:443/tcp",
            "--duration",
            "-5",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let reply = json(&out);
    assert_eq!(reply["command"], "permits");
    assert_eq!(reply["error"]["code"], "usage");
    assert_eq!(reply["error"]["headline"], NEGATIVE);
    assert_eq!(reply["error"]["recording"], "not-recorded");
}

#[test]
fn the_equals_spelling_gives_the_same_shape_as_a_bad_number() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &[
            "permits",
            "p.toml",
            "--to",
            "192.0.2.10:443/tcp",
            "--duration=-5",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 2, "{stderr}");
    assert!(
        lines[0].starts_with("hallpass permits: error: usage: invalid value '-5' for '--duration"),
        "{stderr}"
    );
    assert_eq!(lines[1], "Nothing was permitted.");
}

#[test]
fn other_clap_errors_keep_clap_detail_after_hallpass_headline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), &["spend", "p.toml", "calls", "--bogus"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.starts_with("hallpass spend: error: usage: unexpected argument '--bogus' found\n"),
        "{stderr}"
    );
    assert!(stderr.contains("\n  Usage: hallpass spend"), "{stderr}");
    assert!(stderr.ends_with("Nothing was permitted.\n"), "{stderr}");
    assert!(!stderr.contains("For more information"), "{stderr}");

    let out = run(
        dir.path(),
        &["--json", "spend", "p.toml", "calls", "--bogus"],
    );
    let reply = json(&out);
    assert_eq!(
        reply["error"]["headline"],
        "unexpected argument '--bogus' found"
    );
    assert!(
        !reply["error"]["headline"]
            .as_str()
            .unwrap_or_default()
            .contains('\n')
    );
    assert_eq!(reply["command"], "spend");
}

#[test]
fn an_unknown_subcommand_has_no_command_prefix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), &["frobnicate"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.starts_with("hallpass: error: usage: unrecognized subcommand 'frobnicate'\n"),
        "{stderr}"
    );
    let out = run(dir.path(), &["--json", "frobnicate"]);
    let reply = json(&out);
    assert_eq!(
        reply["error"]["headline"],
        "unrecognized subcommand 'frobnicate'"
    );
    assert!(reply["command"].is_null(), "{reply}");
}

#[test]
fn no_command_still_lists_the_commands_in_text_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), &[]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Usage: hallpass [OPTIONS] <COMMAND>"),
        "{stderr}"
    );
    assert!(stderr.contains("Commands:"), "{stderr}");
}

#[test]
fn a_future_pass_warns_once_in_each_command() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ahead = SystemTime::now() + Duration::from_secs(3600);
    let pass = pass_dated(dir.path(), ahead);
    let pass = pass.to_str().expect("utf-8 path");
    let needle = "which is in the future";

    let status = json(&run(dir.path(), &["--json", "status", pass]));
    assert_eq!(count(&status["warnings"], needle), 1, "{status}");

    let permits = run(
        dir.path(),
        &["--json", "permits", pass, "--to", "192.0.2.10:443/tcp"],
    );
    let reply = json(&permits);
    assert_eq!(count(&reply["warnings"], needle), 1, "{reply}");

    let permits_text = run(dir.path(), &["permits", pass, "--to", "192.0.2.10:443/tcp"]);
    let stderr = String::from_utf8_lossy(&permits_text.stderr);
    assert_eq!(stderr.matches(needle).count(), 1, "{stderr}");

    let spend = json(&run(dir.path(), &["--json", "spend", pass, "calls"]));
    assert_eq!(count(&spend["warnings"], needle), 1, "{spend}");
}

#[test]
fn a_repeated_warning_is_dropped_but_order_is_kept() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ahead = SystemTime::now() + Duration::from_secs(3600);
    let pass = pass_dated(dir.path(), ahead);
    let pass = pass.to_str().expect("utf-8 path");
    let out = json(&run(dir.path(), &["--json", "status", pass]));
    let warnings = out["warnings"].as_array().expect("warnings");
    let distinct: std::collections::BTreeSet<String> =
        warnings.iter().map(ToString::to_string).collect();
    assert_eq!(distinct.len(), warnings.len(), "{warnings:?}");
    let stderr = String::from_utf8_lossy(&run(dir.path(), &["status", pass]).stderr).into_owned();
    assert_eq!(
        stderr.matches("which is in the future").count(),
        1,
        "{stderr}"
    );
}
