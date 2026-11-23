//! Integration tests for the order of counter checks: a counter the pass
//! does not know is named before a missing required counter, on every debit
//! shape the CLI offers. Helpers are copied from tests/cli.rs.

use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const CLOCK: &str = "HALLPASS_UNSAFE_TEST_CLOCK";
/// Inside the window of `METERED_SCANS`.
const NOW: &str = "2026-11-20T09:00:00Z";

/// Required counters on a pass that also meters scans.
const METERED_SCANS: &str = r#"format = 1
id = "metered-scans"
name = "Metered API and scans"
required_counters_v1 = ["requests", "bytes"]

[approval]
owner = "Example owner"
reference = "Documentation fixture"
operator = "Example reviewer"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = 443

[ceilings]
requests = 5
bytes = 100
scans = 3
"#;

struct Case {
    dir: tempfile::TempDir,
}

thread_local! {
    /// The home directory of the current test's newest [`Case`].
    static HOME: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        fs::create_dir(&home).expect("home");
        HOME.with(|h| *h.borrow_mut() = Some(home));
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write a pass file, mode 0600.
    fn pass(&self, name: &str, text: &str) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        path
    }
}

/// A command for the binary, with the environment of the current case.
fn hallpass() -> Command {
    let home = HOME
        .with(|h| h.borrow().clone())
        .expect("create a Case before running hallpass");
    let mut command = Command::new(BIN);
    command
        .env_remove(CLOCK)
        .env_remove("FORMAT")
        .env_remove("HALLPASS_FORMAT")
        .env("HOME", &home)
        .env("XDG_STATE_HOME", home.join("state"));
    command
}

fn run(args: &[&str], now: Option<&str>) -> Output {
    let mut command = hallpass();
    command.args(args);
    if let Some(now) = now {
        command.env(CLOCK, now);
    }
    command.output().expect("run hallpass")
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("exit code")
}

/// Run with `--format json`; return the exit code and the parsed object.
fn json(args: &[&str], now: Option<&str>) -> (i32, Value) {
    let mut all = vec!["--format", "json"];
    all.extend_from_slice(args);
    let output = run(&all, now);
    let stdout = String::from_utf8(output.stdout.clone()).expect("utf8");
    let value: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "not JSON ({e}): {stdout:?} / stderr {:?}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (code(&output), value)
}

fn s(path: &Path) -> &str {
    path.to_str().expect("utf8 path")
}

#[test]
fn a_misspelt_counter_is_unknown_before_the_missing_required_counter() {
    let case = Case::new();
    let file = case.pass("rc.toml", METERED_SCANS);
    // `scan` is a typo for `scans`; the request has no `bytes` either.
    let (rc, out) = json(
        &["spend", s(&file), "scan", "--to", "192.0.2.10:443/tcp"],
        Some(NOW),
    );
    assert_eq!(rc, 2, "{out}");
    assert_eq!(out["result"], "refused", "{out}");
    assert_eq!(out["refusal"]["code"], "unknown-counter", "{out}");
    let message = out["refusal"]["message"].as_str().expect("message");
    assert!(message.contains("`scan`"), "names the typo: {message}");
    assert!(
        !message.contains("must charge"),
        "does not report the required counter first: {message}"
    );
    // Nothing was recorded.
    assert_eq!(out["seq"], Value::Null, "{out}");
}

#[test]
fn a_misspelt_counter_in_a_multi_charge_dry_run_is_unknown() {
    let case = Case::new();
    let file = case.pass("rc.toml", METERED_SCANS);
    let (rc, out) = json(
        &[
            "spend",
            s(&file),
            "--dry-run",
            "--charge",
            "requests=1",
            "--charge",
            "scan=1",
            "--to",
            "192.0.2.10:443/tcp",
        ],
        Some(NOW),
    );
    assert_eq!(rc, 2, "{out}");
    assert_eq!(out["refusal"]["code"], "unknown-counter", "{out}");
    assert!(
        out["refusal"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("`scan`")),
        "{out}"
    );
}

#[test]
fn a_valid_counter_without_the_required_one_is_still_refused() {
    let case = Case::new();
    let file = case.pass("rc.toml", METERED_SCANS);
    // Every name is a ceiling, but `bytes` is missing.
    let (rc, out) = json(
        &["spend", s(&file), "requests", "--to", "192.0.2.10:443/tcp"],
        Some(NOW),
    );
    assert_eq!(rc, 2, "{out}");
    assert_eq!(out["refusal"]["code"], "required-counter-missing", "{out}");
    assert!(
        out["refusal"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("`bytes`")),
        "{out}"
    );
    assert_eq!(out["seq"], Value::Null, "{out}");
}

#[test]
fn a_known_counter_set_with_every_required_counter_is_allowed() {
    let case = Case::new();
    let file = case.pass("rc.toml", METERED_SCANS);
    let (rc, out) = json(
        &[
            "spend",
            s(&file),
            "--charge",
            "requests=1",
            "--charge",
            "bytes=24",
            "--to",
            "192.0.2.10:443/tcp",
        ],
        Some(NOW),
    );
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["result"], "allowed", "{out}");
}

// ---- reconcile manifest errors ------------------------------------------

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// The text hallpass prints when `reconcile` refuses a manifest with `units`.
fn reconcile_refusal(case: &Case, units: &Value) -> String {
    let pass = case.pass("rc.toml", METERED_SCANS);
    let manifest = case.path("manifest.json");
    let body = serde_json::json!({"version": 1, "pass_id": "metered-scans", "units": units});
    fs::write(&manifest, body.to_string()).expect("manifest");
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).expect("chmod");
    let output = run(&["reconcile", s(&pass), s(&manifest)], Some(NOW));
    assert_eq!(code(&output), 1, "a manifest error is a usage error");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A valid row with the given caller reference and destinations.
fn row(caller_ref: &str, targets: &Value) -> Value {
    serde_json::json!({
        "caller_ref": caller_ref,
        "digest": DIGEST,
        "charges": [{"counter": "requests", "n": 1}, {"counter": "bytes", "n": 24}],
        "targets": targets,
    })
}

#[test]
fn a_non_canonical_name_names_its_row_field_value_and_canonical_form() {
    let case = Case::new();
    let units = serde_json::json!([
        row(
            "ref-1",
            &serde_json::json!([{"target": "192.0.2.10:443/tcp"}])
        ),
        row(
            "ref-2",
            &serde_json::json!([{"target": "192.0.2.10:443/tcp", "name": "App.Example.com"}]),
        ),
        row("ref-3", &serde_json::Value::Null),
    ]);
    let text = reconcile_refusal(&case, &units);
    assert!(
        text.contains(
            "manifest row 2 (caller_ref \"ref-2\"): targets[1].name is not canonical: \"App.Example.com\""
        ),
        "{text}"
    );
    assert!(text.contains("write `app.example.com`"), "{text}");
    assert!(text.contains("run reconcile again"), "{text}");
}

#[test]
fn a_non_canonical_address_names_its_row_field_value_and_canonical_form() {
    let case = Case::new();
    let units = serde_json::json!([row(
        "ref-1",
        &serde_json::json!([
            {"target": "192.0.2.10:443/tcp"},
            {"target": "[2001:DB8::10]:443/tcp"}
        ]),
    )]);
    let text = reconcile_refusal(&case, &units);
    assert!(
        text.contains(
            "manifest row 1 (caller_ref \"ref-1\"): targets[2].target is not canonical: \"[2001:DB8::10]:443/tcp\""
        ),
        "{text}"
    );
    assert!(text.contains("write `[2001:db8::10]:443/tcp`"), "{text}");
}

#[test]
fn a_repeated_caller_ref_names_both_rows_and_the_field() {
    let case = Case::new();
    let units = serde_json::json!([
        row("ref-1", &serde_json::Value::Null),
        row("ref-2", &serde_json::Value::Null),
        row("ref-1", &serde_json::Value::Null),
    ]);
    let text = reconcile_refusal(&case, &units);
    assert!(
        text.contains(
            "manifest row 3 (caller_ref \"ref-1\"): caller_ref repeats the caller_ref of row 1"
        ),
        "{text}"
    );
}

#[test]
fn an_escaped_value_is_shown_one_line_and_never_raw() {
    let case = Case::new();
    let units = serde_json::json!([row(
        "ref-1",
        &serde_json::json!([{"target": "192.0.2.10:443/tcp", "name": "bad\u{1b}[2J.example"}]),
    )]);
    let text = reconcile_refusal(&case, &units);
    assert!(text.contains("targets[1].name"), "{text}");
    assert!(text.contains("\\u{001b}"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
}
