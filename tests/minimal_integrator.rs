#![cfg(feature = "cli")]
//! Runs `docs/minimal-caller/minimal_caller.py` against the built binary: one
//! allowed unit, one destination outside the pass and one unit past the
//! ceiling. The ledger holds exactly the allowed unit.
//!
//! The caller runs with `--rehearsal` at a pinned `HALLPASS_UNSAFE_TEST_CLOCK`
//! (debug builds, or `--features test-clock`) and a private `HOME` and
//! `XDG_STATE_HOME`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const PASSFILE: &str = "engagement.pass.toml";
const WEB: &str = "192.0.2.10:443/tcp@app.example.org";
const PASS: &str = r#"format = 1
id = "web-2026-11"
name = "Web edge"
require_target_v1 = true

[approval]
owner = "Pat Owner"
reference = "email of 2026-11-19"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = 443
names = ["app.example.org"]

[ceilings]
requests = 1
"#;

fn caller(dir: &Path, to: &str, reference: &str) -> (Option<i32>, String, String) {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/minimal-caller/minimal_caller.py");
    let bin_dir = Path::new(BIN).parent().expect("binary directory");
    let mut paths = vec![bin_dir.to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let home = dir.join("home");
    let output = Command::new("python3")
        .arg("-I")
        .arg(script)
        .args(["--rehearsal", PASSFILE, to, reference])
        .current_dir(dir)
        .env("PATH", std::env::join_paths(paths).expect("PATH"))
        .env("HOME", &home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
        .env_remove("FORMAT")
        .env_remove("HALLPASS_FORMAT")
        .output()
        .expect("run the minimal caller");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    eprintln!("{to} {reference}\n{stdout}{stderr}");
    (output.status.code(), stdout, stderr)
}

#[test]
fn the_minimal_caller_sends_only_the_allowed_unit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    fs::create_dir(root.join("home")).expect("home");
    fs::set_permissions(root.join("home"), fs::Permissions::from_mode(0o700)).expect("mode");
    fs::write(root.join(PASSFILE), PASS).expect("pass");
    fs::set_permissions(root.join(PASSFILE), fs::Permissions::from_mode(0o600)).expect("mode");

    // One allowed unit: exit 0, and the work ran.
    let (code, stdout, _) = caller(root, WEB, "unit-1");
    assert_eq!(code, Some(0));
    assert_eq!(stdout, "sent unit-1\n");

    // A destination outside the pass: refused at the preflight, no work.
    let (code, stdout, stderr) = caller(root, "192.0.2.99:443/tcp", "unit-2");
    assert_eq!(code, Some(2));
    assert_eq!(stdout, "");
    assert!(stderr.contains("not in any destination"), "{stderr}");

    // The ceiling of one request is spent: refused by the spend, no work.
    let (code, stdout, stderr) = caller(root, WEB, "unit-3");
    assert_eq!(code, Some(2));
    assert_eq!(stdout, "");
    assert!(stderr.contains("ceiling"), "{stderr}");

    // The ledger holds the header and exactly the allowed unit.
    let ledger = fs::read_to_string(root.join(format!("{PASSFILE}.ledger"))).expect("ledger");
    let lines: Vec<Value> = ledger
        .lines()
        .map(|line| serde_json::from_str(line).expect("json"))
        .collect();
    assert_eq!(lines.len(), 2, "{ledger}");
    assert_eq!(lines[1]["event"], "debit");
    assert_eq!(lines[1]["seq"], 1);
    assert_eq!(lines[1]["receipt"]["caller_ref"], "unit-1");
}
