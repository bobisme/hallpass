#![cfg(feature = "cli")]
use std::fs;
use std::process::Command;
use tempfile::tempdir;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const PASS: &str = r#"format = 1
id = "practice-a"
name = "loopback"
[approval]
owner = "owner"
reference = "bench"
operator = "operator"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false
[[destination]]
label = "loopback"
address = "127.0.0.1"
protocol = "tcp"
ports = [8080]
[ceilings]
calls = 2
"#;

fn spend(pass: &std::path::Path, home: &std::path::Path) -> serde_json::Value {
    let out = Command::new(BIN)
        .args([
            "--format",
            "json",
            "spend",
            pass.to_str().expect("path"),
            "calls",
            "--to",
            "127.0.0.1:8080/tcp",
        ])
        .env("HOME", home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z")
        .output()
        .expect("binary");
    serde_json::from_slice(&out.stdout).expect("json")
}

#[test]
fn practice_runs_are_isolated_and_restart_keeps_budget() {
    let dir = tempdir().expect("tempdir");
    let home = dir.path().join("home");
    fs::create_dir(&home).expect("home");
    let a = dir.path().join("a.pass.toml");
    fs::write(&a, PASS).expect("pass");
    assert_eq!(spend(&a, &home)["result"], "allowed");
    let b = dir.path().join("b.pass.toml");
    fs::write(&b, PASS.replace("practice-a", "practice-b")).expect("separate approval");
    assert_eq!(spend(&b, &home)["remaining"], 1);
    assert_eq!(spend(&a, &home)["remaining"], 0);
    assert_eq!(spend(&a, &home)["refusal"]["code"], "ceiling-reached");
    assert_eq!(spend(&b, &home)["remaining"], 0);
    let copy = dir.path().join("copy.pass.toml");
    fs::copy(&a, &copy).expect("copy");
    let output = Command::new(BIN)
        .args([
            "--format",
            "json",
            "spend",
            copy.to_str().expect("path"),
            "calls",
            "--to",
            "127.0.0.1:8080/tcp",
        ])
        .env("HOME", &home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z")
        .output()
        .expect("binary");
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(json["error"]["code"], "ledger-missing");
}
