//! Evidence commands agree on recorded debit times and on what an older
//! copy of a ledger is called.
#![cfg(feature = "cli")]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

struct Fixture {
    dir: tempfile::TempDir,
    pass: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let pass = dir.path().join("approval");
        let body = format!(
            "{}\n[ceilings]\ncalls = 10\n",
            include_str!("../docs/review-approval.toml")
        );
        fs::write(&pass, body).expect("pass");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("chmod");
        Self { dir, pass }
    }

    fn path(&self) -> &str {
        self.pass.to_str().expect("utf8")
    }

    fn ledger(&self) -> String {
        format!("{}.ledger", self.path())
    }

    fn run(&self, clock: &str, args: &[&str]) -> (i32, Value) {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .arg("--json")
            .args(args)
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", clock)
            .output()
            .expect("run");
        let value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (out.status.code().expect("code"), value)
    }

    fn spend(&self, clock: &str, caller_ref: &str) {
        let (code, v) = self.run(
            clock,
            &["spend", self.path(), "calls", "--caller-ref", caller_ref],
        );
        assert_eq!(code, 0, "{v}");
    }
}

#[test]
fn ledger_and_receipt_give_the_same_sub_second_time() {
    let f = Fixture::new();
    let clock = "2026-11-20T09:00:00.123456789Z";
    f.spend(clock, "ref-1");
    let (code, receipt) = f.run(clock, &["receipt", f.path(), "--caller-ref", "ref-1"]);
    assert_eq!(code, 0, "{receipt}");
    let from_receipt = receipt["matches"][0]["time"].as_str().expect("time");
    assert!(from_receipt.contains(".123456789"), "{from_receipt}");
    let (code, ledger) = f.run(clock, &["ledger", f.path()]);
    assert_eq!(code, 0, "{ledger}");
    let times: Vec<&str> = ledger["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter_map(|e| e["time"].as_str())
        .collect();
    assert!(times.contains(&from_receipt), "{times:?} vs {from_receipt}");
}

#[test]
fn older_copy_is_shorter_in_both_commands() {
    let f = Fixture::new();
    let clock = "2026-11-20T09:00:00Z";
    f.spend(clock, "a");
    let old = f.dir.path().join("old.ledger");
    fs::copy(f.ledger(), &old).expect("copy");
    fs::set_permissions(&old, fs::Permissions::from_mode(0o600)).expect("chmod");
    f.spend(clock, "b");
    let (_, cp) = f.run(clock, &["checkpoint", f.path()]);
    let saved = f.dir.path().join("checkpoint.json");
    fs::write(&saved, cp.to_string()).expect("save");
    let old = old.to_str().expect("utf8");
    let (code, v) = f.run(
        clock,
        &["verify-checkpoint", old, saved.to_str().expect("utf8")],
    );
    assert_eq!(code, 2, "{v}");
    assert_eq!(v["result"], "mismatch");
    assert_eq!(v["relation"], "shorter");
    let (_, b) = f.run(clock, &["compare-backups", f.path(), old]);
    assert_eq!(b["candidates"][0]["relation"], "shorter", "{b}");
    // The full ledger is exact in both.
    let (code, v) = f.run(
        clock,
        &[
            "verify-checkpoint",
            &f.ledger(),
            saved.to_str().expect("utf8"),
        ],
    );
    assert_eq!((code, v["relation"].as_str()), (0, Some("exact")));
}
