#![cfg(feature = "cli")]

use std::{fmt::Write as _, fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

use serde_json::{Value, json};

const METERED: &str = include_str!("../docs/required-counters.toml");
const NOW: &str = "2026-11-20T09:00:00Z";
const WEB: &str = "192.0.2.10:443/tcp@app.example.org";
const COSTS: &[&str] = &["--charge", "requests=1", "--charge", "bytes=24"];

struct Fixture {
    dir: tempfile::TempDir,
    pass: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("directory");
        let pass = dir.path().join("pass");
        let f = Self { dir, pass };
        f.write_pass(10, 100, false);
        fs::set_permissions(&f.pass, fs::Permissions::from_mode(0o600)).expect("private pass");
        f
    }

    fn write_pass(&self, requests: u64, bytes: u64, target_required: bool) {
        let mut source = METERED
            .replace("requests = 5", &format!("requests = {requests}"))
            .replace("bytes = 100", &format!("bytes = {bytes}"));
        if target_required {
            source = source.replace(
                "required_counters_v1",
                "require_target_v1 = true\nrequired_counters_v1",
            );
        }
        fs::write(&self.pass, source).expect("write pass");
    }

    fn command(&self, command: &str, args: &[&str], code: i32) -> Value {
        self.at(command, args, code, NOW)
    }

    fn at(&self, command: &str, args: &[&str], code: i32, now: &str) -> Value {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .args(["--format", "json", command])
            .arg(&self.pass)
            .args(args)
            .env("HALLPASS_UNSAFE_TEST_CLOCK", now)
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .output()
            .expect("hallpass");
        assert_eq!(
            out.status.code(),
            Some(code),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        serde_json::from_slice(&out.stdout).expect("JSON")
    }
}

#[test]
fn count_matches_rehearsal_and_keeps_a_fresh_pass_untouched() {
    let f = Fixture::new();
    let mut args = vec!["--to", WEB, "--duration", "30"];
    args.extend(COSTS);
    let capacity = f.command("capacity", &args, 0);
    assert_eq!(capacity["result"], "capacity");
    assert_eq!(capacity["units"], 4);
    assert_eq!(capacity["limiting_counters"], json!(["bytes"]));
    assert_eq!(capacity["targets"][0]["label"], "web");
    assert_eq!(
        capacity["counters"],
        json!([
            {"counter":"requests","n":1,"total":10,"spent":0,"remaining":10,"units":10,"remaining_after":6},
            {"counter":"bytes","n":24,"total":100,"spent":0,"remaining":100,"units":4,"remaining_after":4}
        ])
    );
    assert!(capacity["unit_refusal"].is_null());
    let mut scenario = "version = 1\n".to_owned();
    for i in 1..=5 {
        writeln!(
            scenario,
            "\n[[step]]\nid = 'unit-{i}'\nat = '{NOW}'\nduration = 30\ntargets = ['{WEB}']\ncharges = [{{counter = 'requests', n = 1}}, {{counter = 'bytes', n = 24}}]"
        ).expect("scenario");
    }
    let path = f.dir.path().join("scenario");
    fs::write(&path, scenario).expect("scenario");
    let replay = f.command("rehearse", &[path.to_str().expect("path")], 2);
    assert_eq!(replay["stopped_at"], "unit-5");
    assert_eq!(replay["projected_spent"], json!({"requests":4,"bytes":96}));
    assert_eq!(replay["steps"][4]["refusal"]["code"], "ceiling-reached");
    assert!(!hallpass::ledger_path(&f.pass).exists());
    assert!(!f.dir.path().join("state").exists());
}

#[test]
fn exact_integer_count_handles_ties_zero_and_revised_ceilings() {
    let f = Fixture::new();
    for (requests, bytes, units) in [(4, 100, 4), (1, 24, 1), (10, 23, 0)] {
        f.write_pass(requests, bytes, false);
        let capacity = f.command("capacity", COSTS, 0);
        assert_eq!(capacity["units"], units);
        if units == 0 {
            assert_eq!(capacity["unit_refusal"]["code"], "ceiling-reached");
            assert_eq!(capacity["limiting_counters"], json!(["bytes"]));
        } else {
            assert_eq!(capacity["limiting_counters"], json!(["requests", "bytes"]));
        }
    }
    let max = hallpass::MAX_CEILING;
    f.write_pass(max, max, false);
    let capacity = f.command(
        "capacity",
        &["--charge", "requests=1", "--charge", "bytes=1"],
        0,
    );
    assert_eq!(capacity["units"], max);
    assert_eq!(capacity["limiting_counters"], json!(["requests", "bytes"]));
    let max_charge = format!("bytes={max}");
    let capacity = f.command(
        "capacity",
        &["--charge", "requests=1", "--charge", &max_charge],
        0,
    );
    assert_eq!(capacity["units"], 1);
    assert_eq!(capacity["counters"][1]["remaining_after"], 0);

    f.command(
        "spend",
        &["--charge", "requests=1", "--charge", "bytes=80"],
        0,
    );
    f.write_pass(10, 70, false);
    let capacity = f.command("capacity", COSTS, 0);
    assert_eq!(capacity["units"], 0);
    assert_eq!(capacity["counters"][1]["spent"], 80);
    assert_eq!(capacity["counters"][1]["remaining"], 0);
}

#[test]
fn policy_refusals_have_no_usable_count_even_if_a_known_charge_is_exhausted() {
    let f = Fixture::new();
    f.write_pass(10, 23, true);
    let good_target = ["--to", WEB];
    let mut scoped = COSTS.to_vec();
    scoped.extend(good_target);
    let mut outside = scoped.clone();
    outside.extend(["--to", "192.0.2.12:443/tcp"]);
    let mut unknown = scoped.clone();
    unknown.extend(["--charge", "other=1"]);
    let mut changed = scoped.clone();
    let wrong = hallpass::Digest::of(b"another revision").to_string();
    changed.extend(["--digest", &wrong]);
    let mut too_long = scoped.clone();
    too_long.extend(["--duration", "28801"]);
    for (args, reason) in [
        (COSTS, "target-required"),
        (outside.as_slice(), "address-not-listed"),
        (unknown.as_slice(), "unknown-counter"),
        (
            &["requests", "--n", "2", "--to", WEB],
            "required-counter-missing",
        ),
        (changed.as_slice(), "pass-changed"),
        (too_long.as_slice(), "window-too-short"),
    ] {
        let reply = f.command("capacity", args, 2);
        assert_eq!(reply["result"], "refused");
        assert_eq!(reply["refusal"]["code"], reason);
        assert!(reply["units"].is_null());
        if reason == "address-not-listed" {
            assert_eq!(reply["refused_target"], 2);
        }
    }
    let reply = f.at("capacity", &scoped, 2, "2026-11-20T17:00:00Z");
    assert_eq!(reply["refusal"]["code"], "expired");
    assert!(reply["units"].is_null());
    assert_eq!(
        f.command("capacity", &["--charge", "bytes=0"], 1)["result"],
        "error"
    );

    let source = METERED.replace("required_counters_v1 = [\"requests\", \"bytes\"]", "");
    fs::write(&f.pass, source).expect("legacy without required charges");
    let reply = f.command("capacity", &["requests", "--n", "2"], 0);
    assert_eq!(reply["units"], 2);
    assert_eq!(reply["limiting_counters"], json!(["requests"]));
    assert!(!hallpass::ledger_path(&f.pass).exists());
}
