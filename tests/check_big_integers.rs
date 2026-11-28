//! An integer too large for 64 bits is one problem on its own line, and the
//! other problems in the pass are still reported (bn-2tyx).
#![cfg(feature = "cli")]

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const TOO_BIG: &str = "18446744073709551616";

fn time_now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time")
            .as_secs(),
    )
    .expect("fits")
}

fn stamp(secs: i64) -> String {
    let t = hallpass::time::OffsetDateTime::from_unix_timestamp(secs).expect("instant");
    t.format(&hallpass::time::format_description::well_known::Rfc3339)
        .expect("RFC 3339")
}

/// A pass with no problems: live today, one destination, two ceilings.
fn valid_pass() -> String {
    let now = time_now();
    format!(
        r#"format = 1
id = "bigints"
name = "Big integers"

[approval]
owner = "Pat Owner"
reference = "email of today"
operator = "Eve Operator"
valid_from = {}
valid_until = {}
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = 443

[ceilings]
requests = 5
calls = 7
"#,
        stamp(now - 3_600),
        stamp(now + 6 * 3_600),
    )
}

fn write(dir: &Path, file: &str, body: &str) {
    let path = dir.join(file);
    fs::write(&path, body).expect("pass");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    File::options()
        .write(true)
        .open(&path)
        .and_then(|f| f.set_modified(SystemTime::now() - Duration::from_secs(60)))
        .expect("backdate");
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
        .output()
        .expect("run")
}

/// The `(field, message)` pairs that `check --json` reports for `body`.
fn problems(body: &str) -> Vec<(String, String)> {
    let tmp = tempfile::tempdir().expect("dir");
    write(tmp.path(), "p.toml", body);
    let out = run(tmp.path(), &["--json", "check", "p.toml"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    v["problems"]
        .as_array()
        .expect("problems")
        .iter()
        .map(|p| {
            (
                p["field"].as_str().expect("field").to_owned(),
                p["message"].as_str().expect("message").to_owned(),
            )
        })
        .collect()
}

#[test]
fn a_valid_base_pass_has_no_problems() {
    let tmp = tempfile::tempdir().expect("dir");
    write(tmp.path(), "p.toml", &valid_pass());
    let out = run(tmp.path(), &["check", "p.toml"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn an_overflowing_ceiling_with_other_mistakes_reports_all_of_them() {
    let body = valid_pass()
        .replace("id = \"bigints\"", "id = \"bad id\"")
        .replace("revoked = false", "revoked = \"no\"")
        .replace("ports = 443", "ports = 0")
        .replace("calls = 7", &format!("calls = 7\nbytes = {TOO_BIG}"));
    let found = problems(&body);
    let fields: Vec<&str> = found.iter().map(|(f, _)| f.as_str()).collect();
    assert_eq!(
        fields,
        [
            "ceilings.bytes",
            "id",
            "approval.revoked",
            "destination[1].ports"
        ],
        "{found:?}"
    );
    let (_, message) = &found[0];
    assert_eq!(
        message,
        &format!(
            "{TOO_BIG} is not a whole number from 0 to 1000000000000; write a ceiling in that range"
        )
    );
    assert!(
        !found.iter().any(|(_, m)| m.contains("not valid TOML")),
        "{found:?}"
    );
}

#[test]
fn a_pass_with_only_an_overflowing_ceiling_reports_exactly_one_problem() {
    let body = valid_pass().replace("calls = 7", &format!("calls = {TOO_BIG}"));
    let found = problems(&body);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, "ceilings.calls");
}

#[test]
fn every_overflowing_integer_is_its_own_problem() {
    let body = valid_pass()
        .replace("format = 1", "format = 99999999999999999999")
        .replace(
            "calls = 7",
            &format!("calls = {TOO_BIG}\nbytes = -{TOO_BIG}"),
        );
    let found = problems(&body);
    let fields: Vec<&str> = found.iter().map(|(f, _)| f.as_str()).collect();
    assert_eq!(
        fields,
        ["format", "ceilings.calls", "ceilings.bytes"],
        "{found:?}"
    );
}

#[test]
fn an_overflowing_port_is_one_problem_with_its_destination() {
    let body = valid_pass().replace("ports = 443", "ports = 99999999999999999999");
    let found = problems(&body);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, "destination[1].ports");
    assert!(found[0].1.contains("is not a port"), "{found:?}");
}
