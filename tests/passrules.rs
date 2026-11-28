//! Counters that left the pass (bn-2vo), leading zeros in CLI numbers,
//! duplicate destinations and oversized integers in a pass (bn-2uy).
#![cfg(feature = "cli")]

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const TARGET: &str = "192.0.2.30:443/tcp";

fn pass_text() -> String {
    let now = time_now();
    format!(
        r#"format = 1
id = "passrules"
name = "Pass rules"

[approval]
owner = "Pat Owner"
reference = "email of today"
operator = "Eve Operator"
valid_from = {}
valid_until = {}
revoked = false

[[destination]]
label = "web"
address = "192.0.2.30"
protocol = "tcp"
ports = 443

[ceilings]
requests = 200
bytes = 5000
"#,
        stamp(now - 3600),
        stamp(now + 172_800)
    )
}

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

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn json(dir: &Path, args: &[&str]) -> Value {
    let mut all = vec!["--json"];
    all.extend_from_slice(args);
    serde_json::from_slice(&run(dir, &all).stdout).expect("json")
}

fn spent_dir(times: usize) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("dir");
    write(tmp.path(), "p.toml", &pass_text());
    for _ in 0..times {
        let out = run(
            tmp.path(),
            &[
                "spend", "--to", TARGET, "--n", "10", "--", "p.toml", "requests",
            ],
        );
        assert!(out.status.success(), "{}", text(&out));
    }
    tmp
}

fn rename_requests(dir: &Path) {
    write(
        dir,
        "p.toml",
        &pass_text().replace("requests = 200", "reqs = 200"),
    );
}

#[test]
fn a_renamed_counter_warns_at_spend_in_text_and_json() {
    let tmp = spent_dir(5);
    rename_requests(tmp.path());
    let args = ["spend", "--to", TARGET, "--", "p.toml", "reqs"];
    let v = json(tmp.path(), &args);
    assert_eq!(v["result"], "allowed", "{v}");
    let warnings = v["warnings"].as_array().expect("warnings");
    let w = warnings
        .iter()
        .filter_map(Value::as_str)
        .find(|w| w.contains("no longer has"))
        .unwrap_or_else(|| panic!("no warning in {v}"));
    assert!(w.contains("\"requests\" (50 spent)"), "{w}");
    assert!(w.contains("\"reqs\""), "{w}");
    assert!(w.contains("does not count against the new ceiling"), "{w}");
    let out = run(tmp.path(), &args);
    assert!(out.status.success());
    assert!(
        text(&out).contains("\"requests\" (50 spent)"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_renamed_counter_warns_at_a_charge_spend() {
    let tmp = spent_dir(2);
    rename_requests(tmp.path());
    let v = json(
        tmp.path(),
        &[
            "spend", "--to", TARGET, "--charge", "reqs=1", "--", "p.toml",
        ],
    );
    assert_eq!(v["result"], "allowed", "{v}");
    assert!(
        v["warnings"]
            .to_string()
            .contains("\"requests\\\" (20 spent)"),
        "{v}"
    );
}

#[test]
fn no_warning_when_no_counter_was_dropped() {
    let tmp = spent_dir(2);
    let v = json(
        tmp.path(),
        &["spend", "--to", TARGET, "--", "p.toml", "requests"],
    );
    assert_eq!(v["result"], "allowed", "{v}");
    assert_eq!(v["warnings"], serde_json::json!([]), "{v}");
}

#[test]
fn leading_zeros_in_cli_numbers_are_refused() {
    let tmp = spent_dir(0);
    let d = tmp.path();
    for args in [
        vec![
            "spend", "--to", TARGET, "--n", "010", "--", "p.toml", "requests",
        ],
        vec![
            "spend",
            "--to",
            TARGET,
            "--charge",
            "requests=007",
            "--",
            "p.toml",
        ],
        vec![
            "spend",
            "--lock-timeout-ms",
            "05",
            "--",
            "p.toml",
            "requests",
        ],
        vec!["spend", "--duration", "00", "--", "p.toml", "requests"],
        vec![
            "permits",
            "--to",
            TARGET,
            "--duration",
            "01",
            "--",
            "p.toml",
        ],
        vec!["ledger", "--tail", "02", "p.toml"],
    ] {
        let out = run(d, &args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", text(&out));
        assert!(
            text(&out).contains("leading zero"),
            "{args:?}: {}",
            text(&out)
        );
    }
    // Plain zero and ordinary numbers still work.
    let out = run(
        d,
        &["permits", "--to", TARGET, "--duration", "0", "--", "p.toml"],
    );
    assert!(out.status.success(), "{}", text(&out));
    let out = run(
        d,
        &[
            "spend", "--to", TARGET, "--n", "10", "--", "p.toml", "requests",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
}

#[test]
fn a_duplicate_destination_warns_in_check_and_lint() {
    let tmp = tempfile::tempdir().expect("dir");
    let twice = pass_text().replace(
        "[ceilings]",
        "[[destination]]\nlabel = \"web2\"\naddress = \"192.0.2.30\"\nprotocol = \"tcp\"\nports = 443\n\n[ceilings]",
    );
    write(tmp.path(), "p.toml", &twice);
    for command in ["check", "lint"] {
        let v = json(tmp.path(), &[command, "p.toml"]);
        assert_eq!(v["result"], "ok", "{v}");
        let w = v["warnings"].to_string();
        assert!(
            w.contains("`web2` repeats destination `web`"),
            "{command}: {v}"
        );
        let out = run(tmp.path(), &[command, "p.toml"]);
        assert!(
            text(&out).contains("`web2` repeats destination `web`"),
            "{}",
            text(&out)
        );
    }
    // A different port is not a repeat.
    write(
        tmp.path(),
        "q.toml",
        &twice.replace("ports = 443\n\n[ceilings]", "ports = 444\n\n[ceilings]"),
    );
    let v = json(tmp.path(), &["check", "q.toml"]);
    assert!(!v["warnings"].to_string().contains("repeats"), "{v}");
}

#[test]
fn oversized_integers_get_the_field_rule() {
    let tmp = tempfile::tempdir().expect("dir");
    for (find, replace, expect) in [
        (
            "requests = 200",
            "requests = 9223372036854775808",
            "ceilings.requests: 9223372036854775808 is not a whole number from 0 to 1000000000000",
        ),
        (
            "requests = 200",
            "requests = 18446744073709551615",
            "ceilings.requests: 18446744073709551615 is not a whole number from 0 to 1000000000000",
        ),
        (
            "ports = 443",
            "ports = 99999999999999999999",
            "destination[1].ports: 99999999999999999999 is not a port",
        ),
    ] {
        write(tmp.path(), "p.toml", &pass_text().replace(find, replace));
        let out = run(tmp.path(), &["check", "p.toml"]);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out));
        assert!(text(&out).contains(expect), "{}", text(&out));
        assert!(!text(&out).contains("not valid TOML"), "{}", text(&out));
    }
}
