//! Integration tests: run the built `hallpass` binary for every command and
//! every refusal path. The clock is set with `HALLPASS_UNSAFE_TEST_CLOCK`,
//! which debug builds (and `--features test-clock`) honour; no test sleeps.
//!
//! The witness state directory is never the real one: every run gets
//! `XDG_STATE_HOME` and `HOME` inside the temporary directory of the test's
//! current [`Case`], and a run outside any case panics.

use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const CLOCK: &str = "HALLPASS_UNSAFE_TEST_CLOCK";
/// Inside the window of `PASS`.
const NOW: &str = "2026-11-20T09:00:00Z";

const PASS: &str = r#"# A test pass. Documentation addresses only.
format = 1
id = "example-2026-11"
name = "Example voice edge"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "sip-edge"
address = "192.0.2.10"
protocol = "udp"
ports = [5060, "10000-10100"]
hostname = "sip.example.net"

[[destination]]
label = "web"
network = "2001:db8::/120"
protocol = "tcp"
ports = 443

[ceilings]
calls = 6
requests = 500
"#;

struct Case {
    dir: tempfile::TempDir,
}

thread_local! {
    /// The home directory of the current test's newest [`Case`]. Each test
    /// runs on its own thread.
    static HOME: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

impl Case {
    /// A fresh directory; from now on this thread's runs use its `home`
    /// (and `home/state` as `XDG_STATE_HOME`).
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        fs::create_dir(&home).expect("home");
        HOME.with(|h| *h.borrow_mut() = Some(home));
        Self { dir }
    }

    /// The state directory that hallpass uses in this case.
    fn state(&self) -> PathBuf {
        self.dir.path().join("home").join("state").join("hallpass")
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

/// A command for the binary with the environment of the current case.
fn hallpass() -> Command {
    let home = HOME.with(|h| h.borrow().clone()).expect(
        "create a Case before running hallpass: tests must never touch the real state directory",
    );
    assert!(
        home.is_dir(),
        "the case directory is gone: {}",
        home.display()
    );
    let mut command = Command::new(BIN);
    command
        .env_remove(CLOCK)
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

fn fields(value: &Value) -> Vec<String> {
    value["problems"]
        .as_array()
        .expect("problems")
        .iter()
        .map(|p| p["field"].as_str().expect("field").to_owned())
        .collect()
}

fn spend(file: &Path, counter: &str, now: &str) -> (i32, Value) {
    json(&["spend", s(file), counter], Some(now))
}

// ---- init --------------------------------------------------------------

#[test]
fn init_writes_private_template_that_permits_nothing() {
    let case = Case::new();
    let file = case.path("new.pass.toml");
    let (rc, out) = json(&["init", s(&file)], None);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["result"], "ok");
    let mode = fs::metadata(&file).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let (rc, out) = json(&["check", s(&file)], None);
    assert_eq!(rc, 1);
    assert!(fields(&out).contains(&"destination".to_owned()));
    let (rc, out) = json(
        &["permits", s(&file), "--to", "192.0.2.10:5060/udp"],
        Some(NOW),
    );
    assert_eq!(rc, 1, "{out}");
}

#[test]
fn init_never_overwrites() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let (rc, out) = json(&["init", s(&file)], None);
    assert_eq!(rc, 1);
    assert_eq!(out["error"]["code"], "exists");
    assert_eq!(fs::read_to_string(&file).expect("read"), PASS);
    let link = case.path("link.toml");
    std::os::unix::fs::symlink(case.path("target-does-not-exist"), &link).expect("symlink");
    let (rc, out) = json(&["init", s(&link)], None);
    assert_eq!(rc, 1);
    assert_eq!(out["error"]["code"], "exists");
    assert!(!case.path("target-does-not-exist").exists());
}

// ---- check -------------------------------------------------------------

#[test]
fn check_accepts_good_pass() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let (rc, out) = json(&["check", s(&file)], None);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["result"], "ok");
    assert_eq!(out["pass_id"], "example-2026-11");
    let text = run(&["check", s(&file)], None);
    assert_eq!(code(&text), 0);
    assert!(String::from_utf8_lossy(&text.stdout).contains("OK"));
}

fn check_problems(text: &str) -> Vec<(String, String)> {
    let case = Case::new();
    let file = case.pass("p.toml", text);
    let (rc, out) = json(&["check", s(&file)], None);
    assert_eq!(rc, 1, "{out}");
    assert_eq!(out["error"]["code"], "invalid-pass");
    out["problems"]
        .as_array()
        .expect("problems")
        .iter()
        .map(|p| {
            (
                p["field"].as_str().expect("f").to_owned(),
                p["message"].as_str().expect("m").to_owned(),
            )
        })
        .collect()
}

#[test]
fn check_refuses_unknown_key() {
    let p = check_problems(&PASS.replace("protocol = \"udp\"", "protocol = \"udp\"\nprots = 80"));
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].0, "destination[1].prots");
    assert!(p[0].1.contains("unknown key"));
}

#[test]
fn check_refuses_hostname_where_address_required() {
    let p =
        check_problems(&PASS.replace("address = \"192.0.2.10\"", "address = \"sip.example.net\""));
    assert_eq!(p[0].0, "destination[1].address");
    assert!(p[0].1.contains("host name"), "{p:?}");
}

#[test]
fn check_refuses_network_broader_than_cap() {
    let p = check_problems(&PASS.replace("2001:db8::/120", "2001:db8::/56"));
    assert_eq!(p[0].0, "destination[2].network");
    assert!(p[0].1.contains("breadth cap"), "{p:?}");
    let v4 = PASS.replace(
        "network = \"2001:db8::/120\"",
        "network = \"198.51.100.0/23\"",
    );
    assert!(check_problems(&v4)[0].1.contains("/24 breadth cap"));
    let case = Case::new();
    let approved = case.pass(
        "p.toml",
        &v4.replace("ports = 443", "ports = 443\nwhole_network_approved = true"),
    );
    assert_eq!(json(&["check", s(&approved)], None).0, 0);
}

#[test]
fn check_refuses_strict_spellings_and_special_addresses() {
    for (bad, hint) in [
        ("010.0.2.10", "leading zero"),
        ("192.0.2", "shortened"),
        ("::ffff:192.0.2.10", "carries the IPv4 address 192.0.2.10"),
        ("0.0.0.0", "unspecified"),
        ("224.0.0.5", "multicast"),
        ("255.255.255.255", "broadcast"),
        ("169.254.169.254", "link-local"),
        ("2001:DB8::1", "canonical"),
        (
            "2002:c000:20a::1",
            "6to4 address (2002::/16) that carries the IPv4 address 192.0.2.10",
        ),
        (
            "2001:0:c633:6401:8000:f227:34ff:8efa",
            "Teredo address (2001::/32) that carries the IPv4 address 203.0.113.5",
        ),
        ("2001:db8::5efe:c000:20a", "ISATAP"),
        ("::ffff:0:c000:20a", "IPv4-translated"),
    ] {
        let p = check_problems(&PASS.replace("192.0.2.10", bad));
        assert_eq!(p.len(), 1, "{bad}: {p:?}");
        assert!(p[0].1.contains(hint), "{bad}: {p:?}");
    }
    let p = check_problems(&PASS.replace("2001:db8::/120", "2001:db8::1/120"));
    assert!(p[0].1.contains("host bits"), "{p:?}");
}

#[test]
fn check_refuses_timestamp_without_offset_and_reports_all() {
    let text = PASS
        .replace("2026-11-20T08:00:00Z", "2026-11-20T08:00:00")
        .replace("calls = 6", "calls = 6.5")
        .replace("protocol = \"tcp\"", "protocol = \"sctp\"");
    let p = check_problems(&text);
    let f: Vec<&str> = p.iter().map(|(f, _)| f.as_str()).collect();
    assert_eq!(
        f,
        vec![
            "approval.valid_from",
            "destination[2].protocol",
            "ceilings.calls"
        ]
    );
    assert!(p[0].1.contains("no offset"));
}

#[test]
fn a_window_end_beyond_the_calendar_is_a_problem_not_a_crash() {
    // Year 10000 in UTC. `check` used to accept it and `status` and
    // `permits` then aborted with exit code 101 and no message.
    let text = PASS.replace("2026-11-20T17:00:00Z", "9999-12-31T23:59:59-01:00");
    let p = check_problems(&text);
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0].0, "approval.valid_until");
    let case = Case::new();
    let file = case.pass("p.toml", &text);
    for args in [
        vec!["status", s(&file)],
        vec!["permits", s(&file), "--to", "192.0.2.10:5060/udp"],
        vec!["spend", s(&file), "calls"],
    ] {
        let (rc, out) = json(&args, Some(NOW));
        assert_eq!(rc, 1, "{args:?}: {out}");
        assert_eq!(out["error"]["code"], "invalid-pass", "{args:?}");
    }
}

#[test]
fn check_refuses_bad_toml_and_files() {
    let p = check_problems("format = 1\nid = \n");
    assert_eq!(p[0].0, "(file)");
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let link = case.path("link.toml");
    std::os::unix::fs::symlink(&file, &link).expect("symlink");
    let (rc, out) = json(&["check", s(&link)], None);
    assert_eq!((rc, out["error"]["code"].as_str()), (1, Some("symlink")));
    fs::set_permissions(&file, fs::Permissions::from_mode(0o664)).expect("chmod");
    let (rc, out) = json(&["check", s(&file)], None);
    assert_eq!(
        (rc, out["error"]["code"].as_str()),
        (1, Some("insecure-permissions"))
    );
    let (rc, out) = json(&["check", s(&case.path("missing.toml"))], None);
    assert_eq!((rc, out["error"]["code"].as_str()), (1, Some("io")));
    let (rc, out) = json(&["check", s(case.dir.path())], None);
    assert_eq!(
        (rc, out["error"]["code"].as_str()),
        (1, Some("not-regular-file"))
    );
}

// ---- status ------------------------------------------------------------

#[test]
fn status_shows_everything() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    let (rc, out) = json(&["status", s(&file)], Some(NOW));
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["result"], "ok");
    assert_eq!(out["test_clock"], true);
    assert_eq!(out["pass"]["owner"], "Pat Owner, Example Corp");
    assert_eq!(out["window"]["state"], "valid");
    assert_eq!(out["window"]["seconds_remaining"], 8 * 3600);
    assert_eq!(out["destinations"][0]["destination"], "192.0.2.10");
    assert_eq!(out["destinations"][0]["ports_text"], "5060, 10000-10100");
    assert_eq!(out["destinations"][1]["kind"], "network");
    assert_eq!(out["counters"][0]["name"], "calls");
    assert_eq!(out["counters"][0]["spent"], 1);
    assert_eq!(out["counters"][0]["remaining"], 5);
    assert_eq!(out["counters"][1]["remaining"], 500);
    let text = run(&["status", s(&file)], Some(NOW));
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.contains("VALID, 8 h 0 min left"), "{stdout}");
    assert!(String::from_utf8_lossy(&text.stderr).contains("test clock"));
}

#[test]
fn status_refuses_outside_window() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let (rc, out) = json(&["status", s(&file)], Some("2026-11-20T07:30:00Z"));
    assert_eq!(rc, 2);
    assert_eq!(out["window"]["state"], "not-yet-valid");
    assert_eq!(out["window"]["seconds_until_open"], 1800);
    let (rc, out) = json(&["status", s(&file)], Some("2026-11-20T17:00:00Z"));
    assert_eq!(rc, 2);
    assert_eq!(out["window"]["state"], "expired");
    let revoked = case.pass(
        "r.toml",
        &PASS.replace(
            "revoked = false",
            "revoked = true\nrevoked_reason = \"owner asked to stop\"",
        ),
    );
    let (rc, out) = json(&["status", s(&revoked)], Some(NOW));
    assert_eq!(rc, 2);
    assert_eq!(out["window"]["state"], "revoked");
    assert_eq!(out["window"]["revoked_reason"], "owner asked to stop");
    assert_eq!(out["refusal"]["code"], "revoked");
}

// ---- permits -----------------------------------------------------------

fn permits(file: &Path, to: &str, now: &str) -> (i32, Value) {
    json(&["permits", s(file), "--to", to], Some(now))
}

#[test]
fn permits_allowed() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let (rc, out) = permits(&file, "192.0.2.10:10042/udp", NOW);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["result"], "allowed");
    assert_eq!(out["label"], "sip-edge");
    let (rc, out) = permits(&file, "[2001:db8::1]:443/tcp", NOW);
    assert_eq!((rc, out["label"].as_str()), (0, Some("web")));
    let text = run(
        &["permits", s(&file), "--to", "[2001:db8::1]:443/tcp"],
        Some(NOW),
    );
    assert!(String::from_utf8_lossy(&text.stdout).starts_with("ALLOWED"));
}

#[test]
fn permits_refusals() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    for (to, now, want) in [
        ("192.0.2.11:5060/udp", NOW, "address-not-listed"),
        ("[2001:db8::100]:443/tcp", NOW, "address-not-listed"),
        ("192.0.2.10:5060/tcp", NOW, "port-not-listed"),
        ("192.0.2.10:5061/udp", NOW, "port-not-listed"),
        ("[::ffff:192.0.2.10]:5060/udp", NOW, "embedded-ipv4"),
        ("[2002:c000:20a::1]:5060/udp", NOW, "embedded-ipv4"),
        (
            "[2001:0:c633:6401:8000:f227:34ff:8efa]:5060/udp",
            NOW,
            "embedded-ipv4",
        ),
        ("[2001:db8::5efe:c000:20a]:443/tcp", NOW, "embedded-ipv4"),
        (
            "192.0.2.10:5060/udp",
            "2026-11-20T07:59:59Z",
            "not-yet-valid",
        ),
        ("192.0.2.10:5060/udp", "2026-11-20T17:00:00Z", "expired"),
    ] {
        let (rc, out) = permits(&file, to, now);
        assert_eq!(rc, 2, "{to} {out}");
        assert_eq!(out["result"], "refused");
        assert_eq!(out["refusal"]["code"], want, "{to}");
    }
    let (rc, out) = json(
        &[
            "permits",
            s(&file),
            "--to",
            "192.0.2.10:5060/udp",
            "--duration",
            "600",
        ],
        Some("2026-11-20T16:55:00Z"),
    );
    assert_eq!(
        (rc, out["refusal"]["code"].as_str()),
        (2, Some("window-too-short"))
    );
    let revoked = case.pass("r.toml", &PASS.replace("revoked = false", "revoked = true"));
    let (rc, out) = permits(&revoked, "192.0.2.10:5060/udp", NOW);
    assert_eq!((rc, out["refusal"]["code"].as_str()), (2, Some("revoked")));
}

#[test]
fn permits_refuses_network_and_broadcast_addresses() {
    let case = Case::new();
    let text = PASS.replace(
        "network = \"2001:db8::/120\"",
        "network = \"198.51.100.0/24\"",
    ) + "\n[[destination]]\nlabel = \"pair\"\nnetwork = \"203.0.113.6/31\"\nprotocol = \"udp\"\nports = 5060\n";
    // Keep [ceilings] last: move the new destination above it.
    let text =
        text.replace("[ceilings]\ncalls = 6\nrequests = 500\n", "") + "\n[ceilings]\ncalls = 6\n";
    let file = case.pass("p.toml", &text);
    assert_eq!(json(&["check", s(&file)], None).0, 0);
    for edge in ["198.51.100.0:443/tcp", "198.51.100.255:443/tcp"] {
        let (rc, out) = permits(&file, edge, NOW);
        assert_eq!(rc, 2, "{edge}: {out}");
        assert_eq!(out["refusal"]["code"], "network-or-broadcast", "{edge}");
        let message = out["refusal"]["message"].as_str().expect("m");
        assert!(
            message.contains("198.51.100.0/24") && message.contains("web"),
            "{message}"
        );
    }
    assert_eq!(permits(&file, "198.51.100.254:443/tcp", NOW).0, 0);
    assert_eq!(permits(&file, "203.0.113.6:5060/udp", NOW).0, 0);
    assert_eq!(permits(&file, "203.0.113.7:5060/udp", NOW).0, 0);
}

#[test]
fn permits_bad_target_is_an_error() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    for to in [
        "sip.example.net:5060/udp",
        "2001:db8::1:443/tcp",
        "192.0.2.10:5060",
        "010.0.2.10:5060/udp",
        "192.0.2.10:0/udp",
    ] {
        let (rc, out) = permits(&file, to, NOW);
        assert_eq!(rc, 1, "{to} {out}");
        assert_eq!(out["error"]["code"], "usage");
    }
}

// ---- spend -------------------------------------------------------------

#[test]
fn spend_until_ceiling_reached() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let (rc, out) = json(
        &[
            "spend",
            s(&file),
            "calls",
            "--n",
            "4",
            "--note",
            "matrix run 1",
        ],
        Some(NOW),
    );
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["result"], "allowed");
    assert_eq!(
        (out["spent"].as_u64(), out["remaining"].as_u64()),
        (Some(4), Some(2))
    );
    assert_eq!(out["seq"], 1);
    assert_eq!(
        out["warnings"],
        serde_json::json!([]),
        "a first spend has nothing to warn about"
    );
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    let (rc, out) = spend(&file, "calls", NOW);
    assert_eq!(rc, 2);
    assert_eq!(out["refusal"]["code"], "ceiling-reached");
    assert_eq!(out["spent"], 6);
    assert!(
        out["refusal"]["message"]
            .as_str()
            .expect("m")
            .contains("Nothing was recorded")
    );
    let ledger = case.path("p.toml.ledger");
    let lines = fs::read_to_string(&ledger).expect("ledger");
    assert_eq!(lines.lines().count(), 4, "header and three entries");
    assert!(lines.contains("matrix run 1"));
    assert_eq!(
        fs::metadata(&ledger).expect("m").permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn spend_to_a_destination_is_one_decision() {
    let case = Case::new();
    let file = named_pass(&case);
    let (rc, out) = json(
        &[
            "spend",
            s(&file),
            "calls",
            "--to",
            "192.0.2.10:5060/udp",
            "--duration",
            "120",
        ],
        Some(NOW),
    );
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["result"], "allowed");
    assert_eq!(out["target"], "192.0.2.10:5060/udp");
    assert_eq!(out["label"], "sip-edge");
    assert_eq!(out["name"], Value::Null);
    assert_eq!(
        (out["spent"].as_u64(), out["seq"].as_u64()),
        (Some(1), Some(1))
    );
    // Without --to the fields are there and null.
    let (_, out) = spend(&file, "calls", NOW);
    assert_eq!(
        (&out["target"], &out["label"]),
        (&Value::Null, &Value::Null)
    );

    // A destination refusal: exit 2, the code of `permits`, nothing recorded.
    for (to, name, want) in [
        ("192.0.2.11:5060/udp", None, "address-not-listed"),
        ("192.0.2.10:5061/udp", None, "port-not-listed"),
        ("[::ffff:192.0.2.10]:5060/udp", None, "embedded-ipv4"),
        ("198.51.100.7:443/tcp", None, "name-required"),
        (
            "198.51.100.7:443/tcp",
            Some("other.example.org"),
            "name-not-listed",
        ),
    ] {
        let mut args = vec!["spend", s(&file), "calls", "--to", to];
        if let Some(name) = name {
            args.extend(["--name", name]);
        }
        let (rc, out) = json(&args, Some(NOW));
        assert_eq!(rc, 2, "{to}: {out}");
        assert_eq!(out["result"], "refused");
        assert_eq!(out["refusal"]["code"], want, "{to}");
        assert_eq!(out["seq"], Value::Null);
        assert_eq!(out["spent"], 2, "{to}: nothing was recorded");
        assert_eq!(out["label"], Value::Null);
    }
    let (rc, out) = json(
        &[
            "spend",
            s(&file),
            "calls",
            "--to",
            "198.51.100.7:443/tcp",
            "--name",
            "APP.example.com.",
        ],
        Some(NOW),
    );
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["name"], "app.example.com");
    assert_eq!(out["label"], "shared-web");

    // A target or name that is not one address or one name is an error.
    for extra in [
        vec!["--to", "sip.example.net:5060/udp"],
        vec!["--to", "192.0.2.10:5060"],
        vec!["--to", "192.0.2.10:5060/udp", "--name", "*.example.com"],
    ] {
        let mut args = vec!["spend", s(&file), "calls"];
        args.extend(extra);
        let (rc, out) = json(&args, Some(NOW));
        assert_eq!(
            (rc, out["error"]["code"].as_str()),
            (1, Some("usage")),
            "{out}"
        );
    }
    // A name without a target is refused by the command line itself.
    let lone = run(
        &["spend", s(&file), "calls", "--name", "app.example.com"],
        Some(NOW),
    );
    assert_eq!(code(&lone), 1);
    let (_, out) = json(&["status", s(&file)], Some(NOW));
    assert_eq!(out["counters"][0]["spent"], 3);

    let text = run(
        &["spend", s(&file), "calls", "--to", "192.0.2.10:5060/udp"],
        Some(NOW),
    );
    let stdout = String::from_utf8_lossy(&text.stdout).into_owned();
    assert!(
        stdout.starts_with(
            "RECORDED: 1 calls for 192.0.2.10:5060/udp by destination sip-edge (4 of 6 spent, 2 left; ledger entry 4)"
        ),
        "{stdout}"
    );
}

#[test]
fn spend_refusals_record_nothing() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    for (args, now, want) in [
        (vec!["bogus"], NOW, "unknown-counter"),
        (vec!["calls"], "2026-11-20T07:00:00Z", "not-yet-valid"),
        (vec!["calls"], "2026-11-21T00:00:00Z", "expired"),
        (vec!["calls", "--n", "7"], NOW, "ceiling-reached"),
        (
            vec!["calls", "--duration", "3600"],
            "2026-11-20T16:30:00Z",
            "window-too-short",
        ),
    ] {
        let mut all = vec!["spend", s(&file)];
        all.extend(args);
        let (rc, out) = json(&all, Some(now));
        assert_eq!(rc, 2, "{want}: {out}");
        assert_eq!(out["refusal"]["code"], want);
    }
    let (_, out) = json(&["status", s(&file)], Some(NOW));
    assert_eq!(out["counters"][0]["spent"], 0);
    for bad in [
        vec!["--n", "0"],
        vec!["--note", "a\nb"],
        vec!["--digest", "nope"],
    ] {
        let mut all = vec!["spend", s(&file), "calls"];
        all.extend(bad);
        let (rc, out) = json(&all, Some(NOW));
        assert_eq!(
            (rc, out["error"]["code"].as_str()),
            (1, Some("usage")),
            "{out}"
        );
    }
}

#[test]
fn spend_refused_after_revocation_between_two_spends() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    fs::write(
        &file,
        PASS.replace(
            "revoked = false",
            "revoked = true\nrevoked_reason = \"stop now\"",
        ),
    )
    .expect("revoke");
    let (rc, out) = spend(&file, "calls", "2026-11-20T09:01:00Z");
    assert_eq!(rc, 2);
    assert_eq!(out["refusal"]["code"], "revoked");
    assert!(
        out["refusal"]["message"]
            .as_str()
            .expect("m")
            .contains("stop now")
    );
    assert_eq!(out["spent"], 1);
}

#[test]
fn spend_refused_when_pass_changed_under_digest() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let (_, d) = json(&["digest", s(&file)], None);
    let digest = d["digest"].as_str().expect("digest").to_owned();
    let (rc, _) = json(
        &["spend", s(&file), "calls", "--digest", &digest],
        Some(NOW),
    );
    assert_eq!(rc, 0);
    fs::write(&file, format!("{PASS}# edited\n")).expect("edit");
    let (rc, out) = json(
        &["spend", s(&file), "calls", "--digest", &digest],
        Some(NOW),
    );
    assert_eq!(
        (rc, out["refusal"]["code"].as_str()),
        (2, Some("pass-changed"))
    );
}

#[test]
fn spend_edit_raises_ceiling_without_reset() {
    let case = Case::new();
    let file = case.pass("p.toml", &PASS.replace("calls = 6", "calls = 2"));
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    assert_eq!(spend(&file, "calls", NOW).0, 2);
    fs::write(&file, PASS.replace("calls = 6", "calls = 3")).expect("raise");
    let (rc, out) = spend(&file, "calls", NOW);
    assert_eq!((rc, out["spent"].as_u64()), (0, Some(3)));
    assert_eq!(spend(&file, "calls", NOW).0, 2);
    fs::write(&file, PASS.replace("example-2026-11", "renamed")).expect("rename id");
    let (rc, out) = spend(&file, "calls", NOW);
    assert_eq!(
        (rc, out["error"]["code"].as_str()),
        (1, Some("ledger-foreign"))
    );
}

#[test]
fn spend_two_concurrent_spenders_never_exceed_total() {
    // 3 rounds of 12 processes, each spending 15 of the 500 requests at the
    // same moment: 36 attempts, of which exactly 33 fit (495).
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let mut recorded = 0u64;
    for round in 0..3 {
        // Start every process before waiting for any.
        #[allow(clippy::needless_collect)]
        let children: Vec<_> = (0..12)
            .map(|_| {
                hallpass()
                    .args(["spend", s(&file), "requests", "--n", "15"])
                    .env(CLOCK, NOW)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("spawn")
            })
            .collect();
        let codes: Vec<i32> = children
            .into_iter()
            .map(|mut c| c.wait().expect("wait").code().expect("code"))
            .collect();
        assert!(
            codes.iter().all(|c| *c == 0 || *c == 2),
            "round {round}: {codes:?}"
        );
        recorded += codes.iter().filter(|c| **c == 0).count() as u64;
        let (_, out) = json(&["status", s(&file)], Some(NOW));
        let spent = out["counters"][1]["spent"].as_u64().expect("spent");
        assert_eq!(
            spent,
            recorded * 15,
            "round {round}: ledger and exit codes disagree"
        );
        assert!(spent <= 500, "round {round}: overspent {spent}");
    }
    assert_eq!(recorded, 33);
    let ledger = fs::read_to_string(case.path("p.toml.ledger")).expect("ledger");
    assert_eq!(ledger.lines().count(), 34, "header and 33 entries");
    let witness: Value = serde_json::from_slice(
        &fs::read(case.state().join("example-2026-11.witness")).expect("witness"),
    )
    .expect("json");
    assert_eq!(witness["seq"], 33);
    assert_eq!(witness["totals"]["requests"], 495);
}

#[test]
fn spend_fails_closed_on_corrupt_ledger() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    let ledger = case.path("p.toml.ledger");
    let good = fs::read(&ledger).expect("read");
    for (damaged, what) in [
        (good[..good.len() - 3].to_vec(), "cut short"),
        (Vec::new(), "empty"),
        (b"not json\n".to_vec(), "header"),
        (
            String::from_utf8(good.clone())
                .expect("utf8")
                .replace("\"n\":1", "\"n\":9")
                .into_bytes()
                .into_iter()
                .chain(b"{\"seq\":2}\n".iter().copied())
                .collect(),
            "complete ledger entry",
        ),
    ] {
        fs::write(&ledger, &damaged).expect("damage");
        for args in [vec!["spend", s(&file), "calls"], vec!["status", s(&file)]] {
            let (rc, out) = json(&args, Some(NOW));
            assert_eq!(rc, 1, "{what}: {out}");
            assert_eq!(out["error"]["code"], "ledger-corrupt", "{what}");
            assert!(
                out["error"]["message"].as_str().expect("m").contains(what),
                "{what}: {out}"
            );
        }
    }
    fs::write(&ledger, &good).expect("restore");
    assert_eq!(spend(&file, "calls", NOW).0, 0);
}

#[test]
fn spend_refuses_symlinked_pass_and_ledger() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let link = case.path("link.toml");
    std::os::unix::fs::symlink(&file, &link).expect("symlink");
    let (rc, out) = spend(&link, "calls", NOW);
    assert_eq!((rc, out["error"]["code"].as_str()), (1, Some("symlink")));
    let (rc, out) = permits(&link, "192.0.2.10:5060/udp", NOW);
    assert_eq!((rc, out["error"]["code"].as_str()), (1, Some("symlink")));
    let elsewhere = case.path("elsewhere.ledger");
    fs::write(&elsewhere, "").expect("write");
    std::os::unix::fs::symlink(&elsewhere, case.path("p.toml.ledger")).expect("symlink");
    let (rc, out) = spend(&file, "calls", NOW);
    assert_eq!((rc, out["error"]["code"].as_str()), (1, Some("symlink")));
    assert_eq!(fs::read(&elsewhere).expect("read").len(), 0);
}

#[test]
fn spend_refuses_readable_ledger() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    let ledger = case.path("p.toml.ledger");
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o640)).expect("chmod");
    let (rc, out) = spend(&file, "calls", NOW);
    assert_eq!(
        (rc, out["error"]["code"].as_str()),
        (1, Some("insecure-permissions"))
    );
}

#[test]
fn spend_on_invalid_pass_is_an_error() {
    let case = Case::new();
    let file = case.pass(
        "p.toml",
        &PASS.replace("revoked = false", "revoked = \"no\""),
    );
    let (rc, out) = spend(&file, "calls", NOW);
    assert_eq!(
        (rc, out["error"]["code"].as_str()),
        (1, Some("invalid-pass"))
    );
    assert!(!case.path("p.toml.ledger").exists());
}

// ---- digest ------------------------------------------------------------

#[test]
fn digest_tracks_every_byte() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let first = run(&["digest", s(&file)], None);
    assert_eq!(code(&first), 0);
    let first = String::from_utf8(first.stdout).expect("utf8");
    assert!(
        first.starts_with("sha256:") && first.trim().len() == 71,
        "{first}"
    );
    fs::write(&file, PASS.replace("# A test pass", "# A test pass.")).expect("edit");
    let (rc, out) = json(&["digest", s(&file)], None);
    assert_eq!(rc, 0);
    assert_ne!(out["digest"].as_str(), Some(first.trim()));
    let bad = case.pass("bad.toml", "format = 1\n");
    assert_eq!(json(&["digest", s(&bad)], None).0, 1);
}

// ---- ledger ------------------------------------------------------------

#[test]
fn ledger_without_entries_says_so() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let (rc, out) = json(&["ledger", s(&file)], None);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["exists"], false);
    assert_eq!(out["entries"].as_array().map(Vec::len), Some(0));
    assert_eq!(out["totals"][0]["name"], "calls");
    assert_eq!(out["totals"][0]["spent"], 0);
    let text = run(&["ledger", s(&file)], None);
    assert_eq!(code(&text), 0);
    assert!(String::from_utf8_lossy(&text.stdout).contains("No ledger yet"));
    assert!(!case.path("p.toml.ledger").exists(), "ledger is read-only");
}

#[test]
fn ledger_lists_entries_and_totals() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let (_, d) = json(&["digest", s(&file)], None);
    let digest = d["digest"].as_str().expect("digest").to_owned();
    let (rc, _) = json(
        &[
            "spend",
            s(&file),
            "calls",
            "--n",
            "2",
            "--note",
            "matrix run 1",
        ],
        Some(NOW),
    );
    assert_eq!(rc, 0);
    assert_eq!(
        json(
            &["spend", s(&file), "requests", "--n", "40"],
            Some("2026-11-20T10:00:00Z")
        )
        .0,
        0
    );
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    let (rc, out) = json(&["ledger", s(&file)], None);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["result"], "ok");
    assert_eq!(out["exists"], true);
    assert_eq!(out["verified"], true);
    let entries = out["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["seq"], 1);
    assert_eq!(entries[0]["time"], NOW);
    assert_eq!(entries[0]["counter"], "calls");
    assert_eq!(entries[0]["n"], 2);
    assert_eq!(entries[0]["note"], "matrix run 1");
    assert_eq!(entries[0]["digest"], digest.as_str());
    assert_eq!(entries[1]["note"], Value::Null);
    let totals = out["totals"].as_array().expect("totals");
    assert_eq!(totals[0]["name"], "calls");
    assert_eq!(
        (totals[0]["spent"].as_u64(), totals[0]["remaining"].as_u64()),
        (Some(3), Some(3))
    );
    assert_eq!(totals[1]["spent"], 40);

    let (rc, out) = json(&["ledger", s(&file), "--counter", "requests"], None);
    assert_eq!(rc, 0);
    assert_eq!(out["entries"].as_array().map(Vec::len), Some(1));
    assert_eq!(out["totals"].as_array().map(Vec::len), Some(1));
    assert_eq!(out["counter"], "requests");

    let text = run(&["ledger", s(&file)], None);
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.contains("matrix run 1"), "{stdout}");
    assert!(
        stdout.contains("3 line(s) after the header, chain verified, the witness matches"),
        "{stdout}"
    );
    assert!(stdout.contains(&digest[..19]), "{stdout}");

    let (rc, out) = json(&["ledger", s(&file), "--counter", "Bad Name"], None);
    assert_eq!((rc, out["error"]["code"].as_str()), (1, Some("usage")));
}

#[test]
fn ledger_reports_damage_with_its_line() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    let ledger = case.path("p.toml.ledger");
    let text = fs::read_to_string(&ledger).expect("read");
    fs::write(&ledger, text.replacen("\"n\":1", "\"n\":2", 1)).expect("damage");
    let (rc, out) = json(&["ledger", s(&file)], None);
    assert_eq!(rc, 1, "{out}");
    assert_eq!(out["error"]["code"], "ledger-corrupt");
    assert_eq!(out["error"]["line"], 3);
    let shown = run(&["ledger", s(&file)], None);
    assert_eq!(code(&shown), 1);
    assert!(String::from_utf8_lossy(&shown.stderr).contains("damaged at line 3"));
    fs::write(&ledger, "").expect("empty");
    let (rc, out) = json(&["ledger", s(&file)], None);
    assert_eq!(
        (rc, out["error"]["code"].as_str()),
        (1, Some("ledger-corrupt"))
    );
}

#[test]
fn notes_cannot_forge_output_lines_or_control_the_terminal() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    for bad in [
        "ok\n    2  2026-11-20T09:00:00Z  calls  1  forged",
        "\u{1b}[2J\u{1b}[Hcleared",
        "\u{9b}31mred",
        "x\u{2028}y",
        "evil\u{202e}txt.exe",
    ] {
        let (rc, out) = json(&["spend", s(&file), "calls", "--note", bad], Some(NOW));
        assert_eq!(
            (rc, out["error"]["code"].as_str()),
            (1, Some("usage")),
            "{bad:?}: {out}"
        );
    }
    assert!(!case.path("p.toml.ledger").exists());
    // A ledger from an older hallpass may hold a bidi control in a note
    // (0.1 refused only control characters). It is shown escaped.
    assert_eq!(
        json(
            &["spend", s(&file), "calls", "--note", "PLACEHOLDER"],
            Some(NOW)
        )
        .0,
        0
    );
    let ledger = case.path("p.toml.ledger");
    let text = fs::read_to_string(&ledger).expect("read");
    let lines: Vec<&str> = text.lines().collect();
    let entry = lines[1].replace("PLACEHOLDER", "evil\\u202etxt.exe \\\\u{000a}");
    fs::write(&ledger, format!("{}\n{entry}\n", lines[0])).expect("write");
    // This machine's witness notices the edit; a 0.1 ledger has no witness.
    assert_eq!(
        json(&["ledger", s(&file)], None).1["error"]["code"],
        "ledger-changed"
    );
    fs::remove_file(case.state().join("example-2026-11.witness")).expect("forget witness");
    let shown = run(&["ledger", s(&file)], None);
    assert_eq!(code(&shown), 0, "{shown:?}");
    let stdout = String::from_utf8(shown.stdout).expect("utf8");
    assert!(
        stdout.contains("evil\\u{202e}txt.exe \\\\u{000a}"),
        "{stdout}"
    );
    assert!(!stdout.contains('\u{202e}'));
    let (_, out) = json(&["ledger", s(&file)], None);
    assert_eq!(out["entries"][0]["note"], "evil\u{202e}txt.exe \\u{000a}");
}

// ---- the witness -------------------------------------------------------

fn error_code(value: &Value) -> Option<&str> {
    value["error"]["code"].as_str()
}

#[test]
fn deleting_the_ledger_does_not_reset_the_count() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    assert_eq!(
        json(&["spend", s(&file), "calls", "--n", "4"], Some(NOW)).0,
        0
    );
    fs::remove_file(case.path("p.toml.ledger")).expect("delete ledger");
    for args in [
        vec!["spend", s(&file), "calls"],
        vec!["status", s(&file)],
        vec!["permits", s(&file), "--to", "192.0.2.10:5060/udp"],
        vec!["ledger", s(&file)],
    ] {
        let (rc, out) = json(&args, Some(NOW));
        assert_eq!(
            (rc, error_code(&out)),
            (1, Some("ledger-missing")),
            "{args:?}: {out}"
        );
        let message = out["error"]["message"].as_str().expect("message");
        assert!(message.contains("spent: calls 4"), "{message}");
        assert!(message.contains("hallpass adopt"), "{message}");
    }
    let text = run(&["status", s(&file)], Some(NOW));
    assert_eq!(code(&text), 1);
    assert!(!String::from_utf8_lossy(&text.stdout).contains("0 spent"));
    assert!(String::from_utf8_lossy(&text.stderr).contains("is missing"));
    assert!(!case.path("p.toml.ledger").exists(), "nothing was created");

    assert_eq!(
        code(&run(&["adopt", s(&file)], Some(NOW))),
        1,
        "--reason is required"
    );
    let (rc, out) = json(
        &[
            "adopt",
            s(&file),
            "--reason",
            "ledger lost when the laptop was reimaged",
        ],
        Some(NOW),
    );
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["case"], "ledger-missing");
    assert_eq!(out["created"], true);
    assert_eq!(out["carried"]["calls"], 4);
    assert_eq!(out["previous"]["seq"], 1);
    let (rc, out) = json(&["status", s(&file)], Some(NOW));
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["counters"][0]["spent"], 4);
    assert_eq!(out["ledger"]["witness"], "matches");
    assert_eq!(out["ledger"]["adoptions"], 1);
    assert_eq!(
        json(&["spend", s(&file), "calls", "--n", "2"], Some(NOW)).0,
        0
    );
    let (rc, out) = spend(&file, "calls", NOW);
    assert_eq!(
        (rc, out["refusal"]["code"].as_str()),
        (2, Some("ceiling-reached"))
    );
    let (_, out) = json(&["ledger", s(&file)], None);
    assert_eq!(
        out["adoptions"][0]["reason"],
        "ledger lost when the laptop was reimaged"
    );
    assert_eq!(out["adoptions"][0]["carried"]["calls"], 4);
    let shown = run(&["ledger", s(&file)], None);
    assert!(
        String::from_utf8_lossy(&shown.stdout)
            .contains("ADOPTED, carried from the witness: calls 4")
    );
    // Nothing more to adopt.
    let (rc, out) = json(&["adopt", s(&file), "--reason", "again"], Some(NOW));
    assert_eq!((rc, error_code(&out)), (1, Some("usage")));
}

#[test]
fn an_edited_last_line_is_caught_everywhere() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    assert_eq!(
        json(
            &["spend", s(&file), "calls", "--n", "5", "--note", "run 1"],
            Some(NOW)
        )
        .0,
        0
    );
    let ledger = case.path("p.toml.ledger");
    let good = fs::read_to_string(&ledger).expect("read");
    fs::write(&ledger, good.replace("\"n\":5", "\"n\":1")).expect("edit");
    for args in [
        vec!["spend", s(&file), "calls"],
        vec!["status", s(&file)],
        vec!["permits", s(&file), "--to", "192.0.2.10:5060/udp"],
        vec!["ledger", s(&file)],
    ] {
        let (rc, out) = json(&args, Some(NOW));
        assert_eq!(
            (rc, error_code(&out)),
            (1, Some("ledger-changed")),
            "{args:?}: {out}"
        );
    }
    fs::write(&ledger, &good).expect("restore");
    assert_eq!(permits(&file, "192.0.2.10:5060/udp", NOW).0, 0);
}

#[test]
fn a_pass_moved_without_its_ledger_is_refused_and_with_it_accepted() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    fs::create_dir(case.path("archive")).expect("mkdir");
    let moved = case.path("archive/p.toml");
    fs::rename(&file, &moved).expect("move pass");
    let (rc, out) = spend(&moved, "calls", NOW);
    assert_eq!((rc, error_code(&out)), (1, Some("ledger-missing")), "{out}");
    let message = out["error"]["message"].as_str().expect("m");
    assert!(message.contains("last seen at"), "{message}");
    assert!(message.contains("p.toml.ledger"), "{message}");
    fs::rename(
        case.path("p.toml.ledger"),
        case.path("archive/p.toml.ledger"),
    )
    .expect("move ledger");
    let (rc, out) = spend(&moved, "calls", NOW);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["spent"], 2);
    let warning = out["warnings"][0].as_str().expect("warning");
    assert!(warning.contains("moved or copied"), "{warning}");
    let (_, out) = spend(&moved, "calls", NOW);
    assert_eq!(out["warnings"].as_array().map(Vec::len), Some(0));
}

#[test]
fn a_pass_from_another_machine_is_accepted_with_a_warning() {
    let first = Case::new();
    let file = first.pass("p.toml", PASS);
    assert_eq!(spend(&file, "calls", NOW).0, 0);
    // A second home: another machine or user, with no witness yet.
    let _other = Case::new();
    let (rc, out) = json(&["status", s(&file)], Some(NOW));
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["counters"][0]["spent"], 1);
    assert_eq!(out["ledger"]["witness"], "missing");
    assert!(
        out["warnings"][0]
            .as_str()
            .expect("w")
            .contains("no witness")
    );
    let text = run(&["status", s(&file)], Some(NOW));
    assert!(
        String::from_utf8_lossy(&text.stderr).contains("hallpass: warning: there is no witness")
    );
    assert!(String::from_utf8_lossy(&text.stdout).contains("NO WITNESS yet"));
    let (rc, out) = spend(&file, "calls", NOW);
    assert_eq!(rc, 0, "{out}");
    assert!(
        out["warnings"][0]
            .as_str()
            .expect("w")
            .contains("one is recorded now")
    );
    let (_, out) = json(&["status", s(&file)], Some(NOW));
    assert_eq!(out["ledger"]["witness"], "matches");
}

#[test]
fn an_unusable_state_directory_fails_closed_for_spends() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let not_a_dir = case.path("not-a-dir");
    fs::write(&not_a_dir, "").expect("write");
    let with_state = |state: Option<&Path>, home: Option<&Path>, args: &[&str]| {
        let mut command = hallpass();
        command.env_remove("XDG_STATE_HOME").env_remove("HOME");
        if let Some(state) = state {
            command.env("XDG_STATE_HOME", state);
        }
        if let Some(home) = home {
            command.env("HOME", home);
        }
        let output = command
            .args(["--format", "json"])
            .args(args)
            .env(CLOCK, NOW)
            .output()
            .expect("run");
        let value: Value = serde_json::from_slice(&output.stdout).expect("json");
        (code(&output), value)
    };
    let spend_args = ["spend", s(&file), "calls"];
    let (rc, out) = with_state(Some(&not_a_dir), None, &spend_args);
    assert_eq!(
        (rc, error_code(&out)),
        (1, Some("witness-unavailable")),
        "{out}"
    );
    let (rc, out) = with_state(None, None, &spend_args);
    assert_eq!(
        (rc, error_code(&out)),
        (1, Some("witness-unavailable")),
        "{out}"
    );
    assert!(
        out["error"]["message"]
            .as_str()
            .expect("m")
            .contains("XDG_STATE_HOME")
    );
    assert!(!case.path("p.toml.ledger").exists(), "nothing was recorded");
    // Read-only commands still answer, with a warning.
    let (rc, out) = with_state(None, None, &["status", s(&file)]);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["ledger"]["witness"], "not-checked");
    assert!(
        out["warnings"][0]
            .as_str()
            .expect("w")
            .contains("not checked against its witness"),
        "{out}"
    );
    let (rc, out) = with_state(
        None,
        None,
        &["permits", s(&file), "--to", "192.0.2.10:5060/udp"],
    );
    assert_eq!(rc, 0, "{out}");

    // A relative XDG_STATE_HOME is ignored (XDG rules): HOME is used.
    let home = case.path("home2");
    fs::create_dir(&home).expect("mkdir");
    let (rc, out) = with_state(Some(Path::new("relative/state")), Some(&home), &spend_args);
    assert_eq!(rc, 0, "{out}");
    let state = home.join(".local/state/hallpass");
    assert!(state.join("example-2026-11.witness").is_file());
    assert_eq!(
        fs::metadata(&state).expect("meta").permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(state.join("example-2026-11.witness"))
            .expect("meta")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    // Not writable: refused before anything is recorded.
    fs::set_permissions(&state, fs::Permissions::from_mode(0o500)).expect("chmod");
    let (rc, out) = with_state(None, Some(&home), &spend_args);
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("chmod");
    assert_eq!(
        (rc, error_code(&out)),
        (1, Some("witness-unavailable")),
        "{out}"
    );
    let (_, out) = with_state(None, Some(&home), &["ledger", s(&file)]);
    assert_eq!(out["entries"].as_array().map(Vec::len), Some(1), "{out}");
}

// ---- clock and usage ---------------------------------------------------

#[test]
fn malformed_test_clock_is_an_error() {
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    let (rc, out) = json(&["status", s(&file)], Some("tomorrow"));
    assert_eq!((rc, out["error"]["code"].as_str()), (1, Some("usage")));
    let (rc, out) = json(&["status", s(&file)], Some("2026-11-20T09:00:00"));
    assert_eq!(rc, 1, "{out}");
}

#[test]
fn real_clock_without_variable() {
    let case = Case::new();
    let past = PASS
        .replace("2026-11-20T08:00:00Z", "2000-01-01T00:00:00Z")
        .replace("2026-11-20T17:00:00Z", "2000-01-02T00:00:00Z");
    let file = case.pass("p.toml", &past);
    let (rc, out) = json(&["status", s(&file)], None);
    assert_eq!(out["test_clock"], false);
    assert_eq!(rc, 2, "a window in 2000 has ended on the real clock: {out}");
    assert_eq!(out["window"]["state"], "expired");
}

/// Only in a release build without the `test-clock` feature: the variable
/// is ignored, said so, and the real clock decides. Run with
/// `cargo test --release --test cli -- release_build`.
#[cfg(not(any(debug_assertions, feature = "test-clock")))]
#[test]
fn release_build_ignores_the_test_clock() {
    let case = Case::new();
    let past = PASS
        .replace("2026-11-20T08:00:00Z", "2000-01-01T00:00:00Z")
        .replace("2026-11-20T17:00:00Z", "2000-01-02T00:00:00Z");
    let file = case.pass("p.toml", &past);
    // The test clock says the window is open; the real clock says it ended.
    let output = run(
        &["--format", "json", "spend", s(&file), "calls"],
        Some("2000-01-01T12:00:00Z"),
    );
    let out: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(code(&output), 2, "{out}");
    assert_eq!(out["test_clock"], false);
    assert_eq!(out["refusal"]["code"], "expired");
    assert!(String::from_utf8_lossy(&output.stderr).contains("is set but ignored"));
    let (_, out) = json(&["ledger", s(&file)], None);
    assert_eq!(out["entries"].as_array().map(Vec::len), Some(0), "{out}");
}

#[test]
fn usage_errors_exit_one() {
    let _case = Case::new();
    assert_eq!(code(&run(&["frobnicate"], None)), 1);
    assert_eq!(code(&run(&["spend"], None)), 1);
    assert_eq!(code(&run(&["--help"], None)), 0);
}

#[test]
fn usage_errors_are_json_when_json_was_asked_for() {
    // A caller that reads JSON gets one object for a command line that
    // could not be read too, never empty output.
    let case = Case::new();
    let file = case.pass("p.toml", PASS);
    for args in [
        vec!["frobnicate"],
        vec!["spend"],
        vec!["permits", s(&file)],
        vec!["spend", s(&file), "calls", "--n", "many"],
        vec!["spend", s(&file), "calls", "--name", "app.example.com"],
        vec![
            "permits",
            s(&file),
            "--to",
            "192.0.2.10:5060/udp",
            "--to",
            "192.0.2.10:5060/udp",
            "--name",
            "ambiguous.example",
        ],
    ] {
        let (rc, out) = json(&args, Some(NOW));
        assert_eq!(rc, 1, "{args:?}: {out}");
        assert_eq!(out["result"], "error", "{args:?}");
        assert_eq!(out["error"]["code"], "usage", "{args:?}");
        assert_ne!(out["error"]["message"], "", "{args:?}");
        assert_eq!(out["warnings"], serde_json::json!([]));
    }
    // The other spelling of the option, and the text on standard error.
    let output = run(&["--format=json", "spend"], None);
    assert_eq!(code(&output), 1);
    let out: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(out["error"]["code"], "usage");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
    // Text mode prints nothing on standard output.
    let output = run(&["spend"], None);
    assert_eq!(output.stdout, b"");
    assert!(!case.path("p.toml.ledger").exists());
}

// ---- names -------------------------------------------------------------

const NAMED: &str = r#"
[[destination]]
label = "shared-web"
address = "198.51.100.7"
protocol = "tcp"
ports = 443
names = ["app.example.com", "admin.example.com"]

[ceilings]
"#;

fn named_pass(case: &Case) -> PathBuf {
    let text = PASS.replacen("\n[ceilings]\n", NAMED, 1);
    assert!(text.contains("shared-web"));
    case.pass("p.toml", &text)
}

fn permits_as(file: &Path, to: &str, name: &str) -> (i32, Value) {
    json(&["permits", s(file), "--to", to, "--name", name], Some(NOW))
}

#[test]
fn permits_with_names() {
    let case = Case::new();
    let file = named_pass(&case);
    assert_eq!(json(&["check", s(&file)], None).0, 0);
    let to = "198.51.100.7:443/tcp";

    let (rc, out) = permits_as(&file, to, "App.Example.com.");
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["label"], "shared-web");
    assert_eq!(out["name"], "app.example.com");

    let (rc, out) = permits_as(&file, to, "other.example.org");
    assert_eq!(
        (rc, out["refusal"]["code"].as_str()),
        (2, Some("name-not-listed"))
    );
    assert!(
        out["refusal"]["message"]
            .as_str()
            .expect("m")
            .contains("admin.example.com"),
        "{out}"
    );

    let (rc, out) = permits(&file, to, NOW);
    assert_eq!(
        (rc, out["refusal"]["code"].as_str()),
        (2, Some("name-required"))
    );
    assert_eq!(out["name"], Value::Null);

    // A name never grants: an approved name on an unlisted address.
    let (rc, out) = permits_as(&file, "198.51.100.9:443/tcp", "app.example.com");
    assert_eq!(
        (rc, out["refusal"]["code"].as_str()),
        (2, Some("address-not-listed"))
    );

    // A destination without names takes any name.
    let (rc, out) = permits_as(&file, "192.0.2.10:5060/udp", "whatever.example.org");
    assert_eq!((rc, out["label"].as_str()), (0, Some("sip-edge")));

    let text = run(
        &["permits", s(&file), "--to", to, "--name", "app.example.com"],
        Some(NOW),
    );
    let text = String::from_utf8_lossy(&text.stdout).into_owned();
    assert!(
        text.starts_with(
            "ALLOWED: 198.51.100.7:443/tcp as app.example.com by destination shared-web"
        ),
        "{text}"
    );
}

#[test]
fn permits_bad_name_is_an_error() {
    let case = Case::new();
    let file = named_pass(&case);
    for name in [
        "*.example.com",
        "192.0.2.10",
        "a b",
        "",
        "https://app.example.com",
    ] {
        let (rc, out) = permits_as(&file, "198.51.100.7:443/tcp", name);
        assert_eq!(rc, 1, "{name:?} {out}");
        assert_eq!(out["error"]["code"], "usage", "{name:?}");
    }
}

#[test]
fn status_shows_names() {
    let case = Case::new();
    let file = named_pass(&case);
    let (rc, out) = json(&["status", s(&file)], Some(NOW));
    assert_eq!(rc, 0, "{out}");
    let destinations = out["destinations"].as_array().expect("list");
    let shared = destinations
        .iter()
        .find(|d| d["label"] == "shared-web")
        .expect("shared-web");
    assert_eq!(
        shared["names"],
        serde_json::json!(["app.example.com", "admin.example.com"])
    );
    let plain = destinations
        .iter()
        .find(|d| d["label"] == "sip-edge")
        .expect("sip-edge");
    assert_eq!(plain["names"], serde_json::json!([]));
    let text = run(&["status", s(&file)], Some(NOW));
    assert!(
        String::from_utf8_lossy(&text.stdout)
            .contains("[only as: app.example.com, admin.example.com]")
    );
}

#[test]
fn check_refuses_a_bad_names_list() {
    let case = Case::new();
    let text = PASS.replacen("\n[ceilings]\n", NAMED, 1).replace(
        "names = [\"app.example.com\", \"admin.example.com\"]",
        "names = [\"*.example.com\"]",
    );
    let file = case.pass("p.toml", &text);
    let (rc, out) = json(&["check", s(&file)], None);
    assert_eq!(rc, 1, "{out}");
    assert_eq!(out["problems"][0]["field"], "destination[3].names[1]");
}

#[test]
fn a_planned_unit_then_a_pinned_followup_uses_one_debit() {
    let case = Case::new();
    let pass = case.pass(
        "unit.toml",
        &PASS.replace("ports = 443", "ports = 443\nnames = [\"edge.example\"]"),
    );
    let file = s(&pass);
    let a = "192.0.2.10:5060/udp";
    let b = "[2001:db8::1]:443/tcp@edge.example";
    let pin = json(&["digest", file], None).1["digest"]
        .as_str()
        .expect("pin")
        .to_owned();
    let mut args = vec![
        "spend",
        "--to",
        a,
        "--to",
        b,
        "--digest",
        &pin,
        "--dry-run",
        "--",
        file,
        "calls",
    ];
    let (rc, preview) = json(&args, Some(NOW));
    assert_eq!(rc, 0, "{preview}");
    assert_eq!(preview["result"], "would-allow");
    assert_eq!(preview["projected_spent"], 1);
    assert!(preview["seq"].is_null());
    assert!(!case.state().exists());
    assert!(!hallpass::ledger_path(&pass).exists());
    args.retain(|arg| *arg != "--dry-run");
    let (rc, debit) = json(&args, Some(NOW));
    assert_eq!(rc, 0, "{debit}");
    assert_eq!(debit["seq"], 1);
    assert_eq!(debit["targets"][1]["label"], "web");
    let denied = json(
        &[
            "spend",
            "--to",
            a,
            "--to",
            "[2001:db8::1]:443/tcp",
            "--",
            file,
            "calls",
        ],
        Some(NOW),
    );
    assert_eq!(denied.0, 2);
    assert_eq!(denied.1["refused_target"], 2);
    assert_eq!(denied.1["refusal"]["code"], "name-required");
    assert_eq!(
        json(
            &["permits", "--to", b, "--digest", &pin, "--", file],
            Some(NOW)
        )
        .0,
        0
    );
    let mut changed = fs::read_to_string(&pass).expect("read");
    changed.push_str("\n# revised\n");
    fs::write(&pass, changed).expect("edit");
    let (rc, reply) = json(
        &["permits", "--to", b, "--digest", &pin, "--", file],
        Some(NOW),
    );
    assert_eq!(
        (rc, reply["refusal"]["code"].as_str()),
        (2, Some("pass-changed"))
    );
    assert_eq!(json(&["permits", "--to", b, "--", file], Some(NOW)).0, 0);
    assert_eq!(
        json(&["ledger", file], None).1["entries"]
            .as_array()
            .expect("entries")
            .len(),
        1
    );
}

#[test]
fn preview_uses_current_totals_and_requires_usable_evidence() {
    let case = Case::new();
    let pass = case.pass("p.toml", &PASS.replace("calls = 6", "calls = 1"));
    let file = s(&pass);
    let preview = ["spend", file, "calls", "--dry-run"];
    assert_eq!(json(&preview, Some(NOW)).1["result"], "would-allow");
    assert_eq!(json(&["spend", file, "calls"], Some(NOW)).0, 0);
    let before = fs::read(hallpass::ledger_path(&pass)).expect("ledger");
    assert_eq!(
        json(&preview, Some(NOW)).1["refusal"]["code"],
        "ceiling-reached"
    );
    assert_eq!(
        fs::read(hallpass::ledger_path(&pass)).expect("ledger"),
        before
    );
    fs::set_permissions(case.state(), fs::Permissions::from_mode(0o755)).expect("chmod");
    assert_eq!(
        json(&preview, Some(NOW)).1["error"]["code"],
        "witness-unavailable"
    );
    fs::set_permissions(case.state(), fs::Permissions::from_mode(0o700)).expect("chmod");
    fs::remove_file(hallpass::ledger_path(&pass)).expect("fixture removes ledger");
    for args in [
        vec!["spend", file, "calls", "--dry-run"],
        vec!["permits", file, "--to", "192.0.2.10:5060/udp"],
    ] {
        assert_eq!(json(&args, Some(NOW)).1["error"]["code"], "ledger-missing");
    }
}

#[test]
fn cli_version_matches_package() {
    let _case = Case::new();
    assert_eq!(
        String::from_utf8(run(&["--version"], None).stdout)
            .expect("output")
            .trim(),
        concat!("hallpass ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn caller_kit_consumes_genuine_production_decisions() {
    use std::io::Write;
    use std::process::Stdio;
    let case = Case::new();
    let real = hallpass::time::OffsetDateTime::now_utc();
    let window = PASS
        .replace(
            "2026-11-20T08:00:00Z",
            &hallpass::stamp(real - hallpass::time::Duration::days(1)),
        )
        .replace(
            "2026-11-20T17:00:00Z",
            &hallpass::stamp(real + hallpass::time::Duration::days(1)),
        )
        .replace("calls = 6", "calls = 1");
    let p = case.pass("real.pass", &window);
    let mut samples = Vec::new();
    for action in ["proceed", "stop"] {
        let output = run(&["--format", "json", "spend", s(&p), "calls"], None);
        samples.push(serde_json::json!({"id":"live","exit":code(&output),"stdout":String::from_utf8(output.stdout).expect("utf8"),"action":action}));
    }
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/conformance/check.py");
    assert!(
        Command::new("python3")
            .arg(&script)
            .status()
            .expect("run offline client corpus")
            .success()
    );
    let mut reference = Command::new("python3")
        .arg(script)
        .arg("--stdin-cases")
        .stdin(Stdio::piped())
        .spawn()
        .expect("reference");
    reference
        .stdin
        .take()
        .expect("stdin")
        .write_all(serde_json::to_vec(&samples).expect("serialize").as_slice())
        .expect("pipe genuine results");
    assert!(reference.wait().expect("reference").success());
}
