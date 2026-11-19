//! Integration tests: run the built `hallpass` binary for every command and
//! every refusal path. The clock is set with `HALLPASS_UNSAFE_TEST_CLOCK`,
//! which debug builds (and `--features test-clock`) honour; no test sleeps.

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

impl Case {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
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

fn run(args: &[&str], now: Option<&str>) -> Output {
    let mut command = Command::new(BIN);
    command.args(args).env_remove(CLOCK);
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
                Command::new(BIN)
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

#[test]
fn usage_errors_exit_one() {
    assert_eq!(code(&run(&["frobnicate"], None)), 1);
    assert_eq!(code(&run(&["spend"], None)), 1);
    assert_eq!(code(&run(&["--help"], None)), 0);
}
