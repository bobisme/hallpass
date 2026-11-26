//! The spend reply: one key set for every flag combination, the warning on
//! a debit that checked no destination, and ledger lines that the reply
//! view does not change.
//!
//! Like `tests/cli.rs`, this sets the clock with `HALLPASS_UNSAFE_TEST_CLOCK`
//! (debug builds, or `--features test-clock`) and gives every run a private
//! `HOME` and `XDG_STATE_HOME`.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use hallpass::Digest;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const CLOCK: &str = "HALLPASS_UNSAFE_TEST_CLOCK";
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
calls = 60
requests = 500
"#;

/// The keys of every spend reply, as docs/spec.md lists them.
const REPLY_KEYS: [&str; 26] = [
    "advice",
    "charges",
    "command",
    "counter",
    "digest",
    "file",
    "label",
    "n",
    "name",
    "note",
    "now",
    "pass_id",
    "projected_spent",
    "receipt",
    "reference_evidence",
    "refusal",
    "refused_target",
    "remaining",
    "result",
    "seq",
    "spent",
    "target",
    "targets",
    "test_clock",
    "total",
    "warnings",
];
const CHARGE_KEYS: [&str; 6] = [
    "counter",
    "n",
    "projected_spent",
    "remaining",
    "spent",
    "total",
];
const SCALAR_KEYS: [&str; 6] = [
    "counter",
    "n",
    "total",
    "spent",
    "remaining",
    "projected_spent",
];
const NO_TARGET: &str = "no destination was checked";

/// A private directory with a home and state directory for the binary.
struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        Self { dir }
    }

    fn pass(&self, name: &str, text: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        fs::write(&path, text).expect("write pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        path
    }

    /// Run the binary; `now` sets the test clock, `None` uses the real one.
    fn run(&self, args: &[&str], now: Option<&str>) -> Output {
        let home = self.dir.path().join("home");
        let mut command = Command::new(BIN);
        command
            .env_remove(CLOCK)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .args(args);
        if let Some(now) = now {
            command.env(CLOCK, now);
        }
        command.output().expect("run hallpass")
    }

    /// Run with `--format json` at `NOW`; return the exit code and the reply.
    fn json(&self, args: &[&str]) -> (i32, Value) {
        let output = self.run(&[&["--format", "json"], args].concat(), Some(NOW));
        let value = serde_json::from_slice(&output.stdout).expect("one JSON object");
        (output.status.code().expect("exit code"), value)
    }
}

fn s(path: &Path) -> &str {
    path.to_str().expect("utf8 path")
}

fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect()
}

fn warns_no_target(reply: &Value) -> bool {
    reply["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .any(|w| w.as_str().is_some_and(|w| w.starts_with(NO_TARGET)))
}

/// The same keys at every level, whatever the flags and the result.
fn assert_reply_shape(reply: &Value, at: &str) {
    assert_eq!(keys(reply), BTreeSet::from(REPLY_KEYS), "{at}: {reply}");
    for charge in reply["charges"].as_array().expect("charges") {
        assert_eq!(keys(charge), BTreeSet::from(CHARGE_KEYS), "{at}: {charge}");
    }
    for target in reply["targets"].as_array().expect("targets") {
        assert_eq!(keys(target), BTreeSet::from(["label", "name", "target"]));
    }
    if !reply["receipt"].is_null() {
        assert_eq!(
            keys(&reply["receipt"]),
            BTreeSet::from(["caller_ref", "targets"])
        );
        for target in reply["receipt"]["targets"].as_array().expect("targets") {
            assert_eq!(keys(target), BTreeSet::from(["label", "name", "target"]));
        }
    }
    // The scalar fields repeat the only charge, or are null for several.
    let charges = reply["charges"].as_array().expect("charges");
    for key in SCALAR_KEYS {
        let expected = match charges.as_slice() {
            [only] => only[key].clone(),
            _ => Value::Null,
        };
        assert_eq!(reply[key], expected, "{at}: {key}");
    }
}

#[test]
fn every_spend_reply_has_the_same_keys() {
    let case = Case::new();
    let p = case.pass("p.toml", PASS);
    let file = s(&p);
    let to = [
        "--to",
        "192.0.2.10:5060/udp",
        "--to",
        "[2001:db8::1]:443/tcp",
    ];
    let receipt = [&to[..], &["--record-target", "--caller-ref", "run-1"]].concat();
    let variants: Vec<(&str, Vec<&str>, i32)> = vec![
        ("scalar", vec!["calls"], 0),
        (
            "scalar with --caller-ref",
            vec!["calls", "--caller-ref", "run-0"],
            0,
        ),
        ("scalar with --to", [&["calls"], &to[..]].concat(), 0),
        ("one --charge", vec!["--charge", "calls=1"], 0),
        (
            "several --charge",
            vec!["--charge", "calls=1", "--charge", "requests=2"],
            0,
        ),
        (
            "receipt",
            [&["--charge", "calls=1"], &receipt[..]].concat(),
            0,
        ),
        ("scalar --dry-run", vec!["calls", "--dry-run"], 0),
        (
            "charged --dry-run",
            vec!["--charge", "calls=1", "--charge", "requests=2", "--dry-run"],
            0,
        ),
        ("scalar refused", vec!["calls", "--n", "100"], 2),
        (
            "charged refused",
            vec!["--charge", "calls=1", "--charge", "requests=501"],
            2,
        ),
        (
            "refused target",
            vec!["calls", "--to", "192.0.2.11:5060/udp"],
            2,
        ),
        (
            "refused preview",
            vec!["calls", "--n", "100", "--dry-run"],
            2,
        ),
        (
            "duplicate reference",
            vec!["calls", "--caller-ref", "run-0", "--require-new-ref"],
            2,
        ),
    ];
    for (at, args, exit) in variants {
        let (code, reply) = case.json(&[&["spend", file], &args[..]].concat());
        assert_eq!(code, exit, "{at}: {reply}");
        assert_reply_shape(&reply, at);
    }
    let (_, refused) = case.json(&[
        "spend",
        file,
        "calls",
        "--caller-ref",
        "run-0",
        "--require-new-ref",
    ]);
    assert_eq!(refused["refusal"]["code"], "duplicate-reference");
    assert_eq!(refused["reference_evidence"]["sequences"], json!([2]));
    assert!(refused["receipt"].is_null());
    let (_, plain) = case.json(&["spend", file, "calls"]);
    assert!(plain["receipt"].is_null() && plain["reference_evidence"].is_null());
    assert_eq!(plain["charges"][0]["counter"], "calls");
}

#[test]
fn a_reply_depends_on_the_unit_not_its_spelling() {
    let case = Case::new();
    let p = case.pass("p.toml", PASS);
    let file = s(&p);
    let (_, scalar) = case.json(&["spend", file, "calls", "--n", "2", "--dry-run"]);
    let (_, charged) = case.json(&["spend", file, "--charge", "calls=2", "--dry-run"]);
    assert_eq!(scalar, charged);
    assert_eq!(
        (
            scalar["counter"].as_str(),
            scalar["projected_spent"].as_u64()
        ),
        (Some("calls"), Some(2))
    );
    let (_, several) = case.json(&[
        "spend",
        file,
        "--charge",
        "calls=2",
        "--charge",
        "requests=3",
        "--dry-run",
    ]);
    assert_eq!(several["charges"][1]["projected_spent"], 3);
    for key in SCALAR_KEYS {
        assert!(several[key].is_null(), "{key}: {several}");
    }
}

#[test]
fn receipt_names_are_explicit_and_new_ledger_lines_are_unchanged() {
    let case = Case::new();
    let p = case.pass("p.toml", PASS);
    let file = s(&p);
    let digest = Digest::of(PASS.as_bytes());
    let (_, scalar) = case.json(&["spend", file, "calls", "--note", "first"]);
    let (_, charged) = case.json(&[
        "spend",
        file,
        "--charge",
        "calls=1",
        "--charge",
        "requests=2",
    ]);
    let (_, recorded) = case.json(&[
        "spend",
        file,
        "--charge",
        "calls=1",
        "--caller-ref",
        "run-7",
        "--record-target",
        "--to",
        "192.0.2.10:5060/udp@SIP.example.net.",
        "--to",
        "[2001:db8::1]:443/tcp",
    ]);
    let (_, unreferenced) = case.json(&[
        "spend",
        file,
        "calls",
        "--record-target",
        "--to",
        "[2001:db8::1]:443/tcp",
    ]);
    assert_eq!(
        recorded["receipt"],
        json!({"caller_ref": "run-7", "targets": [
            {"target": "192.0.2.10:5060/udp", "name": "sip.example.net", "label": "sip-edge"},
            {"target": "[2001:db8::1]:443/tcp", "name": null, "label": "web"},
        ]})
    );
    assert_eq!(unreferenced["receipt"]["caller_ref"], Value::Null);
    assert_eq!(unreferenced["receipt"]["targets"][0]["name"], Value::Null);
    for reply in [&scalar, &charged, &recorded, &unreferenced] {
        assert_eq!(reply["result"], "allowed", "{reply}");
    }

    // The ledger keeps its own encoding: no null name, no absent reference.
    let ledger = fs::read_to_string(hallpass::ledger_path(&p)).expect("ledger");
    let lines: Vec<&str> = ledger.lines().collect();
    // `body` precedes the pass digest and `tail` follows it. Each line was
    // written under the test clock, so it carries the marker (bn-2mm).
    let line = |seq: usize, body: &str, tail: &str| {
        format!(
            r#"{{"seq":{seq},"time":"{NOW}",{body},"digest":"{digest}"{tail},"test_clock":true,"prev":"{prev}"}}"#,
            prev = Digest::of(lines[seq - 1].as_bytes()),
        )
    };
    let debit = |seq: usize, charges: &str, receipt: &str| {
        line(
            seq,
            &format!(r#""event":"debit","version":1,"charges":{charges}"#),
            receipt,
        )
    };
    let expected = [
        r#"{"hallpass_ledger":1,"pass_id":"example-2026-11"}"#.to_owned(),
        line(1, r#""counter":"calls","n":1"#, r#","note":"first""#),
        debit(
            2,
            r#"[{"counter":"calls","n":1},{"counter":"requests","n":2}]"#,
            "",
        ),
        debit(
            3,
            r#"[{"counter":"calls","n":1}]"#,
            r#","receipt":{"caller_ref":"run-7","targets":[{"target":"192.0.2.10:5060/udp","name":"sip.example.net","label":"sip-edge"},{"target":"[2001:db8::1]:443/tcp","label":"web"}]}"#,
        ),
        debit(
            4,
            r#"[{"counter":"calls","n":1}]"#,
            r#","receipt":{"targets":[{"target":"[2001:db8::1]:443/tcp","label":"web"}]}"#,
        ),
    ];
    assert_eq!(
        lines,
        expected.iter().map(String::as_str).collect::<Vec<_>>()
    );
    let (code, listed) = case.json(&["ledger", file]);
    assert_eq!((code, &listed["verified"]), (0, &json!(true)), "{listed}");
}

#[test]
fn a_debit_without_a_destination_says_so() {
    let case = Case::new();
    let p = case.pass("p.toml", PASS);
    let file = s(&p);
    for args in [
        vec!["calls"],
        vec!["calls", "--dry-run"],
        vec!["--charge", "calls=1", "--charge", "requests=1"],
        vec!["--charge", "calls=1", "--dry-run"],
        vec!["calls", "--caller-ref", "targetless"],
    ] {
        let (code, reply) = case.json(&[&["spend", file], &args[..]].concat());
        assert_eq!(code, 0, "{args:?}: {reply}");
        assert!(warns_no_target(&reply), "{args:?}: {reply}");
        let message = reply["warnings"]
            .as_array()
            .and_then(|w| w.last())
            .expect("warning");
        assert!(
            message
                .as_str()
                .is_some_and(|m| m.contains("require_target_v1 = true"))
        );
        assert!(reply["advice"].to_string().contains(NO_TARGET), "{reply}");
    }
    for args in [
        vec!["calls", "--to", "192.0.2.10:5060/udp"],
        vec![
            "--charge",
            "calls=1",
            "--to",
            "192.0.2.10:5060/udp",
            "--dry-run",
        ],
        vec!["calls", "--n", "100"],
        vec!["calls", "--to", "192.0.2.11:5060/udp"],
    ] {
        let (_, reply) = case.json(&[&["spend", file], &args[..]].concat());
        assert_eq!(reply["warnings"], json!([]), "{args:?}: {reply}");
    }
    let text = case.run(&["spend", file, "calls"], Some(NOW));
    assert_eq!(text.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&text.stderr);
    assert!(
        stderr.contains(&format!("hallpass: warning: {NO_TARGET}")),
        "{stderr}"
    );
    assert!(String::from_utf8_lossy(&text.stdout).starts_with("RECORDED: 1 calls"));
    let text = case.run(
        &["spend", file, "calls", "--to", "192.0.2.10:5060/udp"],
        Some(NOW),
    );
    assert!(!String::from_utf8_lossy(&text.stderr).contains("hallpass: warning:"));
}

#[test]
fn a_required_target_still_refuses_a_targetless_debit() {
    let case = Case::new();
    let p = case.pass(
        "p.toml",
        &PASS.replace("[approval]", "require_target_v1 = true\n\n[approval]"),
    );
    let file = s(&p);
    for args in [
        vec!["calls"],
        vec!["calls", "--dry-run"],
        vec!["--charge", "calls=1", "--charge", "requests=1"],
        vec!["calls", "--caller-ref", "targetless"],
    ] {
        let (code, reply) = case.json(&[&["spend", file], &args[..]].concat());
        assert_eq!(code, 2, "{args:?}: {reply}");
        assert_eq!(reply["refusal"]["code"], "target-required");
        assert_eq!(reply["warnings"], json!([]), "{args:?}: {reply}");
        assert_reply_shape(&reply, "target-required");
    }
    // Nothing was recorded: at most the ledger header exists.
    let ledger = fs::read_to_string(hallpass::ledger_path(&p)).unwrap_or_default();
    assert!(ledger.lines().count() <= 1, "{ledger}");
    let (code, reply) = case.json(&["spend", file, "calls", "--to", "192.0.2.10:5060/udp"]);
    assert_eq!((code, &reply["warnings"]), (0, &json!([])), "{reply}");
}

/// Real decisions, made with the production clock, pass the reference decoder.
#[test]
fn the_reference_decoder_accepts_genuine_replies() {
    let case = Case::new();
    let real = hallpass::time::OffsetDateTime::now_utc();
    let day = hallpass::time::Duration::days(1);
    let window = PASS
        .replace("2026-11-20T08:00:00Z", &hallpass::stamp(real - day))
        .replace("2026-11-20T17:00:00Z", &hallpass::stamp(real + day));
    let p = case.pass("real.pass", &window);
    let loaded = hallpass::load(&p).expect("validated pass");
    let digest = loaded.digest.to_string();
    let target = json!([{"target": "192.0.2.10:5060/udp", "name": null}]);
    let mut samples = Vec::new();
    for (mode, args, targets) in [
        ("scalar", vec!["calls"], json!([])),
        ("charges", vec!["--charge", "calls=1"], json!([])),
        (
            "charges",
            vec!["--charge", "calls=1", "--to", "192.0.2.10:5060/udp"],
            target.clone(),
        ),
        (
            "scalar",
            vec!["calls", "--to", "192.0.2.10:5060/udp"],
            target,
        ),
    ] {
        let output = case.run(
            &[&["--json", "spend", s(&p), "--digest", &digest], &args[..]].concat(),
            None,
        );
        let stdout = String::from_utf8(output.stdout).expect("utf8");
        let reply: Value = serde_json::from_str(&stdout).expect("reply");
        assert_reply_shape(&reply, mode);
        if targets == json!([]) {
            assert!(warns_no_target(&reply), "{reply}");
        } else {
            assert_eq!(reply["warnings"], json!([]), "{reply}");
        }
        let expected = json!({
            "file": s(&p), "pass_id": loaded.pass.id, "digest": digest, "mode": mode,
            "targets": targets, "charges": [{"counter": "calls", "n": 1}],
            "caller_ref": null, "record_targets": false,
        });
        samples.push(json!({
            "id": format!("{mode} {args:?}"), "expected": expected, "exit": output.status.code(),
            "stdout": stdout, "action": "proceed", "warnings": reply["warnings"],
        }));
    }
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/conformance/check.py");
    let mut reference = Command::new("python3")
        .arg("-I")
        .arg("-B")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(script)
        .arg("--stdin-cases")
        .stdin(Stdio::piped())
        .spawn()
        .expect("reference decoder");
    reference
        .stdin
        .take()
        .expect("stdin")
        .write_all(&serde_json::to_vec(&samples).expect("serialize"))
        .expect("pipe genuine replies");
    assert!(reference.wait().expect("reference").success());
}
