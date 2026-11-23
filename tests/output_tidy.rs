#![cfg(feature = "cli")]
//! Output tidy-ups: over-ceiling flags, debit alignment, seconds left,
//! the ignored relative state directory, the no-witness wording and the
//! reasons `verify-approval` gives.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T10:00:00Z";
const PASS: &str = r#"format = 1
id = "tidy-2026-11"
name = "Tidy"

[approval]
owner = "Pat Owner"
reference = "email"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "web"
network = "192.0.2.0/24"
protocol = "tcp"
ports = 443

[ceilings]
calls = 6
bytes = 100
"#;

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        Self { dir }
    }
    fn home(&self) -> std::path::PathBuf {
        self.dir.path().join("home")
    }
    fn pass(&self, text: &str) -> std::path::PathBuf {
        let p = self.dir.path().join("p.toml");
        fs::write(&p, text).expect("write");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).expect("chmod");
        p
    }
    fn cmd(&self, args: &[&str], now: &str) -> Command {
        let mut c = Command::new(BIN);
        c.env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.home())
            .env("XDG_STATE_HOME", self.home().join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", now)
            .args(args);
        c
    }
    fn run(&self, args: &[&str], now: &str) -> Output {
        self.cmd(args, now).output().expect("run")
    }
    fn json(&self, args: &[&str], now: &str) -> (i32, Value) {
        let mut all = vec!["--format", "json"];
        all.extend_from_slice(args);
        let o = self.run(&all, now);
        let v = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
            panic!(
                "{e}: {} / {}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            )
        });
        (o.status.code().expect("code"), v)
    }
    fn text(&self, args: &[&str], now: &str) -> String {
        let mut all = vec!["--format", "text"];
        all.extend_from_slice(args);
        let o = self.run(&all, now);
        String::from_utf8_lossy(&o.stdout).into_owned()
    }
}

fn s(p: &Path) -> &str {
    p.to_str().expect("utf8")
}

#[test]
fn over_ceiling_is_flagged_in_status_and_ledger() {
    let env = Env::new();
    let file = env.pass(PASS);
    let (rc, out) = env.json(&["spend", s(&file), "calls", "--n", "5"], NOW);
    assert_eq!(rc, 0, "{out}");
    let (_, before) = env.json(&["status", s(&file)], NOW);
    assert_eq!(before["counters"][1]["over_ceiling"], false);
    fs::write(&file, PASS.replace("calls = 6", "calls = 3")).expect("lower");
    let (_, st) = env.json(&["status", s(&file)], NOW);
    let calls = st["counters"]
        .as_array()
        .expect("counters")
        .iter()
        .find(|c| c["name"] == "calls")
        .expect("calls");
    assert_eq!(calls["over_ceiling"], true);
    assert_eq!(calls["over_by"], 2);
    assert_eq!(calls["remaining"], 0);
    let text = env.text(&["status", s(&file)], NOW);
    assert!(text.contains("OVER by 2"), "{text}");
    let (_, led) = env.json(&["ledger", s(&file)], NOW);
    let t = led["totals"]
        .as_array()
        .expect("totals")
        .iter()
        .find(|t| t["name"] == "calls")
        .expect("calls");
    assert_eq!(
        (t["over_ceiling"].as_bool(), t["over_by"].as_u64()),
        (Some(true), Some(2))
    );
    let text = env.text(&["ledger", s(&file)], NOW);
    assert!(text.contains("5 spent of 3: OVER by 2"), "{text}");
}

#[test]
fn multi_counter_debit_rows_align_with_the_columns() {
    let env = Env::new();
    let file = env.pass(PASS);
    let (rc, out) = env.json(&["spend", s(&file), "calls", "--n", "1"], NOW);
    assert_eq!(rc, 0, "{out}");
    let (rc, out) = env.json(
        &[
            "spend",
            s(&file),
            "--charge",
            "calls=1",
            "--charge",
            "bytes=20",
            "--to",
            "192.0.2.1:443/tcp",
        ],
        NOW,
    );
    assert_eq!(rc, 0, "{out}");
    let text = env.text(&["ledger", s(&file)], NOW);
    let header = text
        .lines()
        .find(|l| l.contains("counter"))
        .expect("header");
    let col = header.find("counter").expect("col");
    let calls = text.lines().filter(|l| l.contains("calls")).count();
    assert!(calls >= 2, "{text}");
    for line in text
        .lines()
        .filter(|l| l.contains("bytes ") || l.contains(" calls "))
    {
        if line.contains("spent") {
            continue;
        }
        let name = line.get(col..).expect("wide enough");
        assert!(
            name.starts_with("calls") || name.starts_with("bytes"),
            "misaligned: {line:?}\n{text}"
        );
    }
    assert!(text.contains("DEBIT of 2 counter(s)"), "{text}");
}

#[test]
fn seconds_left_agree_with_the_decision() {
    let env = Env::new();
    let file = env.pass(PASS);
    // 0.5 s before the window closes: open, so never "0 s", but not "1 s"
    // either, since one second of work would be refused.
    let (_, st) = env.json(&["status", s(&file)], "2026-11-20T16:59:59.5Z");
    assert_eq!(st["window"]["state"], "valid", "{st}");
    assert_eq!(st["window"]["seconds_remaining"], 0);
    let text = env.text(&["status", s(&file)], "2026-11-20T16:59:59.5Z");
    assert!(text.contains("VALID, less than 1 s left"), "{text}");
    // 0.5 s before it opens: the wait rounds up.
    let (_, st) = env.json(&["status", s(&file)], "2026-11-20T07:59:59.5Z");
    assert_eq!(st["window"]["seconds_until_open"], 1, "{st}");
    // 1.5 s left, work of 2 s: refused, and the text says 1 s remain, not the
    // 2 s that was refused.
    let (rc, out) = env.json(
        &[
            "spend",
            s(&file),
            "calls",
            "--duration",
            "2",
            "--to",
            "192.0.2.1:443/tcp",
        ],
        "2026-11-20T16:59:58.5Z",
    );
    assert_eq!(rc, 2, "{out}");
    let msg = out["refusal"]["message"].as_str().expect("message");
    assert!(
        msg.contains("; 1 s remain") && !msg.contains("2 s remain"),
        "{msg}"
    );
}

#[test]
fn relative_state_home_is_warned_about() {
    let env = Env::new();
    let file = env.pass(PASS);
    let run = |extra: &[&str]| {
        let mut c = env.cmd(extra, NOW);
        c.env("XDG_STATE_HOME", "relstate");
        c.output().expect("run")
    };
    let o = run(&["--format", "json", "status", s(&file)]);
    let v: Value = serde_json::from_slice(&o.stdout).expect("json");
    let w = v["warnings"].as_array().expect("warnings");
    let w = w
        .iter()
        .filter_map(Value::as_str)
        .find(|w| w.contains("relstate"))
        .expect("warning");
    assert!(w.contains(".local/state/hallpass"), "{w}");
    let o = run(&["--format", "text", "status", s(&file)]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("relstate") && err.contains(".local/state/hallpass"),
        "{err}"
    );
    // An absolute value draws no such warning.
    let (_, v) = env.json(&["status", s(&file)], NOW);
    assert!(!v["warnings"].to_string().contains("XDG_STATE_HOME"), "{v}");
}

#[test]
fn no_witness_warning_holds_for_a_refused_spend() {
    let env = Env::new();
    let file = env.pass(PASS);
    let (rc, _) = env.json(&["spend", s(&file), "calls"], NOW);
    assert_eq!(rc, 0);
    fs::remove_dir_all(env.home().join("state")).expect("drop witness");
    let (_, out) = env.json(
        &[
            "spend",
            s(&file),
            "calls",
            "--caller-ref",
            "r1",
            "--require-new-ref",
        ],
        NOW,
    );
    let all = out["warnings"].to_string();
    assert!(!all.contains("next spend records one"), "{all}");
    if all.contains("no witness") {
        assert!(all.contains("a spend that is allowed records one"), "{all}");
    }
}

fn have_ssh_keygen() -> bool {
    Command::new("ssh-keygen").arg("-?").output().is_ok()
}

#[test]
fn verify_approval_names_the_reason() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let dir = env.dir.path();
    let key = |args: &[&str]| {
        let o = Command::new("ssh-keygen")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("ssh-keygen");
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    for k in ["owner", "other"] {
        key(&["-q", "-t", "ed25519", "-N", "", "-f", k]);
    }
    let owner = fs::read_to_string(dir.join("owner.pub")).expect("pub");
    let other = fs::read_to_string(dir.join("other.pub")).expect("pub");
    fs::write(dir.join("trust"), format!("alice {owner}")).expect("trust");
    fs::write(dir.join("trust-other"), format!("alice {other}")).expect("trust");
    fs::write(dir.join("trust-bob"), format!("bob {owner}")).expect("trust");
    for (f, ns) in [("approval", "hallpass-approval-v1"), ("wrongns", "file")] {
        fs::write(dir.join(f), PASS).expect("pass");
        fs::set_permissions(dir.join(f), fs::Permissions::from_mode(0o600)).expect("chmod");
        key(&["-q", "-Y", "sign", "-f", "owner", "-n", ns, f]);
    }
    let verify = |file: &str, sig: &str, trust: &str, who: &str| {
        let (rc, v) = env.json(
            &[
                "verify-approval",
                file,
                "--principal",
                who,
                "--signature",
                sig,
                "--allowed-signers",
                trust,
            ],
            NOW,
        );
        // Run from the temp dir so relative names resolve.
        (rc, v)
    };
    let cwd = std::env::current_dir().expect("cwd");
    let abs = |n: &str| dir.join(n).to_string_lossy().into_owned();
    let _ = cwd;
    let cases = [
        (
            abs("approval"),
            abs("wrongns.sig"),
            "trust",
            "alice",
            "wrong-namespace",
        ),
        (
            abs("approval"),
            abs("approval.sig"),
            "trust-other",
            "alice",
            "untrusted-key",
        ),
        (
            abs("approval"),
            abs("approval.sig"),
            "trust-bob",
            "alice",
            "wrong-principal",
        ),
    ];
    for (file, sig, trust, who, reason) in cases {
        let (rc, v) = verify(&file, &sig, &abs(trust), who);
        assert_eq!(rc, 2, "{v}");
        assert_eq!(v["result"], "unverified");
        assert_eq!(v["reason"], reason, "{v}");
        assert!(v["next_step"].as_str().is_some_and(|s| !s.is_empty()));
    }
    fs::write(dir.join("approval"), format!("{PASS}\n# changed\n")).expect("edit");
    let (rc, v) = verify(
        &abs("approval"),
        &abs("approval.sig"),
        &abs("trust"),
        "alice",
    );
    assert_eq!(
        (rc, v["reason"].as_str()),
        (2, Some("bytes-do-not-match")),
        "{v}"
    );
}
