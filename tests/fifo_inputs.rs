//! Every file a command reads is opened without following a link and
//! without blocking, and only a regular file is read (bn-2mz). The test
//! walks every command of `hallpass help` and puts a FIFO in place of each
//! of its arguments in turn: no command may hang, and every file input must
//! be refused at once with `not-regular-file`.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TARGET: &str = "192.0.2.10:5060/udp";
/// What the bone allows a refusal to take.
const PROMPTLY: Duration = Duration::from_secs(1);

const PASS: &str = r#"format = 1
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
ports = [5060]

[ceilings]
calls = 20
"#;

/// A valid invocation of every command. An argument written `@NAME` is a
/// file the command reads; `NAME` alone is any other value (a directory, an
/// output file, a counter, a reference).
const INVOCATIONS: &[&[&str]] = &[
    &["help", "status"],
    &["version"],
    &["init", "new.toml"],
    &["check", "@p.toml"],
    &["rehearse", "@p.toml", "@scenario.toml"],
    &["capacity", "@p.toml", "calls"],
    &["status", "@p.toml"],
    &["permits", "@p.toml", "--to", TARGET],
    &["spend", "@p.toml", "calls", "--to", TARGET, "--dry-run"],
    &[
        "spend",
        "@p.toml",
        "--charge",
        "calls=1",
        "--caller-ref",
        "run-2",
    ],
    &["digest", "@p.toml"],
    &["ledger", "@p.toml"],
    &["archive", "@p.toml", "archive"],
    &["retrieve", "archive", "DIGEST", "--output", "out.toml"],
    &["receipt", "@p.toml", "--caller-ref", "run-1"],
    &[
        "audit-receipts",
        "@p.toml",
        "archive",
        "--allowed-signers",
        "@signers",
    ],
    &[
        "audit-charges",
        "@p.toml",
        "archive",
        "--allowed-signers",
        "@signers",
    ],
    &["reconcile", "@p.toml", "@manifest.json"],
    &[
        "compare-backups",
        "@p.toml",
        "@backup.ledger",
        "@p.toml.ledger",
    ],
    &["compare-backups", "@p.toml", "--ancestry", "@backup.ledger"],
    &["checkpoint", "@p.toml"],
    &["verify-checkpoint", "@p.toml.ledger", "@checkpoint.json"],
    &["adopt", "@p.toml", "--preview"],
    &["adopt", "@p.toml", "--reason", "restored from backup"],
    &["repair", "@p.toml", "--drop-torn-tail", "--preview"],
    &[
        "reconcile-references",
        "@p.toml",
        "--adoption",
        "1",
        "--references",
        "@references.json",
        "--reason",
        "every reference in the run journal",
    ],
    &[
        "verify-approval",
        "@p.toml",
        "--signature",
        "@p.toml.sig",
        "--allowed-signers",
        "@signers",
        "--principal",
        "owner@example.org",
    ],
    &["diff", "@p.toml", "@q.toml"],
    &["diff", "@p.toml", "@q.toml", "--budget-impact"],
    &["consumer-coverage", "@p.toml", "--can", "endpoints"],
    &["lint", "@p.toml"],
    &["test-pass", "@p.toml", "@suite.toml"],
    &[
        "approval-id",
        "--owner",
        "Example Corp",
        "--reference",
        "approval-42",
    ],
];

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let case = Self {
            dir: tempfile::tempdir().expect("tempdir"),
        };
        fs::create_dir(case.path("home")).expect("home");
        fs::create_dir(case.path("archive")).expect("archive");
        fs::set_permissions(case.path("archive"), fs::Permissions::from_mode(0o700))
            .expect("chmod archive");
        case.private("p.toml", PASS);
        case.private("q.toml", PASS);
        let spent = case.run(&[
            "spend",
            "p.toml",
            "calls",
            "--to",
            TARGET,
            "--caller-ref",
            "run-1",
        ]);
        assert_eq!(spent.status.code(), Some(0), "{}", text(&spent));
        fs::copy(case.path("p.toml.ledger"), case.path("backup.ledger")).expect("backup");
        let archived = case.run(&["archive", "p.toml", "archive"]);
        assert_eq!(archived.status.code(), Some(0), "{}", text(&archived));
        let checkpoint = case.run(&["checkpoint", "p.toml"]);
        assert_eq!(checkpoint.status.code(), Some(0), "{}", text(&checkpoint));
        fs::write(case.path("checkpoint.json"), &checkpoint.stdout).expect("checkpoint");
        let manifest = serde_json::json!({
            "version": 1,
            "pass_id": "example-2026-11",
            "units": [{
                "caller_ref": "run-1",
                "digest": hallpass::Digest::of(PASS.as_bytes()).to_string(),
                "charges": [{"counter": "calls", "n": 1}],
            }],
        });
        case.private("manifest.json", &manifest.to_string());
        case.private(
            "references.json",
            r#"{"version": 1, "pass_id": "example-2026-11", "references": []}"#,
        );
        case.private(
            "scenario.toml",
            "version = 1\n\n[[step]]\nid = \"one\"\nat = \"2026-11-20T09:00:00Z\"\ncharges = [{ counter = \"calls\", n = 1 }]\n",
        );
        case.private(
            "suite.toml",
            "version = 1\n\n[[case]]\nid = \"edge\"\nat = \"2026-11-20T09:00:00Z\"\nto = \"192.0.2.10:5060/udp\"\nexpected = \"allowed\"\n",
        );
        case.private(
            "signers",
            "owner@example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample\n",
        );
        case.private(
            "p.toml.sig",
            "-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\n",
        );
        let fifo = Command::new("mkfifo")
            .arg(case.path("fifo"))
            .status()
            .expect("mkfifo");
        assert!(fifo.success());
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// A private file, dated well in the past so that no read waits for it
    /// to settle.
    fn private(&self, name: &str, text: &str) {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        File::options()
            .write(true)
            .open(&path)
            .and_then(|f| f.set_modified(SystemTime::now() - Duration::from_secs(3600)))
            .expect("backdate");
    }

    fn command(&self, args: &[&str]) -> Command {
        let home = self.path("home");
        let mut command = Command::new(BIN);
        command
            .current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env("TMPDIR", self.dir.path())
            .env_remove("HALLPASS_FORMAT")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(args);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("run")
    }

    /// Run with a watchdog: a command that blocks is killed after five
    /// seconds and reported, instead of hanging the test.
    fn run_timed(&self, args: &[&str]) -> (Duration, Output) {
        let started = Instant::now();
        let child = self.command(args).spawn().expect("spawn");
        let pid = child.id();
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = send.send(child.wait_with_output());
        });
        let Ok(out) = receive.recv_timeout(Duration::from_secs(5)) else {
            let _ = Command::new("kill").arg(pid.to_string()).status();
            panic!("{args:?} blocked for 5 s and was killed");
        };
        (started.elapsed(), out.expect("wait"))
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn reply(args: &[&str], out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {}", text(out)))
}

/// The argument vector of an invocation, with `@` taken off file inputs,
/// `DIGEST` replaced with the digest of the archived pass, and the argument
/// at `fifo` (if any) replaced with the FIFO.
fn argv(invocation: &[&str], fifo: Option<usize>) -> Vec<String> {
    let mut args = vec!["--json".to_owned()];
    for (i, arg) in invocation.iter().enumerate() {
        args.push(if Some(i) == fifo {
            "fifo".to_owned()
        } else if *arg == "DIGEST" {
            hallpass::Digest::of(PASS.as_bytes()).to_string()
        } else {
            arg.strip_prefix('@').unwrap_or(arg).to_owned()
        });
    }
    args
}

#[test]
fn every_command_has_an_invocation_here() {
    let out = Case::new().run(&["--json", "help"]);
    let listed: BTreeSet<String> = reply(&["help"], &out)["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .map(|c| c["name"].as_str().expect("name").to_owned())
        .collect();
    let covered: BTreeSet<String> = INVOCATIONS.iter().map(|i| i[0].to_owned()).collect();
    assert_eq!(
        listed, covered,
        "add an invocation for each new command, marking every file it reads with @"
    );
}

#[test]
fn a_fifo_is_refused_at_once_for_every_file_input_and_blocks_nothing() {
    let case = Case::new();
    for invocation in INVOCATIONS {
        // Without the FIFO no input is refused for its type, so a refusal
        // below is the FIFO's. (An invocation that clap rejected would fail
        // below too: its file inputs would be refused as usage errors.)
        let args = argv(invocation, None);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = case.run(&args);
        let v = reply(&args, &out);
        assert_eq!(v["command"], invocation[0], "{args:?}: {v}");
        assert_ne!(v["error"]["code"], "not-regular-file", "{args:?}: {v}");
        for (i, arg) in invocation.iter().enumerate().skip(1) {
            if arg.starts_with('-') {
                continue;
            }
            let args = argv(invocation, Some(i));
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let (took, out) = case.run_timed(&args);
            assert!(took < PROMPTLY, "{args:?} took {took:?}");
            if arg.starts_with('@') {
                let v = reply(&args, &out);
                assert_eq!(out.status.code(), Some(1), "{args:?}: {v}");
                assert_eq!(v["error"]["code"], "not-regular-file", "{args:?}: {v}");
                let message = v["error"]["message"].as_str().expect("message");
                assert!(
                    message.contains("fifo is not a regular file")
                        && message.contains("save it to a regular file"),
                    "{args:?}: {message}"
                );
            }
        }
    }
}

#[test]
fn a_fifo_in_place_of_the_ledger_is_refused_at_once() {
    let case = Case::new();
    case.private("f.toml", &PASS.replace("example-2026-11", "fifo-ledger"));
    let made = Command::new("mkfifo")
        .arg(case.path("f.toml.ledger"))
        .status()
        .expect("mkfifo");
    assert!(made.success());
    for args in [
        vec!["--json", "status", "f.toml"],
        vec!["--json", "permits", "f.toml", "--to", TARGET],
        vec!["--json", "ledger", "f.toml"],
        vec!["--json", "spend", "f.toml", "calls"],
        vec!["--json", "spend", "f.toml", "calls", "--dry-run"],
        vec!["--json", "checkpoint", "f.toml"],
        vec!["--json", "adopt", "f.toml", "--preview"],
        vec![
            "--json",
            "repair",
            "f.toml",
            "--drop-torn-tail",
            "--preview",
        ],
    ] {
        let (took, out) = case.run_timed(&args);
        assert!(took < PROMPTLY, "{args:?} took {took:?}");
        let v = reply(&args, &out);
        assert_eq!(v["error"]["code"], "not-regular-file", "{args:?}: {v}");
    }
}

#[test]
fn a_backup_that_is_not_a_regular_file_refuses_the_comparison() {
    let case = Case::new();
    let args = [
        "--json",
        "compare-backups",
        "p.toml",
        "backup.ledger",
        "fifo",
    ];
    let out = case.run(&args);
    let v = reply(&args, &out);
    assert_eq!(out.status.code(), Some(1), "{v}");
    assert_eq!(v["result"], "error", "{v}");
    assert_eq!(v["error"]["code"], "not-regular-file", "{v}");
    // A directory too; a missing file or a damaged copy is still a row.
    let dir = [
        "--json",
        "compare-backups",
        "p.toml",
        "backup.ledger",
        "archive",
    ];
    assert_eq!(
        reply(&dir, &case.run(&dir))["error"]["code"],
        "not-regular-file"
    );
    let missing = [
        "--json",
        "compare-backups",
        "p.toml",
        "backup.ledger",
        "gone.ledger",
    ];
    let v = reply(&missing, &case.run(&missing));
    assert_eq!(v["result"], "partial-error", "{v}");
    assert_eq!(v["candidates"][0]["relation"], "exact", "{v}");
    assert_eq!(v["candidates"][1]["error"]["code"], "io", "{v}");
}

#[test]
fn the_library_opens_inputs_without_blocking() {
    let case = Case::new();
    let fifo = case.path("fifo");
    let started = Instant::now();
    assert!(matches!(
        hallpass::open_input(&fifo),
        Err(hallpass::Error::NotRegular { path }) if path == fifo
    ));
    assert!(matches!(
        hallpass::load(&fifo),
        Err(hallpass::Error::NotRegular { .. })
    ));
    std::os::unix::fs::symlink(case.path("suite.toml"), case.path("link")).expect("link");
    assert!(matches!(
        hallpass::open_input(&case.path("link")),
        Err(hallpass::Error::Symlink { .. })
    ));
    assert!(started.elapsed() < PROMPTLY);
    let mut text = String::new();
    std::io::Read::read_to_string(
        &mut hallpass::open_input(&case.path("suite.toml")).expect("a regular file"),
        &mut text,
    )
    .expect("read");
    assert!(text.starts_with("version = 1"));
}
