//! Bidirectional controls in pass text, overlap acknowledgements, and
//! `retrieve --output`.
#![cfg(feature = "cli")]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::Command;

const HEAD: &str = "format = 1\nid = \"p\"\nname = \"n\"\n[approval]\nowner = \"O\"\nreference = \"R\"\noperator = \"Op\"\nvalid_from = 2026-11-20T08:00:00Z\nvalid_until = 2026-11-20T17:00:00Z\nrevoked = false\n";
const WIDE: &str = "[[destination]]\nlabel = \"wide\"\nnetwork = \"198.51.100.0/24\"\nprotocol = \"tcp\"\nports = \"1-1024\"\n";
const APP: &str = "[[destination]]\nlabel = \"app\"\naddress = \"198.51.100.20\"\nprotocol = \"tcp\"\nports = 443\nnames = [\"app.example.com\"]\n";

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }
    fn file(&self, name: &str, text: &str) -> String {
        let path = self.dir.path().join(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        path.to_str().expect("utf8").to_owned()
    }
    fn pass(&self, name: &str, head: &str, body: &str) -> String {
        self.file(name, &format!("{head}{body}"))
    }
    fn command(&self, json: bool, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        if json {
            cmd.arg("--json");
        }
        cmd.args(args)
            .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z")
            .env("XDG_STATE_HOME", self.dir.path().join("state"));
        cmd
    }
    /// Exit code, standard output, standard error.
    fn run(&self, json: bool, args: &[&str]) -> (i32, String, String) {
        let out = self.command(json, args).output().expect("run");
        (
            out.status.code().expect("exit"),
            String::from_utf8(out.stdout).expect("utf8"),
            String::from_utf8(out.stderr).expect("utf8"),
        )
    }
    fn json(&self, args: &[&str]) -> (i32, Value) {
        let (code, out, _) = self.run(true, args);
        (
            code,
            serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}")),
        )
    }
}

// Bidirectional controls in pass text.

#[test]
fn every_text_field_refuses_bidi_and_line_separators() {
    let case = Case::new();
    for c in ['\u{202e}', '\u{2066}', '\u{200f}', '\u{061c}', '\u{2028}'] {
        let escaped = format!("\\u{:04x}", u32::from(c));
        for (field, from, to) in [
            ("name", "name = \"n\"", format!("name = \"n{escaped}\"")),
            (
                "approval.owner",
                "owner = \"O\"",
                format!("owner = \"O{escaped}\""),
            ),
            (
                "approval.reference",
                "reference = \"R\"",
                format!("reference = \"R{escaped}\""),
            ),
            (
                "approval.operator",
                "operator = \"Op\"",
                format!("operator = \"Op{escaped}\""),
            ),
            (
                "approval.revoked_reason",
                "revoked = false",
                format!("revoked = true\nrevoked_reason = \"done{escaped}\""),
            ),
        ] {
            let head = HEAD.replace(from, &to);
            let file = case.pass("bidi.toml", &head, WIDE);
            let (code, value) = case.json(&["check", &file]);
            assert_eq!(code, 1, "{field} {c:?}: {value}");
            let text = value.to_string();
            assert!(
                text.contains(field) && text.contains("bidirectional text control"),
                "{field} {c:?}: {text}"
            );
        }
    }
    // A literal control in the file is refused the same way.
    let head = HEAD.replace("owner = \"O\"", "owner = \"O\u{202e}\"");
    let file = case.pass("literal.toml", &head, WIDE);
    assert_eq!(case.json(&["check", &file]).0, 1);
}

#[test]
fn ordinary_non_ascii_text_still_loads() {
    let case = Case::new();
    let head = HEAD.replace("owner = \"O\"", "owner = \"Zoë Ünal, שלום, مرحبا\"");
    let file = case.pass("ok.toml", &head, WIDE);
    assert_eq!(case.json(&["check", &file]).0, 0);
}

// Overlap acknowledgements.

fn acked(label: &str) -> String {
    APP.replace(
        "names = [",
        &format!("overlap_acknowledged = [\"{label}\"]\nnames = ["),
    )
}

#[test]
fn unacknowledged_overlap_warns_on_status_as_before() {
    let case = Case::new();
    let file = case.pass("p.toml", HEAD, &format!("{WIDE}{APP}"));
    let (code, _, err) = case.run(false, &["status", &file]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("warning: destination `app` restricts names"),
        "{err}"
    );
}

#[test]
fn acknowledged_overlap_is_one_note_in_status_and_full_in_check_and_lint() {
    let case = Case::new();
    let file = case.pass("p.toml", HEAD, &format!("{WIDE}{}", acked("wide")));

    let (code, out, err) = case.run(false, &["status", &file]);
    assert_eq!(code, 0, "{err}");
    assert!(!err.contains("restricts names"), "no warning: {err}");
    assert_eq!(
        out.matches("name-restriction overlap(s) acknowledged")
            .count(),
        1,
        "{out}"
    );
    let (_, value) = case.json(&["status", &file]);
    assert_eq!(value["warnings"], serde_json::json!([]));
    assert_eq!(value["name_restriction_overlaps"][0]["acknowledged"], true);

    let (code, _, err) = case.run(false, &["check", &file]);
    assert_eq!(code, 0);
    assert!(
        err.contains("restricts names") && err.contains("acknowledged"),
        "{err}"
    );
    let (_, value) = case.json(&["check", &file]);
    assert_eq!(value["name_restriction_overlaps"][0]["acknowledged"], true);
    assert_eq!(value["warnings"].as_array().expect("warnings").len(), 1);

    let (_, value) = case.json(&["lint", &file]);
    assert_eq!(value["findings"][0]["code"], "name-restriction-overlap");
    assert_eq!(value["findings"][0]["acknowledged"], true);
    let (_, out, _) = case.run(false, &["lint", &file]);
    assert!(out.contains("acknowledged by the owner"), "{out}");
}

#[test]
fn acknowledgement_never_changes_a_decision() {
    let case = Case::new();
    let plain = case.pass("plain.toml", HEAD, &format!("{WIDE}{APP}"));
    let ack = case.pass("ack.toml", HEAD, &format!("{WIDE}{}", acked("wide")));
    let args = |f: &str| {
        vec![
            "permits".to_owned(),
            f.to_owned(),
            "--to".to_owned(),
            "198.51.100.20:443/tcp".to_owned(),
        ]
    };
    let run = |f: &str| {
        let a = args(f);
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        let (code, mut value) = case.json(&refs);
        value["file"] = Value::Null;
        value["digest"] = Value::Null;
        (code, value)
    };
    assert_eq!(run(&plain), run(&ack));
    assert_eq!(
        run(&ack).0,
        0,
        "an unnamed query is still allowed through wide"
    );
}

#[test]
fn acknowledgement_naming_a_missing_or_wrong_destination_is_a_problem() {
    let case = Case::new();
    for (body, expect) in [
        (
            format!("{WIDE}{}", acked("nope")),
            "is not the label of any destination",
        ),
        (
            format!("{WIDE}{}", acked("app")),
            "names this destination itself",
        ),
        // Acknowledged destination has names, so it cannot defeat another list.
        (
            format!(
                "{WIDE}{}{}",
                acked("other"),
                APP.replace("app\"", "other\"")
                    .replace("198.51.100.20", "198.51.100.21")
            ),
            "has `names`",
        ),
        // On a destination without names.
        (
            format!(
                "{}{APP}",
                WIDE.replace("protocol", "overlap_acknowledged = [\"app\"]\nprotocol")
            ),
            "without `names`",
        ),
        (
            format!(
                "{WIDE}{}",
                APP.replace("names = [", "overlap_acknowledged = []\nnames = [")
            ),
            "empty list",
        ),
        (
            format!(
                "{WIDE}{}",
                APP.replace(
                    "names = [",
                    "overlap_acknowledged = [\"wide\", \"wide\"]\nnames = ["
                )
            ),
            "listed twice",
        ),
        (
            format!(
                "{WIDE}{}",
                APP.replace("names = [", "overlap_acknowledged = \"wide\"\nnames = [")
            ),
            "must be a list",
        ),
    ] {
        let file = case.pass("bad.toml", HEAD, &body);
        let (code, value) = case.json(&["check", &file]);
        assert_eq!(code, 1, "{expect}: {value}");
        assert!(value.to_string().contains(expect), "{expect}: {value}");
    }
}

#[test]
fn acknowledgement_of_a_pair_that_does_not_overlap_is_a_warning() {
    let case = Case::new();
    let apart = APP.replace("198.51.100.20", "203.0.113.20");
    let apart = apart.replace("names = [", "overlap_acknowledged = [\"wide\"]\nnames = [");
    let file = case.pass("p.toml", HEAD, &format!("{WIDE}{apart}"));
    for command in ["check", "status", "lint"] {
        let (code, value) = case.json(&[command, &file]);
        assert_eq!(code, 0, "{command}: {value}");
        let warnings = value["warnings"].to_string();
        assert!(
            warnings.contains("acknowledges an overlap with `wide`")
                && warnings.contains("covers nothing"),
            "{command}: {warnings}"
        );
    }
}

#[test]
fn diff_shows_a_changed_acknowledgement_for_review() {
    let case = Case::new();
    let old = case.pass("old.toml", HEAD, &format!("{WIDE}{APP}"));
    let new = case.pass("new.toml", HEAD, &format!("{WIDE}{}", acked("wide")));
    let (code, value) = case.json(&["diff", &old, &new]);
    assert_eq!(code, 0, "{value}");
    let change = value["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .find(|c| c["field"] == "destination[app].overlap_acknowledged")
        .expect("change");
    assert_eq!(change["after"], "wide");
    assert_eq!(change["review_required"], true);
}

// retrieve --output.

struct Archive {
    case: Case,
    dir: String,
    digest: String,
}

fn archive() -> Archive {
    let case = Case::new();
    let file = case.pass("p.toml", HEAD, WIDE);
    let dir = case.dir.path().join("arch");
    fs::create_dir(&dir).expect("mkdir");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("mode");
    let dir = dir.to_str().expect("utf8").to_owned();
    let (code, value) = case.json(&["archive", &file, &dir]);
    assert_eq!(code, 0, "{value}");
    let digest = value["digest"].as_str().expect("digest").to_owned();
    Archive { case, dir, digest }
}

#[test]
fn retrieve_output_writes_a_private_file_under_a_group_writable_umask() {
    let a = archive();
    let target = a.case.dir.path().join("out.toml");
    let target = target.to_str().expect("utf8");
    let mut cmd = a
        .case
        .command(false, &["retrieve", &a.dir, &a.digest, "--output", target]);
    // Run through the shell so the umask is the common 002.
    let script = format!(
        "umask 002; exec {:?} \"$@\"",
        env!("CARGO_BIN_EXE_hallpass")
    );
    cmd = {
        let mut sh = Command::new("sh");
        sh.arg("-c").arg(script).arg("sh");
        sh.args(cmd.get_args());
        for (k, v) in cmd.get_envs() {
            if let Some(v) = v {
                sh.env(k, v);
            }
        }
        sh
    };
    let out = cmd.output().expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("mode 0600"));
    assert_eq!(
        fs::metadata(target).expect("meta").permissions().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        fs::read_to_string(target).expect("read"),
        format!("{HEAD}{WIDE}")
    );
    // The result is accepted by diff, which refuses a group-writable file.
    let (code, _, err) = a.case.run(false, &["check", target]);
    assert_eq!(code, 0, "{err}");
}

#[test]
fn retrieve_output_refuses_an_existing_file_and_any_link() {
    let a = archive();
    let existing = a.case.file("existing.toml", "keep me\n");
    let (code, _, err) = a.case.run(
        false,
        &["retrieve", &a.dir, &a.digest, "--output", &existing],
    );
    assert_ne!(code, 0);
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(fs::read_to_string(&existing).expect("read"), "keep me\n");

    let victim = a.case.file("victim.toml", "victim\n");
    let link = a.case.dir.path().join("link.toml");
    symlink(&victim, &link).expect("link");
    let (code, _, err) = a.case.run(
        false,
        &[
            "retrieve",
            &a.dir,
            &a.digest,
            "--output",
            link.to_str().expect("utf8"),
        ],
    );
    assert_ne!(code, 0);
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(fs::read_to_string(&victim).expect("read"), "victim\n");

    let dangling = a.case.dir.path().join("dangling.toml");
    symlink(a.case.dir.path().join("nowhere"), &dangling).expect("link");
    let (code, _, _) = a.case.run(
        false,
        &[
            "retrieve",
            &a.dir,
            &a.digest,
            "--output",
            dangling.to_str().expect("utf8"),
        ],
    );
    assert_ne!(code, 0);
    assert!(!a.case.dir.path().join("nowhere").exists());
}

#[test]
fn retrieve_output_json_names_the_file_and_a_bad_digest_creates_nothing() {
    let a = archive();
    let target = a.case.dir.path().join("j.toml");
    let target = target.to_str().expect("utf8");
    let (code, value) = a
        .case
        .json(&["retrieve", &a.dir, &a.digest, "--output", target]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["output"], target);
    assert_eq!(value["mode"], "0600");

    let missing = a.case.dir.path().join("none.toml");
    let bad = format!("sha256:{}", "0".repeat(64));
    let (code, _, _) = a.case.run(
        false,
        &[
            "retrieve",
            &a.dir,
            &bad,
            "--output",
            missing.to_str().expect("utf8"),
        ],
    );
    assert_ne!(code, 0);
    assert!(!missing.exists());
}

#[test]
fn group_writable_pass_error_suggests_retrieve_output() {
    let case = Case::new();
    let file = case.pass("p.toml", HEAD, WIDE);
    fs::set_permissions(&file, fs::Permissions::from_mode(0o664)).expect("mode");
    let (code, _, err) = case.run(false, &["check", &file]);
    assert_ne!(code, 0);
    assert!(
        err.contains("chmod 600") && err.contains("retrieve DIR DIGEST --output FILE"),
        "{err}"
    );
}
