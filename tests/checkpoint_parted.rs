//! A whole-machine restore, then more spends by a worker before anyone
//! compares the ledger with the outside checkpoint than the restore lost
//! (bn-1e7w): the ledger reaches the checkpoint's sequence with a line of
//! its own there (`verify-checkpoint` says mismatch). The checkpoint's line
//! hashes place it as they place a shorter ledger: the adoption carries the
//! checkpoint's totals less what the shared lines count, so the count ends
//! at least at the checkpoint's totals plus every spend since the restore.

#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const TO: &str = "192.0.2.10:443/tcp";
const PASS_FILE: &str = "p.toml";
const CHECKPOINT: &str = "outside.json";

struct Case {
    dir: tempfile::TempDir,
    /// The test clock, or `None` for the real one.
    clock: Option<&'static str>,
}

impl Case {
    /// A pass with `ceiling` requests, valid around the clock in use.
    fn new(ceiling: u64, clock: Option<&'static str>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        let case = Self { dir, clock };
        let (from, until) = if clock.is_some() {
            (
                "2026-11-20T08:00:00Z".to_owned(),
                "2026-11-20T17:00:00Z".to_owned(),
            )
        } else {
            let now = OffsetDateTime::now_utc()
                .replace_nanosecond(0)
                .expect("whole second");
            let at = |t: OffsetDateTime| t.format(&Rfc3339).expect("format");
            (
                at(now - time::Duration::hours(1)),
                at(now + time::Duration::hours(6)),
            )
        };
        write_private(
            &case.path(PASS_FILE),
            &format!(
                r#"format = 1
id = "restore"
name = "Eval pass"

[approval]
owner = "Pat Owner"
reference = "email"
operator = "Sam"
valid_from = {from}
valid_until = {until}
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = [443]

[ceilings]
requests = {ceiling}
"#
            ),
        );
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn state(&self) -> PathBuf {
        self.path("home/state/hallpass")
    }

    fn run_at(&self, clock: Option<&str>, args: &[&str]) -> (i32, Value, String) {
        let mut command = Command::new(BIN);
        command
            .args(["--format", "json"])
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("HALLPASS_FORMAT")
            .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"));
        if let Some(clock) = clock {
            command.env("HALLPASS_UNSAFE_TEST_CLOCK", clock);
        }
        let out = command.output().expect("run hallpass");
        let reply = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "not JSON ({e}): {} / {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (
            out.status.code().expect("exit code"),
            reply,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let (rc, reply, _) = self.run_at(self.clock, args);
        (rc, reply)
    }

    /// One request with caller reference `reference`, at `clock`; the
    /// reply's result.
    fn spend_at(&self, clock: Option<&str>, reference: &str) -> String {
        let (_, out, _) = self.run_at(
            clock,
            &[
                "spend",
                "--caller-ref",
                reference,
                "--to",
                TO,
                "--",
                PASS_FILE,
                "requests",
            ],
        );
        out["result"].as_str().unwrap_or_default().to_owned()
    }

    fn spend(&self, reference: &str) -> String {
        self.spend_at(self.clock, reference)
    }

    fn spends(&self, from: u64, to: u64) {
        for n in from..=to {
            assert_eq!(self.spend(&format!("run-{n}")), "allowed");
        }
    }

    /// Copy the ledger and the state directory aside, as a nightly
    /// snapshot does.
    fn snapshot(&self) {
        fs::create_dir(self.path("snap")).expect("snapshot dir");
        fs::copy(self.path("p.toml.ledger"), self.path("snap/ledger")).expect("copy ledger");
        copy_dir(&self.state(), &self.path("snap/state"));
    }

    /// Put the snapshot back whole: the ledger and the state directory.
    fn restore(&self) {
        fs::copy(self.path("snap/ledger"), self.path("p.toml.ledger")).expect("restore ledger");
        fs::rename(self.state(), self.path("state.lost")).expect("move state");
        copy_dir(&self.path("snap/state"), &self.state());
    }

    /// Export a checkpoint outside the snapshot.
    fn export(&self) -> Value {
        let (rc, out) = self.json(&["checkpoint", PASS_FILE]);
        assert_eq!(rc, 0, "{out}");
        write_private(&self.path(CHECKPOINT), &format!("{out}\n"));
        out
    }

    /// Change the retained checkpoint with `edit`.
    fn edit_checkpoint(&self, edit: impl FnOnce(&mut serde_json::Map<String, Value>)) {
        let mut exported: Value =
            serde_json::from_slice(&fs::read(self.path(CHECKPOINT)).expect("read")).expect("json");
        edit(exported["checkpoint"].as_object_mut().expect("object"));
        write_private(&self.path(CHECKPOINT), &format!("{exported}\n"));
    }

    fn doctor(&self) -> (i32, Value) {
        self.json(&["doctor", PASS_FILE, "--checkpoint", CHECKPOINT])
    }

    fn preview(&self) -> (i32, Value) {
        self.json(&["adopt", PASS_FILE, "--checkpoint", CHECKPOINT, "--preview"])
    }

    /// Preview, then adopt with the preview's token; the adoption's reply.
    fn adopt(&self) -> Value {
        let (rc, preview) = self.preview();
        assert_eq!(rc, 0, "{preview}");
        let token = preview["token"].as_str().expect("token").to_owned();
        let (rc, adopted) = self.json(&[
            "adopt",
            PASS_FILE,
            "--checkpoint",
            CHECKPOINT,
            "--reason",
            "restore; checkpoint from ticket",
            "--token",
            &token,
        ]);
        assert_eq!(rc, 0, "{adopted}");
        adopted
    }

    fn spent(&self) -> u64 {
        let (rc, status) = self.json(&["status", PASS_FILE]);
        assert_eq!(rc, 0, "{status}");
        status["counters"]
            .as_array()
            .or_else(|| status["ceilings"].as_array())
            .and_then(|rows| rows.iter().find(|r| r["name"] == "requests"))
            .and_then(|r| r["spent"].as_u64())
            .unwrap_or_else(|| panic!("no spent count in {status}"))
    }
}

fn write_private(path: &Path, text: &str) {
    fs::write(path, text).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
    fs::File::options()
        .write(true)
        .open(path)
        .expect("open")
        .set_modified(SystemTime::now() - Duration::from_secs(3600))
        .expect("backdate");
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("dir");
    fs::set_permissions(to, fs::Permissions::from_mode(0o700)).expect("chmod");
    for entry in fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        fs::copy(entry.path(), to.join(entry.file_name())).expect("copy");
    }
}

/// The doctor's text: headline, details and step, joined.
fn doctor_text(doctor: &Value) -> String {
    doctor.to_string()
}

fn warnings(reply: &Value) -> String {
    reply["warnings"].as_array().map_or_else(String::new, |w| {
        w.iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n")
    })
}

/// Two spends, a snapshot, two more (4 real), a checkpoint at sequence 4
/// outside the snapshot, the snapshot put back, and `k` spends by a worker
/// before anyone checks. The ceiling is exactly what was really spent.
fn restored_with(k: u64) -> Case {
    let case = Case::new(4 + k, None);
    case.spends(1, 2);
    case.snapshot();
    case.spends(3, 4);
    let out = case.export();
    assert_eq!(out["checkpoint"]["seq"], 4, "{out}");
    assert_eq!(out["checkpoint"]["totals"]["requests"], 4, "{out}");
    case.restore();
    for n in 1..=k {
        assert_eq!(case.spend(&format!("worker-{n}")), "allowed");
    }
    assert_eq!(case.spent(), 2 + k);
    case
}

fn relation(case: &Case) -> Value {
    let (_, verified) = case.json(&["verify-checkpoint", "p.toml.ledger", CHECKPOINT]);
    verified["relation"].clone()
}

/// The eval-18 repro (10-restore.sh) for K = 2, 3 and 5: the count ends at
/// exactly the checkpoint's totals plus every spend since the restore, and
/// the ceiling holds.
#[test]
fn spends_past_the_checkpoint_after_a_restore_are_counted_on_top_of_it() {
    for k in [2, 3, 5] {
        let case = restored_with(k);
        assert_eq!(relation(&case), "mismatch", "k={k}");

        let (rc, doctor) = case.doctor();
        assert_eq!(rc, 2, "k={k}: {doctor}");
        assert_eq!(doctor["problem"], "checkpoint-behind", "k={k}: {doctor}");
        assert_eq!(doctor["next"][1], "adopt", "k={k}: {doctor}");
        assert_eq!(doctor["next"][5], "--preview", "k={k}: {doctor}");
        let text = doctor_text(&doctor);
        // Only what is proved.
        assert!(
            text.contains("the ledger has entries a retained checkpoint does not show"),
            "{text}"
        );
        assert!(text.contains("relation mismatch"), "{text}");
        assert!(
            text.contains("the ledger's entries 1 to 2 are checkpointed"),
            "{text}"
        );
        assert!(
            text.contains("the ledger's entry 3 is not a checkpointed one"),
            "{text}"
        );
        assert!(!text.contains("entries 5 to"), "{text}");

        let (rc, preview) = case.preview();
        assert_eq!(rc, 0, "k={k}: {preview}");
        assert_eq!(preview["case"], "checkpoint-behind", "{preview}");
        assert_eq!(preview["carried"]["requests"], 2, "k={k}: {preview}");
        assert_eq!(preview["totals"]["requests"], 4 + k, "k={k}: {preview}");
        let said = warnings(&preview);
        assert!(
            said.contains(&format!("entries 3 to {} were written since", 2 + k)),
            "{said}"
        );
        assert!(said.contains("no spend since a restore is lost"), "{said}");
        assert!(said.contains("with another line there"), "{said}");
        assert!(said.contains("reference-inconclusive"), "{said}");

        let adopted = case.adopt();
        assert_eq!(adopted["carried"]["requests"], 2, "k={k}: {adopted}");
        assert_eq!(adopted["totals"]["requests"], 4 + k, "k={k}: {adopted}");
        assert_eq!(case.spent(), 4 + k, "k={k}");
        assert_eq!(case.spend("after-1"), "refused", "k={k}");
        assert_eq!(case.spent(), 4 + k, "k={k}");
    }
}

/// The adoption line records the checkpoint, so doctor says it is adopted
/// and a second adoption from it is refused, even after more spends.
#[test]
fn a_second_adoption_of_the_same_checkpoint_is_refused() {
    let case = restored_with(3);
    case.adopt();
    let (_, doctor) = case.doctor();
    assert_eq!(
        doctor["findings"]
            .as_array()
            .and_then(|f| f.iter().find(|f| f["code"] == "checkpoint-adopted"))
            .map(|f| f["code"].clone()),
        Some(Value::from("checkpoint-adopted")),
        "{doctor}"
    );
    let before = fs::read(case.path("p.toml.ledger")).expect("ledger");
    let (rc, preview) = case.preview();
    assert_eq!(rc, 1, "{preview}");
    assert!(
        preview["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("already acted on this checkpoint"),
        "{preview}"
    );
    assert_eq!(
        fs::read(case.path("p.toml.ledger")).expect("ledger"),
        before
    );
}

/// A ledger that holds the checkpoint's line, with more after it, is not
/// placed: nothing is missing, and there is nothing to adopt.
#[test]
fn a_ledger_that_holds_the_checkpointed_line_still_holds() {
    let case = Case::new(10, None);
    case.spends(1, 4);
    case.export();
    case.spends(5, 7);
    assert_eq!(relation(&case), "extended");
    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 0, "{doctor}");
    assert!(
        doctor["findings"]
            .as_array()
            .is_some_and(|f| f.iter().any(|f| f["code"] == "checkpoint-holds")),
        "{doctor}"
    );
    let (rc, preview) = case.preview();
    assert_eq!(rc, 1, "{preview}");
    assert!(
        preview["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("holds the line the checkpoint commits to"),
        "{preview}"
    );
}

/// With no anchor the ledger holds, no line is shared: every ledger line
/// counts as new on top of the checkpoint's totals. Too high, never too
/// low, and the preview says so.
#[test]
fn with_no_shared_line_hash_every_ledger_line_counts_as_new() {
    let case = restored_with(3);
    case.edit_checkpoint(|cp| {
        let other = cp["hash"].clone();
        if let Some(anchors) = cp.get_mut("anchors").and_then(Value::as_object_mut) {
            for hash in anchors.values_mut() {
                *hash = other.clone();
            }
        }
    });
    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["problem"], "checkpoint-behind", "{doctor}");
    let text = doctor_text(&doctor);
    assert!(
        text.contains("no ledger entry is proved a checkpointed one"),
        "{text}"
    );
    assert!(
        text.contains("beyond nothing, counting every ledger entry as new"),
        "{text}"
    );
    let (rc, preview) = case.preview();
    assert_eq!(rc, 0, "{preview}");
    assert_eq!(preview["carried"]["requests"], 4, "{preview}");
    assert_eq!(preview["totals"]["requests"], 9, "{preview}");
    let said = warnings(&preview);
    assert!(
        said.contains("the two histories part from the first entry"),
        "{said}"
    );
    assert!(
        said.contains("counts the ledger's entries 1 to 5 as new"),
        "{said}"
    );
}

/// A checkpoint from a hallpass before line hashes proves no line shared,
/// as for a shorter ledger: every ledger line counts as new.
#[test]
fn a_checkpoint_without_line_hashes_counts_every_line_of_a_longer_ledger_as_new() {
    let case = restored_with(2);
    case.edit_checkpoint(|cp| {
        cp.remove("anchors");
        cp.remove("latest");
    });
    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["problem"], "checkpoint-behind", "{doctor}");
    let text = doctor_text(&doctor);
    assert!(text.contains("records no line hashes"), "{text}");
    assert!(
        text.contains("the ledger's entry 4 is not a checkpointed one"),
        "{text}"
    );
    let adopted = case.adopt();
    assert_eq!(adopted["carried"]["requests"], 4, "{adopted}");
    assert_eq!(adopted["totals"]["requests"], 8, "{adopted}");
}

/// Totals lower than what the shared lines count do not belong to the
/// checkpoint's line hashes: blocked, and nothing is carried.
#[test]
fn totals_below_the_shared_lines_are_refused() {
    let case = restored_with(2);
    case.edit_checkpoint(|cp| {
        cp.insert("totals".to_owned(), serde_json::json!({"requests": 1}));
    });
    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["problem"], "checkpoint-fork", "{doctor}");
    assert_eq!(doctor["next"], Value::Null, "{doctor}");
    let (rc, preview) = case.preview();
    assert_eq!(rc, 1, "{preview}");
    assert!(
        preview["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("do not belong to its line hashes"),
        "{preview}"
    );
}
