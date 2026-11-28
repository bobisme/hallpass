//! A spend after a whole-machine restore, before anyone compares the
//! ledger with the outside checkpoint (bn-3vei): the restored ledger is
//! shorter than the checkpoint, but its last entries are new spends at the
//! sequences the lost ones had. The checkpoint's line hashes (`anchors`)
//! and latest time place the ledger; an adoption counts every line they do
//! not prove shared as new, so the count never ends below what was spent.
//! A plain restore with nothing spent since still carries exactly.

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
const T0: &str = "2026-11-20T09:00:00Z";

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

/// The eval-17 repro (05-restore-fork-undercount.sh), on the real clock:
/// two spends, a snapshot, two more (4 real), a checkpoint outside the
/// snapshot, the snapshot put back, and one spend by a worker before anyone
/// checks (5 real, on a ceiling of 5). The restored ledger's entry 3 is that
/// new spend, not the lost third one.
#[test]
fn a_spend_after_the_restore_is_counted_on_top_of_the_checkpoint() {
    let case = Case::new(5, None);
    case.spends(1, 2);
    case.snapshot();
    case.spends(3, 4);
    let out = case.export();
    assert_eq!(out["checkpoint"]["seq"], 4, "{out}");
    assert_eq!(out["checkpoint"]["totals"]["requests"], 4, "{out}");
    assert!(out["checkpoint"]["latest"].is_string(), "{out}");
    case.restore();
    assert_eq!(case.spend("b1"), "allowed");
    assert_eq!(case.spent(), 3);

    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["problem"], "checkpoint-behind", "{doctor}");
    let text = doctor_text(&doctor);
    // Only what is proved: not "entries 4 to 4 are missing".
    assert!(!text.contains("entries 4 to 4"), "{text}");
    assert!(
        text.contains("checkpointed entries after sequence 2 are missing"),
        "{text}"
    );
    assert!(
        text.contains("the ledger's entries 1 to 2 are checkpointed"),
        "{text}"
    );
    assert!(
        text.contains("the ledger's entry 3 is not a checkpointed one"),
        "{text}"
    );

    let (rc, preview) = case.preview();
    assert_eq!(rc, 0, "{preview}");
    assert_eq!(preview["carried"]["requests"], 2, "{preview}");
    assert_eq!(preview["totals"]["requests"], 5, "{preview}");
    let said = warnings(&preview);
    assert!(said.contains("entry 3 was written since"), "{said}");
    assert!(said.contains("no spend since a restore is lost"), "{said}");

    let adopted = case.adopt();
    assert_eq!(adopted["carried"]["requests"], 2, "{adopted}");
    assert_eq!(adopted["totals"]["requests"], 5, "{adopted}");
    // The count reaches what was really spent, and the ceiling holds.
    assert!(case.spent() >= 5);
    assert_eq!(case.spend("c1"), "refused");
    assert_eq!(case.spend("c2"), "refused");
    assert_eq!(case.spent(), 5);
}

#[test]
fn a_plain_restore_with_nothing_spent_since_still_carries_exactly() {
    let case = Case::new(5, None);
    case.spends(1, 2);
    case.snapshot();
    case.spends(3, 4);
    case.export();
    case.restore();

    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["problem"], "checkpoint-behind", "{doctor}");
    let text = doctor_text(&doctor);
    assert!(
        text.contains("the ledger is behind a retained checkpoint: entries 3 to 4 are missing"),
        "{text}"
    );
    assert!(
        text.contains("an older copy of the checkpointed history"),
        "{text}"
    );

    let (rc, preview) = case.preview();
    assert_eq!(rc, 0, "{preview}");
    assert!(!warnings(&preview).contains("count twice"), "{preview}");
    let adopted = case.adopt();
    assert_eq!(adopted["carried"]["requests"], 2, "{adopted}");
    assert_eq!(adopted["totals"]["requests"], 4, "{adopted}");
    assert_eq!(case.spent(), 4);
    assert_eq!(case.spend("c1"), "allowed");
    assert_eq!(case.spend("c2"), "refused");
}

#[test]
fn the_checkpoint_records_the_latest_time_and_line_hashes_back_from_its_line() {
    let case = Case::new(100, Some(T0));
    case.spends(1, 40);
    let out = case.export();
    let checkpoint = &out["checkpoint"];
    assert_eq!(checkpoint["seq"], 40, "{out}");
    assert_eq!(checkpoint["latest"], T0, "{out}");
    let got: Vec<u64> = checkpoint["anchors"]
        .as_object()
        .expect("anchors")
        .keys()
        .map(|k| k.parse().expect("sequence"))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    // The 16 lines before 40, and those a power of two after the header or
    // before line 40.
    let mut want: std::collections::BTreeSet<u64> = (24..=39).collect();
    want.extend([1, 2, 4, 8, 16, 32, 39, 38, 36, 32, 24, 8]);
    assert_eq!(got, want.into_iter().collect::<Vec<_>>(), "{out}");
    // A checkpoint verifies with them, as before.
    let (rc, verified) = case.json(&["verify-checkpoint", "p.toml.ledger", CHECKPOINT]);
    assert_eq!((rc, &verified["relation"]), (0, &Value::from("exact")));
}

/// A restore far back: the ledger's last lines are older copies, but the
/// checkpoint has no hash for them. They count as new: a spend from before
/// the restore may count twice, never too few.
#[test]
fn lines_the_checkpoint_cannot_place_count_as_new() {
    let case = Case::new(100, Some(T0));
    case.spends(1, 7);
    case.snapshot();
    case.spends(8, 40);
    case.export();
    case.restore();

    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    let text = doctor_text(&doctor);
    assert!(
        text.contains("its entries 5 to 7 cannot be placed"),
        "{text}"
    );
    assert!(
        text.contains("a spend from before it may count twice"),
        "{text}"
    );
    let adopted = case.adopt();
    // Lines 1 to 4 are proved shared (anchor 4); 5 to 7 count again.
    assert_eq!(adopted["carried"]["requests"], 36, "{adopted}");
    assert_eq!(adopted["totals"]["requests"], 43, "{adopted}");
}

/// A spend after the restore whose time is later than every checkpointed
/// line's is proved new by its time, where no anchor reaches it.
#[test]
fn a_time_later_than_the_checkpoint_proves_a_line_new() {
    let case = Case::new(100, Some(T0));
    case.spends(1, 5);
    case.snapshot();
    case.spends(6, 40);
    case.export();
    case.restore();
    assert_eq!(
        case.spend_at(Some("2026-11-20T10:00:00Z"), "after"),
        "allowed"
    );

    let (_, doctor) = case.doctor();
    let text = doctor_text(&doctor);
    assert!(
        text.contains("the ledger's entry 6 is not a checkpointed one"),
        "{text}"
    );
    assert!(text.contains("Its entry 5 may be either"), "{text}");
    let adopted = case.adopt();
    // Shared through 4; 5 and 6 count as new: 40 - 4 = 36 on top of 6.
    assert_eq!(adopted["totals"]["requests"], 42, "{adopted}");
}

/// A restored clock that runs behind: the spend since the restore has an
/// earlier time than the checkpoint's latest, so time proves nothing. The
/// carry does not rely on times, and is the same.
#[test]
fn a_clock_behind_after_the_restore_does_not_lower_the_carry() {
    let case = Case::new(100, Some(T0));
    case.spends(1, 5);
    case.snapshot();
    case.spends(6, 40);
    case.export();
    case.restore();
    assert_eq!(
        case.spend_at(Some("2026-11-20T08:30:00Z"), "skewed"),
        "allowed"
    );

    let (_, doctor) = case.doctor();
    let text = doctor_text(&doctor);
    assert!(
        text.contains("its entries 5 to 6 cannot be placed"),
        "{text}"
    );
    let adopted = case.adopt();
    assert_eq!(adopted["totals"]["requests"], 42, "{adopted}");
}

/// A checkpoint from a hallpass before line hashes proves no ledger line
/// shared, so every line counts as new on top of its totals: the fork is
/// counted in full, and a plain restore counts the restored spends twice.
#[test]
fn a_checkpoint_without_line_hashes_counts_every_ledger_line_as_new() {
    let case = Case::new(10, None);
    case.spends(1, 2);
    case.snapshot();
    case.spends(3, 4);
    case.export();
    case.edit_checkpoint(|cp| {
        cp.remove("anchors");
        cp.remove("latest");
    });
    case.restore();
    assert_eq!(case.spend("b1"), "allowed");

    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    let text = doctor_text(&doctor);
    assert!(text.contains("records no line hashes"), "{text}");
    assert!(!text.contains("entries 4 to 4"), "{text}");
    let (_, preview) = case.preview();
    assert!(
        warnings(&preview).contains("records no line hashes"),
        "{preview}"
    );
    let adopted = case.adopt();
    assert_eq!(adopted["carried"]["requests"], 4, "{adopted}");
    assert_eq!(adopted["totals"]["requests"], 7, "{adopted}");
}

/// The adoption line keeps the shape an older hallpass reads: the
/// checkpoint without its line hashes and time.
#[test]
fn the_adoption_line_records_the_checkpoint_without_its_line_hashes() {
    let case = Case::new(5, None);
    case.spends(1, 2);
    case.snapshot();
    case.spends(3, 4);
    case.export();
    case.restore();
    let adopted = case.adopt();
    let recorded = adopted["checkpoint"].as_object().expect("checkpoint");
    assert!(!recorded.contains_key("anchors"), "{adopted}");
    assert!(!recorded.contains_key("latest"), "{adopted}");
    let ledger = fs::read_to_string(case.path("p.toml.ledger")).expect("ledger");
    assert!(!ledger.contains("anchors"), "{ledger}");
    // Doctor sees the adoption acted on the checkpoint.
    let (_, doctor) = case.doctor();
    assert_eq!(
        doctor["findings"][0]["code"], "checkpoint-adopted",
        "{doctor}"
    );
}

/// Totals lower than what the lines the checkpoint proves its own count do
/// not belong to its line hashes: blocked, and nothing is carried.
#[test]
fn totals_below_the_proved_lines_are_refused() {
    let case = Case::new(10, None);
    case.spends(1, 2);
    case.snapshot();
    case.spends(3, 4);
    case.export();
    case.edit_checkpoint(|cp| {
        cp.insert("totals".to_owned(), serde_json::json!({"requests": 1}));
    });
    case.restore();
    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["problem"], "checkpoint-fork", "{doctor}");
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

#[test]
fn verify_checkpoint_refuses_bad_line_hashes_and_times() {
    let case = Case::new(10, Some(T0));
    case.spends(1, 3);
    case.export();
    let original = fs::read(case.path(CHECKPOINT)).expect("read");
    for (field, value) in [
        ("anchors", serde_json::json!({"3": "sha256:00"})),
        (
            "anchors",
            serde_json::json!({"0": format!("sha256:{}", "0".repeat(64))}),
        ),
        (
            "anchors",
            serde_json::json!({"3": format!("sha256:{}", "0".repeat(64))}),
        ),
        ("latest", serde_json::json!("yesterday")),
    ] {
        fs::write(case.path(CHECKPOINT), &original).expect("reset");
        case.edit_checkpoint(|cp| {
            cp.insert(field.to_owned(), value.clone());
        });
        let (rc, verified) = case.json(&["verify-checkpoint", "p.toml.ledger", CHECKPOINT]);
        assert_eq!(rc, 1, "{field} {value}: {verified}");
        assert!(
            verified["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains(&format!("invalid checkpoint {field}")),
            "{verified}"
        );
    }
}
