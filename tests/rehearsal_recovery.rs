//! A rehearsal run by mistake on the live pass has a safe way back
//! (bn-3ei2).
//!
//! After test-clock spends on the live pass file, a release spend is
//! refused as `ledger-clock-mix`. The obvious way out (move the rehearsal
//! ledger aside, adopt) used to carry the rehearsal units into the live
//! count without a word. Now the witness says when every entry it counts
//! was recorded under a test clock; an adoption on the real clock then
//! refuses to carry those units unless told (`--drop-rehearsal FILE`
//! carries none, once FILE, the rehearsal ledger moved aside, proves the
//! rehearsal; the mark alone is only a hint; `--drop-rehearsal` carries
//! none, `--carry-rehearsal` carries them and names them); and the
//! clock-mix message and doctor name that recovery.
//!
//! The debug binary honours `HALLPASS_UNSAFE_TEST_CLOCK`; a command run
//! without it here uses the real clock, as a release build would.
#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

use hallpass::time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use hallpass::{Error, RehearsalTotals, SpendRequest, StateDir};
use serde_json::{Value, json};

const TARGET: &str = "192.0.2.40:443/tcp";
/// Where the advice moves the rehearsal ledger, relative to the pass.
const ASIDE: &str = "p.toml.ledger.rehearsal";

fn stamp(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .expect("whole second")
        .format(&Rfc3339)
        .expect("RFC 3339")
}

/// A pass open from an hour ago until two days from now.
fn pass() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        r#"format = 1
id = "live-pass"
name = "Live pass"

[approval]
owner = "Pat Owner"
reference = "email of today"
operator = "Eve Operator"
valid_from = {}
valid_until = {}
revoked = false

[[destination]]
label = "web"
address = "192.0.2.40"
protocol = "tcp"
ports = 443

[ceilings]
requests = 5
"#,
        stamp(now - Duration::hours(1)),
        stamp(now + Duration::days(2)),
    )
}

/// Ten minutes ago: inside the window, a time a rehearsal might choose.
fn rehearsal_clock() -> String {
    stamp(OffsetDateTime::now_utc() - Duration::minutes(10))
}

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Self {
            dir: tempfile::tempdir().expect("directory"),
        };
        let path = env.pass();
        fs::write(&path, pass()).expect("pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
        let earlier = SystemTime::now() - std::time::Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(earlier))
            .expect("date the pass back");
        env
    }

    fn pass(&self) -> PathBuf {
        self.dir.path().join("p.toml")
    }

    fn ledger(&self) -> PathBuf {
        hallpass::ledger_path(&self.pass())
    }

    fn state(&self) -> StateDir {
        StateDir::new(self.dir.path().join("state/hallpass"))
    }

    fn witness(&self) -> Value {
        let path = self.state().witness_path("live-pass").expect("path");
        serde_json::from_slice(&fs::read(path).expect("witness")).expect("JSON")
    }

    fn command(&self, format: &str, args: &[&str], clock: Option<&str>) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        command
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .args(["--format", format])
            .args(args);
        if let Some(clock) = clock {
            command.env("HALLPASS_UNSAFE_TEST_CLOCK", clock);
        }
        command
    }

    /// Run hallpass with JSON output, under the test clock at `clock` when
    /// it is given.
    fn run(&self, args: &[&str], clock: Option<&str>) -> (i32, Value) {
        let out = self
            .command("json", args, clock)
            .output()
            .expect("run hallpass");
        let text = String::from_utf8(out.stdout).expect("utf8");
        let value = serde_json::from_str(text.trim()).expect("one JSON object");
        (out.status.code().expect("exit code"), value)
    }

    /// Run hallpass with text output on the real clock: standard output.
    fn text(&self, args: &[&str]) -> String {
        let out = self
            .command("text", args, None)
            .output()
            .expect("run hallpass");
        String::from_utf8(out.stdout).expect("utf8")
    }

    fn spend(&self, reference: &str, clock: Option<&str>) -> (i32, Value) {
        self.run(
            &[
                "spend",
                "p.toml",
                "requests",
                "--to",
                TARGET,
                "--caller-ref",
                reference,
                "--require-new-ref",
            ],
            clock,
        )
    }

    /// Three rehearsal spends on the live pass, under the test clock.
    fn rehearse(&self) {
        let clock = rehearsal_clock();
        for unit in ["unit-1", "unit-2", "unit-3"] {
            let (code, reply) = self.spend(unit, Some(&clock));
            assert_eq!(code, 0, "{reply}");
            assert_eq!(reply["test_clock"], true, "{reply}");
        }
    }

    /// Move the rehearsal ledger aside, as the advice says.
    fn move_aside(&self) -> PathBuf {
        let aside = self.dir.path().join("p.toml.ledger.rehearsal");
        fs::rename(self.ledger(), &aside).expect("move aside");
        aside
    }

    fn adopt(&self, extra: &[&str]) -> (i32, Value) {
        let mut args = vec!["adopt", "p.toml", "--reason", "rehearsal moved aside"];
        args.extend_from_slice(extra);
        self.run(&args, None)
    }

    /// Adopt as the README does: preview with the same flags, then record
    /// with the token it printed.
    fn adopt_reviewed(&self, reason: &str, extra: &[&str], clock: Option<&str>) -> (i32, Value) {
        let mut preview = vec!["adopt", "p.toml", "--preview"];
        preview.extend_from_slice(extra);
        let (_, shown) = self.run(&preview, clock);
        let token = shown["token"].as_str().expect("token").to_owned();
        let mut args = vec!["adopt", "p.toml", "--reason", reason, "--token", &token];
        args.extend_from_slice(extra);
        self.run(&args, clock)
    }

    fn preview(&self, extra: &[&str]) -> (i32, Value) {
        let mut args = vec!["adopt", "p.toml", "--preview"];
        args.extend_from_slice(extra);
        self.run(&args, None)
    }
}

#[test]
fn the_witness_of_a_rehearsal_is_marked_and_a_live_one_is_not() {
    let env = Env::new();
    env.rehearse();
    let witness = env.witness();
    assert_eq!(witness["test_clock"], true, "{witness}");
    assert_eq!(witness["seq"], 3, "{witness}");

    // A live ledger's witness has no marker: the format is as before.
    let live = Env::new();
    let (code, reply) = live.spend("live-1", None);
    assert_eq!(code, 0, "{reply}");
    let witness = live.witness();
    assert!(witness.get("test_clock").is_none(), "{witness}");

    // A witness from before the marker reads as before; `false` is not a
    // spelling hallpass writes, so such a witness is damaged.
    let path = live.state().witness_path("live-pass").expect("path");
    let mut edited = witness;
    edited["test_clock"] = json!(false);
    fs::write(&path, format!("{edited}\n")).expect("edit");
    let (code, reply) = live.spend("live-2", None);
    assert_eq!(code, 1, "{reply}");
    assert_eq!(reply["error"]["code"], "witness-unavailable", "{reply}");
}

#[test]
fn the_clock_mix_message_and_doctor_name_the_safe_recovery() {
    let env = Env::new();
    env.rehearse();
    let (code, refused) = env.spend("live-1", None);
    assert_eq!(code, 1, "{refused}");
    assert_eq!(refused["error"]["code"], "ledger-clock-mix", "{refused}");
    let message = refused["error"]["message"].as_str().expect("message");
    for part in [
        "move the rehearsal ledger aside and keep it (`mv -n \"p.toml.ledger\" \"p.toml.ledger.rehearsal\"`)",
        "then run `hallpass adopt \"p.toml\" --preview --drop-rehearsal \"p.toml.ledger.rehearsal\"`",
        "If it refuses, use a pass with a new id, with no ledger yet.",
    ] {
        assert!(message.contains(part), "{part}: {message}");
    }

    let (code, doctor) = env.run(&["doctor", "p.toml"], None);
    assert_eq!(code, 2, "{doctor}");
    assert_eq!(doctor["problem"], "ledger-clock-mix", "{doctor}");
    assert_eq!(
        doctor["next"],
        json!(["mv", "p.toml.ledger", "p.toml.ledger.rehearsal"]),
        "{doctor}"
    );
    let step = doctor["next_step"].as_str().expect("step");
    assert!(
        step.contains("`hallpass adopt p.toml --preview --drop-rehearsal p.toml.ledger.rehearsal`"),
        "{step}"
    );

    // A file already there is never named as the target of the move.
    fs::write(env.dir.path().join("p.toml.ledger.rehearsal"), "kept").expect("file");
    let (_, doctor) = env.run(&["doctor", "p.toml"], None);
    assert_eq!(
        doctor["next"],
        json!(["mv", "p.toml.ledger", "p.toml.ledger.rehearsal-2"]),
        "{doctor}"
    );
}

#[test]
fn moved_aside_the_rehearsal_is_adopted_with_nothing_carried() {
    let env = Env::new();
    env.rehearse();
    env.move_aside();

    let (code, doctor) = env.run(&["doctor", "p.toml"], None);
    assert_eq!(code, 2, "{doctor}");
    assert_eq!(doctor["problem"], "ledger-missing", "{doctor}");
    assert_eq!(
        doctor["next"],
        json!([
            "hallpass",
            "adopt",
            "p.toml",
            "--preview",
            "--drop-rehearsal",
            "p.toml.ledger.rehearsal"
        ]),
        "{doctor}"
    );
    let step = doctor["next_step"].as_str().expect("step");
    assert!(
        step.contains("a rehearsal, which spent nothing real"),
        "{step}"
    );

    // Without a choice, both the preview and the adoption refuse, name the
    // units as rehearsal units, and record nothing.
    for (code, refused) in [env.preview(&[]), env.adopt(&[])] {
        assert_eq!(code, 1, "{refused}");
        assert_eq!(refused["error"]["code"], "usage", "{refused}");
        let message = refused["error"]["message"].as_str().expect("message");
        for part in [
            "marks a rehearsal: it was written for a ledger whose entries, to sequence 3, were all recorded under a test clock",
            "(spent: requests 3) look like rehearsal units",
            "so nothing was recorded",
            "--preview --drop-rehearsal REHEARSAL_LEDGER",
            "use --carry-rehearsal instead",
        ] {
            assert!(message.contains(part), "{part}: {message}");
        }
        assert!(
            !env.ledger().exists(),
            "a refused adoption leaves no ledger"
        );
    }

    let (code, preview) = env.preview(&["--drop-rehearsal", ASIDE]);
    assert_eq!(code, 0, "{preview}");
    assert_eq!(preview["case"], "ledger-missing", "{preview}");
    assert_eq!(preview["carried"], json!({}), "{preview}");
    assert_eq!(preview["totals"], json!({}), "{preview}");
    assert_eq!(
        preview["rehearsal"],
        json!({"units": {"requests": 3}, "carried": false, "proof": ASIDE}),
        "{preview}"
    );
    assert_eq!(preview["previous"]["test_clock"], true, "{preview}");
    let warnings = preview["warnings"].to_string();
    assert!(!warnings.contains("reference-inconclusive"), "{warnings}");
    let text = env.text(&["adopt", "p.toml", "--preview", "--drop-rehearsal", ASIDE]);
    assert!(
        text.contains(
            "Carry: nothing (the witness's requests 3 are rehearsal units: \"p.toml.ledger.rehearsal\" proves that every entry was recorded under a test clock, so --drop-rehearsal carries none of them)."
        ),
        "{text}"
    );

    let token = preview["token"].as_str().expect("token");
    let (code, adopted) = env.adopt(&["--drop-rehearsal", ASIDE, "--token", token]);
    assert_eq!(code, 0, "{adopted}");
    assert_eq!(adopted["carried"], json!({}), "{adopted}");
    assert_eq!(adopted["totals"], json!({}), "{adopted}");
    assert_eq!(adopted["test_clock"], false, "{adopted}");
    assert_eq!(adopted["rehearsal"]["carried"], false, "{adopted}");
    // The live witness has no marker: the adoption line is a live line.
    assert!(env.witness().get("test_clock").is_none());
    let line = fs::read_to_string(env.ledger()).expect("ledger");
    assert!(
        line.contains(r#""totals":{"requests":3},"updated":"#)
            && line.contains(r#""test_clock":true},"prev":"#),
        "the adoption records the rehearsal witness it dropped: {line}"
    );

    // The whole live budget is there, a guarded spend is not
    // reference-inconclusive (rehearsal references are not live ones), and
    // a reference used in the rehearsal is new for live work.
    let (code, spent) = env.spend("unit-1", None);
    assert_eq!(code, 0, "{spent}");
    assert_eq!(spent["result"], "allowed", "{spent}");
    assert_eq!(spent["spent"], 1, "{spent}");
    assert_eq!(spent["remaining"], 4, "{spent}");
    let (code, doctor) = env.run(&["doctor", "p.toml"], None);
    assert_eq!(code, 0, "{doctor}");
    assert_eq!(doctor["result"], "healthy", "{doctor}");
}

#[test]
fn carry_rehearsal_counts_the_units_and_names_them() {
    let env = Env::new();
    env.rehearse();
    env.move_aside();
    let (code, preview) = env.preview(&["--carry-rehearsal"]);
    assert_eq!(code, 0, "{preview}");
    assert_eq!(preview["carried"], json!({"requests": 3}), "{preview}");
    assert_eq!(
        preview["rehearsal"],
        json!({"units": {"requests": 3}, "carried": true, "proof": null}),
        "{preview}"
    );
    let token = preview["token"].as_str().expect("token").to_owned();
    let text = env.text(&[
        "adopt",
        "p.toml",
        "--reason",
        "keep them",
        "--carry-rehearsal",
        "--token",
        &token,
    ]);
    assert!(
        text.contains(
            "Carried from the witness: requests 3 (rehearsal units: the witness's requests 3 were recorded under a test clock, and they count against the ceilings). Spent now: requests 3."
        ),
        "{text}"
    );
    // Both flags at once are a usage error.
    let (code, both) = env.preview(&["--carry-rehearsal", "--drop-rehearsal", ASIDE]);
    assert_eq!(
        (code, &both["error"]["code"]),
        (1, &json!("usage")),
        "{both}"
    );
}

#[test]
fn a_witness_that_counts_live_units_is_never_dropped() {
    // A live spend, its ledger lost, then a rehearsal that adopted the
    // loss under the test clock: the rehearsal ledger carries the live
    // unit, so its witness shows no rehearsal.
    let env = Env::new();
    let (code, live) = env.spend("live-1", None);
    assert_eq!(code, 0, "{live}");
    fs::remove_file(env.ledger()).expect("lose");
    let clock = rehearsal_clock();
    let (code, adopted) = env.adopt_reviewed("lost before the rehearsal", &[], Some(&clock));
    assert_eq!(code, 0, "{adopted}");
    assert_eq!(adopted["carried"], json!({"requests": 1}), "{adopted}");
    let (code, reply) = env.run(
        &["spend", "p.toml", "requests", "--to", TARGET],
        Some(&clock),
    );
    assert_eq!(code, 0, "{reply}");
    assert!(
        env.witness().get("test_clock").is_none(),
        "{}",
        env.witness()
    );

    env.move_aside();
    let (code, refused) = env.preview(&["--drop-rehearsal", ASIDE]);
    assert_eq!(code, 1, "{refused}");
    let message = refused["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("the adoption at entry 1 carried an amount, which may be live work"),
        "{message}"
    );
    // Without the flag, the adoption carries the whole count, as before.
    let (code, preview) = env.preview(&[]);
    assert_eq!(code, 0, "{preview}");
    assert_eq!(preview["carried"], json!({"requests": 2}), "{preview}");
    assert_eq!(preview["rehearsal"], Value::Null, "{preview}");
}

#[test]
fn a_rehearsal_adopting_its_own_units_carries_them_as_before() {
    let env = Env::new();
    env.rehearse();
    env.move_aside();
    let clock = rehearsal_clock();
    let (code, adopted) = env.adopt_reviewed("rehearsal ledger lost", &[], Some(&clock));
    assert_eq!(code, 0, "{adopted}");
    assert_eq!(adopted["carried"], json!({"requests": 3}), "{adopted}");
    assert_eq!(adopted["rehearsal"], Value::Null, "{adopted}");
    // That adoption carried an amount, so the witness no longer shows a
    // rehearsal that could be dropped.
    assert!(
        env.witness().get("test_clock").is_none(),
        "{}",
        env.witness()
    );
}

#[test]
fn the_library_refuses_by_default_and_drops_on_request() {
    let env = Env::new();
    let state = env.state();
    let at = OffsetDateTime::now_utc();
    let mut request = SpendRequest::new("requests", 1);
    request.target = Some(TARGET.parse().expect("target"));
    hallpass::with_test_clock(|| {
        for _ in 0..2 {
            let out = hallpass::spend_in(&env.pass(), &request, at, &state).expect("rehearse");
            assert!(out.refusal.is_none(), "{:?}", out.refusal);
        }
    });
    env.move_aside();
    assert!(state.witness_shows_rehearsal("live-pass"));
    let refused = hallpass::adopt(&env.pass(), "moved aside", at, &state);
    assert!(matches!(refused, Err(Error::Usage(_))), "{refused:?}");
    assert!(!env.ledger().exists());
    let drop = RehearsalTotals::Drop(env.dir.path().join(ASIDE));
    let preview = hallpass::preview_adopt_rehearsal(&env.pass(), &state, false, drop.clone())
        .expect("preview");
    assert!(preview.carried.is_empty());
    assert!(!preview.makes_references_inconclusive());
    let adopted = hallpass::adopt_guarded_rehearsal(
        &env.pass(),
        "moved aside",
        at,
        &state,
        Some(&preview.token),
        false,
        drop.clone(),
    )
    .expect("adopt");
    assert!(adopted.adoption.carried.is_empty());
    assert!(adopted.totals.is_empty());
    assert_eq!(adopted.rehearsal, Some(drop));
    assert!(!adopted.adoption.makes_references_inconclusive());
    let loaded = hallpass::load(&env.pass()).expect("pass");
    let view = hallpass::read_summary(&loaded, &state).expect("summary");
    assert_eq!(view.unreconciled_adoption, None);
    assert!(!state.witness_shows_rehearsal("live-pass"));
}

/// The refusal message of a `--drop-rehearsal` preview with `file`, after
/// checking that nothing was recorded.
fn drop_refusal(env: &Env, file: &str) -> String {
    let (code, refused) = env.preview(&["--drop-rehearsal", file]);
    assert_eq!(code, 1, "{refused}");
    assert_eq!(refused["error"]["code"], "usage", "{refused}");
    let (code, adopt) = env.adopt(&["--drop-rehearsal", file]);
    assert_eq!(code, 1, "{adopt}");
    assert!(
        !env.ledger().exists(),
        "a refused adoption leaves no ledger"
    );
    refused["error"]["message"]
        .as_str()
        .expect("message")
        .to_owned()
}

#[test]
fn a_live_witness_edited_to_look_like_a_rehearsal_is_never_dropped() {
    // Two live spends, then the witness edited to carry the rehearsal mark
    // and the live ledger moved aside: the mark alone proves nothing.
    let env = Env::new();
    for unit in ["live-1", "live-2"] {
        let (code, live) = env.spend(unit, None);
        assert_eq!(code, 0, "{live}");
    }
    let path = env.state().witness_path("live-pass").expect("path");
    let mut forged = env.witness();
    forged["test_clock"] = json!(true);
    fs::write(&path, format!("{forged}\n")).expect("forge");
    env.move_aside();
    let message = drop_refusal(&env, ASIDE);
    for part in [
        "--drop-rehearsal: \"p.toml.ledger.rehearsal\" does not prove that the witness of pass `live-pass` counts only a rehearsal",
        "entry 1 was recorded at the real time, so it may be live work",
        "Nothing was recorded",
    ] {
        assert!(message.contains(part), "{part}: {message}");
    }
    // The count stays: carrying is still possible, never a reset.
    let (code, preview) = env.preview(&["--carry-rehearsal"]);
    assert_eq!(code, 0, "{preview}");
    assert_eq!(preview["carried"], json!({"requests": 2}), "{preview}");
}

#[test]
fn a_file_that_is_not_the_witnessed_ledger_proves_nothing() {
    let env = Env::new();
    env.rehearse();
    env.move_aside();

    // No such file.
    let message = drop_refusal(&env, "nowhere.ledger");
    assert!(
        message.contains("\"nowhere.ledger\" does not prove")
            && message.contains("it is not an intact ledger of this pass"),
        "{message}"
    );

    // Another rehearsal ledger of the same pass id, two entries long: it
    // does not end with the line the witness recorded.
    let other = Env::new();
    let clock = rehearsal_clock();
    for unit in ["other-1", "other-2"] {
        let (code, reply) = other.spend(unit, Some(&clock));
        assert_eq!(code, 0, "{reply}");
    }
    fs::copy(other.ledger(), env.dir.path().join("other.ledger")).expect("copy");
    let message = drop_refusal(&env, "other.ledger");
    assert!(
        message.contains(
            "it does not end with the line the witness recorded (sequence 3), so it is not the witnessed ledger"
        ),
        "{message}"
    );

    // The witnessed ledger with a line cut off.
    let text = fs::read_to_string(env.dir.path().join(ASIDE)).expect("ledger");
    let cut: Vec<&str> = text.lines().collect();
    let short = env.dir.path().join("short.ledger");
    fs::write(&short, format!("{}\n", cut[..cut.len() - 1].join("\n"))).expect("short");
    fs::set_permissions(&short, fs::Permissions::from_mode(0o600)).expect("private");
    let message = drop_refusal(&env, "short.ledger");
    assert!(
        message.contains("it does not end with the line the witness recorded"),
        "{message}"
    );

    // The real one still proves it.
    let (code, preview) = env.preview(&["--drop-rehearsal", ASIDE]);
    assert_eq!(code, 0, "{preview}");
}
