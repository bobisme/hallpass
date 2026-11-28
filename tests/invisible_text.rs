//! Invisible characters and look-alike spaces (bn-2gh), and the text rules
//! of `approval-id` (bn-38c).
//!
//! Beyond the Unicode format characters of bn-1tt, new caller references,
//! notes, reasons, reference lists and pass text refuse every
//! default-ignorable code point (such as U+034F, U+3164 and the variation
//! selectors) and every space other than the ASCII space (such as U+00A0
//! and U+2003). A ledger written earlier that holds one still reads, shows
//! it escaped and still finds its references. `approval-id` refuses what a
//! pass refuses, so every id it prints can be carried by a pass that loads.
#![cfg(feature = "cli")]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use hallpass::{Digest, Pass, Problem};
use proptest::prelude::*;
use serde_json::{Value, json};

const NOW: &str = "2026-11-20T09:00:00Z";
const TARGET: &str = "192.0.2.10:443/tcp";

/// How a message names a space other than the ASCII space.
const SPACE: &str = "a look-alike space";
/// How a message names another default-ignorable character.
const INVISIBLE: &str = "an invisible character";

/// One character of each class bn-2gh refuses: a name, the character and
/// how a message names it.
const SAMPLES: [(&str, char, &str); 18] = [
    ("no-break space", '\u{a0}', SPACE),
    ("Ogham space mark", '\u{1680}', SPACE),
    ("em space", '\u{2003}', SPACE),
    ("narrow no-break space", '\u{202f}', SPACE),
    ("medium mathematical space", '\u{205f}', SPACE),
    ("ideographic space", '\u{3000}', SPACE),
    ("combining grapheme joiner", '\u{34f}', INVISIBLE),
    ("Hangul choseong filler", '\u{115f}', INVISIBLE),
    ("Hangul jungseong filler", '\u{1160}', INVISIBLE),
    ("Hangul filler", '\u{3164}', INVISIBLE),
    ("halfwidth Hangul filler", '\u{ffa0}', INVISIBLE),
    ("Khmer inherent vowel", '\u{17b4}', INVISIBLE),
    ("Mongolian variation selector", '\u{180b}', INVISIBLE),
    ("variation selector", '\u{fe0f}', INVISIBLE),
    ("supplementary variation selector", '\u{e0100}', INVISIBLE),
    ("reserved ignorable", '\u{2065}', INVISIBLE),
    ("reserved ignorable specials", '\u{fff0}', INVISIBLE),
    ("reserved ignorable past the tags", '\u{e0080}', INVISIBLE),
];

/// The pass of these tests, with `id`, `owner` and `reference` written as
/// TOML values.
fn pass_text(id: &str, owner: &str, reference: &str) -> String {
    format!(
        "format = 1
id = {id}
name = \"Invisible text\"
[approval]
owner = {owner}
reference = {reference}
operator = \"Operator\"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false
[[destination]]
label = \"web\"
address = \"192.0.2.10\"
protocol = \"tcp\"
ports = 443
[ceilings]
calls = 100
"
    )
}

/// `text` as a TOML basic string, written as a person would write it: a
/// quote and a backslash escaped, a tab as `\t`, another control character
/// as `\u....`, and every other character as itself.
fn toml_string(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The pass of these tests with its usual owner and reference.
fn plain_pass() -> String {
    pass_text("\"text-2\"", "\"Owner\"", "\"Email\"")
}

fn code_point(c: char) -> String {
    format!("U+{:04X}", u32::from(c))
}

/// `c` as text output escapes it.
fn escaped(c: char) -> String {
    format!("\\u{{{:04x}}}", u32::from(c))
}

/// No sample character appears raw in `out`.
fn assert_none_raw(out: &str) {
    for (class, c, _) in SAMPLES {
        assert!(!out.contains(c), "{class} shown raw: {out:?}");
    }
}

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

    /// A private file, dated back so that reading it does not wait for a
    /// rewrite in place to settle.
    fn file(&self, name: &str, text: &str) -> String {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        let earlier = SystemTime::now() - Duration::from_secs(10);
        fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(earlier))
            .expect("date the file back");
        path.to_str().expect("utf8").to_owned()
    }

    fn pass(&self) -> String {
        self.file("p.toml", &plain_pass())
    }

    /// Exit code, standard output and standard error, with the state
    /// directory `state` (each one holds its own witness).
    fn run_in(&self, state: &str, format: &str, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env("XDG_STATE_HOME", self.path(state))
            .args(["--format", format])
            .args(args)
            .output()
            .expect("run");
        (
            out.status.code().expect("exit"),
            String::from_utf8(out.stdout).expect("utf8"),
            String::from_utf8(out.stderr).expect("utf8"),
        )
    }

    /// Adopt as the README does: preview, then record with its token.
    fn adopt_reviewed(&self, pass: &str, reason: &str) -> (i32, Value) {
        let (_, preview) = self.json(&["adopt", pass, "--preview"]);
        let token = preview["token"].as_str().expect("token").to_owned();
        self.json(&["adopt", pass, "--reason", reason, "--token", &token])
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let (code, out, _) = self.run_in("state", "json", args);
        let value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
        (code, value)
    }

    /// Spend once, lose the ledger and adopt the loss, so that references
    /// can be reconciled against adoption 1.
    fn lose_and_adopt(&self, pass: &str) {
        assert_eq!(self.json(&["spend", pass, "calls"]).0, 0);
        fs::rename(format!("{pass}.ledger"), self.path("lost.ledger")).expect("lose the ledger");
        assert_eq!(self.adopt_reviewed(pass, "lost").0, 0);
    }

    /// `reconcile-references` for adoption 1 with `references` and `reason`.
    fn reconcile_references(&self, pass: &str, references: &[&str], reason: &str) -> (i32, Value) {
        let list = self.file(
            "refs.json",
            &json!({"version": 1, "pass_id": "text-2", "references": references}).to_string(),
        );
        self.json(&[
            "reconcile-references",
            pass,
            "--adoption",
            "1",
            "--references",
            &list,
            "--reason",
            reason,
        ])
    }
}

fn message(value: &Value) -> &str {
    value["error"]["message"].as_str().expect("message")
}

// New input refuses each class.

#[test]
fn new_references_notes_and_reasons_refuse_invisible_characters_and_look_alike_spaces() {
    let case = Case::new();
    let pass = case.pass();
    for (class, c, kind) in SAMPLES {
        let text = format!("ref{c}1");
        let named = format!("{kind} ({})", code_point(c));
        for (flag, start) in [
            ("--caller-ref", "the caller reference contains "),
            ("--note", "the note contains "),
        ] {
            let (code, value) = case.json(&["spend", &pass, "calls", flag, &text]);
            assert_eq!(code, 1, "{class} in {flag}: {value}");
            assert_eq!(value["error"]["code"], "usage", "{class}: {value}");
            let message = message(&value);
            assert!(
                message.starts_with(&format!("{start}{named}")),
                "{class}: {message}"
            );
            assert!(message.contains("nothing was recorded"), "{message}");
        }
        let (code, value) = case.json(&["adopt", &pass, "--reason", &text]);
        assert_eq!(code, 1, "{class} in a reason: {value}");
        assert!(
            message(&value).contains(&format!("the reason contains {named}")),
            "{class}: {value}"
        );
    }
    assert!(!Path::new(&format!("{pass}.ledger")).exists());
}

#[test]
fn a_new_reference_list_and_its_reason_refuse_invisible_characters_and_look_alike_spaces() {
    let case = Case::new();
    let pass = case.pass();
    case.lose_and_adopt(&pass);
    for (class, c, kind) in SAMPLES {
        let named = format!("{kind} ({})", code_point(c));
        let bad = format!("ref{c}1");
        let (code, value) = case.reconcile_references(&pass, &["ok", &bad], "from the run log");
        assert_eq!(code, 1, "{class}: {value}");
        let expected = format!(
            "reference 2 (\"ref{}1\") is not a caller reference: it contains {named}",
            escaped(c)
        );
        assert!(message(&value).contains(&expected), "{class}: {value}");

        let (code, value) = case.reconcile_references(&pass, &["ok"], &format!("from the log{c}"));
        assert_eq!(code, 1, "{class} in the reason: {value}");
        assert!(
            message(&value).contains(&format!("the reason contains {named}")),
            "{class}: {value}"
        );
    }
    let (_, value) = case.json(&["ledger", &pass]);
    assert_eq!(value["reference_reconciliations"], json!([]), "{value}");
}

#[test]
fn every_pass_text_field_refuses_invisible_characters_and_look_alike_spaces() {
    let case = Case::new();
    let plain = plain_pass();
    for (class, c, kind) in SAMPLES {
        let named = format!("contains {kind} ({})", code_point(c));
        for (field, from, to) in [
            (
                "name",
                "name = \"Invisible text\"",
                format!("name = \"Invisible{c} text\""),
            ),
            (
                "approval.owner",
                "owner = \"Owner\"",
                format!("owner = \"Own{c}er\""),
            ),
            (
                "approval.reference",
                "reference = \"Email\"",
                format!("reference = \"Email{c}\""),
            ),
            (
                "approval.operator",
                "operator = \"Operator\"",
                format!("operator = \"{c}Operator\""),
            ),
            (
                "approval.revoked_reason",
                "revoked = false",
                format!("revoked = true\nrevoked_reason = \"done{c}\""),
            ),
            (
                "destination[1].hostname",
                "ports = 443\n",
                format!("ports = 443\nhostname = \"web{c} server\"\n"),
            ),
        ] {
            let file = case.file("bad.toml", &plain.replace(from, &to));
            let (code, value) = case.json(&["check", &file]);
            assert_eq!(code, 1, "{class} in {field}: {value}");
            let problems = value["problems"].as_array().expect("problems");
            assert!(
                problems.iter().any(|p| p["field"] == field
                    && p["message"].as_str().is_some_and(|m| m.starts_with(&named))),
                "{class} in {field}: {value}"
            );
        }
    }
}

#[test]
fn a_refusal_message_shows_an_invisible_character_escaped() {
    let case = Case::new();
    let pass = case.pass();
    case.lose_and_adopt(&pass);
    // A refused reference list: the reference is quoted, escaped once.
    let list = case.file(
        "refs.json",
        &json!({"version": 1, "pass_id": "text-2", "references": ["ref\u{3164}1"]}).to_string(),
    );
    let args = [
        "reconcile-references",
        &pass,
        "--adoption",
        "1",
        "--references",
        &list,
        "--reason",
        "from the run log",
    ];
    let (code, out, err) = case.run_in("state", "text", &args);
    assert_eq!(code, 1, "{out}{err}");
    let shown = format!("{out}{err}");
    assert!(
        shown.contains(
            r#"reference 1 ("ref\u{3164}1") is not a caller reference: it contains an invisible character (U+3164)"#
        ),
        "{shown}"
    );
    assert!(!shown.contains('\u{3164}'), "{shown:?}");
    // A path is not quoted, so the message escapes the character itself.
    let missing = case.path("gone\u{3164}.toml");
    let missing = missing.to_str().expect("utf8");
    let (code, out, err) = case.run_in("state", "text", &["check", missing]);
    assert_eq!(code, 1, "{out}{err}");
    let shown = format!("{out}{err}");
    assert!(shown.contains(r"gone\u{3164}.toml"), "{shown}");
    assert!(!shown.contains('\u{3164}'), "{shown:?}");
}

// A ledger written earlier.

/// Rewrite every line of the ledger beside `pass` with `edit`, and each
/// `prev` hash to match the line before it, as an older hallpass that
/// accepted the new text would have written them.
fn rewrite_ledger(pass: &str, edit: impl Fn(&str) -> String) {
    let path = format!("{pass}.ledger");
    let text = fs::read_to_string(&path).expect("read the ledger");
    let old: Vec<&str> = text.lines().collect();
    let mut new: Vec<String> = Vec::with_capacity(old.len());
    for (index, line) in old.iter().enumerate() {
        let mut line = edit(line);
        if let Some(previous) = index.checked_sub(1) {
            line = line.replace(
                &Digest::of(old[previous].as_bytes()).to_string(),
                &Digest::of(new[previous].as_bytes()).to_string(),
            );
        }
        new.push(line);
    }
    fs::write(&path, format!("{}\n", new.join("\n"))).expect("write the ledger");
}

/// `line` with the placeholders `"REF00"`, `"NOTE00"` and so on replaced by
/// the reference and note of each sample, and `"REASON"` by `reason`.
fn fill_in(line: &str, reason: &str) -> String {
    let mut line = line.replace("\"REASON\"", &format!("\"{reason}\""));
    for (i, (_, c, _)) in SAMPLES.iter().enumerate() {
        line = line
            .replace(
                &format!("\"REF{i:02}\""),
                &format!("\"{}\"", old_reference(*c)),
            )
            .replace(&format!("\"NOTE{i:02}\""), &format!("\"{}\"", old_note(*c)));
    }
    line
}

/// The note an older hallpass recorded with sample `c`.
fn old_note(c: char) -> String {
    format!("no{c}te")
}

/// The reference an older hallpass recorded with sample `c`.
fn old_reference(c: char) -> String {
    format!("ref{c}one")
}

/// The same reference as text output shows it.
fn shown_reference(c: char) -> String {
    format!("\"ref{}one\"", escaped(c))
}

#[test]
fn a_ledger_written_earlier_with_each_class_still_reads_shows_it_escaped_and_finds_it() {
    let case = Case::new();
    let pass = case.pass();
    for i in 0..SAMPLES.len() {
        let (reference, note) = (format!("REF{i:02}"), format!("NOTE{i:02}"));
        let (code, value) = case.json(&[
            "spend",
            &pass,
            "calls",
            "--to",
            TARGET,
            "--record-target",
            "--caller-ref",
            &reference,
            "--note",
            &note,
        ]);
        assert_eq!(code, 0, "{value}");
    }
    // An adoption in a second state directory, which had no witness.
    let (code, _, err) = case.run_in("second", "json", &["adopt", &pass, "--reason", "REASON"]);
    assert_eq!(code, 0, "{err}");
    // An older hallpass accepted these, and serde_json writes them raw.
    let reason: String = std::iter::once("moved".to_owned())
        .chain(SAMPLES.iter().map(|(_, c, _)| c.to_string()))
        .collect();
    rewrite_ledger(&pass, |line| fill_in(line, &reason));

    // Read with no witness, as a copy of the ledger would be: it reads, and
    // shows every character escaped.
    let (code, out, err) = case.run_in("third", "text", &["ledger", &pass]);
    assert_eq!(code, 0, "{out}{err}");
    for (class, c, _) in SAMPLES {
        let row = format!(
            "receipt: ref {}, targets \"{TARGET}\" label \"web\"  note: no{}te",
            shown_reference(c),
            escaped(c)
        );
        assert!(out.contains(&row), "{class}: {out}");
    }
    let shown_reason: String = SAMPLES.iter().map(|(_, c, _)| escaped(*c)).collect();
    assert!(
        out.contains(&format!("reason: moved{shown_reason}")),
        "{out}"
    );
    assert_none_raw(&out);
    // JSON carries the exact text.
    let (code, out, _) = case.run_in("third", "json", &["ledger", &pass]);
    assert_eq!(code, 0, "{out}");
    let value: Value = serde_json::from_str(&out).expect("json");
    for (i, (class, c, _)) in SAMPLES.iter().enumerate() {
        let entry = &value["entries"][i];
        assert_eq!(entry["receipt"]["caller_ref"], old_reference(*c), "{class}");
        assert_eq!(entry["note"], old_note(*c), "{class}");
    }
    assert_eq!(value["adoptions"][0]["reason"], reason);
    found_again(&case, &pass, &value);
}

/// Each recorded reference of `ledger` (the JSON of `ledger`) is still
/// found by `receipt --caller-ref` and a `reconcile` manifest, and a new
/// spend cannot record it again.
fn found_again(case: &Case, pass: &str, ledger: &Value) {
    let mut units = Vec::new();
    for (i, (class, c, _)) in SAMPLES.iter().enumerate() {
        let reference = old_reference(*c);
        let (code, out, err) = case.run_in(
            "third",
            "text",
            &["receipt", pass, "--caller-ref", &reference],
        );
        assert_eq!(code, 0, "{class}: {out}{err}");
        assert!(
            out.starts_with(&format!(
                "Receipt found for {}. 1 matches.",
                shown_reference(*c)
            )),
            "{class}: {out}"
        );
        assert_none_raw(&out);
        units.push(json!({
            "caller_ref": reference,
            "digest": ledger["entries"][i]["digest"],
            "charges": [{"counter": "calls", "n": 1}],
            "targets": [{"target": TARGET}],
        }));
        let (code, value) = case.json(&["spend", pass, "calls", "--caller-ref", &reference]);
        assert_eq!(code, 1, "{class}: {value}");
    }
    let manifest = case.file(
        "manifest.json",
        &json!({"version": 1, "pass_id": "text-2", "units": units}).to_string(),
    );
    let (_, out, err) = case.run_in("third", "text", &["reconcile", pass, &manifest]);
    for (seq, (class, c, _)) in (1..).zip(SAMPLES) {
        let line = format!(
            "  match        {} (ledger sequence {seq})",
            shown_reference(c)
        );
        assert!(out.contains(&line), "{class}: {out}{err}");
    }
    assert_none_raw(&out);
}

#[test]
fn a_reference_reconciliation_written_earlier_with_each_class_still_reads() {
    let case = Case::new();
    let pass = case.pass();
    case.lose_and_adopt(&pass);
    let placeholders: Vec<String> = (0..SAMPLES.len()).map(|i| format!("REF{i:02}")).collect();
    let placeholders: Vec<&str> = placeholders.iter().map(String::as_str).collect();
    let (code, value) = case.reconcile_references(&pass, &placeholders, "REASON");
    assert_eq!(code, 0, "{value}");
    let reason: String = std::iter::once("from the log".to_owned())
        .chain(SAMPLES.iter().map(|(_, c, _)| c.to_string()))
        .collect();
    rewrite_ledger(&pass, |line| fill_in(line, &reason));
    let (code, out, err) = case.run_in("other", "text", &["ledger", &pass]);
    assert_eq!(code, 0, "{out}{err}");
    // Text shows the first ten references, each escaped.
    let shown: Vec<String> = SAMPLES[..10]
        .iter()
        .map(|(_, c, _)| shown_reference(*c))
        .collect();
    assert!(
        out.contains(&format!("references: {}, and 8 more", shown.join(", "))),
        "{out}"
    );
    let shown_reason: String = SAMPLES.iter().map(|(_, c, _)| escaped(*c)).collect();
    assert!(
        out.contains(&format!("reason: from the log{shown_reason}")),
        "{out}"
    );
    assert_none_raw(&out);
    let (_, out, _) = case.run_in("other", "json", &["ledger", &pass]);
    let value: Value = serde_json::from_str(&out).expect("json");
    let recorded = &value["reference_reconciliations"][0];
    let references: Vec<String> = SAMPLES.iter().map(|(_, c, _)| old_reference(*c)).collect();
    assert_eq!(recorded["references"], json!(references));
    assert_eq!(recorded["reason"], reason);
}

// bn-38c: approval-id applies the pass text rules.

/// One character of every class a pass text field refuses: a control
/// character, the line and paragraph separators, a bidirectional control,
/// format characters, and the classes of bn-2gh.
fn refused_characters() -> Vec<(&'static str, char)> {
    let mut all = vec![
        ("tab", '\t'),
        ("line separator", '\u{2028}'),
        ("paragraph separator", '\u{2029}'),
        ("right-to-left override", '\u{202e}'),
        ("zero-width space", '\u{200b}'),
        ("soft hyphen", '\u{ad}'),
        ("tag character", '\u{e0065}'),
    ];
    all.extend(SAMPLES.iter().map(|(class, c, _)| (*class, *c)));
    all
}

#[test]
fn approval_id_refuses_each_character_a_pass_refuses_as_check_does() {
    let case = Case::new();
    for (class, c) in refused_characters() {
        let bad = format!("Pat{c}Owner");
        for (flag, field) in [
            ("--owner", "approval.owner"),
            ("--reference", "approval.reference"),
        ] {
            let (owner, reference) = if flag == "--owner" {
                (bad.as_str(), "CHG-1")
            } else {
                ("Pat Owner", bad.as_str())
            };
            let (code, value) =
                case.json(&["approval-id", "--owner", owner, "--reference", reference]);
            assert_eq!(code, 1, "{class} in {flag}: {value}");
            assert_eq!(value["result"], "error", "{value}");
            assert_eq!(value["error"]["code"], "usage", "{value}");
            assert!(value.get("id").is_none(), "{value}");
            let problems = value["problems"].as_array().expect("problems");
            assert_eq!(problems.len(), 1, "{value}");
            assert_eq!(problems[0]["field"], field, "{value}");
            let problem = problems[0]["message"].as_str().expect("problem");
            assert!(
                message(&value).starts_with(&format!("{flag} ({field}) {problem}. ")),
                "{class}: {value}"
            );
            // The character is named, as check names it: a control
            // character by its kind, any other by its code point.
            if !c.is_control() {
                assert!(problem.contains(&code_point(c)), "{class}: {problem}");
            }
            // check refuses a pass with the same text, with the same problem.
            let file = case.file(
                "p.toml",
                &pass_text("\"text-2\"", &toml_string(owner), &toml_string(reference)),
            );
            let (code, checked) = case.json(&["check", &file]);
            assert_eq!(code, 1, "{class} in {field}: {checked}");
            assert!(
                checked["problems"]
                    .as_array()
                    .is_some_and(|all| all.contains(&problems[0])),
                "{class}: {checked} lacks {value}"
            );
        }
    }
}

#[test]
fn approval_id_text_names_the_option_the_field_and_the_character() {
    let case = Case::new();
    let (code, out, err) = case.run_in(
        "state",
        "text",
        &[
            "approval-id",
            "--owner",
            "Pat\u{200b}Owner",
            "--reference",
            " CHG-1",
        ],
    );
    assert_eq!(code, 1, "{out}{err}");
    let shown = format!("{out}{err}");
    assert!(
        shown.contains(
            "hallpass approval-id: error: usage: --owner (approval.owner) contains a Unicode format character (U+200B), which can make it display as something else; write one plain line without it. --reference (approval.reference) has leading or trailing spaces; remove them. A pass with this owner and reference would not load, so no id was printed"
        ),
        "{shown}"
    );
    assert!(!shown.contains("hp1-"), "{shown}");
}

#[test]
fn a_pass_carrying_the_id_approval_id_prints_loads() {
    let case = Case::new();
    for (owner, reference) in [
        ("Pat Owner", "Change 9812 / Voice edge (approved)"),
        (
            "Owner One / EU",
            "Email / Legal #42: ‘quoted’, [revised] — 2026-11-20",
        ),
        ("O'Brien \"Ops\"", r"C:\approvals\42"),
        ("Zoë Ünal", "変更 9812"),
        ("مالك الخدمة", "שינוי 9812"),
    ] {
        let (code, value) = case.json(&["approval-id", "--owner", owner, "--reference", reference]);
        assert_eq!(code, 0, "{value}");
        let id = value["id"].as_str().expect("id");
        let file = case.file(
            "p.toml",
            &pass_text(
                &toml_string(id),
                &toml_string(owner),
                &toml_string(reference),
            ),
        );
        let (code, checked) = case.json(&["check", &file]);
        assert_eq!(code, 0, "{owner} / {reference}: {checked}");
        assert_eq!(checked["pass_id"], id);
    }
}

/// Owners and references near every rule: ASCII, the characters a pass
/// refuses or must escape in TOML, letters, about 200 characters, and any
/// text.
fn identity_text() -> BoxedStrategy<String> {
    prop_oneof![
        "[ -~]{0,12}",
        "[ a\"\\\\\\t\\x00\\x7f\\x{85}\\x{a0}\\x{ad}\\x{34f}\\x{200b}\\x{2003}\\x{2028}\\x{202e}\\x{3164}\\x{fe0f}\\x{e0065}\\x{e0100}éש]{0,8}",
        "a[ a]{195,205}",
        any::<String>(),
    ]
    .boxed()
}

proptest! {
    /// approval-id gives an id exactly when a pass with that owner,
    /// reference and id loads; when it refuses, the pass is refused with the
    /// same problems.
    #[test]
    fn approval_id_and_pass_loading_agree(owner in identity_text(), reference in identity_text()) {
        let id = hallpass::review::approval_id(&owner, &reference);
        let pass_id = id.as_deref().map_or_else(|_| "\"text-2\"".to_owned(), toml_string);
        let parsed = Pass::parse(&pass_text(&pass_id, &toml_string(&owner), &toml_string(&reference)));
        match id {
            Ok(id) => {
                let pass = parsed.map_err(|p| TestCaseError::fail(format!("{p:?}")))?;
                prop_assert_eq!(pass.id, id);
                prop_assert_eq!(pass.approval.owner, owner);
                prop_assert_eq!(pass.approval.reference, reference);
            }
            Err(problems) => {
                prop_assert!(!problems.is_empty());
                let found: Vec<Problem> = parsed.err().unwrap_or_default();
                for problem in &problems {
                    prop_assert!(found.contains(problem), "{problem:?} not in {found:?}");
                }
            }
        }
    }
}
