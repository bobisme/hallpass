//! Text that callers and passes supply. Text output quotes such a value once
//! (bn-2g2), so a crafted caller reference cannot read as more receipt
//! fields. New references, notes, reasons and pass text refuse the Unicode
//! format characters (bn-1tt), a ledger written earlier that holds one still
//! reads, and every text output shows one escaped.
#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use hallpass::Digest;
use serde_json::{Value, json};

const NOW: &str = "2026-11-20T09:00:00Z";
const TARGET: &str = "192.0.2.10:443/tcp";
const PASS: &str = "format = 1
id = \"text-1\"
name = \"Text safety\"
[approval]
owner = \"Owner\"
reference = \"Email\"
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
";

/// The crafted reference of bn-2g2: escaped twice, it read as a second,
/// out-of-scope target.
const CRAFTED: &str = r#"x", targets "203.0.113.66:22/tcp" label "ssh"#;

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
        self.file("p.toml", PASS)
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

    fn text(&self, args: &[&str]) -> (i32, String) {
        let (code, out, _) = self.run_in("state", "text", args);
        (code, out)
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
}

/// The value quoted at the start of `text`, with its escapes (`\"`, `\\`
/// and `\u{…}`) undone, and the text after its closing quote. This is how a
/// reader takes a quoted value apart, written independently of hallpass.
fn unquote(text: &str) -> Option<(String, &str)> {
    let mut chars = text.strip_prefix('"')?.char_indices();
    let mut value = String::new();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return Some((value, &text[at + 2..])),
            '\\' => match chars.next()?.1 {
                '"' => value.push('"'),
                '\\' => value.push('\\'),
                'u' => {
                    let start = chars.next().filter(|(_, c)| *c == '{')?.0 + 2;
                    let end = text[start..].find('}')? + start;
                    value.push(char::from_u32(
                        u32::from_str_radix(&text[start..end], 16).ok()?,
                    )?);
                    while chars.next()?.1 != '}' {}
                }
                _ => return None,
            },
            c => value.push(c),
        }
    }
    None
}

/// The value quoted right after `marker` in `text`, and what follows it.
fn quoted_after<'a>(text: &'a str, marker: &str) -> (String, &'a str) {
    let at = text
        .find(marker)
        .unwrap_or_else(|| panic!("no {marker:?} in {text}"));
    unquote(&text[at + marker.len()..]).unwrap_or_else(|| panic!("not quoted: {text}"))
}

// bn-2g2: a caller reference is escaped once in spend, ledger and receipt text.

#[test]
fn spend_ledger_and_receipt_text_show_one_rendering_of_a_reference() {
    let case = Case::new();
    let pass = case.pass();
    // Each reference and the one rendering every text output must show.
    let cases = [
        (r#"q"uote"#, r#""q\"uote""#),
        (r"back\slash", r#""back\\slash""#),
        (
            CRAFTED,
            r#""x\", targets \"203.0.113.66:22/tcp\" label \"ssh""#,
        ),
    ];
    let receipt_rest = format!(", targets \"{TARGET}\" label \"web\"");
    for (seq, (reference, shown)) in (1..).zip(cases) {
        let (code, spend) = case.text(&[
            "spend",
            &pass,
            "calls",
            "--to",
            TARGET,
            "--record-target",
            "--caller-ref",
            reference,
        ]);
        assert_eq!(code, 0, "{spend}");
        let spend_line = format!("  receipt ref {shown}{receipt_rest}\n");
        assert!(spend.contains(&spend_line), "{reference}: {spend}");
        // A reader who undoes the escapes gets the reference back, and the
        // recorded target after it: nothing else.
        let (value, rest) = quoted_after(&spend, "receipt ref ");
        assert_eq!(value, reference);
        assert!(rest.starts_with(&format!("{receipt_rest}\n")), "{rest}");

        let (code, ledger) = case.text(&["ledger", &pass]);
        assert_eq!(code, 0, "{ledger}");
        let row = ledger
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("{seq} ")))
            .unwrap_or_else(|| panic!("no row {seq}: {ledger}"));
        assert!(
            row.ends_with(&format!("receipt: ref {shown}{receipt_rest}")),
            "{reference}: {row}"
        );
        let (value, rest) = quoted_after(row, "receipt: ref ");
        assert_eq!(value, reference);
        assert_eq!(rest, receipt_rest);

        let (code, receipt) = case.text(&["receipt", &pass, "--caller-ref", reference]);
        assert_eq!(code, 0, "{receipt}");
        assert!(
            receipt.starts_with(&format!("Receipt found for {shown}. 1 matches.")),
            "{reference}: {receipt}"
        );
        let (value, rest) = quoted_after(&receipt, "Receipt found for ");
        assert_eq!(value, reference);
        assert!(rest.starts_with(". 1 matches."), "{rest}");
    }
    // The crafted target appears only inside the quoted reference.
    let (_, ledger) = case.text(&["ledger", &pass]);
    assert!(!ledger.contains("targets \"203.0.113.66"), "{ledger}");
    // No quote is escaped twice.
    assert!(!ledger.contains(r#"\\""#), "{ledger}");
    // JSON carries the exact text.
    let (_, value) = case.json(&["ledger", &pass]);
    let refs: Vec<&str> = value["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter_map(|e| e["receipt"]["caller_ref"].as_str())
        .collect();
    assert_eq!(refs, [r#"q"uote"#, r"back\slash", CRAFTED]);
}

#[test]
fn reconcile_and_reference_reconciliation_text_quote_references_once() {
    let case = Case::new();
    let pass = case.pass();
    let (code, spent) = case.json(&[
        "spend",
        &pass,
        "calls",
        "--to",
        TARGET,
        "--record-target",
        "--caller-ref",
        CRAFTED,
    ]);
    assert_eq!(code, 0, "{spent}");
    let digest = spent["digest"].as_str().expect("digest");
    let manifest = case.file(
        "manifest.json",
        &json!({"version": 1, "pass_id": "text-1", "units": [{
            "caller_ref": CRAFTED,
            "digest": digest,
            "charges": [{"counter": "calls", "n": 1}],
            "targets": [{"target": TARGET}],
        }]})
        .to_string(),
    );
    let (code, out) = case.text(&["reconcile", &pass, &manifest]);
    assert_eq!(code, 0, "{out}");
    let (value, rest) = quoted_after(&out, "  match        ");
    assert_eq!(value, CRAFTED);
    assert!(rest.starts_with(" (ledger sequence 1)\n"), "{out}");

    // Lose the ledger, adopt, and reconcile the references it may have held.
    fs::rename(format!("{pass}.ledger"), case.path("lost.ledger")).expect("lose the ledger");
    let (_, preview) = case.json(&["adopt", &pass, "--preview"]);
    let token = preview["token"].as_str().expect("token").to_owned();
    let (code, out) = case.text(&[
        "adopt",
        &pass,
        "--reason",
        r#"lost "by" \ mistake"#,
        "--token",
        &token,
    ]);
    assert_eq!(code, 0, "{out}");
    let (value, rest) = quoted_after(&out, "with the reason ");
    assert_eq!(value, r#"lost "by" \ mistake"#);
    assert!(rest.starts_with(".\n  - Carried from the witness"), "{out}");
    let list = case.file(
        "refs.json",
        &json!({"version": 1, "pass_id": "text-1", "references": [CRAFTED, r"back\slash"]})
            .to_string(),
    );
    let reconcile = [
        "reconcile-references",
        &pass,
        "--adoption",
        "1",
        "--references",
        &list,
        "--reason",
        "from the run log",
    ];
    let (code, out) = case.text(&reconcile);
    assert_eq!(code, 0, "{out}");
    let (_, ledger) = case.text(&["ledger", &pass]);
    let (first, rest) = quoted_after(&ledger, "references: ");
    assert_eq!(first, CRAFTED);
    let (second, rest) = unquote(rest.strip_prefix(", ").expect("a second reference"))
        .unwrap_or_else(|| panic!("{ledger}"));
    assert_eq!(second, r"back\slash");
    assert!(rest.starts_with("  reason: from the run log\n"), "{ledger}");
}

// bn-1tt: Unicode format characters.

/// One character of each class the evaluation found accepted, as a name and
/// the character.
const FORMAT_SAMPLES: [(&str, char); 7] = [
    ("zero-width space", '\u{200b}'),
    ("zero-width joiner", '\u{200d}'),
    ("word joiner", '\u{2060}'),
    ("byte order mark", '\u{feff}'),
    ("soft hyphen", '\u{ad}'),
    ("interlinear annotation", '\u{fff9}'),
    ("tag character", '\u{e0065}'),
];

fn code_point(c: char) -> String {
    format!("U+{:04X}", u32::from(c))
}

#[test]
fn new_references_notes_and_reasons_refuse_format_characters() {
    let case = Case::new();
    let pass = case.pass();
    for (class, c) in FORMAT_SAMPLES {
        let text = format!("ref{c}1");
        for flag in ["--caller-ref", "--note"] {
            let (code, value) = case.json(&["spend", &pass, "calls", flag, &text]);
            assert_eq!(code, 1, "{class} in {flag}: {value}");
            assert_eq!(value["error"]["code"], "usage", "{class}: {value}");
            let message = value["error"]["message"].as_str().expect("message");
            assert!(message.contains(&code_point(c)), "{class}: {message}");
            assert!(message.contains("nothing was recorded"), "{message}");
        }
        let (code, value) = case.json(&["adopt", &pass, "--reason", &text]);
        assert_eq!(code, 1, "{class} in a reason: {value}");
        assert!(
            value["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains(&code_point(c))),
            "{class}: {value}"
        );
    }
    assert!(!Path::new(&format!("{pass}.ledger")).exists());
}

#[test]
fn new_references_refuse_leading_and_trailing_spaces() {
    let case = Case::new();
    let pass = case.pass();
    for text in [" ref-1", "ref-1 ", "\u{a0}ref-1", "ref-1\u{3000}"] {
        let (code, value) = case.json(&["spend", &pass, "calls", "--caller-ref", text]);
        assert_eq!(code, 1, "{text:?}: {value}");
        let message = value["error"]["message"].as_str().expect("message");
        // Since bn-2gh a look-alike space is refused anywhere, and named.
        let expected = text.chars().find(|c| !c.is_ascii()).map_or_else(
            || "the caller reference has leading or trailing spaces".to_owned(),
            |c| {
                format!(
                    "the caller reference contains a look-alike space ({})",
                    code_point(c)
                )
            },
        );
        assert!(message.starts_with(&expected), "{message}");
    }
    // A space inside a reference, and a note's surrounding spaces, are fine.
    let (code, value) = case.json(&[
        "spend",
        &pass,
        "calls",
        "--caller-ref",
        "run 1",
        "--note",
        " x ",
    ]);
    assert_eq!(code, 0, "{value}");
}

#[test]
fn a_new_reference_list_refuses_what_a_new_reference_refuses() {
    let case = Case::new();
    let pass = case.pass();
    let (code, _) = case.json(&["spend", &pass, "calls"]);
    assert_eq!(code, 0);
    fs::rename(format!("{pass}.ledger"), case.path("lost.ledger")).expect("lose the ledger");
    assert_eq!(case.adopt_reviewed(&pass, "lost").0, 0);
    for (bad, part) in [
        (
            "ref\u{200b}1",
            r#"reference 2 ("ref\u{200b}1") is not a caller reference: it contains a Unicode format character (U+200B)"#,
        ),
        (
            "ref-1 ",
            r#"reference 2 ("ref-1 ") is not a caller reference: it has leading or trailing spaces"#,
        ),
    ] {
        let list = case.file(
            "refs.json",
            &json!({"version": 1, "pass_id": "text-1", "references": ["ok", bad]}).to_string(),
        );
        let (code, value) = case.json(&[
            "reconcile-references",
            &pass,
            "--adoption",
            "1",
            "--references",
            &list,
            "--reason",
            "from the run log",
        ]);
        assert_eq!(code, 1, "{value}");
        let message = value["error"]["message"].as_str().expect("message");
        assert!(message.contains(part), "{message}");
    }
}

#[test]
fn every_pass_text_field_refuses_format_characters() {
    let case = Case::new();
    for (class, c) in FORMAT_SAMPLES {
        for (field, from, to) in [
            (
                "name",
                "name = \"Text safety\"",
                format!("name = \"Text{c} safety\""),
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
            let file = case.file("bad.toml", &PASS.replace(from, &to));
            let (code, value) = case.json(&["check", &file]);
            assert_eq!(code, 1, "{class} in {field}: {value}");
            let problems = value["problems"].as_array().expect("problems");
            assert!(
                problems.iter().any(|p| p["field"] == field
                    && p["message"]
                        .as_str()
                        .is_some_and(|m| m.contains(&code_point(c)))),
                "{class} in {field}: {value}"
            );
        }
    }
}

#[test]
fn diff_names_an_invisible_change_instead_of_showing_two_equal_values() {
    let case = Case::new();
    let old = case.file("old.toml", PASS);
    let new = case.file(
        "new.toml",
        &PASS.replace("owner = \"Owner\"", "owner = \"Own\u{200b}er\""),
    );
    let (code, out, err) = case.run_in("state", "text", &["diff", &old, &new]);
    assert_eq!(code, 1, "{out}{err}");
    let shown = format!("{out}{err}");
    assert!(
        shown.contains("approval.owner: contains a Unicode format character (U+200B)"),
        "{shown}"
    );
    assert!(!shown.contains('\u{200b}'), "{shown:?}");
}

/// Rewrite line `index` of the ledger beside `pass` with `edit`, and the
/// `prev` hash of the line after it, as an older hallpass that accepted the
/// new text would have written it.
fn rewrite_line(pass: &str, index: usize, edit: impl Fn(&str) -> String) {
    let path = format!("{pass}.ledger");
    let text = fs::read_to_string(&path).expect("read the ledger");
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let old = Digest::of(lines[index].as_bytes()).to_string();
    lines[index] = edit(&lines[index]);
    let new = Digest::of(lines[index].as_bytes()).to_string();
    if let Some(next) = lines.get_mut(index + 1) {
        *next = next.replace(&old, &new);
    }
    fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write the ledger");
}

#[test]
fn a_ledger_written_earlier_with_format_characters_still_reads_and_shows_them() {
    let case = Case::new();
    let pass = case.pass();
    let (code, _) = case.json(&[
        "spend",
        &pass,
        "calls",
        "--to",
        TARGET,
        "--record-target",
        "--caller-ref",
        "REF",
        "--note",
        "NOTE",
    ]);
    assert_eq!(code, 0);
    // An adoption in a second state directory, which had no witness.
    let (code, _, err) = case.run_in("second", "json", &["adopt", &pass, "--reason", "REASON"]);
    assert_eq!(code, 0, "{err}");
    // An older hallpass accepted these, and serde_json writes them raw.
    let reference = "ref\u{200b}1\u{e0065} ";
    let note = "fir\u{feff}st\u{ad}";
    let reason = "moved\u{2060}";
    rewrite_line(&pass, 1, |line| {
        line.replace("\"REF\"", &format!("\"{reference}\""))
            .replace("\"NOTE\"", &format!("\"{note}\""))
    });
    rewrite_line(&pass, 2, |line| {
        line.replace("\"REASON\"", &format!("\"{reason}\""))
    });
    assert!(
        fs::read_to_string(format!("{pass}.ledger"))
            .expect("ledger")
            .contains('\u{200b}')
    );

    // Read with no witness, as a copy of the ledger would be: it reads.
    let (code, out, err) = case.run_in("third", "text", &["ledger", &pass]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(!out.contains("ledger-corrupt") && !err.contains("ledger-corrupt"));
    assert!(
        out.contains(r#"receipt: ref "ref\u{200b}1\u{e0065} ", targets "192.0.2.10:443/tcp" label "web"  note: fir\u{feff}st\u{00ad}"#),
        "{out}"
    );
    assert!(out.contains(r"reason: moved\u{2060}"), "{out}");
    for c in [reference, note, reason]
        .concat()
        .chars()
        .filter(|c| !c.is_ascii())
    {
        assert!(!out.contains(c), "{c:?} shown raw: {out:?}");
    }
    // JSON carries the exact text.
    let (code, out, _) = case.run_in("third", "json", &["ledger", &pass]);
    assert_eq!(code, 0, "{out}");
    let value: Value = serde_json::from_str(&out).expect("json");
    let debit = &value["entries"][0];
    assert_eq!(debit["receipt"]["caller_ref"], reference);
    assert_eq!(debit["note"], note);
    assert_eq!(value["adoptions"][0]["reason"], reason);
    // The recorded reference can still be looked up, and is shown escaped.
    let (code, out, err) = case.run_in(
        "third",
        "text",
        &["receipt", &pass, "--caller-ref", reference],
    );
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        out.starts_with(r#"Receipt found for "ref\u{200b}1\u{e0065} ". 1 matches."#),
        "{out}"
    );
    // A reconcile manifest can name it too.
    let digest = value["entries"][0]["digest"].as_str().expect("digest");
    let manifest = case.file(
        "manifest.json",
        &json!({"version": 1, "pass_id": "text-1", "units": [{
            "caller_ref": reference,
            "digest": digest,
            "charges": [{"counter": "calls", "n": 1}],
            "targets": [{"target": TARGET}],
        }]})
        .to_string(),
    );
    let (_, out, err) = case.run_in("third", "text", &["reconcile", &pass, &manifest]);
    assert!(
        out.contains(r#"  match        "ref\u{200b}1\u{e0065} " (ledger sequence 1)"#),
        "{out}{err}"
    );
    // A new spend cannot record it again.
    let (code, value) = case.json(&["spend", &pass, "calls", "--caller-ref", reference]);
    assert_eq!(code, 1, "{value}");
}

#[test]
fn a_reference_reconciliation_written_earlier_with_format_characters_still_reads() {
    let case = Case::new();
    let pass = case.pass();
    assert_eq!(case.json(&["spend", &pass, "calls"]).0, 0);
    fs::rename(format!("{pass}.ledger"), case.path("lost.ledger")).expect("lose the ledger");
    assert_eq!(case.adopt_reviewed(&pass, "lost").0, 0);
    let list = case.file(
        "refs.json",
        &json!({"version": 1, "pass_id": "text-1", "references": ["REF"]}).to_string(),
    );
    let (code, value) = case.json(&[
        "reconcile-references",
        &pass,
        "--adoption",
        "1",
        "--references",
        &list,
        "--reason",
        "REASON",
    ]);
    assert_eq!(code, 0, "{value}");
    let reference = "\u{feff}ref\u{200b}1 ";
    let reason = "from the log\u{ad}";
    rewrite_line(&pass, 2, |line| {
        line.replace("\"REF\"", &format!("\"{reference}\""))
            .replace("\"REASON\"", &format!("\"{reason}\""))
    });
    let (code, out, err) = case.run_in("other", "text", &["ledger", &pass]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        out.contains(r#"references: "\u{feff}ref\u{200b}1 "  reason: from the log\u{00ad}"#),
        "{out}"
    );
    let (_, out, _) = case.run_in("other", "json", &["ledger", &pass]);
    let value: Value = serde_json::from_str(&out).expect("json");
    let recorded = &value["reference_reconciliations"][0];
    assert_eq!(recorded["references"][0], reference);
    assert_eq!(recorded["reason"], reason);
}

// The table of format characters, invisible characters and look-alike
// spaces.

/// Every code point of general category Cf in Unicode 16.0 outside the Tags
/// block, one by one, from `UnicodeData.txt`.
const FORMAT_OUTSIDE_TAGS: [u32; 73] = [
    0x00ad, 0x0600, 0x0601, 0x0602, 0x0603, 0x0604, 0x0605, 0x061c, //
    0x06dd, 0x070f, 0x0890, 0x0891, 0x08e2, 0x180e, 0x200b, 0x200c, //
    0x200d, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, //
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2066, 0x2067, 0x2068, //
    0x2069, 0x206a, 0x206b, 0x206c, 0x206d, 0x206e, 0x206f, 0xfeff, //
    0xfff9, 0xfffa, 0xfffb, 0x110bd, 0x110cd, 0x13430, 0x13431, 0x13432, //
    0x13433, 0x13434, 0x13435, 0x13436, 0x13437, 0x13438, 0x13439, 0x1343a, //
    0x1343b, 0x1343c, 0x1343d, 0x1343e, 0x1343f, 0x1bca0, 0x1bca1, 0x1bca2, //
    0x1bca3, 0x1d173, 0x1d174, 0x1d175, 0x1d176, 0x1d177, 0x1d178, 0x1d179, //
    0x1d17a,
];

/// Every `Default_Ignorable_Code_Point` of Unicode 16.0, as the inclusive
/// ranges of `DerivedCoreProperties.txt` (4174 code points; Perl's
/// `\p{Default_Ignorable_Code_Point}` of Unicode 16.0 gives the same).
/// Python's `unicodedata` has no such property.
const DEFAULT_IGNORABLE: [(u32, u32); 17] = [
    (0x00ad, 0x00ad),
    (0x034f, 0x034f),
    (0x061c, 0x061c),
    (0x115f, 0x1160),
    (0x17b4, 0x17b5),
    (0x180b, 0x180f),
    (0x200b, 0x200f),
    (0x202a, 0x202e),
    (0x2060, 0x206f),
    (0x3164, 0x3164),
    (0xfe00, 0xfe0f),
    (0xfeff, 0xfeff),
    (0xffa0, 0xffa0),
    (0xfff0, 0xfff8),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0000, 0xe0fff),
];

/// Every code point of general category Zs in Unicode 16.0, one by one,
/// from Python's `unicodedata` (`unidata_version` 16.0.0).
const SPACE_SEPARATORS: [u32; 17] = [
    0x0020, 0x00a0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, //
    0x2007, 0x2008, 0x2009, 0x200a, 0x202f, 0x205f, 0x3000,
];

/// What text output must escape: control characters, the line and
/// paragraph separators, every format character and the whole Tags block
/// (U+E0001 and U+E0020 to U+E007F are format characters; the rest of it is
/// reserved for more tags), every default-ignorable code point (bn-2gh) and
/// every space separator but the ASCII space (bn-2gh).
fn must_escape(c: char) -> bool {
    let n = u32::from(c);
    c.is_control()
        || n == 0x2028
        || n == 0x2029
        || FORMAT_OUTSIDE_TAGS.contains(&n)
        || (0xe0000..=0xe007f).contains(&n)
        || DEFAULT_IGNORABLE
            .iter()
            .any(|&(first, last)| (first..=last).contains(&n))
        || (n != 0x20 && SPACE_SEPARATORS.contains(&n))
}

#[test]
fn the_escaped_characters_are_exactly_the_known_list() {
    for c in (0..=0x10_ffff_u32).filter_map(char::from_u32) {
        if c == '\\' {
            continue;
        }
        let text = c.to_string();
        let shown = hallpass::display_safe(&text);
        let escaped = format!("\\u{{{:04x}}}", u32::from(c));
        if must_escape(c) {
            assert_eq!(shown, escaped, "{}", code_point(c));
            // Rust's own Unicode tables agree that it is not printable, but
            // for the Hangul fillers: letters (Lo) to Rust, which show
            // nothing or a blank.
            if !matches!(c, '\u{115f}' | '\u{1160}' | '\u{3164}' | '\u{ffa0}') {
                assert_ne!(c.escape_debug().to_string(), text, "{}", code_point(c));
            }
        } else {
            assert_eq!(shown, text, "{}", code_point(c));
        }
    }
}
