//! Rules over the whole pass file (bn-3qp) and the review rules of bn-1on.
//!
//! A pass file may hold no character that can make it display as
//! something else anywhere, comments, keys and whitespace included, and no
//! control character but a tab and a line end. Labels may not differ only
//! in ASCII letter case, a destination may not list a port twice, `lint`
//! flags a destination that grants more than 1,024 ports, and an approval
//! id whose owner or reference could be typed another way comes with a
//! warning. The first line of `lint` counts every finding and warning it
//! gives.
#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};

use hallpass::{Pass, Problem, review, time::macros::datetime};
use serde_json::Value;

const NOW: &str = "2026-11-20T09:00:00Z";

/// A valid pass of 17 lines.
const PASS: &str = "format = 1
id = \"rules-1\"
name = \"File rules\"
[approval]
owner = \"Pat Owner\"
reference = \"CHG-1\"
operator = \"Sam Tester\"
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

/// One character of each kind the bone names: a bidirectional control, a
/// zero-width character and a look-alike space, with how a message names it.
const KINDS: [(&str, char, &str); 3] = [
    (
        "right-to-left override",
        '\u{202e}',
        "a bidirectional text control (U+202E)",
    ),
    (
        "zero-width space",
        '\u{200b}',
        "a Unicode format character (U+200B)",
    ),
    ("no-break space", '\u{a0}', "a look-alike space (U+00A0)"),
];

fn problems(text: &str) -> Vec<Problem> {
    Pass::parse(text).expect_err("refused")
}

/// The problem a hidden character at `line` and `column` gives.
fn hidden_at(line: usize, column: usize, named: &str) -> String {
    format!(
        "line {line}, column {column} holds {named}, which can make the file display as something else; delete it, then have the owner approve the edited file"
    )
}

/// `problems` holds the hidden-character problem for `named` at `line` and
/// `column`, as a `(file)` problem.
fn assert_hidden(problems: &[Problem], line: usize, column: usize, named: &str, what: &str) {
    let wanted = hidden_at(line, column, named);
    assert!(
        problems
            .iter()
            .any(|p| p.field == "(file)" && p.message == wanted),
        "{what}: no {wanted:?} in {problems:#?}"
    );
}

#[test]
fn a_comment_with_a_hidden_character_is_refused_with_its_line_and_column() {
    for (class, c, named) in KINDS {
        // A comment of its own at the end, after a value, and in a header.
        let own = format!("{PASS}# owner also approved port 22 by phone {c}\n");
        assert_hidden(&problems(&own), 18, 40, named, class);
        let after = PASS.replace("revoked = false", &format!("revoked = false # no{c}te"));
        assert_hidden(&problems(&after), 10, 21, named, class);
        let header = PASS.replace("[ceilings]", &format!("[ceilings] #{c}"));
        let found = problems(&header);
        assert_hidden(&found, 16, 13, named, class);
        assert_eq!(found.len(), 1, "{class}: {found:#?}");
    }
}

#[test]
fn a_key_with_a_hidden_character_is_refused_with_its_line_and_column() {
    for (class, c, named) in KINDS {
        // A quoted key is TOML; it is also an unknown key.
        let quoted = PASS.replace("owner = ", &format!("\"own{c}er\" = "));
        let found = problems(&quoted);
        assert_hidden(&found, 5, 5, named, class);
        assert!(
            found.iter().any(
                |p| p.field.starts_with("approval.own") && p.message.starts_with("unknown key")
            ),
            "{class}: {found:#?}"
        );
        // A bare key is not TOML; the character comes before the syntax
        // error it explains.
        let bare = PASS.replace("operator = ", &format!("oper{c}ator = "));
        let found = problems(&bare);
        assert_eq!(found.len(), 2, "{class}: {found:#?}");
        assert_eq!(found[0].message, hidden_at(7, 5, named), "{class}");
        assert!(
            found[1]
                .message
                .starts_with("the file is not valid TOML at line 7, column 5"),
            "{class}: {found:#?}"
        );
    }
}

#[test]
fn whitespace_with_a_hidden_character_is_refused_with_its_line_and_column() {
    for (class, c, named) in KINDS {
        for (from, to, line, column) in [
            ("owner = ", format!("owner{c}= "), 5, 6),
            ("revoked = false", format!("revoked ={c}false"), 10, 10),
            ("ports = 443", format!("{c}ports = 443"), 15, 1),
            ("[ceilings]\n", format!("[ceilings]{c}\n"), 16, 11),
        ] {
            let found = problems(&PASS.replace(from, &to));
            assert_eq!(
                found[0].message,
                hidden_at(line, column, named),
                "{class}: {to}"
            );
            assert_eq!(found[0].field, "(file)");
        }
    }
}

#[test]
fn a_hidden_character_in_a_string_value_is_reported_once_by_its_field() {
    for (class, c, named) in KINDS {
        let text = PASS.replace("owner = \"Pat Owner\"", &format!("owner = \"Pat{c}Owner\""));
        let found = problems(&text);
        assert_eq!(
            found,
            vec![Problem {
                field: "approval.owner".to_owned(),
                message: format!(
                    "contains {named}, which can make it display as something else; write one plain line without it"
                ),
            }],
            "{class}"
        );
    }
}

#[test]
fn tabs_and_line_ends_are_still_fine() {
    let tabs = PASS
        .replace("revoked = false", "revoked\t=\tfalse\t# a\ttab")
        .replace("ports = 443", "\tports = [443,\t8443]");
    let pass = Pass::parse(&tabs).expect("tabs load");
    assert!(pass.destinations[0].ports.contains(8443));
    let crlf = PASS.replace('\n', "\r\n");
    Pass::parse(&crlf).expect("CRLF line ends load");
    let comments = format!("# Copied from the owner's email of 2026-11-18.\n{PASS}# end\n\n");
    Pass::parse(&comments).expect("plain comments load");
    // Letters of any script, and right-to-left text, are not hidden.
    let letters = format!("{PASS}# Zoë Ünal, 変更 9812, مالك الخدمة, שינוי 9812, ‘quoted’ — ok\n");
    Pass::parse(&letters).expect("letters load");
}

#[test]
fn every_character_text_output_escapes_is_refused_in_a_comment_and_no_other() {
    // The set is the one `display_safe` escapes, which tests/text_safety.rs
    // pins to lists taken from Unicode 16.0; a pass file allows only the tab
    // and the line feed of it (and the backslash, escaped so that escapes
    // cannot be forged).
    let mut allowed = String::new();
    for c in (0..=0x10_ffff_u32).filter_map(char::from_u32) {
        let shown = hallpass::display_safe(&c.to_string()).into_owned();
        if shown == c.to_string() || matches!(c, '\t' | '\n' | '\\') {
            if c != '\n' {
                allowed.push(c);
                if allowed.len() % 4096 < 4 {
                    allowed.push_str("\n# ");
                }
            }
            continue;
        }
        // A letter after it, so a carriage return does not end the line.
        let found = problems(&format!("{PASS}# {c}x\n"));
        let code = format!("(U+{:04X})", u32::from(c));
        assert_eq!(found[0].field, "(file)", "{code}: {found:?}");
        assert!(
            found[0].message.starts_with("line 18, column 3 holds ")
                && found[0].message.contains(&code),
            "{code}: {found:?}"
        );
    }
    Pass::parse(&format!("{PASS}# {allowed}\n")).expect("every other character loads");
}

#[test]
fn a_byte_order_mark_is_named() {
    let found = problems(&format!("\u{feff}{PASS}"));
    assert_eq!(
        found,
        vec![Problem {
            field: "(file)".to_owned(),
            message: "the file starts with a byte order mark (U+FEFF), an invisible character; save the file as UTF-8 without one, then have the owner approve the edited file".to_owned(),
        }]
    );
}

#[test]
fn many_hidden_characters_are_counted_after_sixteen() {
    let text = format!("{PASS}{}", "# \u{a0}\n".repeat(40));
    let found = problems(&text);
    assert_eq!(found.len(), 17, "{found:#?}");
    assert_eq!(
        found[15].message,
        hidden_at(33, 3, "a look-alike space (U+00A0)")
    );
    assert_eq!(
        found[16].message,
        "24 more characters like these follow line 33, column 3; delete them too"
    );
}

// bn-1on: labels, ports and review advice.

#[test]
fn labels_that_differ_only_in_letter_case_are_refused() {
    let second = "[[destination]]\nlabel = \"WEB\"\naddress = \"192.0.2.11\"\nprotocol = \"tcp\"\nports = 443\n";
    let text = PASS.replace("[ceilings]", &format!("{second}[ceilings]"));
    let found = problems(&text);
    assert_eq!(
        found,
        vec![Problem {
            field: "destination[2].label".to_owned(),
            message: "\"WEB\" differs from \"web\", the label of destination[1], only in letter case; people read and type labels, so make the two differ in more than case".to_owned(),
        }]
    );
    // The same label twice keeps its own problem.
    let found = problems(&text.replace("label = \"WEB\"", "label = \"web\""));
    assert_eq!(found[0].field, "destination[2].label");
    assert_eq!(
        found[0].message,
        "\"web\" is also the label of destination[1]; labels must be unique"
    );
    // Labels that differ in more than case load.
    Pass::parse(&text.replace("label = \"WEB\"", "label = \"web-2\"")).expect("distinct labels");
}

#[test]
fn a_port_listed_twice_is_refused_and_named() {
    for (ports, message) in [
        ("[443, 443]", "lists `443` twice; remove one"),
        ("[443, \"443-443\"]", "lists `443` twice; remove one"),
        (
            "[80, \"1-1024\"]",
            "lists port 80 twice, in `80` and in `1-1024`; list each port once",
        ),
        (
            "[\"8000-8100\", \"8050-8200\"]",
            "lists port 8050 twice, in `8000-8100` and in `8050-8200`; list each port once",
        ),
    ] {
        let found = problems(&PASS.replace("ports = 443", &format!("ports = {ports}")));
        assert_eq!(
            found,
            vec![Problem {
                field: "destination[1].ports".to_owned(),
                message: message.to_owned(),
            }],
            "{ports}"
        );
    }
    for ports in ["[\"1-80\", \"81-100\"]", "[80, 443, 8443]", "[\"1-65535\"]"] {
        Pass::parse(&PASS.replace("ports = 443", &format!("ports = {ports}"))).expect(ports);
    }
}

#[test]
fn lint_flags_a_destination_that_grants_more_than_1024_ports() {
    let now = datetime!(2026-11-20 09:00 UTC);
    let with = |ports: &str| {
        Pass::parse(&PASS.replace("ports = 443", &format!("ports = {ports}"))).expect(ports)
    };
    for ports in ["443", "[\"1-1024\"]", "[\"1-1000\", \"2000-2023\"]"] {
        assert!(
            review::lint(&with(ports), now).port_findings.is_empty(),
            "{ports}"
        );
    }
    let all = review::lint(&with("[\"1-65535\"]"), now).port_findings;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].code, "wide-port-grant");
    assert_eq!(all[0].port_count, 65535);
    assert_eq!(all[0].ports, "1-65535");
    assert_eq!(
        all[0].message,
        "destination `web` grants every port, 1-65535, on tcp; check that the owner's written approval names these ports"
    );
    let many = review::lint(&with("[443, \"1000-2024\"]"), now).port_findings;
    assert_eq!(many.len(), 1);
    assert_eq!(many[0].port_count, 1026);
    assert_eq!(
        many[0].message,
        "destination `web` grants 1026 ports (443, 1000-2024), more than the 1024 that raise no finding, on tcp; check that the owner's written approval names these ports"
    );
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

    /// A private pass file, dated back so that reading it does not wait for
    /// a rewrite in place to settle.
    fn file(&self, name: &str, text: &str) -> String {
        let path: PathBuf = self.dir.path().join(name);
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

    /// Exit code, standard output and standard error.
    fn run(&self, format: &str, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
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

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let (code, out, _) = self.run("json", args);
        let value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
        (code, value)
    }
}

#[test]
fn every_command_that_loads_the_pass_refuses_a_bidi_control_in_a_comment() {
    let case = Case::new();
    let file = case.file(
        "p.toml",
        &format!("{PASS}# owner also approved port 22 by phone \u{202e}\u{200b}\n"),
    );
    let good = case.file("good.toml", PASS);
    let (code, out, err) = case.run("text", &["check", &file]);
    assert_eq!(code, 1, "{out}{err}");
    for named in [
        "line 18, column 40 holds a bidirectional text control (U+202E)",
        "line 18, column 41 holds a Unicode format character (U+200B)",
    ] {
        assert!(err.contains(named), "{err}");
    }
    assert!(
        !err.contains('\u{202e}') && !err.contains('\u{200b}'),
        "{err}"
    );
    for args in [
        vec!["status", file.as_str()],
        vec!["permits", file.as_str(), "--to", "192.0.2.10:443/tcp"],
        vec!["spend", file.as_str(), "calls"],
        vec!["lint", file.as_str()],
        vec!["digest", file.as_str()],
        vec!["diff", good.as_str(), file.as_str()],
    ] {
        let (code, value) = case.json(&args);
        assert_eq!(code, 1, "{args:?}: {value}");
        assert_eq!(value["error"]["code"], "invalid-pass", "{args:?}: {value}");
        assert_eq!(value["problems"][0]["field"], "(file)", "{args:?}: {value}");
    }
    assert!(!case.dir.path().join("p.toml.ledger").exists());
}

/// The lint report's first line, its `findings` and its `warnings`.
fn lint(case: &Case, file: &str) -> (String, usize, usize, String) {
    let (code, out, err) = case.run("text", &["lint", file]);
    assert_eq!(code, 0, "{out}{err}");
    let (code, value) = case.json(&["lint", file]);
    assert_eq!(code, 0, "{value}");
    let count = |key: &str| value[key].as_array().map_or(0, Vec::len);
    (
        out.lines().next().unwrap_or_default().to_owned(),
        count("findings"),
        count("warnings"),
        err,
    )
}

#[test]
fn the_lint_count_agrees_with_what_lint_prints() {
    let case = Case::new();
    let long = PASS.replace(
        "valid_until = 2026-11-20T17:00:00Z",
        "valid_until = 2027-11-20T17:00:00Z",
    );
    // A window warning alone: counted as a warning, not hidden by "0".
    let (first, findings, warnings, err) = lint(&case, &case.file("long.toml", &long));
    assert_eq!(first, "0 advisory finding(s) and 1 warning(s) for rules-1");
    assert_eq!((findings, warnings), (0, 1));
    assert_eq!(err.matches("hallpass: warning: ").count(), 1, "{err}");
    // A wide port grant, a long window and an owner with two spaces.
    let all = long
        .replace("ports = 443", "ports = [\"1-65535\"]")
        .replace("Pat Owner", "Pat  Owner");
    let file = case.file("all.toml", &all);
    let (first, findings, warnings, err) = lint(&case, &file);
    assert_eq!(first, "1 advisory finding(s) and 2 warning(s) for rules-1");
    assert_eq!((findings, warnings), (1, 2));
    assert_eq!(err.matches("hallpass: warning: ").count(), 2, "{err}");
    let (_, out, _) = case.run("text", &["lint", &file]);
    assert!(
        out.contains("wide-port-grant: destination `web` grants every port, 1-65535, on tcp"),
        "{out}"
    );
    let (_, value) = case.json(&["lint", &file]);
    assert_eq!(value["findings"][0]["code"], "wide-port-grant");
    assert_eq!(value["findings"][0]["port_count"], 65535);
    // A clean pass.
    let (first, findings, warnings, err) = lint(&case, &case.file("p.toml", PASS));
    assert_eq!(first, "0 advisory finding(s) and 0 warning(s) for rules-1");
    assert_eq!((findings, warnings), (0, 0));
    assert!(!err.contains("warning"), "{err}");
}

/// The JSON warnings of `approval-id` for `owner`, after checking that it
/// still gives the id.
fn id_warnings(case: &Case, owner: &str) -> (String, Vec<String>) {
    let (code, value) = case.json(&["approval-id", "--owner", owner, "--reference", "CHG-1"]);
    assert_eq!(code, 0, "{value}");
    let warnings = value["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .filter_map(|w| w.as_str().map(str::to_owned))
        .collect();
    (value["id"].as_str().expect("id").to_owned(), warnings)
}

#[test]
fn an_id_that_depends_on_invisible_spelling_comes_with_a_warning() {
    let case = Case::new();
    let (nfc, plain) = id_warnings(&case, "Caf\u{e9} SA");
    assert!(plain.is_empty(), "{plain:?}");
    let (nfd, marked) = id_warnings(&case, "Cafe\u{301} SA");
    assert_ne!(nfc, nfd);
    assert_eq!(marked.len(), 1, "{marked:?}");
    assert!(
        marked[0].starts_with("--owner (approval.owner) holds a combining mark (U+0301)")
            && marked[0].contains("The approval id depends on the exact characters")
            && marked[0].contains("a copy typed or pasted differently gives another id"),
        "{marked:?}"
    );
    let (_, single) = id_warnings(&case, "Pat Owner");
    assert!(single.is_empty(), "{single:?}");
    let (_, double) = id_warnings(&case, "Pat  Owner");
    assert_eq!(double.len(), 1, "{double:?}");
    assert!(
        double[0].starts_with("--owner (approval.owner) holds two or more spaces in a row")
            && double[0].contains("a copy typed or pasted with one space gives another id"),
        "{double:?}"
    );
    // The reference is checked too, and the text output warns on standard
    // error and still prints the id alone on standard output.
    let (code, out, err) = case.run(
        "text",
        &[
            "approval-id",
            "--owner",
            "Pat Owner",
            "--reference",
            "Change  9812",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("hp1-") && out.lines().count() == 1, "{out}");
    assert!(
        err.contains(
            "hallpass: warning: --reference (approval.reference) holds two or more spaces in a row"
        ),
        "{err}"
    );
}

#[test]
fn check_and_lint_give_the_approval_text_warnings() {
    let case = Case::new();
    let text = PASS
        .replace("Pat Owner", "Rene\u{301} Owner")
        .replace("CHG-1", "CHG  1");
    let file = case.file("p.toml", &text);
    let (code, value) = case.json(&["check", &file]);
    assert_eq!(code, 0, "{value}");
    let warnings: Vec<&str> = value["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].starts_with("approval.owner holds a combining mark (U+0301)"));
    assert!(warnings[1].starts_with("approval.reference holds two or more spaces in a row"));
    let (_, lint) = case.json(&["lint", &file]);
    assert_eq!(lint["warnings"], value["warnings"], "{lint}");
    // The library gives the same advice, with the fields.
    let advice = review::approval_identity_warnings("Rene\u{301} Owner", "CHG  1");
    let fields: Vec<&str> = advice.iter().map(|p| p.field.as_str()).collect();
    assert_eq!(fields, ["approval.owner", "approval.reference"]);
    assert_eq!(
        review::approval_identity_warnings("Ren\u{e9} Owner", "CHG 1"),
        Vec::<Problem>::new()
    );
}
