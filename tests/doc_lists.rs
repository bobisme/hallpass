//! Keeps the reference lists of `docs/spec.md` in step with the code: the
//! refusal codes, the error codes, the command table and the JSON fields.
//!
//! The codes are read from the `match` in `RefusalCode::as_str` and in
//! `Error::code`. Both matches are exhaustive, so the compiler keeps them
//! complete, and a new code fails this test until the spec lists it. The
//! commands come from `hallpass help --format json`, and the JSON fields
//! from real replies.

use std::collections::BTreeSet;
use std::path::PathBuf;

use hallpass::{Error, RefusalCode};

const SPEC: &str = include_str!("../docs/spec.md");
const DECISION_RS: &str = include_str!("../src/decision.rs");
const ERROR_RS: &str = include_str!("../src/error.rs");

/// The text of the spec without its fenced code blocks.
fn prose(text: &str) -> String {
    let mut fenced = false;
    let mut out = String::new();
    for line in text.lines() {
        if line.starts_with("```") {
            fenced = !fenced;
        } else if !fenced {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// The lines after the heading line `heading`, up to the next heading of
/// the same or a higher level.
fn section(heading: &str) -> String {
    let level = heading.chars().take_while(|c| *c == '#').count();
    let text = prose(SPEC);
    let mut lines = text.lines();
    assert!(
        lines.by_ref().any(|line| line == heading),
        "docs/spec.md has no heading {heading:?}"
    );
    let mut out = String::new();
    for line in lines {
        let depth = line.chars().take_while(|c| *c == '#').count();
        if depth > 0 && depth <= level && line[depth..].starts_with(' ') {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Every word inside the inline code spans of `text`: `{code, message}`
/// gives `code` and `message`. Spans can wrap across lines.
fn code_words(text: &str) -> BTreeSet<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .flat_map(|span| span.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-')))
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The string literals returned by the arms of the `match` in the function
/// declared by `signature`, the first one after `owner` in `source`.
fn returned_codes(source: &str, owner: &str, signature: &str) -> BTreeSet<String> {
    let rest = &source[source.find(owner).expect("owner")..];
    let body = &rest[rest.find(signature).expect("signature") + signature.len()..];
    let body = &body[..body.find("\n    }\n").expect("end of the function")];
    let arms = body
        .lines()
        .filter(|line| line.trim_start().starts_with("Self::"))
        .count();
    let codes: BTreeSet<String> = body
        .lines()
        .filter_map(|line| line.split_once("=> \""))
        .filter_map(|(_, literal)| literal.split_once('"'))
        .map(|(code, _)| code.to_owned())
        .collect();
    assert_eq!(
        codes.len(),
        arms,
        "every arm of `{signature}` must return one literal on its own line"
    );
    codes
}

fn refusal_codes() -> BTreeSet<String> {
    let codes = returned_codes(
        DECISION_RS,
        "impl RefusalCode {",
        "pub const fn as_str(self) -> &'static str {",
    );
    // The parser found at least the codes this test knows by name.
    for code in [
        RefusalCode::NotYetValid,
        RefusalCode::Expired,
        RefusalCode::Revoked,
        RefusalCode::WindowTooShort,
        RefusalCode::EmbeddedIpv4,
        RefusalCode::NetworkOrBroadcast,
        RefusalCode::AddressNotListed,
        RefusalCode::PortNotListed,
        RefusalCode::NameRequired,
        RefusalCode::NameNotListed,
        RefusalCode::UnknownCounter,
        RefusalCode::RequiredCounterMissing,
        RefusalCode::TargetRequired,
        RefusalCode::DuplicateReference,
        RefusalCode::ReferenceInconclusive,
        RefusalCode::CeilingReached,
        RefusalCode::PassChanged,
    ] {
        assert!(codes.contains(code.as_str()), "{}", code.as_str());
    }
    codes
}

fn error_codes() -> BTreeSet<String> {
    let codes = returned_codes(
        ERROR_RS,
        "impl Error {",
        "pub const fn code(&self) -> &'static str {",
    );
    let path = PathBuf::from("x");
    for error in [
        Error::Usage(String::new()),
        Error::LockTimeout { path: path.clone() },
        Error::Exists { path: path.clone() },
        Error::UntrustedOwner {
            path,
            owner: 1,
            effective: 2,
        },
    ] {
        assert!(codes.contains(error.code()), "{}", error.code());
    }
    assert!(codes.len() >= 17, "{codes:?}");
    codes
}

#[test]
fn the_spec_lists_every_refusal_code_and_no_other() {
    let codes = refusal_codes();
    let listed = code_words(&section("### Refusal codes"));
    assert_eq!(
        listed, codes,
        "the \"Refusal codes\" list of docs/spec.md differs from `RefusalCode::as_str`"
    );
}

#[test]
fn the_spec_lists_every_error_code_and_no_other() {
    let codes = error_codes();
    // The code is the last cell of each row of the table.
    let listed: BTreeSet<String> = section("### Fail-closed cases")
        .lines()
        .filter(|line| line.starts_with('|') && !line.starts_with("|---"))
        .filter_map(|line| line.trim_end_matches('|').rsplit('|').next())
        .map(|cell| cell.trim().trim_matches('`').to_owned())
        .filter(|cell| cell != "Code")
        .collect();
    assert_eq!(
        listed, codes,
        "the \"Fail-closed cases\" table of docs/spec.md differs from `Error::code`"
    );
}

#[cfg(feature = "cli")]
mod cli {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    use serde_json::Value;

    use super::{code_words, section};

    /// A pass with a named destination that a nameless one overlaps, so that
    /// `check` and `status` report a name-restriction overlap.
    const PASS: &str = r#"format = 1
id = "doc-lists"
name = "Documented fields"

[approval]
owner = "Example owner"
reference = "Documentation fixture"
operator = "Example operator"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = 443
names = ["app.example.org"]

[[destination]]
label = "subnet"
network = "192.0.2.0/28"
protocol = "tcp"
ports = 443

[ceilings]
requests = 5
bytes = 100
"#;

    fn hallpass(dir: &Path, args: &[&str]) -> Value {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .arg("--format")
            .arg("json")
            .args(args)
            .current_dir(dir)
            .env("HOME", dir)
            .env("XDG_STATE_HOME", dir.join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z")
            .output()
            .expect("run hallpass");
        serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{args:?}: not one JSON object ({e})"))
    }

    fn write_pass(dir: &Path, name: &str, text: &str) {
        let path = dir.join(name);
        fs::write(&path, text).expect("write pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    }

    /// The command names of `hallpass help`.
    fn commands(dir: &Path) -> BTreeSet<String> {
        let help = hallpass(dir, &["help"]);
        help["commands"]
            .as_array()
            .expect("command directory")
            .iter()
            .map(|c| c["name"].as_str().expect("name").to_owned())
            .collect()
    }

    #[test]
    fn the_command_table_lists_every_command_and_no_other() {
        let dir = tempfile::tempdir().expect("tempdir");
        let commands = commands(dir.path());
        assert!(commands.contains("spend"), "{commands:?}");
        let table: BTreeSet<String> = section("## Command line")
            .lines()
            .filter_map(|line| line.strip_prefix("| `"))
            .filter_map(|line| line.split_once("` |"))
            .map(|(name, _)| name.to_owned())
            .collect();
        assert_eq!(
            table, commands,
            "the command table of docs/spec.md differs from `hallpass help`"
        );
    }

    #[test]
    fn the_json_fields_name_every_command() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fields = section("### JSON fields");
        for command in commands(dir.path()) {
            assert!(
                fields.contains(&format!("**{command}**")),
                "\"JSON fields\" in docs/spec.md has no entry for {command}"
            );
        }
    }

    /// The list item of "JSON fields" that names `command` in bold.
    fn bullet(fields: &str, command: &str) -> String {
        let mark = format!("**{command}**");
        let mut items = Vec::new();
        for line in fields.lines() {
            if line.starts_with("- ") {
                items.push(String::new());
            } else if line.is_empty() || !line.starts_with("  ") {
                items.push(String::new());
                continue;
            }
            if let Some(item) = items.last_mut() {
                item.push_str(line);
                item.push('\n');
            }
        }
        items
            .into_iter()
            .find(|item| item.contains(&mark))
            .unwrap_or_else(|| panic!("no JSON fields entry for {command}"))
    }

    /// Every key of `value` below the top level.
    fn nested_keys(value: &Value, out: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map {
                    out.insert(key.clone());
                    nested_keys(inner, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|v| nested_keys(v, out)),
            _ => {}
        }
    }

    /// Every top-level key of `reply` is in the entry for `command` or in
    /// the paragraph before the entries; every deeper key is somewhere in
    /// "JSON fields".
    fn assert_documented(command: &str, reply: &Value) {
        let fields = section("### JSON fields");
        let general = code_words(fields.split("\n- ").next().expect("paragraph"));
        let entry = code_words(&bullet(&fields, command));
        let anywhere = code_words(&fields);
        let object = reply.as_object().expect("object");
        for key in object.keys() {
            assert!(
                entry.contains(key) || general.contains(key),
                "{command}: `{key}` is not in its \"JSON fields\" entry of docs/spec.md: {reply}"
            );
        }
        let mut deeper = BTreeSet::new();
        for inner in object.values() {
            nested_keys(inner, &mut deeper);
        }
        for key in deeper {
            assert!(
                anywhere.contains(&key),
                "{command}: `{key}` is not in \"JSON fields\" of docs/spec.md: {reply}"
            );
        }
    }

    #[test]
    fn the_json_fields_cover_real_replies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir = dir.path();
        write_pass(dir, "p.toml", PASS);
        write_pass(
            dir,
            "q.toml",
            &PASS
                .replace("bytes = 100", "bytes = 200")
                .replace("network = \"192.0.2.0/28\"", "network = \"192.0.2.0/27\""),
        );

        let check = hallpass(dir, &["check", "p.toml"]);
        assert_eq!(
            check["name_restriction_overlaps"].as_array().map(Vec::len),
            Some(1),
            "{check}"
        );
        assert_documented("check", &check);
        let empty = hallpass(dir, &["checkpoint", "p.toml"]);
        assert_eq!(empty["result"], "empty");
        assert_documented("checkpoint", &empty);

        let to = "192.0.2.10:443/tcp@app.example.org";
        let allowed = hallpass(
            dir,
            &[
                "spend",
                "p.toml",
                "--charge",
                "requests=1",
                "--charge",
                "bytes=4",
                "--to",
                to,
                "--caller-ref",
                "run-1",
                "--record-target",
            ],
        );
        assert_eq!(allowed["result"], "allowed", "{allowed}");
        let duplicate = hallpass(
            dir,
            &[
                "spend",
                "p.toml",
                "--charge",
                "requests=1",
                "--to",
                to,
                "--caller-ref",
                "run-1",
                "--require-new-ref",
            ],
        );
        assert_eq!(
            duplicate["refusal"]["code"], "duplicate-reference",
            "{duplicate}"
        );
        let preview = hallpass(dir, &["spend", "p.toml", "requests", "--dry-run"]);
        assert_eq!(preview["result"], "would-allow", "{preview}");
        for reply in [&allowed, &duplicate, &preview] {
            assert_documented("spend", reply);
        }

        let permits = hallpass(
            dir,
            &[
                "permits",
                "p.toml",
                "--to",
                to,
                "--to",
                "192.0.2.99:443/tcp",
            ],
        );
        assert_eq!(permits["refused_target"], 2, "{permits}");
        assert_documented("permits", &permits);
        assert_documented("status", &hallpass(dir, &["status", "p.toml"]));
        let exported = hallpass(dir, &["checkpoint", "p.toml"]);
        assert_eq!(exported["result"], "ok", "{exported}");
        assert_documented("checkpoint", &exported);

        let digest = allowed["digest"].as_str().expect("digest");
        fs::write(
            dir.join("manifest.json"),
            format!(
                r#"{{"version": 1, "pass_id": "doc-lists", "units": [{{"caller_ref": "run-1", "digest": "{digest}", "charges": [{{"counter": "requests", "n": 2}}, {{"counter": "bytes", "n": 4}}]}}]}}"#
            ),
        )
        .expect("manifest");
        let reconcile = hallpass(dir, &["reconcile", "p.toml", "manifest.json"]);
        assert_eq!(
            reconcile["rows"][0]["differences"][0]["field"], "charge.requests",
            "{reconcile}"
        );
        assert_documented("reconcile", &reconcile);

        let diff = hallpass(dir, &["diff", "p.toml", "q.toml"]);
        assert_eq!(diff["changes"].as_array().map(Vec::len), Some(2), "{diff}");
        assert_documented("diff", &diff);

        let error = hallpass(dir, &["status", "missing.toml"]);
        assert_eq!(error["result"], "error", "{error}");
        assert_documented("error", &error);
    }
}
