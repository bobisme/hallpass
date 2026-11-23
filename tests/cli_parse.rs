//! Argument parse errors have the shape of every other error, and the default
//! output format comes from `HALLPASS_FORMAT`.

use std::collections::BTreeSet;
use std::process::{Command, Output};

use serde_json::Value;

fn hallpass(args: &[&str], env: &[(&str, &str)]) -> (Output, tempfile::TempDir) {
    let home = tempfile::tempdir().expect("home");
    let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .args(args)
        .env_remove("FORMAT")
        .env_remove("HALLPASS_FORMAT")
        .envs(env.iter().copied())
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", home.path().join("state"))
        .current_dir(home.path())
        .output()
        .expect("run");
    (out, home)
}

fn reply(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).expect("one JSON object")
}

fn keys(value: &Value) -> BTreeSet<String> {
    value.as_object().expect("object").keys().cloned().collect()
}

#[test]
fn parse_errors_have_the_usage_error_shape() {
    let (out, _h) = hallpass(
        &[
            "--format", "json", "spend", "p.toml", "calls", "--to", "bad",
        ],
        &[],
    );
    let reference = reply(&out);
    assert_eq!(reference["error"]["code"], "usage");
    for (args, command) in [
        (
            vec![
                "--format",
                "json",
                "spend",
                "p.toml",
                "calls",
                "--n",
                "x",
                "--to",
                "192.0.2.10:443/tcp",
            ],
            Some("spend"),
        ),
        (
            vec!["--format", "json", "spend", "p.toml", "--nope"],
            Some("spend"),
        ),
        (vec!["--format", "json", "frobnicate"], None),
        (vec!["--json", "frobnicate"], None),
    ] {
        let (out, _h) = hallpass(&args, &[]);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert_eq!(out.stderr, b"", "{args:?}");
        let value = reply(&out);
        assert_eq!(value["command"], command.map_or(Value::Null, Value::from));
        assert_eq!(value["result"], "error");
        assert_eq!(value["error"]["code"], "usage");
        assert_eq!(value["error"]["recording"], "not-recorded");
        assert_eq!(keys(&value), keys(&reference), "{args:?}");
        assert_eq!(keys(&value["error"]), keys(&reference["error"]), "{args:?}");
    }
}

#[test]
fn hallpass_format_selects_the_format() {
    let (out, _h) = hallpass(&["version"], &[("HALLPASS_FORMAT", "json")]);
    assert_eq!(reply(&out)["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(out.stderr, b"");
    let (out, _h) = hallpass(
        &["--format", "text", "version"],
        &[("HALLPASS_FORMAT", "json")],
    );
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("hallpass "));
    let (out, _h) = hallpass(
        &["--format", "text", "version"],
        &[("HALLPASS_FORMAT", "yaml")],
    );
    assert!(out.status.success());
}

#[test]
fn the_unprefixed_format_variable_is_ignored_with_a_warning() {
    let (out, _h) = hallpass(&["version"], &[("FORMAT", "json")]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("hallpass "));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("FORMAT") && err.contains("HALLPASS_FORMAT"),
        "{err}"
    );
    let (out, _h) = hallpass(&["--format", "json", "version"], &[("FORMAT", "yaml")]);
    let value = reply(&out);
    let warnings = value["warnings"].as_array().expect("warnings");
    assert!(
        warnings[0]
            .as_str()
            .expect("text")
            .contains("HALLPASS_FORMAT")
    );
    assert_eq!(out.stderr, b"");
    let (out, _h) = hallpass(
        &["version"],
        &[("FORMAT", "yaml"), ("HALLPASS_FORMAT", "json")],
    );
    assert_eq!(reply(&out)["warnings"], serde_json::json!([]));
}

#[test]
fn an_invalid_hallpass_format_names_the_variable() {
    let (out, _h) = hallpass(&["version"], &[("HALLPASS_FORMAT", "yaml")]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(out.stdout, b"");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("HALLPASS_FORMAT") && err.contains("yaml"),
        "{err}"
    );
}
