#![cfg(feature = "cli")]
//! `docs/minimal-caller/minimal_caller.py` charges the counter named by its
//! optional fourth argument (default `requests`), so a pass that has only
//! `calls` can be spent through it (bn-ulz6).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:5060/udp";
const PASS: &str = r#"format = 1
id = "counter-2026-11"
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
calls = 2
"#;

fn caller(dir: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/minimal-caller/minimal_caller.py");
    let bin_dir = Path::new(BIN).parent().expect("binary directory");
    let mut paths = vec![bin_dir.to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let home = dir.join("home");
    let output = Command::new("python3")
        .arg("-I")
        .arg("-B")
        .arg(script)
        .args(["--rehearsal", "p.toml"])
        .args(args)
        .current_dir(dir)
        .env("PATH", std::env::join_paths(paths).expect("PATH"))
        .env("HOME", &home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
        .env_remove("HALLPASS_FORMAT")
        .env_remove("HALLPASS_REVIEWED_DIGEST")
        .output()
        .expect("run the minimal caller");
    (
        output.status.code(),
        String::from_utf8(output.stdout).expect("utf8"),
        String::from_utf8(output.stderr).expect("utf8"),
    )
}

#[test]
fn the_fourth_argument_names_the_counter_that_is_charged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    fs::create_dir(root.join("home")).expect("home");
    fs::set_permissions(root.join("home"), fs::Permissions::from_mode(0o700)).expect("mode");
    fs::write(root.join("p.toml"), PASS).expect("pass");
    fs::set_permissions(root.join("p.toml"), fs::Permissions::from_mode(0o600)).expect("mode");

    // The default counter, `requests`, is not on this pass: refused, no work.
    let (code, stdout, _) = caller(root, &[TO, "u0"]);
    assert_eq!(code, Some(2));
    assert_eq!(stdout, "");

    let (code, stdout, stderr) = caller(root, &[TO, "u1", "calls"]);
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(stdout, "sent u1\n");
    let (code, stdout, _) = caller(root, &[TO, "u2", "calls"]);
    assert_eq!(code, Some(0));
    assert_eq!(stdout, "sent u2\n");
    let (code, stdout, _) = caller(root, &[TO, "u3", "calls"]);
    assert_eq!(code, Some(2));
    assert_eq!(stdout, "");

    let (code, stdout, stderr) = caller(root, &[TO]);
    assert_eq!(code, Some(1));
    assert_eq!(stdout, "");
    assert!(stderr.contains("COUNTER"), "{stderr}");
}
