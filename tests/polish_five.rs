//! Messages and tooling from the fifth evaluation: the over-ceiling wording,
//! advice for a ledger that is not a regular file, each warning printed once,
//! the conformance script's summary line, no bytecode in the docs tree, and
//! the fix for an empty name after `@`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");

const PASS: &str = r#"format = 1
id = "five-1"
name = "five"

[approval]
owner = "O"
reference = "R"
operator = "P"
valid_from = 2026-11-21T00:00:00Z
valid_until = 2026-11-22T00:01:00Z
revoked = false

[[destination]]
label = "a"
address = "192.0.2.10"
protocol = "tcp"
ports = 443

[ceilings]
req = 5
"#;

const NOW: &str = "2026-11-22T00:00:00Z";

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

    fn pass(&self) -> PathBuf {
        self.pass_with(PASS)
    }

    fn pass_with(&self, text: &str) -> PathBuf {
        let path = self.path("pass.toml");
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(&path)
            .expect("open")
            .set_modified(old)
            .expect("date back");
        path
    }

    fn run(&self, args: &[&str]) -> Output {
        let home = self.path("home");
        fs::create_dir_all(&home).expect("home");
        Command::new(BIN)
            .env_remove("FORMAT")
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .args(args)
            .output()
            .expect("run hallpass")
    }
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn s(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

#[test]
fn audit_commands_print_the_no_witness_warning_once() {
    let case = Case::new();
    let pass = case.pass();
    let archive = case.path("archive");
    fs::create_dir(&archive).expect("mkdir");
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("chmod");
    let out = case.run(&["archive", s(&pass), s(&archive)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = case.run(&["spend", s(&pass), "req"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    fs::remove_dir_all(case.path("home/state")).expect("drop the witness");
    for command in ["audit-charges", "audit-receipts"] {
        let out = case.run(&[command, s(&pass), s(&archive)]);
        let all = text(&out);
        let warnings: Vec<&str> = all.lines().filter(|l| l.starts_with("Warning:")).collect();
        eprintln!("{command}: {all}");
        let mut unique = warnings.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(warnings.len(), unique.len(), "{command}: {all}");
        assert_eq!(
            all.matches("no witness").count() + all.matches("no local witness").count(),
            1,
            "{command}: {all}"
        );
    }
}

#[test]
fn over_ceiling_status_states_what_is_known_and_offers_a_lowered_ceiling_as_one_cause() {
    let case = Case::new();
    let pass = case.pass();
    for _ in 0..2 {
        let out = case.run(&["spend", s(&pass), "req"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    }
    case.pass_with(&PASS.replace("req = 5", "req = 1"));
    let out = case.run(&["status", s(&pass)]);
    let all = text(&out);
    assert!(all.contains("OVER by 1"), "{all}");
    assert!(
        all.contains("more is spent than the ceiling allows"),
        "{all}"
    );
    assert!(
        !all.contains("the ceiling was lowered below what is spent"),
        "{all}"
    );
    assert!(
        all.contains("for example because the ceiling was lowered"),
        "{all}"
    );
}

#[test]
fn a_ledger_that_is_a_directory_gets_advice_that_fits_a_ledger() {
    let case = Case::new();
    let pass = case.pass();
    fs::create_dir(case.path("pass.toml.ledger")).expect("ledger directory");
    let out = case.run(&["ledger", s(&pass)]);
    let all = text(&out);
    assert_eq!(out.status.code(), Some(1), "{all}");
    assert!(all.contains("is not a regular file"), "{all}");
    assert!(
        all.contains("For a ledger, check the path and restore"),
        "{all}"
    );
}

#[test]
fn conformance_check_prints_one_summary_line_and_leaves_no_bytecode() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/conformance/check.py");
    let out = Command::new("python3")
        .arg("-B")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(&script)
        .output()
        .expect("run check.py");
    assert!(out.status.success(), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.trim_end();
    assert_eq!(line.lines().count(), 1, "{stdout}");
    assert!(line.ends_with(" cases passed"), "{stdout}");
    assert!(
        line.split(' ')
            .next()
            .is_some_and(|n| n.parse::<u32>().is_ok_and(|n| n > 0))
    );
}

#[test]
fn the_minimal_caller_leaves_no_bytecode_in_the_docs_tree() {
    let case = Case::new();
    // Run copies laid out as in docs/, so the check does not depend on what
    // earlier runs left in the checkout.
    let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");
    let tree = case.path("docs");
    fs::create_dir_all(tree.join("minimal-caller")).expect("caller dir");
    fs::create_dir_all(tree.join("conformance")).expect("conformance dir");
    let script = tree.join("minimal-caller/minimal_caller.py");
    fs::copy(docs.join("minimal-caller/minimal_caller.py"), &script).expect("copy caller");
    fs::copy(
        docs.join("conformance/check.py"),
        tree.join("conformance/check.py"),
    )
    .expect("copy decoder");
    // Run it with bytecode writing otherwise allowed; the script itself must
    // switch it off before it imports the decoder.
    let source = fs::read_to_string(&script).expect("read script");
    let off = source
        .find("sys.dont_write_bytecode = True")
        .expect("switch");
    let import = source.find("from check import").expect("import");
    assert!(off < import, "bytecode is switched off before the import");
    let pass = case.pass();
    let out = Command::new("python3")
        .arg(&script)
        .args(["--rehearsal", s(&pass), "192.0.2.10:443/tcp", "u1"])
        .env_remove("PYTHONDONTWRITEBYTECODE")
        .env(
            "PATH",
            format!(
                "{}:/usr/bin:/bin",
                Path::new(BIN).parent().expect("dir").display()
            ),
        )
        .env("HOME", case.path("home"))
        .env("XDG_STATE_HOME", case.path("home/state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
        .output()
        .expect("run caller");
    eprintln!("{}", text(&out));
    assert!(
        tree.join("conformance/check.py").exists()
            && !tree.join("conformance/__pycache__").exists(),
        "the caller wrote bytecode beside the decoder"
    );
}

#[test]
fn an_empty_name_after_at_says_how_to_fix_it() {
    let case = Case::new();
    let pass = case.pass();
    let out = case.run(&["spend", s(&pass), "req", "--to", "192.0.2.10:443/tcp@"]);
    let all = text(&out);
    assert!(all.contains("the name after `@` is empty"), "{all}");
    assert!(all.contains("drop the `@`"), "{all}");
    assert!(all.contains("192.0.2.10:443/tcp@app.example.com"), "{all}");
}

/// The missing-ledger refusal tells an account whose ledger moved away not to
/// adopt or spend, so the moved ledger stays the only count.
#[test]
fn a_missing_ledger_says_not_to_adopt_one_that_moved() {
    let case = Case::new();
    let pass = case.pass();
    let spent = case.run(&["spend", s(&pass), "req", "--to", "192.0.2.10:443/tcp"]);
    assert_eq!(spent.status.code(), Some(0), "{}", text(&spent));
    fs::rename(case.path("pass.toml.ledger"), case.path("moved.ledger")).expect("move");
    let refused = case.run(&["status", s(&pass)]);
    assert_eq!(refused.status.code(), Some(1));
    let message = text(&refused);
    assert!(
        message.contains("moved to another account on purpose, do not adopt or spend here"),
        "{message}"
    );
}
