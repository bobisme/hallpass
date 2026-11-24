//! Warnings, refusals and verify-approval lines show each value escaped once,
//! as `display_quoted` writes it (bn-tdc).
//!
//! Each test uses a value with a backslash and a double quote, and where the
//! input allows it a bidi or format character. An independent unquote must
//! give the value back. Tests that sign need OpenSSH `ssh-keygen` and return
//! early without it.
#![cfg(feature = "cli")]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

const NOW: &str = "2026-11-20T09:00:00Z";
const WEB: &str = "192.0.2.10:443/tcp@app.example.com";
/// A backslash, a quote and a right-to-left override.
const WEIRD: &str = "ops\\lead\"\u{202e}x";
/// What ssh-keygen accepts as a principal in a signers file: a backslash and
/// a zero-width space, but no quote.
const TRUSTED: &str = "ops\\lead\u{200b}x";

fn pass() -> String {
    format!(
        "{}[ceilings]\nrequests = 100\n",
        include_str!("../docs/review-approval.toml")
    )
}

fn have_ssh_keygen() -> bool {
    Command::new("ssh-keygen")
        .arg("-?")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Undo `display_quoted` without using it: the text between the quotes with
/// `\"`, `\\` and `\u{...}` decoded; `None` for anything else.
fn unquote(shown: &str) -> Option<String> {
    let inner = shown.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return None,
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'u' => {
                    let rest = chars.as_str().strip_prefix('{')?;
                    let end = rest.find('}')?;
                    out.push(char::from_u32(u32::from_str_radix(&rest[..end], 16).ok()?)?);
                    chars = rest[end + 1..].chars();
                }
                _ => return None,
            },
            c => out.push(c),
        }
    }
    Some(out)
}

/// The quoted value that starts `line` after `prefix`: its text up to the
/// first unescaped closing quote.
fn quoted_after<'a>(line: &'a str, prefix: &str) -> &'a str {
    let rest = line
        .split_once(prefix)
        .unwrap_or_else(|| panic!("`{prefix}` not in {line}"))
        .1;
    assert!(rest.starts_with('"'), "{rest}");
    let mut escaped = false;
    for (i, c) in rest.char_indices().skip(1) {
        match c {
            '\\' if !escaped => escaped = true,
            '"' if !escaped => return &rest[..=i],
            _ => escaped = false,
        }
    }
    panic!("no closing quote in {rest}");
}

/// Check that `shown` holds `value` once, quoted, and nothing doubled.
fn assert_quoted_once(output: &str, prefix: &str, value: &str) {
    let line = output
        .lines()
        .find(|l| l.contains(prefix))
        .unwrap_or_else(|| panic!("no `{prefix}` line in {output}"));
    let shown = quoted_after(line, prefix);
    assert_eq!(unquote(shown).as_deref(), Some(value), "{line}");
    assert_eq!(line.matches(shown).count(), 1, "{line}");
    assert!(
        !line.chars().any(|c| c.is_control() || c == '\u{202e}'),
        "{line}"
    );
}

struct Env {
    dir: tempfile::TempDir,
    state: Option<PathBuf>,
}

struct Ran {
    code: i32,
    out: String,
    err: String,
}

impl Env {
    fn new() -> Self {
        let env = Self {
            dir: tempfile::tempdir().expect("tempdir"),
            state: None,
        };
        let archive = env.path("arch");
        fs::create_dir(&archive).expect("archive");
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("private");
        env
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write a private file, dated back so that hallpass reads it at once.
    fn write(&self, name: &str, text: &str) {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
        let earlier = SystemTime::now() - Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(earlier))
            .expect("date the file back");
    }

    fn run(&self, args: &[&str]) -> Ran {
        let state = self.state.clone().unwrap_or_else(|| self.path("state"));
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", state)
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .args(["--format", "text"])
            .args(args)
            .output()
            .expect("run hallpass");
        Ran {
            code: out.status.code().expect("exit code"),
            out: String::from_utf8(out.stdout).expect("utf8"),
            err: String::from_utf8(out.stderr).expect("utf8"),
        }
    }

    fn keygen(&self, args: &[&str]) {
        let out = Command::new("ssh-keygen")
            .args(args)
            .current_dir(self.dir.path())
            .output()
            .expect("ssh-keygen");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A signed pass, and a trusted signers file naming each principal.
    fn signed(&self, principals: &[&str]) {
        self.write("p.toml", &pass());
        self.keygen(&["-q", "-t", "ed25519", "-N", "", "-f", "key"]);
        let public = fs::read_to_string(self.path("key.pub")).expect("public key");
        let mut trust = String::new();
        for principal in principals {
            let _ = write!(trust, "{principal} {public}");
        }
        self.write("signers", &trust);
        self.keygen(&[
            "-q",
            "-Y",
            "sign",
            "-f",
            "key",
            "-n",
            "hallpass-approval-v1",
            "p.toml",
        ]);
    }

    fn verify(&self, principal: &str, archive: bool) -> Ran {
        let mut args = vec![
            "verify-approval",
            "p.toml",
            "--signature",
            "p.toml.sig",
            "--allowed-signers",
            "signers",
            "--principal",
            principal,
        ];
        if archive {
            args.extend(["--archive", "arch"]);
        }
        self.run(&args)
    }
}

#[test]
fn verified_line_quotes_the_principal_once() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    env.signed(&[TRUSTED]);
    let ran = env.verify(TRUSTED, false);
    assert_eq!(ran.code, 0, "{}{}", ran.out, ran.err);
    assert_quoted_once(&ran.out, "Verified signature from ", TRUSTED);
}

#[test]
fn unverified_line_quotes_the_principal_once() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    env.signed(&["owner@example.org"]);
    let ran = env.verify(WEIRD, false);
    assert_eq!(ran.code, 2, "{}{}", ran.out, ran.err);
    assert_quoted_once(&ran.out, "Unverified signature for ", WEIRD);
}

#[test]
fn kept_record_warning_quotes_the_principal_once() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    env.signed(&[TRUSTED, "other"]);
    let first = env.verify(TRUSTED, true);
    assert_eq!(first.code, 0, "{}{}", first.out, first.err);
    let second = env.verify("other", true);
    assert_eq!(second.code, 0, "{}{}", second.out, second.err);
    // The warning is printed once, on standard error.
    assert_eq!(
        second.err.matches("different signature record").count(),
        1,
        "{}",
        second.err
    );
    assert_quoted_once(&second.err, "(principal ", TRUSTED);
    // The archive's own line quotes the kept principal too.
    let archive = env.run(&["archive", "p.toml", "arch"]);
    assert_quoted_once(&archive.out, "signature record for principal ", TRUSTED);
}

/// A pass revoked with a reason that has a backslash and quotes.
fn revoked(env: &Env) {
    let text = pass().replace(
        "revoked = false",
        "revoked = true\nrevoked_reason = 'ops\\lead \"x\"'",
    );
    env.write("p.toml", &text);
}

const REASON: &str = "ops\\lead \"x\"";

#[test]
fn refused_lines_quote_the_revoked_reason_once() {
    let env = Env::new();
    revoked(&env);
    let reason_of = |text: &str| {
        let line = text
            .lines()
            .find(|l| l.starts_with("REFUSED:") || l.contains("NOTHING"))
            .unwrap_or_else(|| panic!("no refusal in {text}"))
            .to_owned();
        assert_quoted_once(&line, "revoked this pass (", REASON);
    };
    // spend, and spend --dry-run
    let spend = env.run(&["spend", "p.toml", "--charge", "requests=1", "--to", WEB]);
    assert_eq!(spend.code, 2, "{}{}", spend.out, spend.err);
    reason_of(&spend.out);
    let dry = env.run(&[
        "spend",
        "p.toml",
        "--charge",
        "requests=1",
        "--to",
        WEB,
        "--dry-run",
    ]);
    reason_of(&dry.out);
    // permits
    let permits = env.run(&["permits", "p.toml", "--to", WEB]);
    assert_eq!(permits.code, 2, "{}{}", permits.out, permits.err);
    reason_of(&permits.out);
    // a debit unit (capacity)
    let capacity = env.run(&["capacity", "p.toml", "--charge", "requests=1", "--to", WEB]);
    assert_eq!(capacity.code, 2, "{}{}", capacity.out, capacity.err);
    reason_of(&capacity.out);
    // status
    let status = env.run(&["status", "p.toml"]);
    reason_of(&status.out);
}

#[test]
fn evidence_warning_quotes_the_path_once_and_escapes_controls() {
    // A state directory with a backslash, a quote, a bidi override and an
    // escape character in its name.
    let name = "st\\\"\u{202e}\u{1b}x";
    let mut env = Env::new();
    env.state = Some(env.path(name));
    env.write("p.toml", &pass());
    let spend = env.run(&[
        "spend",
        "p.toml",
        "--charge",
        "requests=1",
        "--to",
        WEB,
        "--record-target",
    ]);
    assert_eq!(spend.code, 0, "{}{}", spend.out, spend.err);
    let witness = env.path(name).join("hallpass/review-example.witness");
    fs::set_permissions(&witness, fs::Permissions::from_mode(0o644)).expect("loosen");
    fs::copy(env.path("p.toml.ledger"), env.path("b.ledger")).expect("backup");
    let ran = env.run(&["compare-backups", "p.toml", "b.ledger"]);
    let warning = ran
        .out
        .lines()
        .find(|l| l.starts_with("Warning: "))
        .unwrap_or_else(|| panic!("no warning in {}{}", ran.out, ran.err));
    let shown = quoted_after(warning, "cannot be used: ");
    let full = env.path(name).join("hallpass/review-example.witness");
    assert_eq!(unquote(shown).as_deref(), full.to_str(), "{warning}");
    assert!(
        warning.contains("\\u{001b}") && warning.contains("\\u{202e}"),
        "{warning}"
    );
    // The state directory is quoted too, once.
    let dir = quoted_after(warning, "state directory (");
    assert_eq!(
        unquote(dir).as_deref(),
        env.path(name).join("hallpass").to_str(),
        "{warning}"
    );
    // No control character reaches the terminal, and the same warning is
    // not printed a second time on standard error.
    assert!(!ran.out.contains('\u{1b}') && !ran.err.contains('\u{1b}'));
    assert_eq!(ran.err.matches("cannot be used").count(), 0, "{}", ran.err);
}
