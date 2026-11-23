#![cfg(feature = "cli")]
//! Runs `docs/WALKTHROUGH.md`: every `sh` block in order, in one shell, from
//! the checkout root. A `text` block that follows an `sh` block with only
//! blank lines between them is that block's expected standard output. Then
//! the ledger, the journal and the outbox are checked: two debits, the
//! narrowed totals and the caller outcome of each unit.
//!
//! The walkthrough pins `HALLPASS_UNSAFE_TEST_CLOCK` itself (debug builds, or
//! `--features test-clock`) and keeps its state in a fresh temporary
//! directory.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const DOC: &str = include_str!("../docs/WALKTHROUGH.md");
const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const MARK: &str = "@@walkthrough-block-";

struct Block {
    tag: String,
    body: String,
    /// Only blank lines separate this block from the one before it.
    adjacent: bool,
}

fn blocks() -> Vec<Block> {
    let mut out = Vec::new();
    let mut open: Option<Block> = None;
    let mut adjacent = false;
    for line in DOC.lines() {
        if let Some(block) = open.as_mut() {
            if line == "```" {
                out.extend(open.take());
                adjacent = true;
            } else {
                block.body.push_str(line);
                block.body.push('\n');
            }
        } else if let Some(tag) = line.strip_prefix("```") {
            open = Some(Block {
                tag: tag.to_owned(),
                body: String::new(),
                adjacent,
            });
        } else if !line.trim().is_empty() {
            adjacent = false;
        }
    }
    assert!(open.is_none(), "an unclosed block");
    out
}

/// The `sh` blocks with the output each one must print, if the page shows it.
fn steps() -> Vec<(String, Option<String>)> {
    let blocks = blocks();
    let mut out = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        if block.tag == "sh" {
            let shown = blocks
                .get(i + 1)
                .filter(|next| next.tag == "text" && next.adjacent)
                .map(|next| next.body.clone());
            out.push((block.body.clone(), shown));
        }
    }
    out
}

fn lines(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .expect("read")
        .lines()
        .map(|line| serde_json::from_str(line).expect("one JSON object per line"))
        .collect()
}

/// Each reference's journal events, with the spend outcome and code.
fn outcomes(journal: &[Value], reference: &str) -> Vec<String> {
    journal
        .iter()
        .filter(|record| record["ref"] == reference)
        .map(|record| {
            let event = record["event"].as_str().expect("event");
            match (record["outcome"].as_str(), record["code"].as_str()) {
                (Some(outcome), Some(code)) => format!("{event} {outcome} {code}"),
                (Some(outcome), None) => format!("{event} {outcome}"),
                _ => event.to_owned(),
            }
        })
        .collect()
}

/// Runs the `sh` blocks in one shell, compares the output each block shows,
/// and returns the temporary directory with the walkthrough's work directory.
fn run_walkthrough() -> (tempfile::TempDir, PathBuf) {
    let steps = steps();
    assert!(steps.len() >= 10, "the walkthrough lost its commands");
    let mut script = String::from("set -eu\n");
    for (i, (body, _)) in steps.iter().enumerate() {
        writeln!(script, "echo '{MARK}{i}'").expect("write to a String");
        script.push_str(body);
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    fs::create_dir(&home).expect("home");
    let bin_dir = Path::new(BIN).parent().expect("binary directory");
    let mut paths = vec![bin_dir.to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let output = Command::new("bash")
        .arg("-c")
        .arg(&script)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("PATH", std::env::join_paths(paths).expect("PATH"))
        .env("HOME", &home)
        .env("TMPDIR", dir.path())
        .env_remove("XDG_STATE_HOME")
        .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
        .env_remove("FORMAT")
        .env_remove("REFERENCE_CALLER_INTERRUPT")
        .output()
        .expect("run bash");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");

    // Split the output at the markers, one part per block.
    let mut printed = vec![String::new(); steps.len()];
    let mut current = None;
    for line in stdout.lines() {
        if let Some(i) = line.strip_prefix(MARK) {
            current = Some(i.parse::<usize>().expect("block number"));
        } else {
            let part = &mut printed[current.expect("output before the first block")];
            part.push_str(line);
            part.push('\n');
        }
    }
    for ((body, shown), printed) in steps.iter().zip(&printed) {
        if let Some(shown) = shown {
            assert_eq!(printed, shown, "the output of:\n{body}");
        }
    }

    // The work directory that the first block made with `mktemp -d`.
    let work: Vec<PathBuf> = fs::read_dir(dir.path())
        .expect("list")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.file_name().is_some_and(|n| n != "home"))
        .collect();
    let [work] = work.as_slice() else {
        panic!("expected one work directory: {work:?}");
    };
    let work = work.clone();
    (dir, work)
}

#[test]
fn the_walkthrough_runs_as_written() {
    let (dir, work) = run_walkthrough();
    let work = work.as_path();
    let home = dir.path().join("home");
    let ledger = Command::new(BIN)
        .args(["--format", "json", "ledger", "engagement.pass.toml"])
        .current_dir(work)
        .env("HOME", &home)
        .env("XDG_STATE_HOME", work.join("state"))
        .output()
        .expect("ledger");
    let ledger: Value = serde_json::from_slice(&ledger.stdout).expect("ledger JSON");
    assert_eq!(ledger["verified"], true, "{ledger}");
    assert_eq!(ledger["witness"], "matches", "{ledger}");
    let debits: Vec<(u64, &str)> = ledger["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| {
            (
                entry["seq"].as_u64().expect("seq"),
                entry["receipt"]["caller_ref"].as_str().expect("reference"),
            )
        })
        .collect();
    assert_eq!(debits, [(1, "shift-1/unit-1"), (2, "shift-1/unit-3")]);
    let totals: Vec<(&str, u64, u64)> = ledger["totals"]
        .as_array()
        .expect("totals")
        .iter()
        .map(|t| {
            (
                t["name"].as_str().expect("name"),
                t["spent"].as_u64().expect("spent"),
                t["total"].as_u64().expect("total"),
            )
        })
        .collect();
    assert_eq!(totals, [("bytes", 48, 60), ("requests", 2, 5)]);

    let journal = lines(&work.join("shift.jsonl"));
    let sent = ["intent", "spend debited", "callback-start", "callback-done"];
    assert_eq!(outcomes(&journal, "shift-1/unit-1"), sent);
    assert_eq!(
        outcomes(&journal, "shift-1/unit-2"),
        ["intent", "spend refused pass-changed"]
    );
    assert_eq!(outcomes(&journal, "shift-1/unit-3"), sent);
    let pins: Vec<&Value> = journal.iter().filter(|r| r["event"] == "pin").collect();
    assert_eq!(pins.len(), 2);
    assert_ne!(pins[0]["digest"], pins[1]["digest"]);
    let intent = |reference: &str| {
        journal
            .iter()
            .find(|r| r["ref"] == reference && r["event"] == "intent")
            .expect("intent")["digest"]
            .clone()
    };
    assert_eq!(intent("shift-1/unit-2"), pins[0]["digest"]);
    assert_eq!(intent("shift-1/unit-3"), pins[1]["digest"]);

    let outbox: Vec<Value> = lines(&work.join("outbox.jsonl"));
    let refs: Vec<&str> = outbox
        .iter()
        .map(|line| line["ref"].as_str().expect("ref"))
        .collect();
    assert_eq!(refs, ["shift-1/unit-1", "shift-1/unit-3"]);
}

#[test]
fn every_code_block_says_what_it_is() {
    for block in blocks() {
        assert!(
            ["sh", "text"].contains(&block.tag.as_str()),
            "an untagged or unknown code block: {:?}",
            block.tag
        );
    }
}
