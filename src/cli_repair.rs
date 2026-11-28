//! `hallpass repair --drop-torn-tail`: the preview and the guarded repair.

use std::path::Path;

use hallpass::{StateDir, TornTail};
use serde_json::{Value, json};

use super::{OK, Output, error_output, safe};

/// `kinds` is (`--restore-final-newline`, `--drop-blank-tail`).
pub fn repair(file: &Path, kinds: (bool, bool), preview: bool, token: Option<&str>) -> Output {
    let state = StateDir::from_env();
    if kinds.0 {
        return restore_newline(file, &state, preview, token);
    }
    if kinds.1 {
        return drop_blank(file, &state, preview, token);
    }
    let result = match token {
        Some(token) if !preview => hallpass::drop_torn_tail(file, &state, token),
        _ => hallpass::preview_drop_torn_tail(file, &state),
    };
    let torn = match result {
        Ok(torn) => torn,
        Err(e) => return error_output("repair", Some(file), &e),
    };
    let ledger = safe(&torn.ledger.display().to_string()).into_owned();
    let text = torn.copy.as_ref().map_or_else(
        || {
            format!(
                "TORN LINE PREVIEW: the ledger {ledger} ends with {} bytes of {} after sequence {}. The witness recorded sequence {}, so that line was never counted. To remove those bytes and keep a copy of them beside the ledger, run `hallpass repair {} --drop-torn-tail --token TOKEN` with this token. Token: {}\n",
                torn.removed_bytes,
                if torn.nul_only { "NUL bytes" } else { "a line cut short" },
                torn.seq,
                torn.witness_seq,
                safe(&file.display().to_string()),
                torn.token
            )
        },
        |copy| {
            format!(
                "REPAIRED: removed {} bytes of {} after sequence {} from {ledger}. A copy of them is in {}. The ledger now ends at sequence {}; nothing was recorded or permitted.\n",
                torn.removed_bytes,
                if torn.nul_only { "NUL bytes" } else { "a line cut short" },
                torn.seq,
                safe(&copy.display().to_string()),
                torn.seq
            )
        },
    );
    Output {
        code: OK,
        json: reply(file, &torn),
        text,
    }
}

fn reply(file: &Path, torn: &TornTail) -> Value {
    json!({
        "command": "repair",
        "result": if torn.copy.is_some() { "repaired" } else { "preview" },
        "file": file.display().to_string(),
        "ledger": torn.ledger.display().to_string(),
        "pass_id": torn.pass_id,
        "seq": torn.seq,
        "witness_seq": torn.witness_seq,
        "kept_bytes": torn.kept_bytes,
        "removed_bytes": torn.removed_bytes,
        "nul_only": torn.nul_only,
        "token": torn.token,
        "copy": torn.copy.as_ref().map(|c| c.display().to_string()),
    })
}

/// `--restore-final-newline`: the preview and the guarded repair.
fn restore_newline(file: &Path, state: &StateDir, preview: bool, token: Option<&str>) -> Output {
    let result = match token {
        Some(token) if !preview => hallpass::restore_final_newline(file, state, token),
        _ => hallpass::preview_restore_final_newline(file, state),
    };
    let done = match result {
        Ok(done) => done,
        Err(e) => return error_output("repair", Some(file), &e),
    };
    let ledger = safe(&done.ledger.display().to_string()).into_owned();
    let text = if done.restored {
        format!(
            "REPAIRED: added the missing line end after sequence {} of {ledger}. No line was changed or removed; nothing was recorded or permitted.\n",
            done.seq
        )
    } else {
        format!(
            "NEWLINE PREVIEW: the last line of the ledger {ledger} (sequence {}) is whole and is the line the witness recorded, but it has no line end. To add the line end, and nothing else, run `hallpass repair {} --restore-final-newline --token TOKEN` with this token. Token: {}\n",
            done.seq,
            safe(&file.display().to_string()),
            done.token
        )
    };
    Output {
        code: OK,
        json: json!({
            "command": "repair",
            "repair": "restore-final-newline",
            "result": if done.restored { "repaired" } else { "preview" },
            "file": file.display().to_string(),
            "ledger": done.ledger.display().to_string(),
            "pass_id": done.pass_id,
            "seq": done.seq,
            "witness_seq": done.seq,
            "length": done.length,
            "token": done.token,
        }),
        text,
    }
}

/// `--drop-blank-tail`: the preview and the guarded repair.
fn drop_blank(file: &Path, state: &StateDir, preview: bool, token: Option<&str>) -> Output {
    let result = match token {
        Some(token) if !preview => hallpass::drop_blank_tail(file, state, token),
        _ => hallpass::preview_drop_blank_tail(file, state),
    };
    let done = match result {
        Ok(done) => done,
        Err(e) => return error_output("repair", Some(file), &e),
    };
    let ledger = safe(&done.ledger.display().to_string()).into_owned();
    let text = if done.repaired {
        format!(
            "REPAIRED: removed {} bytes of blank lines after sequence {} of {ledger}. No line hallpass wrote was changed; nothing was recorded or permitted.\n",
            done.removed_bytes, done.seq
        )
    } else {
        format!(
            "BLANK TAIL PREVIEW: the ledger {ledger} ends with {} bytes of empty lines or white space after sequence {}, which is the line the witness recorded. To remove those bytes, and nothing else, run `hallpass repair {} --drop-blank-tail --token TOKEN` with this token. Token: {}\n",
            done.removed_bytes,
            done.seq,
            safe(&file.display().to_string()),
            done.token
        )
    };
    Output {
        code: OK,
        json: json!({
            "command": "repair",
            "repair": "drop-blank-tail",
            "result": if done.repaired { "repaired" } else { "preview" },
            "file": file.display().to_string(),
            "ledger": done.ledger.display().to_string(),
            "pass_id": done.pass_id,
            "seq": done.seq,
            "witness_seq": done.seq,
            "kept_bytes": done.kept_bytes,
            "removed_bytes": done.removed_bytes,
            "token": done.token,
        }),
        text,
    }
}
