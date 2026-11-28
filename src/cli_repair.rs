//! `hallpass repair --drop-torn-tail`: the preview and the guarded repair.

use std::path::Path;

use hallpass::{StateDir, TornTail};
use serde_json::{Value, json};

use super::{OK, Output, error_output, safe};

pub fn repair(file: &Path, preview: bool, token: Option<&str>) -> Output {
    let state = StateDir::from_env();
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
                "TORN LINE PREVIEW: the ledger {ledger} ends with {} bytes of a line cut short after sequence {}. The witness recorded sequence {}, so that line was never counted. To remove those bytes and keep a copy of them beside the ledger, run `hallpass repair {} --drop-torn-tail --token TOKEN` with this token. Token: {}\n",
                torn.removed_bytes,
                torn.seq,
                torn.witness_seq,
                safe(&file.display().to_string()),
                torn.token
            )
        },
        |copy| {
            format!(
                "REPAIRED: removed {} bytes of a line cut short after sequence {} from {ledger}. A copy of them is in {}. The ledger now ends at sequence {}; nothing was recorded or permitted.\n",
                torn.removed_bytes,
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
        "token": torn.token,
        "copy": torn.copy.as_ref().map(|c| c.display().to_string()),
    })
}
