//! Exercise the installed CLI contract using only the enclosing case's private files.
use super::*;

const SUBSECOND: &str = "2026-11-20T09:00:00.000000123Z";
const ENDPOINT: &str = "192.0.2.10:443/tcp@app.example.com";
const REFERENCE: &str = "batch-42";

fn approval() -> String {
    format!(
        "{}\n[ceilings]\nrequests=1000\nbytes=1000\n",
        include_str!("../../docs/review-approval.toml")
    )
}

fn checked(args: &[&str], expected: i32) -> Value {
    let (code, reply) = json(args, Some(SUBSECOND));
    assert_eq!(code, expected, "{args:?}: {reply}");
    reply
}

fn debit(file: &str, reference: &str) -> Value {
    checked(
        &[
            "spend",
            file,
            "--charge",
            "requests=1",
            "--charge",
            "bytes=4",
            "--to",
            ENDPOINT,
            "--record-target",
            "--caller-ref",
            reference,
        ],
        0,
    )
}

fn witness(case: &Case) -> PathBuf {
    case.state().join("review-example.witness")
}

fn bytes(path: &Path) -> Vec<u8> {
    fs::read(path).expect("fixture bytes")
}

/// Record a signature over an archived revision, as `verify-approval
/// --archive` does after ssh-keygen accepts it. Without `--allowed-signers`
/// the audits read this record and do not verify the signature again, so
/// these tests need no keys, and an audit whose replay finds nothing wrong is
/// `incomplete` with only a `signature-not-reverified` gap (see [`clean`]).
/// `tests/audit_reverify.rs` verifies real signatures.
fn approve(archive: &Path, archived: &Value) {
    let digest = archived["digest"]
        .as_str()
        .expect("archived digest")
        .parse()
        .expect("digest");
    hallpass::archive_verified_signature(
        archive,
        digest,
        b"signature",
        "owner@example.org",
        hallpass::Digest::of(b"trusted signers"),
    )
    .expect("signature record");
}

/// An audit whose replay found nothing wrong, over revisions that each have a
/// signature record it did not verify again (bn-2ld), of a ledger recorded
/// under the test clock (bn-2mm).
fn clean(audit: &Value) {
    assert_eq!(audit["result"], "incomplete", "{audit}");
    assert_eq!(audit["mismatches"]["count"], 0, "{audit}");
    let gaps = audit["gaps"].as_object().expect("gaps");
    assert_eq!(
        gaps.keys().map(String::as_str).collect::<Vec<_>>(),
        ["signature-not-reverified", "test-clock-entry"],
        "{audit}"
    );
}

fn archive(case: &Case) -> PathBuf {
    let path = case.path("archive");
    fs::create_dir(&path).expect("archive");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private archive");
    path
}

#[test]
fn exact_reference_across_revisions_ambiguous_lost_and_fresh_are_distinct() {
    let case = Case::new();
    let p = case.pass("pass", &approval());
    let file = s(&p);
    let ledger = hallpass::ledger_path(&p);
    let find = ["receipt", file, "--caller-ref", REFERENCE];
    let fresh = checked(&find, 2);
    assert_eq!(fresh["result"], "absent");
    assert_eq!(fresh["witness"], "fresh");
    assert!(!ledger.exists() && !case.state().exists());
    checked(
        &["spend", file, "requests", "--note", "private-legacy-note"],
        0,
    );
    checked(&["spend", file, "--charge", "requests=1"], 0);
    let before = bytes(&ledger);
    let spent = debit(file, REFERENCE);
    fs::write(&p, approval().replace("revoked = false", "revoked = true")).expect("revoke");
    let stable = (bytes(&ledger), bytes(&witness(&case)));
    let found = checked(&find, 0);
    assert_eq!(found["result"], "found");
    assert_eq!(found["witness"], "matches");
    assert_eq!(found["match_count"], 1);
    let row = &found["matches"][0];
    assert_eq!(row["seq"], spent["seq"]);
    assert_eq!(row["digest"], spent["digest"]);
    assert_eq!(row["charges"][1]["counter"], "bytes");
    assert_eq!(row["charges"][1]["n"], 4);
    assert_eq!(row["targets"][0]["name"], "app.example.com");
    assert_eq!(row["time"], SUBSECOND);
    assert!(!found.to_string().contains("private-legacy-note"));
    assert_eq!((bytes(&ledger), bytes(&witness(&case))), stable);
    fs::write(&p, approval()).expect("restore");
    debit(file, REFERENCE);
    let duplicate = checked(&find, 2);
    assert_eq!(duplicate["result"], "ambiguous");
    assert_eq!(duplicate["match_count"], 2);
    assert_eq!(duplicate["matches"][1]["seq"], 4);
    let other = checked(&["receipt", file, "--caller-ref", "Batch-42"], 2);
    assert_eq!(other["result"], "absent");
    let mut invalid = bytes(&ledger);
    invalid.extend(b"bad suffix\n");
    fs::write(&ledger, invalid).expect("corrupt");
    let bad = checked(&find, 1);
    assert_eq!(bad["error"]["code"], "ledger-corrupt");
    assert!(bad.get("matches").is_none());
    fs::remove_file(&ledger).expect("lost ledger");
    assert_eq!(checked(&find, 1)["error"]["code"], "ledger-missing");
    case.pass(
        "pass.ledger",
        std::str::from_utf8(&before).expect("ledger text"),
    );
    checked(&["adopt", file, "--reason", "restored two older debits"], 0);
    let carried = checked(&find, 2);
    assert_eq!(carried["adoption_count"], 1);
    assert!(carried["warnings"].to_string().contains("Carried"));
    let manifest = serde_json::json!({"version":1,"pass_id":"review-example","units":[{"caller_ref":REFERENCE,"digest":spent["digest"],"charges":[{"counter":"requests","n":1}]}]});
    let manifest_path = case.pass("lost-receipt.json", &manifest.to_string());
    let reconciled = checked(&["reconcile", file, s(&manifest_path)], 2);
    assert_eq!(reconciled["rows"][0]["result"], "absent");
    assert_eq!(reconciled["adoption_count"], 1);
    assert!(reconciled["warnings"].to_string().contains("Carried"));
    let a = archive(&case);
    let charge_audit = checked(&["audit-charges", file, s(&a)], 2);
    assert_eq!(charge_audit["gaps"]["adoption-carry"]["sequences"][0], 3);
    let incomplete = checked(&["audit-receipts", file, s(&a)], 2);
    // A scalar spend line and a debit without targets both keep no target.
    for (sequences, reason) in [
        (serde_json::json!([1, 2]), "targets-unrecorded"),
        (serde_json::json!([3]), "adoption-carry"),
    ] {
        assert_eq!(
            incomplete["gaps"][reason]["sequences"], sequences,
            "{incomplete}"
        );
    }
}

#[test]
fn audit_historical_revisions_exact_instant_mismatch_precedence_and_archive_integrity() {
    let case = Case::new();
    let a = archive(&case);
    // A decision at the stored subsecond passes. Truncating it to seconds would refuse.
    let old = approval().replace("08:00:00Z", "09:00:00.0000001Z");
    let p = case.pass("pass", &old);
    let file = s(&p);
    let cmd = ["audit-receipts", file, s(&a)];
    let saved = checked(&["archive", file, s(&a)], 0);
    approve(&a, &saved);
    debit(file, "one");
    let old_witness = bytes(&witness(&case));
    let revised = old.replace("label = \"web\"", "label = \"other\"");
    fs::write(&p, &revised).expect("edit label");
    approve(&a, &checked(&["archive", file, s(&a)], 0));
    checked(
        &[
            "spend",
            file,
            "--charge",
            "requests=1",
            "--to",
            ENDPOINT,
            "--to",
            ENDPOINT,
            "--record-target",
            "--caller-ref",
            "private-reference",
        ],
        0,
    );
    fs::write(&p, revised.replace("revoked = false", "revoked = true")).expect("revoke");
    let ledger = hallpass::ledger_path(&p);
    let stable = (bytes(&ledger), bytes(&witness(&case)));
    let replayed = checked(&cmd, 2);
    clean(&replayed);
    assert_eq!(replayed["witness"], "matches");
    assert_eq!(replayed["corroborated"]["count"], 3);
    let rows = replayed["corroborated"]["details"]
        .as_array()
        .expect("rows");
    assert_eq!(rows[0]["label"], "web");
    assert_eq!(rows[1]["label"], "other");
    assert_eq!(rows[2]["index"], 2);
    assert_ne!(rows[0]["digest"], rows[1]["digest"]);
    assert!(!replayed.to_string().contains("private-reference"));
    assert_eq!((bytes(&ledger), bytes(&witness(&case))), stable);
    let old_path = a.join(saved["digest"].as_str().expect("digest"));
    let original = bytes(&old_path);
    fs::write(&old_path, b"damaged archive").expect("corrupt archive");
    let error = checked(&cmd, 1);
    assert!(
        error["error"]["message"]
            .as_str()
            .expect("message")
            .contains("digest")
    );
    fs::remove_file(&old_path).expect("missing revision");
    let gaps = checked(&cmd, 2);
    assert_eq!(gaps["result"], "incomplete");
    assert_eq!(gaps["gaps"]["archive-missing"]["sequences"][0], 1);
    assert_eq!(gaps["corroborated"]["count"], 2);
    // Only the first debit is independently witnessed. Rewrite the unwitnessed tip
    // without changing the predecessor hash, preserving a valid verified chain.
    fs::write(witness(&case), old_witness).expect("lagging witness");
    let lines = String::from_utf8(stable.0).expect("ledger text");
    let changed = lines.replace("\"label\":\"other\"", "\"label\":\"mistaken\"");
    assert_ne!(changed, lines);
    fs::write(&ledger, &changed).expect("wrong label");
    let mixed = checked(&cmd, 2);
    assert_eq!(mixed["result"], "mismatch");
    assert_eq!(mixed["witness"], "extended");
    assert_eq!(mixed["mismatches"]["count"], 2);
    assert_eq!(mixed["mismatches"]["details"][0]["matched_label"], "other");
    assert_eq!(mixed["gaps"]["archive-missing"]["count"], 1);
    case.pass(s(&old_path), std::str::from_utf8(&original).expect("pass"));
    let refused = changed.replace("192.0.2.10:443/tcp", "192.0.2.11:443/tcp");
    let (prefix, _) = lines.trim_end().rsplit_once('\n').expect("tip");
    let tip = refused.lines().last().expect("mutated tip");
    fs::write(&ledger, format!("{prefix}\n{tip}\n")).expect("wrong literal");
    let mismatch = checked(&cmd, 2);
    assert!(mismatch["mismatches"]["details"][0]["refusal_code"].is_string());
    fs::write(&ledger, format!("{prefix}\n{tip}\nbad suffix\n")).expect("corrupt suffix");
    assert_eq!(checked(&cmd, 1)["error"]["code"], "ledger-corrupt");
}

#[test]
fn backup_candidates_preserve_order_full_tips_branches_and_captured_witness() {
    let case = Case::new();
    let p = case.pass("pass", &approval());
    let file = s(&p);
    let ledger = hallpass::ledger_path(&p);
    let w = witness(&case);
    debit(file, "anchor");
    let anchor_witness = bytes(&w);
    let exact = bytes(&ledger);
    let anchor_text = std::str::from_utf8(&exact).expect("ledger");
    let header = anchor_text.lines().next().expect("header");
    let older = case.pass("older", &format!("{header}\n"));
    let foreign = case.pass(
        "foreign",
        &format!("{}\n", header.replace("review-example", "foreign")),
    );
    let same = case.pass("exact", anchor_text);
    let divergent = case.pass("changed", &anchor_text.replace("anchor", "absent"));
    debit(file, "branchA");
    let extension = fs::read_to_string(&ledger).expect("extension");
    let first = case.pass("extension", &extension);
    let copy = case.pass("copy", &extension);
    let broken = case.pass("broken", &format!("{extension}bad suffix\n"));
    fs::write(&ledger, &exact).expect("restore anchor");
    fs::write(&w, &anchor_witness).expect("restore witness");
    debit(file, "branchB");
    let second = case.pass("other", &fs::read_to_string(&ledger).expect("branch"));
    fs::write(&w, &anchor_witness).expect("captured witness");
    fs::remove_file(&ledger).expect("live ledger lost");
    let base = ["compare-backups", file];
    let choose = |paths: &[&Path], code| {
        let mut args = base.to_vec();
        args.extend(paths.iter().map(|p| s(p)));
        checked(&args, code)
    };
    let partial = choose(
        &[
            &same, &first, &older, &foreign, &broken, &divergent, &copy, &second,
        ],
        1,
    );
    assert_eq!(partial["result"], "partial-error");
    assert_eq!(partial["assessment"], "ambiguous");
    let rows = partial["candidates"].as_array().expect("candidates");
    assert_eq!(
        rows.iter()
            .map(|r| r["relation"].as_str().expect("relation"))
            .collect::<Vec<_>>(),
        [
            "exact", "extended", "shorter", "foreign", "error", "mismatch", "extended", "extended"
        ]
    );
    assert_eq!(partial["anchor"], rows[0]["tip"]);
    assert_eq!(rows[1]["tip_group"], rows[6]["tip_group"]);
    assert_ne!(rows[1]["tip_group"], rows[7]["tip_group"]);
    assert_eq!(rows[3]["tip"]["pass_id"], "foreign");
    assert_eq!(rows[4]["error"]["code"], "ledger-corrupt");
    assert!(rows[4]["tip"].is_null());
    assert_eq!(choose(&[&first, &second], 2)["result"], "ambiguous");
    assert_eq!(choose(&[&copy, &first, &same], 0)["result"], "preserved");
    assert_eq!(choose(&[&older, &foreign], 2)["result"], "no-match");
    assert_eq!(bytes(&w), anchor_witness);
    assert!(!ledger.exists());
    fs::remove_file(&w).expect("unavailable witness");
    let missing = choose(&[&first], 2);
    assert_eq!(missing["result"], "inconclusive");
    assert_eq!(missing["candidates"][0]["relation"], "unanchored");
    assert!(missing["anchor"].is_null() && !w.exists());
    assert_eq!(choose(&[first.as_path(); 33], 1)["error"]["code"], "usage");
}

#[test]
fn count_all_matches_and_endpoints_after_detail_limit() {
    let case = Case::new();
    let a = archive(&case);
    let p = case.pass("pass", &approval());
    let file = s(&p);
    approve(&a, &checked(&["archive", file, s(&a)], 0));
    let limit = hallpass::evidence::DETAIL_LIMIT;
    for _ in 0..=limit {
        debit(file, REFERENCE);
    }
    let found = checked(&["receipt", file, "--caller-ref", REFERENCE], 2);
    assert_eq!(found["match_count"], limit + 1);
    assert_eq!(found["truncated"], true);
    assert_eq!(found["matches"].as_array().expect("matches").len(), limit);
    assert_eq!(found["matches"][limit - 1]["seq"], limit);
    let cmd = ["audit-receipts", file, s(&a)];
    let audit = checked(&cmd, 2);
    clean(&audit);
    assert_eq!(audit["corroborated"]["count"], limit + 1);
    assert_eq!(audit["corroborated"]["truncated"], true);
    assert_eq!(
        audit["corroborated"]["details"]
            .as_array()
            .expect("details")
            .len(),
        limit
    );
    let digest = audit["corroborated"]["details"][0]["digest"]
        .as_str()
        .expect("digest");
    fs::remove_file(a.join(digest)).expect("remove revision");
    let missing = checked(&cmd, 2);
    let gap = &missing["gaps"]["archive-missing"];
    assert_eq!(gap["count"], limit + 1);
    assert_eq!(gap["truncated"], true);
    assert_eq!(gap["sequences"].as_array().expect("sequences").len(), limit);
}

#[test]
fn audit_rejects_wrong_pass_id_and_reports_uncorroborated_history_independently() {
    let case = Case::new();
    let a = archive(&case);
    let p = case.pass("pass", &approval());
    let file = s(&p);
    let cmd = ["audit-receipts", file, s(&a)];
    let revision = checked(&["archive", file, s(&a)], 0);
    approve(&a, &revision);
    debit(file, REFERENCE);
    let w = witness(&case);
    fs::remove_file(&w).expect("unwitnessed history");
    fs::remove_file(w.with_extension("recorded")).expect("and its copy");
    let audit = checked(&cmd, 2);
    clean(&audit);
    assert_eq!(audit["witness"], "missing");
    let other = case.pass(
        "foreign.toml",
        &approval().replace("review-example", "different"),
    );
    let foreign = checked(&["archive", s(&other), s(&a)], 0);
    let ledger = hallpass::ledger_path(&p);
    let original = fs::read_to_string(&ledger).expect("ledger");
    let changed = original.replace(
        revision["digest"].as_str().expect("original digest"),
        foreign["digest"].as_str().expect("foreign digest"),
    );
    fs::write(&ledger, changed).expect("foreign archived pass");
    let error = checked(&cmd, 1);
    assert!(
        error["error"]["message"]
            .as_str()
            .expect("message")
            .contains("belongs to pass")
    );
    fs::write(&ledger, original).expect("original");
    fs::write(&w, "corrupt").expect("unreadable witness");
    fs::set_permissions(&w, fs::Permissions::from_mode(0o600)).expect("private");
    assert_eq!(checked(&cmd, 2)["witness"], "not-checked");
    let found = checked(&["receipt", file, "--caller-ref", REFERENCE], 1);
    assert_eq!(found["error"]["code"], "witness-unavailable");
}

#[test]
fn backup_ancestry_proves_nested_tips_and_keeps_divergent_branches() {
    let case = Case::new();
    let p = case.pass("pass", &approval());
    let file = s(&p);
    let ledger = hallpass::ledger_path(&p);
    debit(file, "anchor1");
    debit(file, "anchor2");
    let anchor = bytes(&ledger);
    let anchor_witness = bytes(&witness(&case));
    let mut paths = Vec::new();
    for n in 3..=8 {
        debit(file, &format!("step{n}"));
        if n % 2 == 0 {
            paths.push(case.pass(
                &format!("tip{n}"),
                &fs::read_to_string(&ledger).expect("ledger"),
            ));
        }
    }
    let copy = case.pass("copy", &fs::read_to_string(&paths[0]).expect("copy"));
    fs::write(&ledger, &anchor).expect("restore");
    fs::write(witness(&case), &anchor_witness).expect("restore witness");
    debit(file, "divergent");
    let other = case.pass("other", &fs::read_to_string(&ledger).expect("other"));
    let broken = case.pass(
        "broken",
        &format!("{}bad\n", fs::read_to_string(&paths[2]).expect("tip")),
    );
    fs::write(witness(&case), &anchor_witness).expect("restore witness");
    let report = checked(
        &[
            "compare-backups",
            file,
            "--ancestry",
            s(&paths[0]),
            s(&paths[1]),
            s(&paths[2]),
            s(&copy),
        ],
        0,
    );
    assert_eq!(report["ancestry"]["maximal_groups"], serde_json::json!([3]));
    assert_eq!(
        report["ancestry"]["prefix_links"],
        serde_json::json!([[1, 2], [1, 3], [2, 3]])
    );
    assert_eq!(report["candidates"][3]["tip_group"], 1);
    let divergent = checked(
        &[
            "compare-backups",
            file,
            "--ancestry",
            s(&paths[2]),
            s(&other),
        ],
        2,
    );
    assert_eq!(divergent["assessment"], "ambiguous");
    assert_eq!(
        divergent["ancestry"]["maximal_groups"],
        serde_json::json!([1, 2])
    );
    let partial = checked(
        &[
            "compare-backups",
            file,
            "--ancestry",
            s(&paths[0]),
            s(&broken),
        ],
        1,
    );
    assert_eq!(partial["result"], "partial-error");
    assert_eq!(
        partial["ancestry"]["maximal_groups"],
        serde_json::json!([1])
    );
}

#[test]
fn charge_audit_uses_each_revision_and_advances_across_missing_archive() {
    let case = Case::new();
    let a = archive(&case);
    let old = approval().replace("requests=1000", "requests=10");
    let p = case.pass("pass", &old);
    let file = s(&p);
    let first = checked(&["archive", file, s(&a)], 0);
    approve(&a, &first);
    assert_eq!(
        checked(&["audit-charges", file, s(&a)], 2)["result"],
        "empty"
    );
    checked(&["spend", file, "requests", "--n", "8"], 0);
    let first_witness = bytes(&witness(&case));
    fs::write(&p, old.replace("requests=10", "requests=5")).expect("lower");
    approve(&a, &checked(&["archive", file, s(&a)], 0));
    fs::write(&p, old.replace("requests=10", "requests=12")).expect("raise");
    approve(&a, &checked(&["archive", file, s(&a)], 0));
    checked(&["spend", file, "--charge", "requests=4"], 0);
    let cmd = ["audit-charges", file, s(&a)];
    let replayed = checked(&cmd, 2);
    clean(&replayed);
    assert_eq!(replayed["checked_debits"], 2);
    fs::remove_file(a.join(first["digest"].as_str().expect("digest"))).expect("missing archive");
    let gap = checked(&cmd, 2);
    assert_eq!(gap["result"], "incomplete");
    assert_eq!(gap["gaps"]["archive-missing"]["sequences"][0], 1);
    let ledger = hallpass::ledger_path(&p);
    let text = fs::read_to_string(&ledger).expect("ledger");
    fs::write(witness(&case), first_witness).expect("lag witness");
    fs::write(&ledger, text.replace("\"n\":4", "\"n\":5")).expect("overcharge");
    let mixed = checked(&cmd, 2);
    assert_eq!(mixed["result"], "mismatch");
    assert_eq!(mixed["mismatches"]["details"][0]["seq"], 2);
    assert_eq!(mixed["mismatches"]["details"][0]["counter"], "requests");
    assert_eq!(mixed["gaps"]["archive-missing"]["count"], 1);
    fs::write(
        &ledger,
        format!("{}bad\n", fs::read_to_string(&ledger).expect("ledger")),
    )
    .expect("corrupt");
    assert_eq!(checked(&cmd, 1)["error"]["code"], "ledger-corrupt");
}

#[test]
fn charge_audit_detects_unknown_and_missing_required_counter() {
    let case = Case::new();
    let a = archive(&case);
    let pass = format!(
        "required_counters_v1 = [\"requests\", \"bytes\"]\n{}",
        approval()
    );
    let p = case.pass("pass", &pass);
    let file = s(&p);
    checked(&["archive", file, s(&a)], 0);
    debit(file, "anchor");
    let old_witness = bytes(&witness(&case));
    debit(file, "tip");
    let ledger = hallpass::ledger_path(&p);
    let text = fs::read_to_string(&ledger).expect("ledger");
    let (prefix, tip) = text.trim_end().rsplit_once('\n').expect("tip");
    let tip = tip.replace("\"counter\":\"bytes\"", "\"counter\":\"other\"");
    fs::write(&ledger, format!("{prefix}\n{tip}\n")).expect("change tip");
    fs::write(witness(&case), old_witness).expect("lag witness");
    let audit = checked(&["audit-charges", file, s(&a)], 2);
    let rows = audit["mismatches"]["details"].as_array().expect("details");
    assert!(rows.iter().any(|r| r["seq"] == 2
        && r["counter"] == "bytes"
        && r["reason"] == "required-counter-missing"));
    assert!(
        rows.iter()
            .any(|r| r["seq"] == 2 && r["counter"] == "other" && r["reason"] == "unknown-counter")
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn reconcile_reports_ordered_discrepancies_and_rejects_bad_input() {
    let case = Case::new();
    let p = case.pass(
        "pass",
        &approval().replace("ports = 443", "ports = [443, 444]"),
    );
    let file = s(&p);
    let exact = debit(file, "exact");
    debit(file, "duplicate");
    debit(file, "duplicate");
    debit(file, "different");
    checked(
        &[
            "spend",
            file,
            "--charge",
            "requests=1",
            "--to",
            ENDPOINT,
            "--to",
            "192.0.2.10:444/tcp@app.example.com",
            "--record-target",
            "--caller-ref",
            "swapped",
        ],
        0,
    );
    checked(
        &[
            "spend",
            file,
            "--charge",
            "requests=1",
            "--caller-ref",
            "unrecorded",
        ],
        0,
    );
    checked(&["spend", file, "--charge", "requests=1"], 0);
    let digest = exact["digest"].as_str().expect("digest");
    let unit = |reference: &str, charges: Value, targets: Option<Value>| {
        let mut v = serde_json::json!({"caller_ref":reference, "digest":digest, "charges":charges});
        if let Some(targets) = targets {
            v["targets"] = targets;
        }
        v
    };
    let charges = serde_json::json!([{"counter":"bytes","n":4},{"counter":"requests","n":1}]);
    let target = serde_json::json!([{"target":"192.0.2.10:443/tcp","name":"app.example.com"}]);
    let manifest = serde_json::json!({"version":1,"pass_id":"review-example","units":[
        unit("exact", charges.clone(), Some(target.clone())),
        unit("missing", charges.clone(), None),
        unit("duplicate", charges, None),
        unit("different", serde_json::json!([{"counter":"requests","n":3}]), None),
        unit("swapped", serde_json::json!([{"counter":"requests","n":1}]), Some(serde_json::json!([{"target":"192.0.2.10:444/tcp","name":"app.example.com"},{"target":"192.0.2.10:443/tcp","name":"app.example.com"}]))),
        unit("unrecorded", serde_json::json!([{"counter":"requests","n":1}]), Some(target)),
    ]});
    let path = case.pass("manifest.json", &manifest.to_string());
    let result = checked(&["reconcile", file, s(&path)], 2);
    assert_eq!(
        result["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .map(|r| r["result"].as_str().expect("result"))
            .collect::<Vec<_>>(),
        [
            "match",
            "absent",
            "ambiguous",
            "mismatch",
            "mismatch",
            "incomplete"
        ]
    );
    assert_eq!(result["rows"][2]["candidate_count"], 2);
    assert_eq!(result["rows"][2]["sequences"], serde_json::json!([2, 3]));
    let mut only = manifest.clone();
    only["units"] = serde_json::json!([manifest["units"][0].clone()]);
    fs::write(&path, only.to_string()).expect("one row");
    assert_eq!(
        checked(&["reconcile", file, s(&path)], 0)["result"],
        "match"
    );
    only["units"] = serde_json::json!([manifest["units"][0].clone(), manifest["units"][0].clone()]);
    fs::write(&path, only.to_string()).expect("duplicate");
    checked(&["reconcile", file, s(&path)], 1);
    fs::write(
        &path,
        vec![b' '; usize::try_from(hallpass::evidence::MAX_MANIFEST_BYTES).expect("limit") + 1],
    )
    .expect("large");
    checked(&["reconcile", file, s(&path)], 1);
    fs::write(&path, manifest.to_string()).expect("manifest");
    let ledger = hallpass::ledger_path(&p);
    fs::write(
        &ledger,
        format!("{}bad\n", fs::read_to_string(&ledger).expect("ledger")),
    )
    .expect("corrupt");
    assert_eq!(
        checked(&["reconcile", file, s(&path)], 1)["error"]["code"],
        "ledger-corrupt"
    );
}

#[test]
fn reconcile_manifest_limits_and_revision_are_enforced() {
    let case = Case::new();
    let p = case.pass("pass", &approval());
    let file = s(&p);
    let record = debit(file, "one");
    let digest = record["digest"].as_str().expect("digest");
    let row = |i| serde_json::json!({"caller_ref":format!("ref-{i}"), "digest":digest, "charges":[{"counter":"requests","n":1}]});
    let mut manifest = serde_json::json!({"version":1,"pass_id":"review-example","units":[{"caller_ref":"one","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","charges":[{"counter":"requests","n":1},{"counter":"bytes","n":4}]}]});
    let path = case.pass("manifest", &manifest.to_string());
    assert_eq!(
        checked(&["reconcile", file, s(&path)], 2)["rows"][0]["result"],
        "mismatch"
    );
    manifest["units"] = serde_json::json!(
        (0..hallpass::evidence::MAX_MANIFEST_ROWS)
            .map(row)
            .collect::<Vec<_>>()
    );
    fs::write(&path, manifest.to_string()).expect("row boundary");
    let report = checked(&["reconcile", file, s(&path)], 2);
    assert_eq!(
        report["rows"].as_array().expect("rows").len(),
        hallpass::evidence::MAX_MANIFEST_ROWS
    );
    manifest["units"]
        .as_array_mut()
        .expect("rows")
        .push(row(hallpass::evidence::MAX_MANIFEST_ROWS));
    fs::write(&path, manifest.to_string()).expect("too many");
    checked(&["reconcile", file, s(&path)], 1);
    manifest["units"] = serde_json::json!([row(0)]);
    let mut bytes = manifest.to_string().into_bytes();
    bytes.resize(
        usize::try_from(hallpass::evidence::MAX_MANIFEST_BYTES).expect("limit"),
        b' ',
    );
    fs::write(&path, &bytes).expect("byte boundary");
    checked(&["reconcile", file, s(&path)], 2);
    bytes.push(b' ');
    fs::write(&path, bytes).expect("too large");
    checked(&["reconcile", file, s(&path)], 1);
}
