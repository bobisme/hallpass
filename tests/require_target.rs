use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use hallpass::{
    Charge, Digest, NamedTarget, Pass, RefusalCode, SpendChargesRequest, SpendRequest, StateDir,
    ledger_path, preview_spend_in, spend_charges_in, spend_in,
    time::{OffsetDateTime, macros::datetime},
};

const METERED: &str = include_str!("../docs/required-counters.toml");
const RULE: &str = "required_counters_v1";
const TERM: &str = "require_target_v1";
const NOW: OffsetDateTime = datetime!(2026-11-20 09:00 UTC);
const WEB: &str = "192.0.2.10:443/tcp@app.example.org";
const OTHER: &str = "192.0.2.12:443/tcp";

fn approval() -> String {
    METERED.replacen(RULE, "require_target_v1 = true\nrequired_counters_v1", 1)
}

fn write_pass(file: &Path, text: &str) {
    fs::write(file, text).expect("write pass");
    fs::set_permissions(file, fs::Permissions::from_mode(0o600)).expect("private pass");
}

#[test]
fn target_term_is_strict_and_optional() {
    assert!(!Pass::parse(METERED).expect("legacy").require_target);
    assert!(
        Pass::parse(&approval())
            .expect("require target")
            .require_target
    );
    for malformed in ["false", "1", "\"true\"", "[]", "{flag = true}"] {
        let source =
            approval().replace("require_target_v1 = true", &format!("{TERM} = {malformed}"));
        assert!(
            Pass::parse(&source)
                .expect_err("malformed term")
                .iter()
                .any(|p| p.field == TERM)
        );
    }
}

#[test]
fn rust_debit_shapes_share_target_policy_and_keep_targets_private() {
    let dir = tempfile::tempdir().expect("directory");
    let file = dir.path().join("pass");
    let state = StateDir::new(dir.path().join("state"));
    let mut scalar = SpendRequest::new("requests", 1);
    write_pass(
        &file,
        &METERED.replace("required_counters_v1 = [\"requests\", \"bytes\"]", ""),
    );
    assert_eq!(
        spend_in(&file, &scalar, NOW, &state).expect("legacy").seq,
        Some(1)
    );
    write_pass(&file, &approval());
    let ledger = ledger_path(&file);
    let before = fs::read(&ledger).expect("ledger");
    for out in [
        preview_spend_in(&file, &scalar, NOW, &state),
        spend_in(&file, &scalar, NOW, &state),
    ] {
        let out = out.expect("decision");
        assert_eq!(
            out.refusal.expect("target required").code,
            RefusalCode::TargetRequired
        );
        assert_eq!(out.spent, 1);
        assert_eq!(out.seq, None);
    }
    scalar.expect_digest = Some(Digest::of(b"other revision"));
    let expired = datetime!(2026-11-20 17:00 UTC);
    let refusal = |scalar: &SpendRequest<'_>| {
        spend_in(&file, scalar, expired, &state)
            .expect("decision")
            .refusal
            .expect("refused")
            .code
    };
    assert_eq!(refusal(&scalar), RefusalCode::PassChanged);
    scalar.expect_digest = None;
    assert_eq!(refusal(&scalar), RefusalCode::Expired);

    let charges = [
        Charge {
            counter: "requests",
            amount: 1,
        },
        Charge {
            counter: "bytes",
            amount: 24,
        },
    ];
    let mut request = SpendChargesRequest::new(&charges);
    for dry_run in [true, false] {
        request.dry_run = dry_run;
        let out = spend_charges_in(&file, &request, NOW, &state).expect("decision");
        assert_eq!(
            out.refusal.expect("target required").code,
            RefusalCode::TargetRequired
        );
        assert_eq!(out.seq, None);
        assert_eq!(out.charges[0].spent, 1);
        assert_eq!(out.charges[1].spent, 0);
    }
    let target: NamedTarget = WEB.parse().expect("target");
    request.policy.target = Some(target.target);
    request.policy.name = target.name.as_ref();
    let additional = [OTHER.parse().expect("target")];
    request.policy.additional_targets = &additional;
    let denied = spend_charges_in(&file, &request, NOW, &state).expect("decision");
    assert_eq!(
        denied.refusal.expect("outside scope").code,
        RefusalCode::AddressNotListed
    );
    assert_eq!(denied.refused_target, Some(2));
    assert_eq!(fs::read(&ledger).expect("ledger"), before);

    request.policy.additional_targets = &[];
    let accepted = spend_charges_in(&file, &request, NOW, &state).expect("decision");
    assert_eq!(accepted.seq, Some(2));
    assert_eq!(accepted.labels, ["web"]);
    assert_eq!(accepted.receipt, None);
    assert!(
        !fs::read_to_string(&ledger)
            .expect("ledger")
            .contains("192.0.2.10")
    );
}

#[cfg(feature = "cli")]
#[test]
fn cli_refuses_targetless_units_and_rehearsal_stops_at_the_first_missing_target() {
    use serde_json::Value;
    let dir = tempfile::tempdir().expect("directory");
    let file = dir.path().join("pass");
    let old = dir.path().join("old");
    let scenario = dir.path().join("scenario");
    write_pass(&file, &approval());
    write_pass(&old, METERED);
    fs::write(&scenario, include_str!("../docs/rehearse.toml")).expect("scenario");
    let cli = |args: &[&str], code| -> Value {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .args(["--format", "json"])
            .args(args)
            .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z")
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .output()
            .expect("hallpass");
        assert_eq!(
            out.status.code(),
            Some(code),
            "{:?}: {}",
            args,
            String::from_utf8_lossy(&out.stdout)
        );
        serde_json::from_slice(&out.stdout).expect("JSON")
    };
    let path = file.to_str().expect("path");
    let charges = ["--charge", "requests=1", "--charge", "bytes=24"];
    for dry_run in [false, true] {
        for cost in [charges.as_slice(), &["requests"]] {
            let mut args = vec!["spend", path];
            args.extend(cost);
            if dry_run {
                args.push("--dry-run");
            }
            let reply = cli(&args, 2);
            assert_eq!(reply["result"], "refused");
            assert_eq!(reply["refusal"]["code"], "target-required");
            assert!(reply["seq"].is_null());
        }
    }

    let mut args = vec!["spend", path, "--to", WEB, "--to", OTHER];
    args.extend(charges);
    let reply = cli(&args, 2);
    assert_eq!(reply["refused_target"], 2);
    assert_eq!(reply["refusal"]["code"], "address-not-listed");
    let reply = cli(&["rehearse", path, scenario.to_str().expect("path")], 2);
    assert_eq!(reply["stopped_at"], "second");
    assert_eq!(reply["steps"][0]["status"], "would-allow");
    assert_eq!(reply["steps"][1]["refusal"]["code"], "target-required");
    assert_eq!(reply["steps"][2]["status"], "unevaluated");

    assert_eq!(cli(&["check", path], 0)["require_target"], true);
    let status = cli(&["status", path], 0);
    assert_eq!(status["require_target"], true);
    assert!(
        status["counters"]
            .as_array()
            .expect("counters")
            .iter()
            .all(|c| c["spent"] == 0)
    );
    let diff = cli(&["diff", old.to_str().expect("path"), path], 0);
    assert!(
        diff["changes"]
            .as_array()
            .expect("changes")
            .iter()
            .any(|c| { c["field"] == TERM && c["review_required"] == true })
    );
    let mut coverage = vec![
        "consumer-coverage",
        path,
        "--can",
        "endpoints",
        "--can",
        "names",
        "--can",
        "live-window",
        "--can",
        "charge:requests",
        "--can",
        "charge:bytes",
    ];
    let reply = cli(&coverage, 2);
    assert_eq!(
        reply["findings"],
        serde_json::json!([{"code":"missing-target-on-every-debit"}])
    );
    coverage.extend(["--can", "target-on-every-debit"]);
    let reply = cli(&coverage, 0);
    assert_eq!(reply["require_target"], true);
    assert_eq!(reply["declared"]["target_on_every_debit"], true);

    let mut args = vec!["spend", path, "--to", WEB];
    args.extend(charges);
    let reply = cli(&args, 0);
    assert_eq!(reply["seq"], 1);
    assert!(reply["receipt"].is_null());
}
