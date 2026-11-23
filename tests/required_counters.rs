use hallpass::{
    Charge, Digest, Pass, RefusalCode, SpendChargesRequest, SpendRequest, StateDir, load,
    preview_spend_in, read_ledger, spend_charges_in, spend_in,
    time::{OffsetDateTime, macros::datetime},
};
use std::{fs, os::unix::fs::PermissionsExt};

const METERED: &str = include_str!("../docs/required-counters.toml");
const RULE: &str = "required_counters_v1 = [\"requests\", \"bytes\"]";
const NOW: OffsetDateTime = datetime!(2026-11-20 09:00 UTC);

#[test]
fn required_counters_are_bounded_declared_and_unique() {
    let pass = Pass::parse(METERED).expect("extended pass");
    assert_eq!(pass.required_counters, ["bytes", "requests"]);
    for invalid in [
        "[]".to_owned(),
        "[\"bytes\", \"bytes\"]".into(),
        "[\"other\"]".into(),
        "[8]".into(),
        "1".into(),
        format!(
            "[{}]",
            vec!["\"bytes\""; hallpass::MAX_COUNTERS + 1].join(",")
        ),
    ] {
        assert!(
            Pass::parse(&METERED.replace(RULE, &format!("required_counters_v1 = {invalid}")))
                .expect_err("invalid list")
                .iter()
                .any(|p| p.field.starts_with("required_counters_v1"))
        );
    }
}

#[test]
fn every_debit_shape_obeys_the_current_rule_after_scope_and_before_accounting() {
    let dir = tempfile::tempdir().expect("temp");
    let file = dir.path().join("pass.toml");
    let state = StateDir::new(dir.path().join("state"));
    fs::write(&file, METERED.replace(RULE, "")).expect("legacy");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("mode");
    let mut scalar = SpendRequest::new("requests", 1);
    assert_eq!(
        spend_in(&file, &scalar, NOW, &state)
            .expect("legacy spend")
            .seq,
        Some(1)
    );
    fs::write(&file, METERED).expect("revision");
    let loaded = load(&file).expect("pass");
    let before = fs::read(hallpass::ledger_path(&file)).expect("ledger");
    for out in [
        preview_spend_in(&file, &scalar, NOW, &state),
        spend_in(&file, &scalar, NOW, &state),
    ] {
        let r = out.expect("decision").refusal.expect("missing cost");
        assert_eq!(r.code, RefusalCode::RequiredCounterMissing);
        assert!(r.message.contains("bytes"));
    }
    let costs = [Charge {
        counter: "requests",
        amount: 1,
    }];
    let mut multi = SpendChargesRequest::new(&costs);
    for dry_run in [true, false] {
        multi.dry_run = dry_run;
        let refusal = spend_charges_in(&file, &multi, NOW, &state)
            .expect("decision")
            .refusal
            .expect("missing cost");
        assert_eq!(refusal.code, RefusalCode::RequiredCounterMissing);
    }
    scalar.target = Some("192.0.2.12:443/tcp".parse().expect("literal"));
    scalar.expect_digest = Some(Digest::of(b"other"));
    assert_eq!(
        spend_in(&file, &scalar, NOW, &state)
            .expect("digest")
            .refusal
            .expect("refusal")
            .code,
        RefusalCode::PassChanged
    );
    scalar.expect_digest = None;
    assert_eq!(
        spend_in(&file, &scalar, datetime!(2026-11-20 17:00 UTC), &state)
            .expect("window")
            .refusal
            .expect("refusal")
            .code,
        RefusalCode::Expired
    );
    assert_eq!(
        spend_in(&file, &scalar, NOW, &state)
            .expect("scope")
            .refusal
            .expect("refusal")
            .code,
        RefusalCode::AddressNotListed
    );
    assert_eq!(
        fs::read(hallpass::ledger_path(&file)).expect("ledger"),
        before
    );
    let charges = [
        Charge {
            counter: "requests",
            amount: 1,
        },
        Charge {
            counter: "bytes",
            amount: 100,
        },
    ];
    let mut req = SpendChargesRequest::new(&charges);
    req.dry_run = true;
    assert!(
        spend_charges_in(&file, &req, NOW, &state)
            .expect("preview")
            .refusal
            .is_none()
    );
    req.dry_run = false;
    assert_eq!(
        spend_charges_in(&file, &req, NOW, &state)
            .expect("debit")
            .seq,
        Some(2)
    );
    let view = read_ledger(&loaded, &state).expect("view");
    assert_eq!(view.tally.spent("requests"), 2);
    assert_eq!(view.tally.spent("bytes"), 100);
}

#[cfg(feature = "cli")]
#[test]
fn cli_reports_missing_costs_and_reviews_the_rule() {
    let dir = tempfile::tempdir().expect("temp");
    let file = dir.path().join("pass.toml");
    fs::write(&file, METERED).expect("fixture");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("mode");
    let cli = |args: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .args(args)
            .env("HALLPASS_FORMAT", "json")
            .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z")
            .env("XDG_STATE_HOME", dir.path().join("cli-state"))
            .output()
            .expect("cli");
        (
            out.status.code().expect("exit"),
            serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("JSON"),
        )
    };
    let path = file.to_str().expect("utf8 path");
    for args in [
        vec!["spend", path, "requests", "--dry-run"],
        vec!["spend", path, "--charge", "requests=1"],
    ] {
        let (code, response) = cli(&args);
        assert_eq!(code, 2);
        assert_eq!(response["refusal"]["code"], "required-counter-missing");
    }
    let old = dir.path().join("old.toml");
    fs::write(&old, METERED.replace(RULE, "")).expect("legacy");
    fs::set_permissions(&old, fs::Permissions::from_mode(0o600)).expect("mode");
    assert_eq!(
        cli(&["status", path]).1["required_counters"],
        serde_json::json!(["bytes", "requests"])
    );
    assert!(
        cli(&["diff", old.to_str().expect("path"), path]).1["changes"]
            .as_array()
            .expect("changes")
            .iter()
            .any(|c| c["field"] == "required_counters_v1" && c["review_required"] == true)
    );
}

#[test]
fn pure_permits_keeps_its_scope_and_window_semantics() {
    let named = "192.0.2.10:443/tcp@app.example.org"
        .parse::<hallpass::NamedTarget>()
        .expect("target");
    assert!(matches!(
        Pass::parse(METERED).expect("pass").permits_named(
            &named.target,
            named.name.as_ref(),
            NOW,
            hallpass::time::Duration::ZERO
        ),
        hallpass::Decision::Allowed { .. }
    ));
}
