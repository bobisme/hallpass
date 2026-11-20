use hallpass::{
    Charge, Error, RefusalCode, SpendChargesRequest, StateDir, adopt, ledger_path,
    scenario::{MAX_SCENARIO_BYTES, MAX_STEPS, rehearse},
    spend_charges_in,
    time::{OffsetDateTime, macros::datetime},
};
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

const PASS: &str = include_str!("../docs/required-counters.toml");
const SCENARIO: &str = include_str!("../docs/rehearse.toml");
const NOW: OffsetDateTime = datetime!(2026-11-20 09:00 UTC);
const TARGET: &str = "192.0.2.10:443/tcp@app.example.org";

struct Fixture {
    _temp: tempfile::TempDir,
    pass: PathBuf,
    scenario: PathBuf,
    state: StateDir,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("temp");
    let pass = temp.path().join("pass.toml");
    let scenario = temp.path().join("plan.toml");
    let state = StateDir::new(temp.path().join("state"));
    fs::write(&pass, PASS).expect("pass");
    fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("mode");
    fs::write(&scenario, SCENARIO).expect("plan");
    Fixture {
        _temp: temp,
        pass,
        scenario,
        state,
    }
}

fn commit(
    file: &Path,
    state: &StateDir,
    bytes: u64,
    at: OffsetDateTime,
    target: bool,
) -> hallpass::SpendChargesOutcome {
    let costs = [
        Charge {
            counter: "requests",
            amount: 1,
        },
        Charge {
            counter: "bytes",
            amount: bytes,
        },
    ];
    let mut request = SpendChargesRequest::new(&costs);
    let named: hallpass::NamedTarget = TARGET.parse().expect("target");
    if target {
        request.policy.target = Some(named.target);
        request.policy.name = named.name.as_ref();
        request.policy.needed = hallpass::time::Duration::seconds(20);
    }
    spend_charges_in(file, &request, at, state).expect("live decision")
}

#[test]
fn cumulative_projection_matches_live_and_creates_no_evidence() {
    let f = fixture();
    let tail = SCENARIO.split("[[step]]").last().expect("last");
    fs::write(
        &f.scenario,
        format!("{SCENARIO}\n[[step]]{}", tail.replace("third", "fourth")),
    )
    .expect("tail");
    let out = rehearse(&f.pass, &f.scenario, &f.state).expect("simulation");
    assert_eq!(out.witness, "fresh");
    assert_eq!(
        out.digest,
        hallpass::Digest::of(PASS.as_bytes()).to_string()
    );
    assert!(!ledger_path(&f.pass).exists());
    assert!(!f.state.path().expect("path").exists());
    assert_eq!(out.steps.len(), 4);
    assert_eq!(out.starting_spent["bytes"], 0);
    assert_eq!(out.steps[0].labels, ["web"]);
    assert_eq!(out.steps[1].balances[1].remaining, Some(20));
    assert_eq!(out.stopped_at.as_deref(), Some("third"));
    assert_eq!(out.steps[2].balances[0].after, 2);
    assert_eq!(out.steps[2].balances[1].after, 80);
    assert_eq!(out.steps[3].status, "unevaluated");
    assert!(out.steps[3].balances.is_empty());
    for (i, at) in [
        NOW,
        datetime!(2026-11-20 09:01 UTC),
        datetime!(2026-11-20 09:02 UTC),
    ]
    .into_iter()
    .enumerate()
    {
        let live = commit(&f.pass, &f.state, 40, at, i == 0);
        let simulated = &out.steps[i];
        assert_eq!(
            live.refusal.as_ref().map(|r| r.code.as_str()),
            simulated.refusal.as_ref().map(|r| r.code)
        );
        assert_eq!(live.labels, simulated.labels);
        for (c, b) in live.charges.iter().zip(&simulated.balances) {
            assert_eq!(
                (c.counter.as_str(), c.spent, c.remaining),
                (b.counter.as_str(), b.after, b.remaining)
            );
        }
    }
    let live = commit(&f.pass, &f.state, 40, NOW, true);
    assert_eq!(
        live.refusal.expect("live sees later spend").code,
        RefusalCode::CeilingReached
    );
}

#[test]
fn historical_and_adopted_balances_are_read_without_modification() {
    let f = fixture();
    let ledger = ledger_path(&f.pass);
    let witness = f.state.witness_path("metered-example").expect("witness");
    assert_eq!(commit(&f.pass, &f.state, 10, NOW, false).seq, Some(1));
    let first = fs::read(&ledger).expect("first commit");
    assert_eq!(commit(&f.pass, &f.state, 15, NOW, false).seq, Some(2));
    fs::write(&ledger, first).expect("restore");
    assert!(rehearse(&f.pass, &f.scenario, &f.state).is_err());
    let adopted = adopt(&f.pass, "restored older journal", NOW, &f.state).expect("adopt");
    assert_eq!(adopted.adoption.carried["bytes"], 15);
    let before = (
        fs::read(&ledger).expect("ledger"),
        fs::read(&witness).expect("witness"),
    );
    let out = rehearse(&f.pass, &f.scenario, &f.state).expect("rehearse");
    assert_eq!(out.witness, "matches");
    assert_eq!(out.starting_spent["bytes"], 25);
    assert_eq!(out.starting_spent["requests"], 2);
    assert_eq!(out.projected_spent["bytes"], 65);
    assert_eq!(out.projected_spent["requests"], 3);
    assert_eq!(out.stopped_at.as_deref(), Some("second"));
    assert_eq!(
        (
            fs::read(&ledger).expect("ledger"),
            fs::read(&witness).expect("witness")
        ),
        before
    );
    fs::write(&ledger, b"damaged\n").expect("corrupt ledger");
    assert!(rehearse(&f.pass, &f.scenario, &f.state).is_err());
    assert_eq!(fs::read(&ledger).expect("damage preserved"), b"damaged\n");
}

#[test]
fn rehearsal_uses_exclusive_expiry_duration_target_and_required_counter_rules() {
    let f = fixture();
    for (scenario, index, code) in [
        (
            SCENARIO.replace("09:02:00", "17:00:00"),
            2,
            RefusalCode::Expired,
        ),
        (
            SCENARIO.replace("duration = 20", "duration = 40000"),
            0,
            RefusalCode::WindowTooShort,
        ),
        (
            SCENARIO.replace("app.example.org", "other.example.org"),
            0,
            RefusalCode::NameNotListed,
        ),
        (
            SCENARIO.replace("{ counter = \"requests\", n = 1 }, ", ""),
            0,
            RefusalCode::RequiredCounterMissing,
        ),
    ] {
        fs::write(&f.scenario, scenario).expect("scenario");
        let out = rehearse(&f.pass, &f.scenario, &f.state).expect("rehearse");
        let refusal = out.steps[index].refusal.as_ref().expect("refusal");
        assert_eq!(refusal.code, code.as_str());
        if code == RefusalCode::NameNotListed {
            assert_eq!(refusal.target, Some(1));
        }
    }
}

#[test]
fn malformed_or_unbounded_scenarios_fail_before_accounting() {
    let f = fixture();
    let template = SCENARIO.split("[[step]]").last().expect("last");
    let mut too_many_steps = String::new();
    for i in 0..=MAX_STEPS {
        too_many_steps.push_str("\n[[step]]");
        too_many_steps.push_str(&template.replace("third", &format!("unit-{i}")));
    }
    let targets = vec![format!("\"{TARGET}\""); hallpass::MAX_TARGETS + 1].join(",");
    for invalid in [
        SCENARIO.replace("version = 1", "version = 2"),
        SCENARIO.replace("09:02:00", "08:00:00"),
        SCENARIO.replace("09:02:00Z", "09:02:00"),
        SCENARIO.replace("third", "first"),
        SCENARIO.replace("third", "bad id"),
        SCENARIO.replace("n = 40", "n = 0"),
        SCENARIO.replace("counter = \"bytes\"", "counter = \"requests\""),
        SCENARIO.replace("duration = 20", "typo = 20"),
        SCENARIO.replace(&format!("\"{TARGET}\""), &targets),
        format!("version = 1{too_many_steps}"),
        " ".repeat(usize::try_from(MAX_SCENARIO_BYTES).expect("limit") + 1),
    ] {
        fs::write(&f.scenario, invalid).expect("scenario");
        assert!(matches!(
            rehearse(&f.pass, &f.scenario, &f.state),
            Err(Error::Usage(_))
        ));
    }
    assert!(!ledger_path(&f.pass).exists());
    assert!(!f.state.path().expect("path").exists());
}

#[cfg(feature = "cli")]
#[test]
fn cli_result_is_distinct_from_a_live_spend_and_has_agent_help() {
    let f = fixture();
    let run = |args: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .arg("--json")
            .args(args)
            .env("XDG_STATE_HOME", f.state.path().expect("state"))
            .output()
            .expect("cli");
        (
            out.status.code().expect("exit"),
            serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("json"),
        )
    };
    let (code, help) = run(&["help", "rehearse"]);
    assert_eq!(code, 0);
    assert!(
        help["examples"][0]
            .as_str()
            .expect("example")
            .contains("rehearse")
    );
    let args = [
        "rehearse",
        f.pass.to_str().expect("pass path"),
        f.scenario.to_str().expect("scenario path"),
    ];
    let (code, report) = run(&args);
    assert_eq!(code, 2);
    assert_eq!(report["command"], "rehearse");
    assert_eq!(report["result"], "simulation-refused");
    assert_eq!(report["steps"][1]["balances"][1]["remaining"], 20);
    assert_eq!(report["stopped_at"], "third");
    assert!(report.get("seq").is_none());
    fs::write(&f.scenario, SCENARIO.replace("n = 40", "n = 20")).expect("fits");
    let (code, report) = run(&args);
    assert_eq!(code, 0);
    assert_eq!(report["result"], "simulated");
}
