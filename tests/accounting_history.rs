//! Serial accounting properties exercised through the public file-backed APIs.
use hallpass::time::{OffsetDateTime, macros::datetime};
use hallpass::{
    Charge, RefusalCode, SpendChargesRequest, SpendRequest, StateDir, WitnessStatus, adopt_guarded,
    ledger_path, load, preview_adopt, read_ledger, spend_charges_in, spend_in,
};
use proptest::prelude::*;
use std::{collections::BTreeMap, fmt::Write as _, fs, os::unix::fs::PermissionsExt, path::Path};

const NOW: OffsetDateTime = datetime!(2026-11-20 09:00 UTC);

fn write_pass(path: &Path, ceilings: &[(&str, u64)]) {
    let mut pass = include_str!("../docs/review-approval.toml").to_owned();
    pass.push_str("\n[ceilings]\n");
    for (name, limit) in ceilings {
        writeln!(pass, "{name} = {limit}").expect("format ceiling");
    }
    fs::write(path, pass).expect("write temp pass");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private pass");
    // A pass modified in the last quarter second is read again once it has
    // gone that long unchanged. This one is complete as written, so date it
    // back and keep the property test fast.
    let earlier = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    fs::File::options()
        .write(true)
        .open(path)
        .and_then(|file| file.set_modified(earlier))
        .expect("date the pass back");
}

fn totals(values: &[(&str, u64)]) -> BTreeMap<String, u64> {
    values
        .iter()
        .map(|&(name, n)| (name.to_owned(), n))
        .collect()
}

fn witness_file(path: &Path, state: &StateDir) -> std::path::PathBuf {
    let id = load(path).expect("load pass").pass.id;
    state.witness_path(&id).expect("witness path")
}

fn assert_witness_totals(path: &Path, state: &StateDir, expected: &BTreeMap<String, u64>) {
    let bytes = fs::read(witness_file(path, state)).expect("read witness");
    let witness: serde_json::Value = serde_json::from_slice(&bytes).expect("parse witness");
    assert_eq!(witness["totals"], serde_json::json!(expected));
}

#[test]
fn divergent_recovery_takes_each_counter_maximum_even_above_its_new_ceiling() {
    let dir = tempfile::tempdir().expect("temporary engagement");
    let live = dir.path().join("live.toml");
    let backup = dir.path().join("backup.toml");
    let state = StateDir::new(dir.path().join("live-state"));
    let backup_state = StateDir::new(dir.path().join("backup-state"));
    let mut limits = [
        ("same", 9),
        ("ahead", hallpass::MAX_CEILING),
        ("behind", 9),
        ("live_only", 9),
        ("backup_only", 9),
    ];
    for (path, side, amounts) in [
        (
            &live,
            &state,
            [("same", 2), ("ahead", 1), ("behind", 8), ("live_only", 4)],
        ),
        (
            &backup,
            &backup_state,
            [
                ("same", 2),
                ("ahead", hallpass::MAX_CEILING),
                ("behind", 3),
                ("backup_only", 5),
            ],
        ),
    ] {
        write_pass(path, &limits);
        let charges = amounts.map(|(counter, amount)| Charge { counter, amount });
        let out = spend_charges_in(path, &SpendChargesRequest::new(&charges), NOW, side)
            .expect("seed history");
        assert_eq!(out.seq, Some(1));
    }
    limits[2].1 = 1;
    write_pass(&live, &limits);
    fs::copy(ledger_path(&backup), ledger_path(&live)).expect("restore divergent ledger");
    let expected = totals(&[
        ("same", 2),
        ("ahead", hallpass::MAX_CEILING),
        ("behind", 8),
        ("live_only", 4),
        ("backup_only", 5),
    ]);
    let carry = totals(&[("behind", 5), ("live_only", 4)]);

    let preview = preview_adopt(&live, &state).expect("recovery preview");
    assert_eq!(preview.carried, carry);
    assert_eq!(preview.totals, expected);
    let applied =
        adopt_guarded(&live, "restore backup", NOW, &state, Some(&preview.token)).expect("adopt");
    assert_eq!(applied.totals, expected);
    let view = read_ledger(&load(&live).expect("reload"), &state).expect("replay adoption");
    assert_eq!(view.adoptions[0].seq, 2);
    assert_eq!(view.adoptions[0].carried, carry);
    assert_eq!(view.tally.spent, expected);
    assert_eq!(view.witness, WitnessStatus::Matches);
    assert_witness_totals(&live, &state, &expected);
    let denied = spend_in(&live, &SpendRequest::new("behind", 1), NOW, &state).expect("decision");
    assert_eq!(
        denied.refusal.as_ref().map(|r| r.code),
        Some(RefusalCode::CeilingReached)
    );
    assert_eq!(denied.spent, 8);
    assert_eq!(denied.remaining(), Some(0));
}

const COUNTERS: [&str; 2] = ["calls", "bytes"];

#[derive(Clone, Copy, Debug)]
enum Step {
    Scalar {
        counter: usize,
        amount: u64,
        preview: bool,
    },
    Pair {
        calls: u64,
        bytes: u64,
        preview: bool,
    },
    Limits([u64; 2]),
    Save,
    Restore,
}

fn steps() -> impl Strategy<Value = Step> {
    prop_oneof![
        4 => (0..2_usize, 1..=9_u64, any::<bool>()).prop_map(|(counter, amount, preview)| Step::Scalar {counter, amount, preview}),
        4 => (1..=9_u64, 1..=9_u64, any::<bool>()).prop_map(|(calls, bytes, preview)| Step::Pair {calls, bytes, preview}),
        2 => prop::array::uniform2(0..=16_u64).prop_map(Step::Limits),
        1 => Just(Step::Save),
        2 => Just(Step::Restore),
    ]
}

#[derive(Clone, Copy)]
struct History {
    spent: [u64; 2],
    spends: u64,
    adoptions: u64,
}

impl History {
    fn sequence(self) -> u64 {
        self.spends + self.adoptions
    }

    fn assert_replay(self, path: &Path, state: &StateDir) {
        let loaded = load(path).expect("reload pass");
        let expected = COUNTERS
            .into_iter()
            .map(str::to_owned)
            .zip(self.spent)
            .filter(|(_, amount)| *amount > 0)
            .collect();
        let view = read_ledger(&loaded, state).expect("replay history");
        assert_eq!(view.tally.spent, expected);
        assert_eq!(view.tally.entries, self.spends);
        assert_eq!(view.adoption_count, self.adoptions);
        assert_eq!(view.witness, WitnessStatus::Matches);
        assert_witness_totals(path, state, &expected);
    }

    fn debit(
        &mut self,
        path: &Path,
        state: &StateDir,
        limits: [u64; 2],
        amounts: [u64; 2],
        preview: bool,
    ) {
        let projected = [self.spent[0] + amounts[0], self.spent[1] + amounts[1]];
        // Only requested counters participate. An unrelated lowered ceiling
        // may already be below its historical balance.
        let fits = (0..2).all(|i| amounts[i] == 0 || projected[i] <= limits[i]);
        let committed = fits && !preview;
        let expected = if committed { projected } else { self.spent };
        let before = preview.then(|| {
            (
                fs::read(ledger_path(path)).expect("ledger"),
                fs::read(witness_file(path, state)).expect("witness"),
            )
        });
        let (seq, refusal) = if amounts.contains(&0) {
            let i = usize::from(amounts[0] == 0); // Index of the charged counter.
            let request = SpendRequest::new(COUNTERS[i], amounts[i]);
            let out = if preview {
                hallpass::preview_spend_in(path, &request, NOW, state)
            } else {
                spend_in(path, &request, NOW, state)
            }
            .expect("scalar decision");
            assert_eq!(out.spent, expected[i]);
            assert_eq!(out.remaining(), Some(limits[i].saturating_sub(expected[i])));
            (out.seq, out.refusal)
        } else {
            let charges = [
                Charge {
                    counter: "calls",
                    amount: amounts[0],
                },
                Charge {
                    counter: "bytes",
                    amount: amounts[1],
                },
            ];
            let mut request = SpendChargesRequest::new(&charges);
            request.dry_run = preview;
            let out = spend_charges_in(path, &request, NOW, state).expect("atomic decision");
            assert_eq!(out.charges.len(), 2);
            for (i, charge) in out.charges.iter().enumerate() {
                assert_eq!(charge.counter, COUNTERS[i]);
                assert_eq!(charge.amount, amounts[i]);
                assert_eq!(charge.spent, expected[i]);
                assert_eq!(
                    charge.remaining,
                    Some(limits[i].saturating_sub(expected[i]))
                );
                assert_eq!(
                    charge.projected_spent,
                    (fits && preview).then_some(projected[i])
                );
            }
            (out.seq, out.refusal)
        };
        assert_eq!(
            refusal.map(|r| r.code),
            (!fits).then_some(RefusalCode::CeilingReached)
        );
        assert_eq!(seq, committed.then_some(self.sequence() + 1));
        if let Some((ledger, witness)) = before {
            assert_eq!(
                fs::read(ledger_path(path)).expect("ledger after preview"),
                ledger
            );
            assert_eq!(
                fs::read(witness_file(path, state)).expect("witness after preview"),
                witness
            );
        }
        self.spent = expected;
        self.spends += u64::from(committed);
    }
}

fn run_history(steps: &[Step]) {
    let dir = tempfile::tempdir().expect("temporary engagement");
    let path = dir.path().join("pass.toml");
    let ledger = ledger_path(&path);
    let state = StateDir::new(dir.path().join("state"));
    let mut limits = [8, 8];
    write_pass(&path, &[("calls", 8), ("bytes", 8)]);
    let seed = spend_in(&path, &SpendRequest::new("calls", 1), NOW, &state).expect("initial spend");
    assert_eq!(seed.seq, Some(1));
    let mut history = History {
        spent: [1, 0],
        spends: 1,
        adoptions: 0,
    };
    let (mut saved_history, mut saved_bytes) =
        (history, fs::read(&ledger).expect("initial backup"));
    for &step in steps {
        match step {
            Step::Scalar {
                counter,
                amount,
                preview,
            } => {
                let mut amounts = [0, 0];
                amounts[counter] = amount;
                history.debit(&path, &state, limits, amounts, preview);
            }
            Step::Pair {
                calls,
                bytes,
                preview,
            } => history.debit(&path, &state, limits, [calls, bytes], preview),
            Step::Limits(new) => {
                limits = new;
                write_pass(&path, &[("calls", limits[0]), ("bytes", limits[1])]);
            }
            Step::Save => {
                (saved_history, saved_bytes) = (history, fs::read(&ledger).expect("save backup"));
            }
            Step::Restore => {
                fs::write(&ledger, &saved_bytes).expect("restore snapshot");
                if history.sequence() == saved_history.sequence() {
                    assert!(matches!(
                        preview_adopt(&path, &state),
                        Err(hallpass::Error::Usage(_))
                    ));
                } else {
                    let projected =
                        std::array::from_fn(|i| history.spent[i].max(saved_history.spent[i]));
                    let preview = preview_adopt(&path, &state).expect("preview restore");
                    let applied = adopt_guarded(
                        &path,
                        "restore saved snapshot",
                        NOW,
                        &state,
                        Some(&preview.token),
                    )
                    .expect("apply preview");
                    assert_eq!(preview.totals, applied.totals);
                    assert_eq!(applied.adoption.seq, saved_history.sequence() + 1);
                    history = History {
                        spent: projected,
                        spends: saved_history.spends,
                        adoptions: saved_history.adoptions + 1,
                    };
                }
            }
        }
        history.assert_replay(&path, &state);
    }
}

#[test]
fn mixed_history_checks_exact_fit_refusal_and_repeated_recovery() {
    run_history(&[
        Step::Pair {
            calls: 7,
            bytes: 3,
            preview: true,
        },
        Step::Pair {
            calls: 7,
            bytes: 3,
            preview: false,
        },
        Step::Save,
        Step::Limits([1, 8]),
        Step::Pair {
            calls: 1,
            bytes: 1,
            preview: false,
        },
        Step::Scalar {
            counter: 1,
            amount: 5,
            preview: false,
        },
        Step::Restore,
        Step::Restore,
        Step::Limits([9, 9]),
        Step::Pair {
            calls: 1,
            bytes: 1,
            preview: false,
        },
    ]);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn mixed_histories_match_serial_accounting(history in prop::collection::vec(steps(), 1..=20)) {
        run_history(&history);
    }
}
