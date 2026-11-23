//! Per-call cost as the ledger grows. Ignored by default because it builds
//! ledgers of 100,000 entries and times hundreds of calls.
//!
//! ```text
//! cargo test --release --test ledger_scale -- --ignored --nocapture
//! HALLPASS_SCALE_SIZES=1000,10000 cargo test --release --test ledger_scale -- --ignored --nocapture
//! ```
//!
//! Each size gets a fresh pass and a synthetic, valid hash-chained ledger in
//! the shapes hallpass writes (half legacy spends, a quarter two-charge
//! debits, a quarter debits with a caller reference and a recorded target),
//! then one real spend so the witness matches. It reports the median and mean
//! of each call. "lib" rows call the library in this process; "cli" rows start
//! the `hallpass` binary once per call, as a tool that shells out does. The
//! "floor" row only reads the ledger and hashes each line: the part of a call
//! that checks every byte. Read-only calls run first; spends commit, so they
//! run last and add at most 5% (or 10 lines) each.
#![cfg(feature = "cli")]

use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use hallpass::time::format_description::well_known::Rfc3339;
use hallpass::time::{self, OffsetDateTime};
use hallpass::{
    Charge, Digest, NamedTarget, SpendChargesRequest, SpendRequest, StateDir, WitnessStatus,
    ledger_path, load, permits_in, read_summary, spend_charges_in, spend_in,
};

const PASS_ID: &str = "scale-bench";

struct Fixture {
    dir: tempfile::TempDir,
    pass: PathBuf,
    state: StateDir,
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .expect("whole second")
        .format(&Rfc3339)
        .expect("format")
}

impl Fixture {
    fn new(entries: u64) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let pass = dir.path().join("scale.toml");
        let now = OffsetDateTime::now_utc();
        let body = format!(
            r#"format = 1
id = "{PASS_ID}"
name = "Ledger scale benchmark"
[approval]
owner = "Example owner"
reference = "Benchmark fixture"
operator = "Example operator"
valid_from = {}
valid_until = {}
revoked = false
[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = 443
[ceilings]
calls = {max}
bytes = {max}
"#,
            rfc3339(now - time::Duration::days(1)),
            rfc3339(now + time::Duration::days(30)),
            max = hallpass::MAX_CEILING,
        );
        fs::write(&pass, body).expect("pass");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("private pass");
        let state = StateDir::new(dir.path().join("state/hallpass"));
        let fixture = Self { dir, pass, state };
        fixture.write_ledger(entries, &rfc3339(now - time::Duration::hours(1)));
        // One real spend records the witness, so every timed call sees a
        // matching witness, as on a long-running engagement.
        let outcome = spend_in(
            &fixture.pass,
            &SpendRequest::new("calls", 1),
            now,
            &fixture.state,
        )
        .expect("anchor spend");
        assert!(outcome.refusal.is_none(), "{:?}", outcome.refusal);
        let view = fixture.summary();
        assert_eq!(view.witness, WitnessStatus::Matches);
        assert_eq!(view.tally.entries, entries + 1);
        fixture
    }

    fn write_ledger(&self, entries: u64, time: &str) {
        let digest = load(&self.pass).expect("pass").digest.to_string();
        let header = format!(r#"{{"hallpass_ledger":1,"pass_id":"{PASS_ID}"}}"#);
        let mut out = Vec::with_capacity(usize::try_from(entries).unwrap_or(0) * 260);
        let mut tail = Digest::of(header.as_bytes());
        writeln!(out, "{header}").expect("header");
        let mut line = String::new();
        for seq in 1..=entries {
            line.clear();
            if seq % 4 == 0 {
                write!(
                    line,
                    r#"{{"seq":{seq},"time":"{time}","event":"debit","version":1,"charges":[{{"counter":"calls","n":1}},{{"counter":"bytes","n":1200}}],"digest":"{digest}","receipt":{{"caller_ref":"run-{seq}","targets":[{{"target":"192.0.2.10:443/tcp","label":"web"}}]}},"prev":"{tail}"}}"#
                )
            } else if seq % 4 == 2 {
                write!(
                    line,
                    r#"{{"seq":{seq},"time":"{time}","event":"debit","version":1,"charges":[{{"counter":"calls","n":1}},{{"counter":"bytes","n":1200}}],"digest":"{digest}","prev":"{tail}"}}"#
                )
            } else {
                write!(
                    line,
                    r#"{{"seq":{seq},"time":"{time}","counter":"calls","n":1,"digest":"{digest}","note":null,"prev":"{tail}"}}"#
                )
            }
            .expect("line");
            tail = Digest::of(line.as_bytes());
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
        let path = ledger_path(&self.pass);
        fs::write(&path, out).expect("ledger");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private ledger");
    }

    fn summary(&self) -> hallpass::LedgerView {
        read_summary(&load(&self.pass).expect("pass"), &self.state).expect("summary")
    }

    fn cli(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        cmd.arg("--json")
            .args(args)
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .env_remove("HALLPASS_UNSAFE_TEST_CLOCK");
        cmd
    }

    fn ledger_bytes(&self) -> u64 {
        fs::metadata(ledger_path(&self.pass)).expect("ledger").len()
    }
}

/// Times calls against one fixture and prints one row per kind of call.
struct Bench {
    entries: u64,
    bytes: u64,
    iterations: usize,
}

impl Bench {
    /// Run `call` `iterations` times and print the median and mean.
    fn row(&self, what: &str, iterations: usize, mut call: impl FnMut()) {
        let mut samples: Vec<Duration> = (0..iterations)
            .map(|_| {
                let start = Instant::now();
                call();
                start.elapsed()
            })
            .collect();
        samples.sort_unstable();
        let total: Duration = samples.iter().sum();
        let mean = total / u32::try_from(samples.len()).expect("few samples");
        eprintln!(
            "entries={:>7} bytes={:>10} {what:<18} median={:>8.3} ms mean={:>8.3} ms",
            self.entries,
            self.bytes,
            ms(samples[samples.len() / 2]),
            ms(mean)
        );
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn sizes() -> Vec<u64> {
    std::env::var("HALLPASS_SCALE_SIZES").map_or_else(
        |_| vec![0, 1_000, 10_000, 100_000],
        |v| {
            v.split(',')
                .map(|s| s.trim().parse().expect("HALLPASS_SCALE_SIZES: numbers"))
                .collect()
        },
    )
}

fn run_ok(mut cmd: Command) {
    let out = cmd.output().expect("run hallpass");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Read the ledger and hash each line, as the chain needs, without decoding
/// anything: the floor for a call that checks every byte.
fn read_and_hash(ledger: &std::path::Path) {
    let mut reader = BufReader::with_capacity(1 << 16, fs::File::open(ledger).expect("ledger"));
    let mut line = Vec::new();
    let mut last = Digest::of(b"");
    while reader.read_until(b'\n', &mut line).expect("read") > 0 {
        last = Digest::of(&line);
        line.clear();
    }
    assert_ne!(last, Digest::of(b""));
}

#[test]
#[ignore = "builds 100k-entry ledgers; run with --release -- --ignored --nocapture"]
fn per_call_latency_at_scale() {
    let target: NamedTarget = "192.0.2.10:443/tcp".parse().expect("target");
    let charges = [
        Charge {
            counter: "calls",
            amount: 1,
        },
        Charge {
            counter: "bytes",
            amount: 1200,
        },
    ];
    for entries in sizes() {
        let built = Instant::now();
        let f = Fixture::new(entries);
        let bench = Bench {
            entries,
            bytes: f.ledger_bytes(),
            iterations: usize::try_from((2_000_000 / entries.max(1)).clamp(10, 200))
                .expect("small count"),
        };
        eprintln!(
            "entries={entries:>7} bytes={:>10} fixture built in {:.1} ms",
            bench.bytes,
            ms(built.elapsed())
        );
        let (path, witnesses, n) = (f.pass.as_path(), &f.state, bench.iterations);

        let ledger = ledger_path(path);
        let file = path.to_str().expect("utf-8 path");
        let cli = n.min(50);
        bench.row("floor read+sha256", n, || read_and_hash(&ledger));
        bench.row("lib permits", n, || {
            let now = OffsetDateTime::now_utc();
            let to = std::slice::from_ref(&target);
            let out =
                permits_in(path, to, None, now, time::Duration::ZERO, witnesses).expect("permits");
            assert!(out.decision.is_ok());
        });
        bench.row("lib status", n, || {
            let view = read_summary(&load(path).expect("pass"), witnesses).expect("status");
            assert_eq!(view.witness, WitnessStatus::Matches);
        });
        bench.row("cli permits", cli, || {
            run_ok(f.cli(&["permits", file, "--to", "192.0.2.10:443/tcp"]));
        });
        bench.row("cli status", cli, || run_ok(f.cli(&["status", file])));

        let spends = n.min(usize::try_from(entries / 20).expect("small").max(10));
        bench.row("lib spend", spends, || {
            let request = SpendRequest::new("calls", 1);
            let out =
                spend_in(path, &request, OffsetDateTime::now_utc(), witnesses).expect("spend");
            assert!(out.seq.is_some());
        });
        bench.row("lib debit", spends, || {
            let request = SpendChargesRequest::new(&charges);
            let out = spend_charges_in(path, &request, OffsetDateTime::now_utc(), witnesses)
                .expect("debit");
            assert!(out.seq.is_some());
        });
        bench.row("cli spend", spends.min(cli), || {
            run_ok(f.cli(&["spend", file, "calls"]));
        });

        concurrent_spends(&f, entries);
        assert_eq!(f.summary().witness, WitnessStatus::Matches);
    }
}

/// 16 threads spending at once: the lock serializes them, so throughput is
/// one over the time a spend holds the lock.
fn concurrent_spends(f: &Fixture, entries: u64) {
    const WORKERS: u64 = 16;
    let per_worker = (200_000 / entries.max(1)).clamp(2, 25);
    let before = f.summary().tally.entries;
    let start = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..WORKERS {
            scope.spawn(|| {
                for _ in 0..per_worker {
                    let out = spend_in(
                        &f.pass,
                        &SpendRequest::new("calls", 1),
                        OffsetDateTime::now_utc(),
                        &f.state,
                    )
                    .expect("concurrent spend");
                    assert!(out.seq.is_some());
                }
            });
        }
    });
    let elapsed = start.elapsed();
    let total = WORKERS * per_worker;
    assert_eq!(f.summary().tally.entries, before + total);
    #[allow(clippy::cast_precision_loss)]
    let rate = total as f64 / elapsed.as_secs_f64();
    eprintln!(
        "entries={entries:>7} bytes={:>10} 16 threads x {per_worker} spends: {rate:.0} spends/s",
        f.ledger_bytes()
    );
}
