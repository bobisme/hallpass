//! Per-call cost as the ledger grows. Ignored by default because it builds
//! ledgers of 100,000 entries and times hundreds of calls.
//!
//! ```text
//! cargo test --release --test ledger_scale -- --ignored --nocapture
//! HALLPASS_SCALE_SIZES=1000,10000 HALLPASS_SCALE_MIXES=receipts cargo test --release --test ledger_scale -- --ignored --nocapture
//! ```
//!
//! Each size and mix gets a fresh pass and a valid hash-chained ledger, then
//! one real spend so the witness matches. There are two mixes of lines:
//!
//! - `plain`: half legacy spends, a quarter two-charge debits, a quarter
//!   debits with a caller reference and a recorded target, with whole-second
//!   times (about 300 bytes a line).
//! - `receipts`: every line is what `spend --charge calls=1 --charge
//!   bytes=N --to 192.0.2.20:443/tcp --name app.example.org --caller-ref REF
//!   --record-target --note NOTE` writes with the real clock (about 470
//!   bytes a line). Times carry fractions of a second, one note in four has
//!   non-ASCII text and one in eight has quotation marks. The first lines
//!   and the last line are real spends through the library, and the fixture
//!   checks that its generator writes each of them byte for byte.
//!
//! It reports the median and mean of each call. "lib" rows call the library
//! in this process; "cli" rows start the `hallpass` binary once per call, as
//! a tool that shells out does. The "floor" row only reads the ledger and
//! hashes each line: the part of a call that checks every byte. Read-only
//! calls run first; spends commit, so they run last and add at most 5% (or
//! 10 lines) each.
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
    evidence, ledger_path, load, permits_in, read_summary, spend_charges_in, spend_in,
};

const PASS_ID: &str = "scale-bench";

/// The named destination that receipt lines record.
const APP: &str = "192.0.2.20:443/tcp";
const APP_NAME: &str = "app.example.org";

/// How many lines of a `receipts` ledger are real spends, before the
/// generator writes the rest.
const REAL_SPENDS: u64 = 8;

/// The kind of line a fixture's ledger holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mix {
    Plain,
    Receipts,
}

impl Mix {
    const fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Receipts => "receipts",
        }
    }
}

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

/// The note of receipt line `seq`: mostly ASCII, one in four with non-ASCII
/// text, one in eight with quotation marks.
fn receipt_note(seq: u64) -> String {
    match seq % 8 {
        3 | 7 => format!("probe batch {seq} – login flow, retry after 503"),
        5 => format!("replay of \"login\" step {seq}"),
        _ => format!("probe batch {seq} of the login flow"),
    }
}

fn receipt_ref(seq: u64) -> String {
    format!("eval-run-7/unit-{seq:06}")
}

const fn receipt_bytes(seq: u64) -> u64 {
    200 + seq % 9000
}

/// The time of receipt line `seq`: about a millisecond apart, with
/// fractions of a second of every length.
fn receipt_time(start: OffsetDateTime, seq: u64) -> OffsetDateTime {
    let step = i64::try_from(seq * 1_000_037 + seq % 7 * 100).expect("small");
    start + time::Duration::nanoseconds(step)
}

/// Receipt line `seq` exactly as hallpass writes it.
fn receipt_line(seq: u64, at: OffsetDateTime, digest: &Digest, prev: &Digest) -> String {
    let quoted = |text: &str| serde_json::to_string(text).expect("quote");
    format!(
        r#"{{"seq":{seq},"time":"{time}","event":"debit","version":1,"charges":[{{"counter":"calls","n":1}},{{"counter":"bytes","n":{bytes}}}],"digest":"{digest}","note":{note},"receipt":{{"caller_ref":{caller_ref},"targets":[{{"target":"{APP}","name":"{APP_NAME}","label":"app"}}]}},"prev":"{prev}"}}"#,
        time = at.format(&Rfc3339).expect("format"),
        bytes = receipt_bytes(seq),
        note = quoted(&receipt_note(seq)),
        caller_ref = quoted(&receipt_ref(seq)),
    )
}

fn app() -> NamedTarget {
    format!("{APP}@{APP_NAME}").parse().expect("target")
}

/// A debit with a note, a caller reference and a recorded named target, as
/// `spend --caller-ref REF --record-target --note NOTE` makes it.
fn receipt_debit(
    f: &Fixture,
    charges: &[Charge<'_>],
    note: &str,
    reference: &str,
    require_new: bool,
    now: OffsetDateTime,
) -> u64 {
    let target = app();
    let mut request = SpendChargesRequest::new(charges);
    request.policy.target = Some(target.target);
    request.policy.name = target.name.as_ref();
    request.policy.note = Some(note);
    request.caller_ref = Some(reference);
    request.require_new_ref = require_new;
    request.record_targets = true;
    let out = spend_charges_in(&f.pass, &request, now, &f.state).expect("receipt debit");
    assert!(out.refusal.is_none(), "{:?}", out.refusal);
    out.seq.expect("recorded")
}

impl Fixture {
    fn new(entries: u64, mix: Mix) -> Self {
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
[[destination]]
label = "app"
address = "192.0.2.20"
protocol = "tcp"
ports = 443
names = ["{APP_NAME}"]
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
        match mix {
            Mix::Plain => {
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
            }
            Mix::Receipts => fixture.write_receipts(entries, now - time::Duration::hours(1)),
        }
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

    /// Receipt line `seq` as a real spend at `at`, checked against the generator.
    fn real_receipt(&self, seq: u64, at: OffsetDateTime) {
        let charges = [
            Charge {
                counter: "calls",
                amount: 1,
            },
            Charge {
                counter: "bytes",
                amount: receipt_bytes(seq),
            },
        ];
        let written = receipt_debit(
            self,
            &charges,
            &receipt_note(seq),
            &receipt_ref(seq),
            false,
            at,
        );
        assert_eq!(written, seq);
        let text = fs::read_to_string(ledger_path(&self.pass)).expect("ledger");
        let mut lines = text.lines().rev();
        let (last, before) = (lines.next().expect("line"), lines.next().expect("line"));
        let digest = load(&self.pass).expect("pass").digest;
        let generated = receipt_line(seq, at, &digest, &Digest::of(before.as_bytes()));
        assert_eq!(last, generated, "the generator differs from a real spend");
    }

    /// A ledger of receipt lines. The first lines and the anchor that records
    /// the witness are real spends; the generator writes the rest exactly as
    /// it wrote the real ones.
    fn write_receipts(&self, entries: u64, start: OffsetDateTime) {
        let real = entries.min(REAL_SPENDS);
        for seq in 1..=real {
            self.real_receipt(seq, receipt_time(start, seq));
        }
        if entries > real {
            let path = ledger_path(&self.pass);
            let text = fs::read_to_string(&path).expect("ledger");
            let mut prev = Digest::of(text.lines().last().expect("line").as_bytes());
            let digest = load(&self.pass).expect("pass").digest;
            let mut out = Vec::with_capacity(usize::try_from(entries).unwrap_or(0) * 480);
            for seq in real + 1..=entries {
                let line = receipt_line(seq, receipt_time(start, seq), &digest, &prev);
                prev = Digest::of(line.as_bytes());
                out.extend_from_slice(line.as_bytes());
                out.push(b'\n');
            }
            fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .and_then(|mut file| file.write_all(&out))
                .expect("append");
        }
        self.real_receipt(entries + 1, OffsetDateTime::now_utc());
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
    mix: Mix,
    entries: u64,
    bytes: u64,
    iterations: usize,
}

impl Bench {
    /// Run `call` `iterations` times, print the median and mean, and return
    /// the median.
    fn row(&self, what: &str, iterations: usize, mut call: impl FnMut()) -> Duration {
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
        let median = samples[samples.len() / 2];
        eprintln!(
            "{:<8} entries={:>7} bytes={:>10} {what:<18} median={:>8.3} ms mean={:>8.3} ms",
            self.mix.name(),
            self.entries,
            self.bytes,
            ms(median),
            ms(mean)
        );
        median
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

fn mixes() -> Vec<Mix> {
    std::env::var("HALLPASS_SCALE_MIXES").map_or_else(
        |_| vec![Mix::Plain, Mix::Receipts],
        |v| {
            v.split(',')
                .map(|s| match s.trim() {
                    "plain" => Mix::Plain,
                    "receipts" => Mix::Receipts,
                    other => panic!("HALLPASS_SCALE_MIXES: plain or receipts, not {other}"),
                })
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
    for mix in mixes() {
        for entries in sizes() {
            measure(mix, entries);
        }
    }
}

fn measure(mix: Mix, entries: u64) {
    let built = Instant::now();
    let f = Fixture::new(entries, mix);
    let bench = Bench {
        mix,
        entries,
        bytes: f.ledger_bytes(),
        iterations: usize::try_from((2_000_000 / entries.max(1)).clamp(10, 200))
            .expect("small count"),
    };
    eprintln!(
        "{:<8} entries={entries:>7} bytes={:>10} fixture built in {:.1} ms",
        mix.name(),
        bench.bytes,
        ms(built.elapsed())
    );
    read_rows(&f, &bench);
    spend_rows(&f, &bench);
    concurrent_spends(&f, mix, entries);
    assert_eq!(f.summary().witness, WitnessStatus::Matches);
}

/// Each mix checks its own destination: `--to` and, for receipts, `--name`.
fn destination(mix: Mix) -> (NamedTarget, Vec<&'static str>) {
    match mix {
        Mix::Plain => (
            "192.0.2.10:443/tcp".parse().expect("target"),
            vec!["--to", "192.0.2.10:443/tcp"],
        ),
        Mix::Receipts => (app(), vec!["--to", APP, "--name", APP_NAME]),
    }
}

const CHARGES: [Charge<'static>; 2] = [
    Charge {
        counter: "calls",
        amount: 1,
    },
    Charge {
        counter: "bytes",
        amount: 1200,
    },
];

/// The calls that only read: they run first, on the ledger as built.
fn read_rows(f: &Fixture, bench: &Bench) {
    let (path, witnesses, n) = (f.pass.as_path(), &f.state, bench.iterations);
    let (to, to_text) = destination(bench.mix);
    let ledger = ledger_path(path);
    let file = path.to_str().expect("utf-8 path");
    let cli = n.min(50);
    bench.row("floor read+sha256", n, || read_and_hash(&ledger));
    bench.row("lib permits", n, || {
        let now = OffsetDateTime::now_utc();
        let out = permits_in(
            path,
            std::slice::from_ref(&to),
            None,
            now,
            time::Duration::ZERO,
            witnesses,
        )
        .expect("permits");
        assert!(out.decision.is_ok());
    });
    let status = bench.row("lib status", n, || {
        let view = read_summary(&load(path).expect("pass"), witnesses).expect("status");
        assert_eq!(view.witness, WitnessStatus::Matches);
    });
    let lines = f.summary().tally.entries;
    #[allow(clippy::cast_precision_loss)]
    let (per_line, per_mb) = (
        status.as_secs_f64() * 1e6 / lines as f64,
        ms(status) * 1e6 / bench.bytes as f64,
    );
    eprintln!(
        "{:<8} entries={:>7} bytes={:>10} lib status costs {per_line:.3} µs a line, {per_mb:.2} ms a MB",
        bench.mix.name(),
        bench.entries,
        bench.bytes,
    );
    let found = receipt_ref(bench.entries + 1);
    if bench.mix == Mix::Receipts {
        bench.row("lib receipt", n, || {
            let loaded = load(path).expect("pass");
            let report = evidence::lookup_receipt(&loaded, witnesses, &found).expect("receipt");
            assert_eq!(report.match_count, 1);
        });
    }
    let mut permits = vec!["permits", file];
    permits.extend(&to_text);
    bench.row("cli permits", cli, || run_ok(f.cli(&permits)));
    bench.row("cli status", cli, || run_ok(f.cli(&["status", file])));
    if bench.mix == Mix::Receipts {
        bench.row("cli receipt", cli, || {
            run_ok(f.cli(&["receipt", file, "--caller-ref", &found]));
        });
    }
}

/// The calls that commit: each adds at most 5% (or 10 lines) to the ledger.
fn spend_rows(f: &Fixture, bench: &Bench) {
    let (path, witnesses, n) = (f.pass.as_path(), &f.state, bench.iterations);
    let file = path.to_str().expect("utf-8 path");
    let spends = n.min(usize::try_from(bench.entries / 20).expect("small").max(10));
    let cli = spends.min(50);
    match bench.mix {
        Mix::Plain => {
            bench.row("lib spend", spends, || {
                let request = SpendRequest::new("calls", 1);
                let out =
                    spend_in(path, &request, OffsetDateTime::now_utc(), witnesses).expect("spend");
                assert!(out.seq.is_some());
            });
            bench.row("lib debit", spends, || {
                let request = SpendChargesRequest::new(&CHARGES);
                let out = spend_charges_in(path, &request, OffsetDateTime::now_utc(), witnesses)
                    .expect("debit");
                assert!(out.seq.is_some());
            });
            bench.row("cli spend", cli, || {
                run_ok(f.cli(&["spend", file, "calls"]));
            });
        }
        Mix::Receipts => {
            let mut k = 0;
            bench.row("lib receipt debit", spends, || {
                k += 1;
                let reference = format!("bench/lib-{k}");
                let now = OffsetDateTime::now_utc();
                receipt_debit(f, &CHARGES, "bench debit", &reference, true, now);
            });
            let (_, to_text) = destination(bench.mix);
            bench.row("cli receipt spend", cli, || {
                k += 1;
                let reference = format!("bench/cli-{k}");
                let mut args = vec!["spend", file, "--charge", "calls=1"];
                args.extend(["--charge", "bytes=1200"]);
                args.extend(&to_text);
                args.extend(["--caller-ref", &reference, "--require-new-ref"]);
                args.extend(["--record-target", "--note", "bench debit"]);
                run_ok(f.cli(&args));
            });
        }
    }
}

/// 16 threads spending at once: the lock serializes them, so throughput is
/// one over the time a spend holds the lock.
fn concurrent_spends(f: &Fixture, mix: Mix, entries: u64) {
    const WORKERS: u64 = 16;
    let per_worker = (200_000 / entries.max(1)).clamp(2, 25);
    let before = f.summary().tally.entries;
    let start = Instant::now();
    std::thread::scope(|scope| {
        for worker in 0..WORKERS {
            scope.spawn(move || {
                for k in 0..per_worker {
                    let now = OffsetDateTime::now_utc();
                    match mix {
                        Mix::Plain => {
                            let request = SpendRequest::new("calls", 1);
                            let out =
                                spend_in(&f.pass, &request, now, &f.state).expect("concurrent");
                            assert!(out.seq.is_some());
                        }
                        Mix::Receipts => {
                            let reference = format!("bench/thread-{worker}-{k}");
                            receipt_debit(f, &CHARGES, "bench debit", &reference, true, now);
                        }
                    }
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
        "{:<8} entries={entries:>7} bytes={:>10} 16 threads x {per_worker} spends: {rate:.0} spends/s",
        mix.name(),
        f.ledger_bytes()
    );
}
