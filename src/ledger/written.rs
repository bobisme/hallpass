//! A direct reader for ledger lines in the one spelling hallpass writes.
//!
//! JSON allows many spellings of one record (any key order, spaces, escapes).
//! Nearly every line of a real ledger has the spelling that hallpass itself
//! writes: keys in declaration order, no spaces, and strings whose only escapes
//! are `\"` and `\\` (the text in a valid ledger has no control characters, so
//! `serde_json` writes no other escape). This reader accepts only that spelling
//! of a legacy spend or a debit (with or without a receipt or the test-clock
//! marker). It declines
//! everything else, adoptions included, and `serde_json` then decodes the line
//! as before.
//!
//! The reader never accepts a line that `serde_json` refuses, and it never
//! decodes a value differently. It reads a line that is already known to be
//! UTF-8. An accepted line is a JSON object with exactly the fields of one
//! record shape. Each string ends at the first `"` that is not escaped, has no
//! control character (which JSON does not allow unescaped), and has no escape
//! other than `\"` and `\\`, which decode to `"` and `\`; every other character
//! is its own value. Each number is a plain unsigned integer without leading
//! zeros that fits its field. The tests compare this reader with `serde_json`.

use super::Entry;
use super::debit::{DebitCharge, DebitLine, DebitReceipt, RecordedTarget};

/// Read a legacy spend or a debit line, or `None` for `serde_json` to decode.
pub(super) fn read(line: &str) -> Option<super::Line> {
    let mut at = Cursor(line);
    at.tag(r#"{"seq":"#)?;
    let seq = at.number()?;
    at.tag(r#","time":""#)?;
    let time = at.text()?;
    if at.tag(r#","counter":""#).is_some() {
        spend(at, seq, time).map(super::Line::Spend)
    } else {
        at.tag(r#","event":""#)?;
        debit(at, seq, time).map(super::Line::Debit)
    }
}

fn spend(mut at: Cursor<'_>, seq: u64, time: String) -> Option<Entry> {
    let counter = at.text()?;
    at.tag(r#","n":"#)?;
    let n = at.number()?;
    at.tag(r#","digest":""#)?;
    let digest = at.text()?;
    let note = if at.tag(r#","note":null"#).is_some() {
        None
    } else {
        at.tag(r#","note":""#)?;
        Some(at.text()?)
    };
    let test_clock = marker(&mut at);
    at.tag(r#","prev":""#)?;
    let prev = at.text()?;
    at.end()?;
    Some(Entry {
        seq,
        time,
        counter,
        n,
        digest,
        note,
        test_clock,
        prev,
    })
}

fn debit(mut at: Cursor<'_>, seq: u64, time: String) -> Option<DebitLine> {
    let event = at.text()?;
    at.tag(r#","version":"#)?;
    let version = u32::try_from(at.number()?).ok()?;
    at.tag(r#","charges":["#)?;
    let mut charges = Vec::new();
    loop {
        at.tag(r#"{"counter":""#)?;
        let counter = at.text()?;
        at.tag(r#","n":"#)?;
        let amount = at.number()?;
        at.tag("}")?;
        charges.push(DebitCharge { counter, amount });
        if at.tag(",").is_none() {
            break;
        }
    }
    at.tag(r#"],"digest":""#)?;
    let digest = at.text()?;
    let note = if at.tag(r#","note":""#).is_some() {
        Some(at.text()?)
    } else {
        None
    };
    let receipt = if at.tag(r#","receipt":{"#).is_some() {
        Some(receipt(&mut at)?)
    } else {
        None
    };
    let test_clock = marker(&mut at);
    at.tag(r#","prev":""#)?;
    let prev = at.text()?;
    at.end()?;
    Some(DebitLine {
        seq,
        time,
        event,
        version,
        charges,
        digest,
        note,
        receipt,
        test_clock,
        prev,
    })
}

/// The test-clock marker as hallpass writes it (`,"test_clock":true`), or
/// `None` when the line has none. Any other spelling, `false` included, is
/// left to `serde_json`.
fn marker(at: &mut Cursor<'_>) -> Option<bool> {
    at.tag(r#","test_clock":true"#).map(|()| true)
}

/// The rest of a receipt whose opening brace was consumed.
fn receipt(at: &mut Cursor<'_>) -> Option<DebitReceipt> {
    let caller_ref = if at.tag(r#""caller_ref":""#).is_some() {
        Some(at.text()?)
    } else {
        None
    };
    let targets_key = if caller_ref.is_some() {
        r#","targets":["#
    } else {
        r#""targets":["#
    };
    let mut targets = Vec::new();
    if at.tag(targets_key).is_some() {
        loop {
            at.tag(r#"{"target":""#)?;
            let target = at.text()?;
            let name = if at.tag(r#","name":""#).is_some() {
                Some(at.text()?)
            } else {
                None
            };
            at.tag(r#","label":""#)?;
            let label = at.text()?;
            at.tag("}")?;
            targets.push(RecordedTarget {
                target,
                name,
                label,
            });
            if at.tag(",").is_none() {
                break;
            }
        }
        at.tag("]")?;
    }
    at.tag("}")?;
    Some(DebitReceipt {
        caller_ref,
        targets,
    })
}

/// The position of the first byte in `text` that ends the plain part of a
/// JSON string: `"`, `\` or a control character below U+0020 (which JSON
/// does not allow unescaped). A byte of a multi-byte UTF-8 character is never
/// one of them.
///
/// Eight bytes are checked at a time. For each byte `b` of a word `x`, the
/// high bit of `x - 0x01…01 & !x & 0x80…80` is set when `b` is zero, and that
/// of `x - 0x20…20 & !x & 0x80…80` when `b` is below 0x20. A byte above a
/// flagged byte can be flagged by the borrow, but the lowest flagged byte is
/// always a match, so its position is the first match.
fn stop(text: &[u8]) -> Option<usize> {
    const ONES: u64 = u64::from_le_bytes([0x01; 8]);
    const HIGH: u64 = u64::from_le_bytes([0x80; 8]);
    let zero = |v: u64| v.wrapping_sub(ONES) & !v & HIGH;
    let (words, rest) = text.as_chunks::<8>();
    for (index, word) in words.iter().enumerate() {
        let x = u64::from_le_bytes(*word);
        let found = zero(x ^ (ONES * u64::from(b'"')))
            | zero(x ^ (ONES * u64::from(b'\\')))
            | (x.wrapping_sub(ONES * 0x20) & !x & HIGH);
        if found != 0 {
            return Some(index * 8 + found.trailing_zeros() as usize / 8);
        }
    }
    let at = rest
        .iter()
        .position(|b| matches!(b, b'"' | b'\\' | 0x00..0x20))?;
    Some(words.len() * 8 + at)
}

/// The unread rest of a line.
struct Cursor<'a>(&'a str);

impl Cursor<'_> {
    /// Consume exactly `literal`.
    fn tag(&mut self, literal: &str) -> Option<()> {
        self.0 = self.0.strip_prefix(literal)?;
        Some(())
    }

    /// The whole line has been read.
    fn end(&mut self) -> Option<()> {
        self.tag("}")?;
        self.0.is_empty().then_some(())
    }

    /// A JSON number that is a plain unsigned integer: `0`, or a digit other
    /// than `0` followed by digits, no larger than `u64::MAX`. A fraction or an
    /// exponent leaves a byte that the next tag refuses.
    fn number(&mut self) -> Option<u64> {
        let len = self.0.bytes().take_while(u8::is_ascii_digit).count();
        let (digits, rest) = self.0.split_at_checked(len)?;
        if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
            return None;
        }
        let mut value = 0u64;
        for digit in digits.bytes() {
            value = value
                .checked_mul(10)?
                .checked_add(u64::from(digit - b'0'))?;
        }
        self.0 = rest;
        Some(value)
    }

    /// The rest of a string whose opening quote was consumed, through the
    /// closing quote. Text that ends at a `"` without any `\` or control
    /// character before it is the whole string, and its value is that text.
    fn text(&mut self) -> Option<String> {
        let (text, from) = self.0.split_at_checked(stop(self.0.as_bytes())?)?;
        match from.strip_prefix('"') {
            Some(rest) => {
                self.0 = rest;
                Some(text.to_owned())
            }
            None => self.escaped(),
        }
    }

    /// The rest of a string with a `\` or a control character. Only the
    /// escapes `\"` and `\\` are read; a string with another escape, or with a
    /// control character, is left to `serde_json` (which refuses a control
    /// character).
    #[cold]
    fn escaped(&mut self) -> Option<String> {
        let mut value = String::new();
        loop {
            let (text, from) = self.0.split_at_checked(stop(self.0.as_bytes())?)?;
            value.push_str(text);
            let (escaped, after) = match from.as_bytes() {
                [b'"', ..] => (None, from.get(1..)?),
                [b'\\', b'"', ..] => (Some('"'), from.get(2..)?),
                [b'\\', b'\\', ..] => (Some('\\'), from.get(2..)?),
                _ => return None,
            };
            self.0 = after;
            match escaped {
                Some(c) => value.push(c),
                None => return Some(value),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::debit::DebitBatchLine;
    use super::super::{AdoptLine, Line, ReconcileLine, WitnessLine};
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    /// The decoder that `Line::decode` replaced: serde tries each shape on a
    /// buffered copy of the line.
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Untagged {
        Spend(Entry),
        Debit(DebitLine),
        DebitBatch(DebitBatchLine),
        Adopt(AdoptLine),
        Reconcile(ReconcileLine),
    }

    fn encode(line: &Line) -> String {
        match line {
            Line::Spend(entry) => serde_json::to_string(entry),
            Line::Debit(debit) => serde_json::to_string(debit),
            Line::DebitBatch(batch) => serde_json::to_string(batch),
            Line::Adopt(adopt) => serde_json::to_string(adopt),
            Line::Reconcile(line) => serde_json::to_string(line),
        }
        .expect("encode")
    }

    /// `Line::decode` accepts exactly the lines the untagged decoder accepts,
    /// as the same shape with the same values.
    fn decodes_as_untagged(line: &[u8]) -> Result<(), TestCaseError> {
        let reference = serde_json::from_slice::<Untagged>(line)
            .ok()
            .map(|u| match u {
                Untagged::Spend(entry) => Line::Spend(entry),
                Untagged::Debit(debit) => Line::Debit(debit),
                Untagged::DebitBatch(batch) => Line::DebitBatch(batch),
                Untagged::Adopt(adopt) => Line::Adopt(adopt),
                Untagged::Reconcile(line) => Line::Reconcile(line),
            });
        let decoded = Line::decode(line);
        let tagged = |line: &Line| (std::mem::discriminant(line), encode(line));
        prop_assert_eq!(
            decoded.as_ref().map(tagged),
            reference.as_ref().map(tagged),
            "{}",
            String::from_utf8_lossy(line)
        );
        Ok(())
    }

    /// The line as serde decodes it, re-encoded so two decodes can be compared.
    fn by_serde(line: &[u8]) -> Option<String> {
        if let Ok(entry) = serde_json::from_slice::<Entry>(line) {
            return serde_json::to_string(&entry).ok();
        }
        if let Ok(debit) = serde_json::from_slice::<DebitLine>(line) {
            return serde_json::to_string(&debit).ok();
        }
        if let Ok(batch) = serde_json::from_slice::<DebitBatchLine>(line) {
            return serde_json::to_string(&batch).ok();
        }
        if let Ok(adopt) = serde_json::from_slice::<AdoptLine>(line) {
            return serde_json::to_string(&adopt).ok();
        }
        serde_json::from_slice::<ReconcileLine>(line)
            .ok()
            .and_then(|reconcile| serde_json::to_string(&reconcile).ok())
    }

    fn by_reader(line: &[u8]) -> Option<String> {
        match read(std::str::from_utf8(line).ok()?)? {
            Line::Spend(entry) => serde_json::to_string(&entry).ok(),
            Line::Debit(debit) => serde_json::to_string(&debit).ok(),
            Line::DebitBatch(batch) => serde_json::to_string(&batch).ok(),
            Line::Adopt(adopt) => serde_json::to_string(&adopt).ok(),
            Line::Reconcile(line) => serde_json::to_string(&line).ok(),
        }
    }

    /// Whatever the reader accepts, serde accepts with the same values.
    fn agrees(line: &[u8]) -> Result<(), TestCaseError> {
        if let Some(read) = by_reader(line) {
            prop_assert_eq!(
                Some(read),
                by_serde(line),
                "{}",
                String::from_utf8_lossy(line)
            );
        }
        Ok(())
    }

    /// Printable ASCII other than `"` and `\\`: strings without escapes.
    const PLAIN: &str = "[ !#-\\[\\]-~]{0,24}";

    /// Strings with many `"` and `\`, which `serde_json` writes as escapes.
    const QUOTED: &str = "[a-z \"\\\\]{0,16}";

    /// Any text without a control character (U+0000 to U+001F): non-ASCII
    /// text, DEL and the C1 controls included.
    const TEXT: &str = "[^\\x00-\\x1f]{0,24}";

    /// Any string; with `plain`, only strings the reader reads: those without
    /// a control character.
    fn text(plain: bool) -> BoxedStrategy<String> {
        if plain {
            return prop_oneof![2 => PLAIN, 1 => QUOTED, 1 => TEXT].boxed();
        }
        prop_oneof![
            4 => PLAIN,
            2 => QUOTED,
            2 => TEXT,
            2 => "[\\x00-\\x7f]{0,12}",
            1 => "[a-z0-9_:.+-]{0,12}",
            1 => "\\PC{0,8}",
            1 => any::<String>(),
            1 => Just("sha256:".to_owned() + &"ab".repeat(32)),
        ]
        .boxed()
    }

    fn number() -> impl Strategy<Value = u64> {
        prop_oneof![0u64..1000, any::<u64>()]
    }

    /// The test-clock marker; with `plain`, only as hallpass writes it
    /// (absent or `true`).
    fn test_clock(plain: bool) -> BoxedStrategy<Option<bool>> {
        if plain {
            return proptest::option::of(Just(true)).boxed();
        }
        proptest::option::of(any::<bool>()).boxed()
    }

    /// A legacy spend line as hallpass writes it, from arbitrary values.
    fn spend_line(plain: bool) -> impl Strategy<Value = String> {
        (
            number(),
            text(plain),
            text(plain),
            number(),
            text(plain),
            proptest::option::of(text(plain)),
            test_clock(plain),
            text(plain),
        )
            .prop_map(|(seq, time, counter, n, digest, note, test_clock, prev)| {
                let entry = Entry {
                    seq,
                    time,
                    counter,
                    n,
                    digest,
                    note,
                    test_clock,
                    prev,
                };
                serde_json::to_string(&entry).expect("encode")
            })
    }

    /// A debit line without a receipt as hallpass writes it, from arbitrary
    /// values (with `plain`, at least one charge).
    fn debit_line(plain: bool) -> impl Strategy<Value = String> {
        (
            (
                number(),
                text(plain),
                text(plain),
                prop_oneof![Just(1u32), any::<u32>()],
            ),
            proptest::collection::vec((text(plain), number()), usize::from(plain)..4),
            (text(plain), proptest::option::of(text(plain))),
            proptest::option::of(receipt(plain)),
            (test_clock(plain), text(plain)),
        )
            .prop_map(
                |(
                    (seq, time, event, version),
                    charges,
                    (digest, note),
                    receipt,
                    (test_clock, prev),
                )| {
                    let debit = DebitLine {
                        seq,
                        time,
                        event,
                        version,
                        charges: charges
                            .into_iter()
                            .map(|(counter, amount)| DebitCharge { counter, amount })
                            .collect(),
                        digest,
                        note,
                        receipt,
                        test_clock,
                        prev,
                    };
                    serde_json::to_string(&debit).expect("encode")
                },
            )
    }

    /// A receipt with a caller reference, recorded targets, or both.
    fn receipt(plain: bool) -> impl Strategy<Value = DebitReceipt> {
        let target = (text(plain), proptest::option::of(text(plain)), text(plain)).prop_map(
            |(target, name, label)| RecordedTarget {
                target,
                name,
                label,
            },
        );
        (
            proptest::option::of(text(plain)),
            proptest::collection::vec(target, 0..3),
        )
            .prop_map(|(caller_ref, targets)| DebitReceipt {
                caller_ref,
                targets,
            })
    }

    /// An adoption line as hallpass writes it, from arbitrary values.
    fn adopt_line() -> impl Strategy<Value = String> {
        (
            (number(), text(false), text(false), text(false)),
            proptest::collection::btree_map(text(false), number(), 0..3),
            proptest::option::of((text(false), number(), text(false), text(false))),
            (text(false), test_clock(false), text(false)),
            proptest::option::of((number(), text(false))),
        )
            .prop_map(
                |(
                    (seq, time, event, reason),
                    carried,
                    witness,
                    (digest, test_clock, prev),
                    checkpoint,
                )| {
                    let adopt = AdoptLine {
                        seq,
                        time,
                        event,
                        reason,
                        digest,
                        carried,
                        witness: witness.map(|(ledger, seq, tail, updated)| WitnessLine {
                            ledger,
                            seq,
                            tail,
                            totals: BTreeMap::new(),
                            updated,
                            test_clock: None,
                        }),
                        checkpoint: checkpoint.map(|(seq, hash)| {
                            Box::new(crate::Checkpoint {
                                version: 1,
                                pass_id: "p".to_owned(),
                                seq,
                                hash,
                                totals: Some(BTreeMap::new()),
                                latest: None,
                                anchors: None,
                            })
                        }),
                        test_clock,
                        prev,
                    };
                    serde_json::to_string(&adopt).expect("encode")
                },
            )
    }

    /// Every kind of line hallpass writes, from arbitrary values.
    fn any_line() -> impl Strategy<Value = String> {
        prop_oneof![
            spend_line(true),
            spend_line(false),
            debit_line(true),
            debit_line(false),
            adopt_line(),
        ]
    }

    /// A line as hallpass writes it, then damaged at random.
    fn damaged(line: String) -> impl Strategy<Value = Vec<u8>> {
        // Bytes that change the JSON structure or the meaning of a number.
        const SPECIAL: &[u8] = b"\" ,:{}[]0-.eE+\\nu";
        let len = line.len();
        let edits = proptest::collection::vec((0..=len, 0u8..6, any::<u8>()), 1..4);
        edits.prop_map(move |edits| {
            let mut bytes = line.clone().into_bytes();
            for (at, kind, byte) in edits {
                let at = at.min(bytes.len());
                let special = SPECIAL[usize::from(byte) % SPECIAL.len()];
                // The position just after the `at`-th (wrapping) occurrence of `mark`.
                let after = |bytes: &[u8], mark: u8| {
                    let marks: Vec<usize> =
                        (0..bytes.len()).filter(|i| bytes[*i] == mark).collect();
                    marks.get(at % marks.len().max(1)).map_or(at, |i| i + 1)
                };
                match kind {
                    0 => bytes.insert(at, byte),
                    1 if at < bytes.len() => {
                        bytes.remove(at);
                    }
                    2 if at < bytes.len() => bytes[at] = byte,
                    3 => {
                        let at = after(&bytes, b':');
                        bytes.insert(at, special);
                    }
                    4 => {
                        let at = after(&bytes, b'"');
                        bytes.insert(at, special);
                    }
                    _ => bytes.insert(at, special),
                }
            }
            bytes
        })
    }

    #[test]
    fn reads_what_hallpass_writes() {
        let digest = format!("sha256:{}", "0f".repeat(32));
        let spend = format!(
            r#"{{"seq":7,"time":"2026-11-20T09:00:00Z","counter":"calls","n":1,"digest":"{digest}","note":null,"prev":"{digest}"}}"#
        );
        let noted = spend.replace(r#""note":null"#, r#""note":"retry 2""#);
        let debit = format!(
            r#"{{"seq":8,"time":"2026-11-20T09:00:00.5Z","event":"debit","version":1,"charges":[{{"counter":"calls","n":1}},{{"counter":"bytes","n":1200}}],"digest":"{digest}","prev":"{digest}"}}"#
        );
        let receipt = debit.replace(
            r#""prev""#,
            r#""receipt":{"caller_ref":"run-81/unit-a","targets":[{"target":"192.0.2.10:5060/udp","name":"sip.example.net","label":"sip"},{"target":"[2001:db8::1]:443/tcp","label":"edge"}]},"prev""#,
        );
        // Operator text as serde_json writes it: non-ASCII as it is, DEL and
        // C1 controls as they are, `"` and `\` escaped.
        let texts = [
            noted.replace("retry 2", "retry 2 – café ✓ 再試行"),
            noted.replace("retry 2", "\u{7f} and \u{85}"),
            noted.replace("retry 2", r#"replay of \"login\" from C:\\tmp\\"#),
            noted.replace("retry 2", r#"\"\\\""#),
            receipt.replace("run-81/unit-a", r#"run \"81\" – unit\\a"#),
        ];
        // Lines written under a test clock carry the marker before `prev`.
        let marked = [
            spend.replace(r#","prev""#, r#","test_clock":true,"prev""#),
            receipt.replace(r#"},"prev""#, r#"},"test_clock":true,"prev""#),
        ];
        for line in [&spend, &noted, &debit, &receipt]
            .into_iter()
            .chain(&texts)
            .chain(&marked)
        {
            assert!(by_reader(line.as_bytes()).is_some(), "{line}");
            assert_eq!(by_reader(line.as_bytes()), by_serde(line.as_bytes()));
        }
        let Some(Line::Spend(escaped)) = read(&texts[3]) else {
            panic!("{}", texts[3]);
        };
        assert_eq!(escaped.note.as_deref(), Some(r#""\""#));
        // Valid JSON in another spelling is left to serde_json, other escapes
        // included.
        for other in [
            spend.replace(r#""n":1"#, r#""n": 1"#),
            spend.replace("calls", r"c\u0061lls"),
            noted.replace("retry 2", r"retry\/2"),
            noted.replace("retry 2", r"retry\n2"),
            noted.replace("retry 2", r#"\"retry\u00e9\""#),
            spend.replace(r#","note":null"#, ""),
            receipt.replace(r#""caller_ref":"run-81/unit-a","#, r#""caller_ref":null,"#),
            receipt.replace(r#","name":"sip.example.net""#, r#","name":null"#),
            debit.replace(r#""prev""#, r#""receipt":{"targets":[]},"prev""#),
            spend.replace(r#","prev""#, r#","test_clock":false,"prev""#),
            debit.replace(r#","prev""#, r#","test_clock":null,"prev""#),
            format!("{spend} "),
        ] {
            assert!(by_reader(other.as_bytes()).is_none(), "{other}");
            assert!(by_serde(other.as_bytes()).is_some(), "{other}");
        }
        // Lines serde_json refuses are refused here too.
        for bad in [
            spend.replace(r#""seq":7"#, r#""seq":07"#),
            spend.replace(r#""n":1"#, r#""n":1.0"#),
            spend.replace(r#""n":1"#, r#""n":18446744073709551616"#),
            spend.replace(r#""n":1"#, r#""n":-1"#),
            spend.replace("calls", "cal\tls"),
            noted.replace("retry 2", "retry \\\" 2\t"),
            noted.replace("retry 2", r"retry 2\"),
            noted.replace("retry 2", r"retry 2\x"),
            noted.replace("retry 2", r"retry 2\u12"),
            debit.replace(r#""version":1"#, r#""version":4294967296"#),
            format!("{spend}}}"),
        ] {
            assert!(by_reader(bad.as_bytes()).is_none(), "{bad}");
            assert!(by_serde(bad.as_bytes()).is_none(), "{bad}");
        }
    }

    /// A ledger for pass `t` with one debit per receipt, each recording `targets`.
    fn ledger_with_targets(lines: &[&str]) -> String {
        let header = r#"{"hallpass_ledger":1,"pass_id":"t"}"#;
        let digest = crate::Digest::of(b"pass");
        let mut tail = crate::Digest::of(header.as_bytes());
        let mut out = format!("{header}\n");
        for (seq, targets) in (1..).zip(lines) {
            let line = format!(
                r#"{{"seq":{seq},"time":"2026-11-20T09:00:00Z","event":"debit","version":1,"charges":[{{"counter":"calls","n":1}}],"digest":"{digest}","receipt":{{"targets":[{targets}]}},"prev":"{tail}"}}"#
            );
            tail = crate::Digest::of(line.as_bytes());
            out.push_str(&line);
            out.push('\n');
        }
        out
    }

    #[test]
    fn pass_digests_are_checked_on_every_line() {
        // A ledger for pass `t` with one spend or debit per digest text.
        let scan = |digests: &[&str]| {
            let header = r#"{"hallpass_ledger":1,"pass_id":"t"}"#;
            let mut tail = crate::Digest::of(header.as_bytes());
            let mut text = format!("{header}\n");
            for (seq, digest) in (1..).zip(digests) {
                let line = if seq % 2 == 0 {
                    format!(
                        r#"{{"seq":{seq},"time":"2026-11-20T09:00:00Z","counter":"calls","n":1,"digest":"{digest}","note":null,"prev":"{tail}"}}"#
                    )
                } else {
                    format!(
                        r#"{{"seq":{seq},"time":"2026-11-20T09:00:00Z","event":"debit","version":1,"charges":[{{"counter":"calls","n":1}}],"digest":"{digest}","prev":"{tail}"}}"#
                    )
                };
                tail = crate::Digest::of(line.as_bytes());
                text.push_str(&line);
                text.push('\n');
            }
            let path = std::path::Path::new("t");
            super::super::parse_ledger(path, text.as_bytes(), "t", true, None).map(|parsed| {
                let spends = parsed.entries.iter().map(|e| (e.seq, e.digest));
                let debits = parsed.debits.iter().map(|d| (d.seq, d.digest));
                let mut all: Vec<_> = spends.chain(debits).collect();
                all.sort_unstable_by_key(|(seq, _)| *seq);
                all.into_iter()
                    .map(|(_, digest)| digest)
                    .collect::<Vec<_>>()
            })
        };
        let (a, b) = (crate::Digest::of(b"a"), crate::Digest::of(b"b"));
        let (a_text, b_text) = (a.to_string(), b.to_string());
        let read = scan(&[&a_text, &a_text, &b_text, &b_text, &a_text]).expect("valid");
        assert_eq!(read, [a, a, b, b, a]);
        // A digest read before does not excuse a different text.
        for bad in [
            a_text.to_uppercase(),
            a_text.replace("sha256:", "sha256 "),
            format!("{a_text}0"),
            a_text[..a_text.len() - 1].to_owned(),
        ] {
            for digests in [
                vec![a_text.as_str(), bad.as_str()],
                vec![a_text.as_str(), a_text.as_str(), bad.as_str()],
                vec![
                    a_text.as_str(),
                    a_text.as_str(),
                    a_text.as_str(),
                    bad.as_str(),
                ],
            ] {
                assert!(scan(&digests).is_err(), "{digests:?}");
            }
        }
    }

    #[test]
    fn recorded_targets_are_checked_on_every_line() {
        let scan = |lines: &[&str]| {
            let text = ledger_with_targets(lines);
            super::super::parse_ledger(std::path::Path::new("t"), text.as_bytes(), "t", false, None)
                .map(|parsed| parsed.tally.entries)
        };
        let web = r#"{"target":"192.0.2.10:443/tcp","name":"app.example.com","label":"web"}"#;
        assert_eq!(scan(&[web, web, web]).ok(), Some(3));
        // A target remembered as valid does not excuse a different one.
        for bad in [
            web.replace("192.0.2.10:443", "192.0.2.10:0443"),
            web.replace("app.example.com", "App.example.com"),
            web.replace(r#""web""#, r#""web site""#),
        ] {
            let pair = format!("{web},{bad}");
            for lines in [
                vec![web, bad.as_str()],
                vec![web, &pair],
                vec![web, web, &pair],
            ] {
                assert!(scan(&lines).is_err(), "{lines:?}");
            }
        }
        // More distinct targets than are remembered are still each checked.
        let many: Vec<String> = (1..=super::super::debit::KNOWN_TARGETS + 4)
            .map(|i| web.replace("192.0.2.10:443", &format!("192.0.2.{i}:443")))
            .collect();
        let mut lines: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(
            scan(&lines).ok(),
            Some(u64::try_from(lines.len()).expect("few"))
        );
        let bad = web.replace("192.0.2.10:443", "192.0.2.99:00443");
        lines.push(&bad);
        assert!(scan(&lines).is_err());
    }

    #[test]
    fn decode_does_not_depend_on_the_guessed_shape() {
        let digest = format!("sha256:{}", "0f".repeat(32));
        let debit = format!(
            r#"{{"seq":8,"time":"t","event":"debit","version":1,"charges":[{{"counter":"calls","n":1}}],"digest":"{digest}","prev":"{digest}"}}"#
        );
        let adopt = format!(
            r#"{{"seq":9,"time":"t","event":"adopt","reason":"r","digest":"{digest}","carried":{{"calls":1}},"witness":null,"prev":"{digest}"}}"#
        );
        // A debit or adoption whose key is spelled differently is still that
        // shape, although the guess (by the plain key) says otherwise.
        for line in [
            debit.replace(r#""charges":"#, r#""charges" :"#),
            debit.replace(r#""charges":"#, r#""ch\u0061rges":"#),
            adopt.replace(r#""carried":"#, r#""carried" :"#),
            adopt.replace(r#""carried":"#, r#""c\u0061rried":"#),
            // A spend whose note mentions the debit key is still a spend.
            format!(
                r#"{{"seq":7,"time":"t","counter":"calls","n":1,"digest":"{digest}","note":"\"charges\":","prev":"{digest}"}}"#
            ),
        ] {
            assert!(Line::decode(line.as_bytes()).is_some(), "{line}");
            decodes_as_untagged(line.as_bytes()).expect("same as untagged");
        }
    }

    /// Bytes around every edge of the word-at-a-time scan, and any byte.
    fn scan_bytes() -> impl Strategy<Value = Vec<u8>> {
        let edge = proptest::sample::select(vec![
            0x00, 0x01, 0x1f, 0x20, 0x21, b'"', 0x23, 0x5b, b'\\', 0x5d, 0x7f, 0x80, 0x9f, 0xa2,
            0xdc, 0xfe, 0xff, b'a',
        ]);
        proptest::collection::vec(prop_oneof![3 => edge, 1 => any::<u8>()], 0..40)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        #[test]
        fn scan_stops_at_the_first_quote_backslash_or_control(bytes in scan_bytes()) {
            let first = bytes.iter().position(|b| *b == b'"' || *b == b'\\' || *b < 0x20);
            prop_assert_eq!(stop(&bytes), first);
        }

        #[test]
        fn plain_lines_are_read_directly(
            line in prop_oneof![spend_line(true), debit_line(true)]
        ) {
            prop_assert!(by_reader(line.as_bytes()).is_some(), "{}", line);
            agrees(line.as_bytes())?;
        }

        #[test]
        fn written_lines_read_the_same(
            line in prop_oneof![spend_line(false), debit_line(false)]
        ) {
            agrees(line.as_bytes())?;
        }

        #[test]
        fn decode_accepts_what_untagged_serde_accepts(line in any_line()) {
            decodes_as_untagged(line.as_bytes())?;
        }

        #[test]
        fn decode_refuses_what_untagged_serde_refuses(
            bytes in any_line().prop_flat_map(damaged)
        ) {
            decodes_as_untagged(&bytes)?;
        }

        #[test]
        fn damaged_lines_are_never_read_differently(
            bytes in prop_oneof![spend_line(false), debit_line(false)].prop_flat_map(damaged)
        ) {
            agrees(&bytes)?;
        }
    }
}
