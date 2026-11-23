//! A direct reader for ledger lines in the one spelling hallpass writes.
//!
//! JSON allows many spellings of one record (any key order, spaces, escapes).
//! Nearly every line of a real ledger has the spelling that hallpass itself
//! writes: keys in declaration order, no spaces, and short ASCII strings without
//! escapes. This reader accepts only that spelling of a legacy spend or a debit
//! (with or without a receipt). It declines everything else, adoptions
//! included, and `serde_json` then decodes the line as before.
//!
//! The reader never accepts a line that `serde_json` refuses, and it never
//! decodes a value differently. An accepted line is a JSON object with exactly
//! the fields of one record shape. Each string contains only printable ASCII
//! other than `"` and `\`, so its value is its own bytes. Each number is a plain
//! unsigned integer without leading zeros that fits its field. The tests compare
//! this reader with `serde_json`.

use super::Entry;
use super::debit::{DebitCharge, DebitLine, DebitReceipt, RecordedTarget};

/// Read a legacy spend or a debit line, or `None` for `serde_json` to decode.
pub(super) fn read(line: &[u8]) -> Option<super::Line> {
    let mut at = Cursor(line);
    at.tag(br#"{"seq":"#)?;
    let seq = at.number()?;
    at.tag(br#","time":""#)?;
    let time = at.text()?;
    if at.tag(br#","counter":""#).is_some() {
        spend(at, seq, time).map(super::Line::Spend)
    } else {
        at.tag(br#","event":""#)?;
        debit(at, seq, time).map(super::Line::Debit)
    }
}

fn spend(mut at: Cursor<'_>, seq: u64, time: String) -> Option<Entry> {
    let counter = at.text()?;
    at.tag(br#","n":"#)?;
    let n = at.number()?;
    at.tag(br#","digest":""#)?;
    let digest = at.text()?;
    let note = if at.tag(br#","note":null"#).is_some() {
        None
    } else {
        at.tag(br#","note":""#)?;
        Some(at.text()?)
    };
    at.tag(br#","prev":""#)?;
    let prev = at.text()?;
    at.end()?;
    Some(Entry {
        seq,
        time,
        counter,
        n,
        digest,
        note,
        prev,
    })
}

fn debit(mut at: Cursor<'_>, seq: u64, time: String) -> Option<DebitLine> {
    let event = at.text()?;
    at.tag(br#","version":"#)?;
    let version = u32::try_from(at.number()?).ok()?;
    at.tag(br#","charges":["#)?;
    let mut charges = Vec::new();
    loop {
        at.tag(br#"{"counter":""#)?;
        let counter = at.text()?;
        at.tag(br#","n":"#)?;
        let amount = at.number()?;
        at.tag(b"}")?;
        charges.push(DebitCharge { counter, amount });
        if at.tag(b",").is_none() {
            break;
        }
    }
    at.tag(br#"],"digest":""#)?;
    let digest = at.text()?;
    let note = if at.tag(br#","note":""#).is_some() {
        Some(at.text()?)
    } else {
        None
    };
    let receipt = if at.tag(br#","receipt":{"#).is_some() {
        Some(receipt(&mut at)?)
    } else {
        None
    };
    at.tag(br#","prev":""#)?;
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
        prev,
    })
}

/// The rest of a receipt whose opening brace was consumed.
fn receipt(at: &mut Cursor<'_>) -> Option<DebitReceipt> {
    let caller_ref = if at.tag(br#""caller_ref":""#).is_some() {
        Some(at.text()?)
    } else {
        None
    };
    let targets_key: &[u8] = if caller_ref.is_some() {
        br#","targets":["#
    } else {
        br#""targets":["#
    };
    let mut targets = Vec::new();
    if at.tag(targets_key).is_some() {
        loop {
            at.tag(br#"{"target":""#)?;
            let target = at.text()?;
            let name = if at.tag(br#","name":""#).is_some() {
                Some(at.text()?)
            } else {
                None
            };
            at.tag(br#","label":""#)?;
            let label = at.text()?;
            at.tag(b"}")?;
            targets.push(RecordedTarget {
                target,
                name,
                label,
            });
            if at.tag(b",").is_none() {
                break;
            }
        }
        at.tag(b"]")?;
    }
    at.tag(b"}")?;
    Some(DebitReceipt {
        caller_ref,
        targets,
    })
}

/// The unread rest of a line.
struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    /// Consume exactly `literal`.
    fn tag(&mut self, literal: &[u8]) -> Option<()> {
        self.0 = self.0.strip_prefix(literal)?;
        Some(())
    }

    /// The whole line has been read.
    fn end(&mut self) -> Option<()> {
        self.tag(b"}")?;
        self.0.is_empty().then_some(())
    }

    /// A JSON number that is a plain unsigned integer: `0`, or a digit other
    /// than `0` followed by digits, no larger than `u64::MAX`. A fraction or an
    /// exponent leaves a byte that the next tag refuses.
    fn number(&mut self) -> Option<u64> {
        let len = self.0.iter().take_while(|b| b.is_ascii_digit()).count();
        let (digits, rest) = self.0.split_at(len);
        if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
            return None;
        }
        let mut value = 0u64;
        for digit in digits {
            value = value
                .checked_mul(10)?
                .checked_add(u64::from(digit - b'0'))?;
        }
        self.0 = rest;
        Some(value)
    }

    /// The rest of a string whose opening quote was consumed, through the
    /// closing quote: printable ASCII other than `\`, so without escapes.
    fn text(&mut self) -> Option<String> {
        let len = self
            .0
            .iter()
            .position(|b| !(b' '..=b'~').contains(b) || matches!(b, b'"' | b'\\'))?;
        let (text, rest) = self.0.split_at(len);
        self.0 = rest.strip_prefix(b"\"")?;
        std::str::from_utf8(text).ok().map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{AdoptLine, Line, WitnessLine};
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
        Adopt(AdoptLine),
    }

    fn encode(line: &Line) -> String {
        match line {
            Line::Spend(entry) => serde_json::to_string(entry),
            Line::Debit(debit) => serde_json::to_string(debit),
            Line::Adopt(adopt) => serde_json::to_string(adopt),
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
                Untagged::Adopt(adopt) => Line::Adopt(adopt),
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
        serde_json::from_slice::<AdoptLine>(line)
            .ok()
            .and_then(|adopt| serde_json::to_string(&adopt).ok())
    }

    fn by_reader(line: &[u8]) -> Option<String> {
        match read(line)? {
            Line::Spend(entry) => serde_json::to_string(&entry).ok(),
            Line::Debit(debit) => serde_json::to_string(&debit).ok(),
            Line::Adopt(adopt) => serde_json::to_string(&adopt).ok(),
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

    /// Printable ASCII other than `"` and `\\`: strings the reader reads.
    const PLAIN: &str = "[ !#-\\[\\]-~]{0,24}";

    /// Any string; with `plain`, only strings that need no escape.
    fn text(plain: bool) -> BoxedStrategy<String> {
        if plain {
            return PLAIN.boxed();
        }
        prop_oneof![
            4 => PLAIN,
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

    /// A legacy spend line as hallpass writes it, from arbitrary values.
    fn spend_line(plain: bool) -> impl Strategy<Value = String> {
        (
            number(),
            text(plain),
            text(plain),
            number(),
            text(plain),
            proptest::option::of(text(plain)),
            text(plain),
        )
            .prop_map(|(seq, time, counter, n, digest, note, prev)| {
                let entry = Entry {
                    seq,
                    time,
                    counter,
                    n,
                    digest,
                    note,
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
            text(plain),
        )
            .prop_map(
                |((seq, time, event, version), charges, (digest, note), receipt, prev)| {
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
            (text(false), text(false)),
        )
            .prop_map(
                |((seq, time, event, reason), carried, witness, (digest, prev))| {
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
                        }),
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
        for line in [&spend, &noted, &debit, &receipt] {
            assert!(by_reader(line.as_bytes()).is_some(), "{line}");
            assert_eq!(by_reader(line.as_bytes()), by_serde(line.as_bytes()));
        }
        // Valid JSON in another spelling is left to serde_json.
        for other in [
            spend.replace(r#""n":1"#, r#""n": 1"#),
            spend.replace("calls", r"c\u0061lls"),
            spend.replace(r#","note":null"#, ""),
            receipt.replace(r#""caller_ref":"run-81/unit-a","#, r#""caller_ref":null,"#),
            receipt.replace(r#","name":"sip.example.net""#, r#","name":null"#),
            debit.replace(r#""prev""#, r#""receipt":{"targets":[]},"prev""#),
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

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
