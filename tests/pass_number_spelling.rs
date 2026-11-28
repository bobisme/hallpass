//! Number and port spellings in a pass file (bn-2ew).
//!
//! `-0` is zero written with a sign, so it is refused the way `+0` is: by
//! the literal check, with the same message. A quoted single port such as
//! `"443"` is not a documented form: a quoted string is a range, so the
//! port is refused with a message that says to write it as a number.

use hallpass::{Pass, Problem};

const BASE: &str = "format = 1
id = \"spelling-1\"
name = \"Number spelling\"
[approval]
owner = \"Pat Owner\"
reference = \"CHG-1\"
operator = \"Sam Tester\"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false
[[destination]]
label = \"web\"
address = \"192.0.2.10\"
protocol = \"tcp\"
ports = 443
[ceilings]
calls = 100
";

fn problems(text: &str) -> Vec<Problem> {
    Pass::parse(text).expect_err("refused")
}

fn literal_message(raw: &str) -> String {
    format!(
        "is written as `{raw}`{}; write the number in plain decimal digits, without a sign, `_` or a base prefix such as 0x, so a reviewer reads the number hallpass uses",
        if raw == "+0" || raw == "-0" {
            " (TOML reads it as 0)"
        } else {
            ""
        }
    )
}

#[test]
fn a_zero_with_a_sign_is_refused_like_a_plus_zero() {
    for raw in ["+0", "-0"] {
        let found = problems(&BASE.replace("calls = 100", &format!("calls = {raw}")));
        assert_eq!(
            found,
            vec![Problem {
                field: "ceilings.calls".to_owned(),
                message: literal_message(raw),
            }],
            "{raw}"
        );
    }
}

#[test]
fn a_negative_number_that_is_not_zero_keeps_its_own_message() {
    let found = problems(&BASE.replace("calls = 100", "calls = -1"));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].field, "ceilings.calls");
    assert!(
        !found[0].message.contains("plain decimal digits"),
        "{found:?}"
    );
}

#[test]
fn a_signed_zero_is_refused_in_every_integer_field_it_covers() {
    // The format version, a ceiling and a port: each goes through the
    // literal check.
    let cases = [
        ("format = 1", "format = -0", "format"),
        ("ports = 443", "ports = -0", "destination[1].ports"),
        ("ports = 443", "ports = [80, -0]", "destination[1].ports[2]"),
    ];
    for (from, to, field) in cases {
        let found = problems(&BASE.replace(from, to));
        assert!(
            found
                .iter()
                .any(|p| p.field == field && p.message == literal_message("-0")),
            "{to}: {found:?}"
        );
    }
}

#[test]
fn a_quoted_single_port_is_refused_and_named() {
    for ports in ["\"443\"", "[80, \"443\"]"] {
        let found = problems(&BASE.replace("ports = 443", &format!("ports = {ports}")));
        assert_eq!(found.len(), 1, "{ports}: {found:?}");
        assert_eq!(found[0].field, "destination[1].ports", "{ports}");
        assert_eq!(
            found[0].message,
            "\"443\" is a port in quotes; write the port as a number, for example 443. Quotes are for a range such as \"8000-8100\"",
            "{ports}"
        );
    }
}

#[test]
fn numbers_and_ranges_in_their_documented_spellings_are_accepted() {
    for ports in [
        "443",
        "[80, 443]",
        "\"8000-8100\"",
        "[5060, \"10000-10100\"]",
    ] {
        Pass::parse(&BASE.replace("ports = 443", &format!("ports = {ports}")))
            .unwrap_or_else(|found| panic!("{ports}: {found:?}"));
    }
}
