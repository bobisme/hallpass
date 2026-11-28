//! The commented template `hallpass init` writes.

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::error::Error;

/// The template: every field present and explained, nothing approved. It
/// does not validate until it is filled in (it has no destination and
/// empty names), so it can never be used by mistake.
pub const TEMPLATE: &str = r#"# hallpass pass: the written permission slip for one authorized test.
# Fill it in from the owner's WRITTEN approval only. See docs/PASS-FORMAT.md.
# Then run `hallpass check FILE` until it reports no problems.
#
# Nothing here is approved yet: there are no destinations, so this pass
# permits nothing.

format = 1

# A stable id for this approval (letters, digits, . _ -). The ledger beside
# this file belongs to this id; a new approval gets a new pass file.
id = ""

# A short human name.
name = ""

# If every debit must check a destination, uncomment the next line.
# Without it, spend can charge a counter without a target.
# require_target_v1 = true

# If every debit must charge specific counters, list them here and set each
# total under [ceilings]. A ceiling alone only limits that counter when charged.
# required_counters_v1 = ["requests", "bytes"]

[approval]
# Who approved (the owner of the destinations), and where the written
# approval is (for example "email of 2026-11-18 from the owner").
owner = ""
reference = ""
# Who runs the test.
operator = ""

# The window, as RFC 3339 timestamps with an explicit offset (Z or +01:00).
# valid_from is the first second allowed; valid_until is the first second
# no longer allowed. A timestamp without an offset is refused.
valid_from = ""
valid_until = ""

# Set to true when the owner withdraws the approval. A spend in progress
# reads this file again and stops.
revoked = false
# revoked_reason = "owner asked to stop on 2026-11-20 at 10:15"

# One [[destination]] per literal address or network the owner approved.
# Hostnames are never authorization: `hostname` only records the name the
# owner uses.
#
# [[destination]]
# label = "sip-edge"              # unique; named in every decision
# address = "192.0.2.10"          # one literal IP, or instead:
# network = "192.0.2.0/28"        # a CIDR (no host bits set)
# protocol = "udp"                # "tcp" or "udp"
# ports = [5060, "10000-10100"]   # a port, a list, or "start-end" ranges
# hostname = "sip.example.net"    # informational only; grants nothing
#
# When the address also serves other parties (a CDN, shared hosting), list
# the only host names the owner approved on it. This narrows and never
# grants: a tool must ask with one of these names and send only that name.
# names = ["app.example.net"]
#
# A network broader than /24 (IPv4) or /64 (IPv6) is refused unless the
# written approval names that whole network; then add:
# whole_network_approved = true

[ceilings]
# Named counters with the total the owner approved. Each tool defines its
# own units. `hallpass spend FILE COUNTER` records spends in the ledger
# beside this file, across every process.
# calls = 6
# requests = 500
# bytes = 1000000
"#;

/// Write the template to `path`, mode 0600. Never overwrites.
///
/// # Errors
///
/// [`Error::Exists`] when anything (a file or a link) is already at `path`,
/// or [`Error::Io`].
pub fn write_template(path: &Path) -> Result<(), Error> {
    write_new_private(path, TEMPLATE.as_bytes())
}

/// Create the file `path` with `bytes`, mode 0600 whatever the umask.
///
/// Never overwrites and never follows a link: anything already at `path`, a
/// dangling link included, is refused. A partly written file is removed.
///
/// # Errors
///
/// [`Error::Exists`] when anything (a file or a link) is already at `path`,
/// or [`Error::Io`].
pub fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if path.symlink_metadata().is_ok() {
        return Err(Error::Exists {
            path: path.to_path_buf(),
        });
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Exists {
                    path: path.to_path_buf(),
                }
            } else {
                Error::io(path, &e)
            }
        })?;
    // The mode given to open is cut by the umask, which can only clear bits.
    crate::files::write_within_size_limit(&mut file, bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| {
            let _ = std::fs::remove_file(path);
            Error::io(path, &e)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pass::Pass;

    #[test]
    fn template_permits_nothing() {
        let problems = Pass::parse(TEMPLATE).expect_err("must not validate");
        let fields: Vec<&str> = problems.iter().map(|p| p.field.as_str()).collect();
        assert!(fields.contains(&"destination"), "{fields:?}");
        assert!(fields.contains(&"approval.owner"), "{fields:?}");
        assert!(fields.contains(&"approval.valid_until"), "{fields:?}");
    }

    #[test]
    fn filled_template_validates() {
        let filled = TEMPLATE
            .replace("id = \"\"", "id = \"t1\"")
            .replace("name = \"\"", "name = \"T\"")
            .replace("owner = \"\"", "owner = \"O\"")
            .replace("reference = \"\"", "reference = \"R\"")
            .replace("operator = \"\"", "operator = \"P\"")
            .replace("valid_from = \"\"", "valid_from = 2026-11-20T08:00:00Z")
            .replace("valid_until = \"\"", "valid_until = 2026-11-20T12:00:00Z")
            .replace("# [[destination]]", "[[destination]]")
            .replace("# label", "label")
            .replace("# address", "address")
            .replace("# protocol", "protocol")
            .replace("# ports", "ports")
            .replace("# hostname", "hostname")
            .replace("# calls", "calls");
        let pass = Pass::parse(&filled).expect("valid");
        assert_eq!(pass.ceilings.get("calls"), Some(&6));
        assert!(!pass.require_target);
        assert_eq!(pass.required_counters, Vec::<String>::new());

        let metered = filled
            .replace("# require_target_v1 =", "require_target_v1 =")
            .replace("# required_counters_v1 =", "required_counters_v1 =")
            .replace("# requests =", "requests =")
            .replace("# bytes =", "bytes =");
        let pass = Pass::parse(&metered).expect("uncommented debit requirements validate");
        assert!(pass.require_target);
        assert_eq!(pass.required_counters, ["bytes", "requests"]);
    }
}
