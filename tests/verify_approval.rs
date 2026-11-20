#![cfg(feature = "cli")]
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

const PASS: &str = include_str!("../docs/review-approval.toml");

fn keygen(dir: &Path, args: &[&str]) {
    let out = Command::new("ssh-keygen")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("OpenSSH ssh-keygen");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn call(dir: &Path, args: &[&str], code: i32, empty_path: bool) -> Value {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-21T10:00:00Z")
        .arg("--json")
        .args(args);
    if empty_path {
        cmd.env("PATH", dir);
    }
    let out = cmd.output().expect("run");
    assert_eq!(
        out.status.code(),
        Some(code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("json")
}

#[test]
fn signature_binds_principal_namespace_and_exact_validated_bytes() {
    let dir = tempfile::tempdir().expect("private directory");
    let dir = dir.path();
    for (key, trust) in [("owner", "trust"), ("other", "other-trust")] {
        keygen(dir, &["-q", "-t", "ed25519", "-N", "", "-f", key]);
        let public = fs::read_to_string(dir.join(format!("{key}.pub"))).expect("public key");
        fs::write(dir.join(trust), format!("owner@example.org {public}")).expect("trust");
    }
    for (file, ns) in [("approval", "hallpass-approval-v1"), ("wrong", "file")] {
        fs::write(dir.join(file), PASS).expect("pass");
        fs::set_permissions(dir.join(file), fs::Permissions::from_mode(0o600))
            .expect("private pass");
        keygen(dir, &["-q", "-Y", "sign", "-f", "owner", "-n", ns, file]);
    }
    let args = |sig, trust, id| {
        [
            "verify-approval",
            "approval",
            "--principal",
            id,
            "--signature",
            sig,
            "--allowed-signers",
            trust,
        ]
    };
    let ok_args = args("approval.sig", "trust", "owner@example.org");
    let verified = call(dir, &ok_args, 0, false);
    assert_eq!(verified["result"], "verified");
    assert_eq!(verified["principal"], "owner@example.org");
    assert_eq!(verified["pass_id"], "review-example");
    assert_eq!(
        verified["digest"],
        hallpass::Digest::of(PASS.as_bytes()).to_string()
    );
    let pin = verified["digest"].as_str().expect("pin");
    let query = [
        "permits",
        "approval",
        "--to",
        "192.0.2.10:443/tcp@app.example.com",
        "--digest",
        pin,
    ];
    assert_eq!(call(dir, &query, 2, false)["refusal"]["code"], "expired");
    for invalid in [
        args("wrong.sig", "trust", "owner@example.org"),
        args("approval.sig", "other-trust", "owner@example.org"),
        args("approval.sig", "trust", "untrusted"),
    ] {
        assert_eq!(call(dir, &invalid, 2, false)["result"], "unverified");
    }
    let missing = call(dir, &ok_args, 1, true);
    assert!(
        missing["error"]["message"]
            .as_str()
            .expect("message")
            .contains("Install OpenSSH")
    );
    fs::write(dir.join("approval"), format!("{PASS}\n# changed\n")).expect("edit");
    assert_eq!(call(dir, &ok_args, 2, false)["result"], "unverified");
    assert_eq!(
        call(dir, &query, 2, false)["refusal"]["code"],
        "pass-changed"
    );
    assert!(!dir.join("state").exists());
}
