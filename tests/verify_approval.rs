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

#[test]
fn archive_retains_the_snapshot_sent_to_the_verifier_after_path_replacement() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("private directory");
    let dir = dir.path();
    keygen(dir, &["-q", "-t", "ed25519", "-N", "", "-f", "owner"]);
    let public = fs::read_to_string(dir.join("owner.pub")).expect("public key");
    fs::write(dir.join("trust"), format!("owner@example.org {public}")).expect("trust");
    let original = PASS.replace('\n', "\r\n");
    fs::write(dir.join("approval"), &original).expect("pass");
    fs::set_permissions(dir.join("approval"), fs::Permissions::from_mode(0o600))
        .expect("private pass");
    keygen(
        dir,
        &[
            "-q",
            "-Y",
            "sign",
            "-f",
            "owner",
            "-n",
            "hallpass-approval-v1",
            "approval",
        ],
    );

    let real = Command::new("which")
        .arg("ssh-keygen")
        .output()
        .expect("which ssh-keygen");
    assert!(real.status.success());
    let real = String::from_utf8(real.stdout).expect("path");
    let wrapper = dir.join("bin");
    fs::create_dir(&wrapper).expect("bin");
    let capture = dir.join("captured");
    let script = "#!/bin/sh\n/usr/bin/cat > \"$HALLPASS_TEST_CAPTURE\"\nprintf '\\n# replaced after verifier read\\n' >> \"$HALLPASS_TEST_SOURCE\"\nexec \"$HALLPASS_TEST_REAL\" \"$@\" < \"$HALLPASS_TEST_CAPTURE\"\n";
    let shim = wrapper.join("ssh-keygen");
    fs::write(&shim, script).expect("shim");
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).expect("executable shim");

    let archive = dir.join("archive");
    fs::create_dir(&archive).expect("archive");
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("private archive");
    let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .current_dir(dir)
        .env("HOME", dir)
        .env("PATH", &wrapper)
        .env("HALLPASS_TEST_CAPTURE", &capture)
        .env("HALLPASS_TEST_SOURCE", dir.join("approval"))
        .env("HALLPASS_TEST_REAL", real.trim())
        .arg("--json")
        .args([
            "verify-approval",
            "approval",
            "--signature",
            "approval.sig",
            "--allowed-signers",
            "trust",
            "--principal",
            "owner@example.org",
            "--archive",
        ])
        .arg(&archive)
        .output()
        .expect("verify");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(value["archive"], archive.display().to_string());
    assert_eq!(
        value["digest"],
        hallpass::Digest::of(original.as_bytes()).to_string()
    );
    let digest = value["digest"]
        .as_str()
        .expect("digest text")
        .parse::<hallpass::Digest>()
        .expect("digest");
    assert_eq!(
        hallpass::retrieve_pass(&archive, digest).expect("retrieve"),
        original.as_bytes()
    );
    assert_ne!(
        fs::read(dir.join("approval")).expect("replacement"),
        original.as_bytes()
    );
}

#[test]
fn archive_is_published_only_after_success_and_checks_private_content_addressing() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("private directory");
    let dir = dir.path();
    keygen(dir, &["-q", "-t", "ed25519", "-N", "", "-f", "owner"]);
    let public = fs::read_to_string(dir.join("owner.pub")).expect("public key");
    fs::write(dir.join("trust"), format!("owner@example.org {public}")).expect("trust");
    fs::write(dir.join("approval"), PASS).expect("pass");
    fs::set_permissions(dir.join("approval"), fs::Permissions::from_mode(0o600))
        .expect("private pass");
    keygen(
        dir,
        &[
            "-q",
            "-Y",
            "sign",
            "-f",
            "owner",
            "-n",
            "hallpass-approval-v1",
            "approval",
        ],
    );
    fs::copy(dir.join("approval"), dir.join("approval-wrong-namespace")).expect("copy pass");
    keygen(
        dir,
        &[
            "-q",
            "-Y",
            "sign",
            "-f",
            "owner",
            "-n",
            "wrong-namespace",
            "approval-wrong-namespace",
        ],
    );
    let archive = dir.join("archive");
    fs::create_dir(&archive).expect("archive");
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("private archive");
    let run = |signature: &str, principal: &str, archive_path: &Path| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        cmd.current_dir(dir)
            .env("HOME", dir)
            .arg("--json")
            .args([
                "verify-approval",
                "approval",
                "--signature",
                signature,
                "--allowed-signers",
                "trust",
                "--principal",
                principal,
                "--archive",
            ])
            .arg(archive_path);
        cmd.output().expect("verify")
    };
    let wrong_sig = run("approval.sig", "other@example.org", &archive);
    assert_eq!(wrong_sig.status.code(), Some(2));
    assert_eq!(fs::read_dir(&archive).expect("empty archive").count(), 0);
    let wrong_namespace = run(
        "approval-wrong-namespace.sig",
        "owner@example.org",
        &archive,
    );
    assert_eq!(wrong_namespace.status.code(), Some(2));
    assert_eq!(fs::read_dir(&archive).expect("empty archive").count(), 0);
    let first = run("approval.sig", "owner@example.org", &archive);
    assert_eq!(first.status.code(), Some(0));
    let first: Value = serde_json::from_slice(&first.stdout).expect("json");
    let digest = first["digest"].as_str().expect("digest").to_owned();
    let second = run("approval.sig", "owner@example.org", &archive);
    assert_eq!(second.status.code(), Some(0));
    let second: Value = serde_json::from_slice(&second.stdout).expect("json");
    assert_eq!(second["digest"], digest);
    // The bytes, the signature and its record.
    assert_eq!(fs::read_dir(&archive).expect("one revision").count(), 3);

    let insecure = dir.join("insecure");
    fs::create_dir(&insecure).expect("insecure archive");
    fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755)).expect("mode");
    assert_eq!(
        run("approval.sig", "owner@example.org", &insecure)
            .status
            .code(),
        Some(1)
    );
    let conflict = archive.join(digest);
    fs::write(&conflict, b"bad entry").expect("damage");
    fs::set_permissions(&conflict, fs::Permissions::from_mode(0o600)).expect("private entry");
    assert_eq!(
        run("approval.sig", "owner@example.org", &archive)
            .status
            .code(),
        Some(1)
    );
}
