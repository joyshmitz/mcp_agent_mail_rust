#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn am_bin() -> PathBuf {
    // Cargo sets this for integration tests.
    PathBuf::from(std::env::var("CARGO_BIN_EXE_am").expect("CARGO_BIN_EXE_am must be set"))
}

fn run_am(args: &[&str]) -> std::process::Output {
    Command::new(am_bin())
        .args(args)
        .output()
        .expect("failed to spawn am")
}

fn write_manifest(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("manifest.json");
    std::fs::write(&path, content).expect("write manifest");
    path
}

fn write_test_signing_key(dir: &Path) -> PathBuf {
    // 32 bytes (ed25519 signing key seed).
    let key_path = dir.join("test.key");
    let key: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    std::fs::write(&key_path, key).expect("write signing key");
    key_path
}

fn mutate_base64(s: &str) -> String {
    // Keep length and character set valid but ensure different string.
    let mut chars: Vec<char> = s.chars().collect();
    for c in &mut chars {
        if *c == 'A' {
            *c = 'B';
            return chars.into_iter().collect();
        }
        if c.is_ascii_alphanumeric() || *c == '+' || *c == '/' {
            *c = 'A';
            return chars.into_iter().collect();
        }
    }
    // Fallback (shouldn't happen for real base64).
    format!("{s}A")
}

#[test]
fn share_verify_ok_with_signature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest = write_manifest(dir.path(), r#"{"test": true}"#);
    let key_path = write_test_signing_key(dir.path());
    let sig_path = dir.path().join("manifest.sig.json");
    mcp_agent_mail_share::sign_manifest(&manifest, &key_path, &sig_path, false)
        .expect("sign manifest");

    let out = run_am(&["share", "verify", dir.path().to_str().unwrap()]);
    assert!(
        out.status.success(),
        "expected success, got status={:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn share_verify_fails_on_tampered_manifest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest = write_manifest(dir.path(), r#"{"test": true}"#);
    let key_path = write_test_signing_key(dir.path());
    let sig_path = dir.path().join("manifest.sig.json");
    mcp_agent_mail_share::sign_manifest(&manifest, &key_path, &sig_path, false)
        .expect("sign manifest");

    // Tamper after signing.
    write_manifest(dir.path(), r#"{"test": false, "tampered": true}"#);

    let out = run_am(&["share", "verify", dir.path().to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "expected failure\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn share_verify_public_key_override_is_used() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest = write_manifest(dir.path(), r#"{"test": true}"#);
    let key_path = write_test_signing_key(dir.path());
    let sig_path = dir.path().join("manifest.sig.json");
    mcp_agent_mail_share::sign_manifest(&manifest, &key_path, &sig_path, false)
        .expect("sign manifest");

    let sig_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sig_path).expect("read sig"))
            .expect("parse sig json");
    let embedded = sig_json
        .get("public_key")
        .and_then(|v| v.as_str())
        .expect("embedded public_key");
    let wrong = mutate_base64(embedded);

    let out = run_am(&[
        "share",
        "verify",
        dir.path().to_str().unwrap(),
        "--public-key",
        &wrong,
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected signature failure with overridden key\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn share_decrypt_rejects_identity_plus_passphrase() {
    let dir = tempfile::tempdir().expect("tempdir");
    let encrypted = dir.path().join("bundle.zip.age");
    std::fs::write(&encrypted, b"not really age data").expect("write dummy age file");
    let identity = dir.path().join("identity.key");
    std::fs::write(&identity, b"not really an identity").expect("write dummy identity");

    let out = run_am(&[
        "share",
        "decrypt",
        encrypted.to_str().unwrap(),
        "-i",
        identity.to_str().unwrap(),
        "-p",
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected failure\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("passphrase cannot be combined"),
        "stderr should mention mutual exclusion, got:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn try_generate_age_identity(dir: &Path) -> Option<(PathBuf, String)> {
    let identity_path = dir.join("identity.txt");
    let out = Command::new("age-keygen")
        .arg("-o")
        .arg(&identity_path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let combined =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    let recipient = combined
        .lines()
        .find(|line| line.contains("public key:"))
        .and_then(|line| line.split_whitespace().last())
        .map(|s| s.to_string())?;
    Some((identity_path, recipient))
}

#[test]
fn share_decrypt_roundtrip_identity_default_output() {
    // Requires age + age-keygen CLIs.
    let dir = tempfile::tempdir().expect("tempdir");
    let Some((identity_path, recipient)) = try_generate_age_identity(dir.path()) else {
        eprintln!("Skipping: age-keygen not available");
        return;
    };

    let input = dir.path().join("bundle.zip");
    std::fs::write(&input, b"test bundle data").expect("write input");

    let encrypted = match mcp_agent_mail_share::encrypt_with_age(&input, &[recipient]) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Skipping: age CLI not available");
            return;
        }
    };

    // Omit -o to exercise default output path behavior.
    let out = run_am(&[
        "share",
        "decrypt",
        encrypted.to_str().unwrap(),
        "-i",
        identity_path.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "expected success\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let output_path = mcp_agent_mail_share::default_decrypt_output(&encrypted);
    assert!(
        output_path.exists(),
        "expected output at {}",
        output_path.display()
    );
    let original = std::fs::read(&input).expect("read original");
    let decrypted = std::fs::read(&output_path).expect("read decrypted");
    assert_eq!(original, decrypted);
}
