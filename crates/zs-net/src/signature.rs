//! Detached OpenPGP signature verification for threat feeds.
//!
//! Verification shells out to `gpgv` (same philosophy as downloads via
//! `curl`): the keyring is passed explicitly, no `~/.gnupg` state is read
//! and the daemon never writes to a GPG home. A missing `gpgv`, keyring or
//! signature is an error — callers must treat any failure as "do not trust
//! this feed" (fail-closed).

use std::path::Path;
use std::process::Command;

use zs_core::error::{ZsError, ZsResult};

/// Upper bound for a detached signature file.
pub const MAX_SIGNATURE_BYTES: u64 = 1024 * 1024;

/// Suffix convention for the detached signature of a feed URL
/// (`https://host/feed.txt` → `https://host/feed.txt.asc`).
pub const SUFFIX: &str = ".asc";

/// Verify `data` against the detached signature `signature` using the
/// public keyring `keyring` (binary format, as produced by `gpg --export`).
///
/// Returns `Ok(())` only on a cryptographically valid signature from a key
/// present in the keyring.
pub fn verify_detached(keyring: &Path, signature: &Path, data: &Path) -> ZsResult<()> {
    let output = Command::new("gpgv")
        .arg("--keyring")
        .arg(keyring)
        .arg(signature)
        .arg(data)
        .output()
        .map_err(|e| ZsError::Security(format!("failed to run gpgv: {e}")))?;

    if output.status.success() {
        tracing::debug!(
            "feed signature verified: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let reason = stderr
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no details from gpgv");
    Err(ZsError::Security(format!(
        "feed signature rejected: {reason}"
    )))
}

/// Ephemeral GPG key fixture for hermetic signature tests.
#[cfg(test)]
pub(crate) mod testutil {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    pub struct GpgFixture {
        pub home: tempfile::TempDir,
        pub keyring: PathBuf,
        pub uid: &'static str,
    }

    /// Whether the local `gpg`/`gpgv` tools are usable. Tests that need a
    /// real key call [`available`] first and skip politely when the tools
    /// are absent, unless `ZS_REQUIRE_GPG` is set (CI installs `gnupg` and
    /// sets it, so a missing toolchain fails loudly there instead of
    /// silently skipping coverage).
    pub fn available() -> bool {
        let has = |bin: &str| {
            Command::new(bin)
                .arg("--version")
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false)
        };
        let ok = has("gpg") && has("gpgv");
        if !ok {
            assert!(
                std::env::var_os("ZS_REQUIRE_GPG").is_none(),
                "gpg/gpgv not found but ZS_REQUIRE_GPG is set (install gnupg)"
            );
            eprintln!("skipping GPG-dependent test: gpg/gpgv not installed");
        }
        ok
    }

    /// Generate an ephemeral signing key in a private GNUPGHOME and export
    /// its public part as a binary keyring for `gpgv`.
    pub fn fixture() -> GpgFixture {
        let uid = "ZeroShield Test Key <feed@zeroshield.invalid>";
        let home = tempfile::tempdir().unwrap();
        let out = Command::new("gpg")
            .env("GNUPGHOME", home.path())
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                uid,
                "ed25519",
                "sign",
                "0",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "quick-generate-key failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let out = Command::new("gpg")
            .env("GNUPGHOME", home.path())
            .arg("--export")
            .output()
            .unwrap();
        assert!(out.status.success(), "gpg --export failed");
        assert!(!out.stdout.is_empty(), "exported keyring is empty");
        let keyring = home.path().join("feeds.gpg");
        std::fs::write(&keyring, &out.stdout).unwrap();

        GpgFixture { home, keyring, uid }
    }

    /// Write an armored detached signature of `data` to `sig`.
    pub fn sign(fixture: &GpgFixture, data: &Path, sig: &Path) {
        let out = Command::new("gpg")
            .env("GNUPGHOME", fixture.home.path())
            .args([
                "--batch",
                "--yes",
                "--armor",
                "--detach-sign",
                "--local-user",
                fixture.uid,
                "--output",
            ])
            .arg(sig)
            .arg(data)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "detach-sign failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{available, fixture, sign};
    use super::*;

    #[test]
    fn verifies_valid_detached_signature() {
        if !available() {
            return;
        }
        let fx = fixture();
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("feed.txt");
        let sig = dir.path().join("feed.txt.asc");
        std::fs::write(&data, b"203.0.113.7\nmalware.example\n").unwrap();
        sign(&fx, &data, &sig);

        verify_detached(&fx.keyring, &sig, &data).expect("valid signature must verify");
    }

    #[test]
    fn rejects_tampered_data() {
        if !available() {
            return;
        }
        let fx = fixture();
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("feed.txt");
        let sig = dir.path().join("feed.txt.asc");
        std::fs::write(&data, b"203.0.113.7\n").unwrap();
        sign(&fx, &data, &sig);

        // Attacker swaps the content after the signature was made.
        std::fs::write(&data, b"203.0.113.7\nattacker.example\n").unwrap();
        let err = verify_detached(&fx.keyring, &sig, &data).unwrap_err();
        assert!(
            err.to_string().contains("rejected"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_signature_from_unknown_key() {
        if !available() {
            return;
        }
        let signer = fixture();
        let other = fixture();
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("feed.txt");
        let sig = dir.path().join("feed.txt.asc");
        std::fs::write(&data, b"203.0.113.7\n").unwrap();
        sign(&signer, &data, &sig);

        // Valid signature, but the key is not in this keyring.
        verify_detached(&other.keyring, &sig, &data).unwrap_err();
    }

    #[test]
    fn missing_files_are_errors_not_panics() {
        let dir = tempfile::tempdir().unwrap();
        let err = verify_detached(
            &dir.path().join("nope.gpg"),
            &dir.path().join("nope.asc"),
            &dir.path().join("nope.txt"),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("gpgv") || msg.contains("rejected"),
            "unexpected error: {msg}"
        );
    }
}
