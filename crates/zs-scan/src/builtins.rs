//! Built-in detection material that ships with ZeroShield.
//!
//! The EICAR test file is assembled at runtime from fragments. This keeps the
//! repository itself clean (most antivirus scanners flag source files that
//! contain the literal string) while still allowing an exact content match.

use zs_core::model::{Detection, Hashes, Severity};

const EICAR_PARTS: [&[u8]; 5] = [
    b"X5O!P%@AP[4",
    b"\\PZX54(P^)7CC)7}",
    b"$EICAR-STANDARD-",
    b"ANTIVIRUS-TEST-FILE!",
    b"$H+H*",
];

/// The 68-byte EICAR test file content.
pub fn eicar_bytes() -> Vec<u8> {
    let mut out = Vec::with_capacity(68);
    for part in EICAR_PARTS {
        out.extend_from_slice(part);
    }
    out
}

/// Well-known hashes of the EICAR test file.
pub const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
pub const EICAR_SHA1: &str = "3395856ce81f2b7382dee72602f798b642f14140";
pub const EICAR_MD5: &str = "44d88612fea8a8f36de82e1278abb02f";

pub struct BuiltinSig {
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub sha256: Option<&'static str>,
    pub sha1: Option<&'static str>,
    pub md5: Option<&'static str>,
}

pub fn builtin_signatures() -> &'static [BuiltinSig] {
    &[BuiltinSig {
        name: "EICAR-Test-File",
        description: "Standard antivirus test file (not real malware)",
        severity: Severity::Critical,
        sha256: Some(EICAR_SHA256),
        sha1: Some(EICAR_SHA1),
        md5: Some(EICAR_MD5),
    }]
}

/// Score assigned to a detection of the given severity.
pub fn score_for_severity(severity: Severity) -> u32 {
    match severity {
        Severity::Critical => 100,
        Severity::High => 80,
        Severity::Medium => 55,
        Severity::Low => 30,
        Severity::Info => 15,
    }
}

/// Hash based lookup against the built-in signatures (works without storage).
pub fn lookup_builtin(hashes: &Hashes) -> Option<Detection> {
    for sig in builtin_signatures() {
        let hit = sig.sha256.map(|h| h == hashes.sha256).unwrap_or(false)
            || sig.sha1.map(|h| h == hashes.sha1).unwrap_or(false)
            || sig.md5.map(|h| h == hashes.md5).unwrap_or(false);
        if hit {
            return Some(
                Detection::new(
                    "signature",
                    format!("signature/{}", sig.name),
                    format!("{} ({})", sig.description, sig.name),
                    score_for_severity(sig.severity),
                )
                .with_tag("signature"),
            );
        }
    }
    None
}

/// Check a content buffer against built-in content signatures (EICAR et al).
pub fn content_checks(buf: &[u8]) -> Vec<Detection> {
    let mut out = Vec::new();
    if contains(buf, &eicar_bytes()) {
        out.push(
            Detection::new(
                "builtin",
                "builtin/eicar",
                "EICAR standard antivirus test file detected",
                100,
            )
            .with_tag("eicar"),
        );
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eicar_assembled_correctly() {
        let e = eicar_bytes();
        assert_eq!(e.len(), 68);
        assert!(String::from_utf8_lossy(&e).starts_with("X5O!P%@AP[4\\PZX54"));
        assert!(String::from_utf8_lossy(&e).ends_with("FILE!$H+H*"));
    }

    #[test]
    fn detects_eicar_content_and_hash() {
        let dets = content_checks(&eicar_bytes());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].name, "builtin/eicar");

        let h = Hashes {
            sha256: EICAR_SHA256.into(),
            sha1: EICAR_SHA1.into(),
            md5: EICAR_MD5.into(),
            size: 68,
        };
        assert!(lookup_builtin(&h).is_some());
        assert!(lookup_builtin(&Hashes::default()).is_none());
    }
}
