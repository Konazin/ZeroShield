//! Hash signature database: built-ins, imports (ClamAV `.hdb`, ZeroShield CSV,
//! plain hash lists) and lookups.

use std::path::Path;
use std::sync::Arc;

use zs_core::error::{ZsError, ZsResult};
use zs_core::model::{Detection, Hashes, Severity};
use zs_core::storage::Storage;

use crate::builtins::{self, score_for_severity};
use crate::hash::algo_of;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigFormat {
    /// Detect from the file extension.
    Auto,
    /// ClamAV `.hdb`: `md5:size:name`
    ClamHdb,
    /// ZeroShield CSV: `sha256,name,severity,description`
    ZeroShieldCsv,
    /// One hash (optionally followed by a name) per line.
    PlainHashes,
}

/// Make sure the built-in signatures exist in storage.
pub fn seed_storage(storage: &Storage) -> ZsResult<u64> {
    let mut n = 0;
    for sig in builtins::builtin_signatures() {
        let mut hashes = Vec::new();
        if let Some(h) = sig.sha256 {
            hashes.push((h, "sha256"));
        }
        if let Some(h) = sig.sha1 {
            hashes.push((h, "sha1"));
        }
        if let Some(h) = sig.md5 {
            hashes.push((h, "md5"));
        }
        for (hash, algo) in hashes {
            storage.insert_signature(
                hash,
                algo,
                sig.name,
                sig.severity,
                sig.description,
                "builtin",
            )?;
            n += 1;
        }
    }
    Ok(n)
}

/// Lookup order: storage (imported/community signatures) then built-ins.
pub fn lookup(storage: Option<&Arc<Storage>>, hashes: &Hashes) -> ZsResult<Option<Detection>> {
    if let Some(storage) = storage {
        if let Some(row) = storage.lookup_signature(hashes)? {
            return Ok(Some(
                Detection::new(
                    "signature",
                    format!("signature/{}", row.name),
                    format!("{} ({})", row.description, row.name),
                    score_for_severity(row.severity),
                )
                .with_tag("signature"),
            ));
        }
    }
    Ok(builtins::lookup_builtin(hashes))
}

/// Parse a signature file and store its entries. Returns the number imported.
pub fn import_file(storage: &Storage, path: &Path, format: SigFormat) -> ZsResult<u64> {
    let text = std::fs::read_to_string(path).map_err(|e| ZsError::io(path, e))?;
    let fmt = match format {
        SigFormat::Auto => match path.extension().and_then(|e| e.to_str()) {
            Some("hdb") | Some("hsb") => SigFormat::ClamHdb,
            Some("csv") => SigFormat::ZeroShieldCsv,
            _ => SigFormat::PlainHashes,
        },
        other => other,
    };
    let source = format!(
        "import:{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("signatures")
    );

    let mut imported = 0u64;
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let parsed = match fmt {
            SigFormat::ClamHdb => parse_clam_line(line),
            SigFormat::ZeroShieldCsv => parse_csv_line(line),
            SigFormat::PlainHashes | SigFormat::Auto => parse_plain_line(line),
        };
        match parsed {
            Some((hash, name, severity, description)) => {
                let Some(algo) = algo_of(&hash) else {
                    tracing::warn!(
                        "{}:{}: '{}' is not a valid md5/sha1/sha256 hash; skipping",
                        path.display(),
                        lineno + 1,
                        hash
                    );
                    continue;
                };
                storage.insert_signature(&hash, algo, &name, severity, &description, &source)?;
                imported += 1;
            }
            None => {
                tracing::warn!(
                    "{}:{}: skipping unparsable signature",
                    path.display(),
                    lineno + 1
                );
            }
        }
    }
    Ok(imported)
}

type ParsedSig = (String, String, Severity, String);

fn parse_clam_line(line: &str) -> Option<ParsedSig> {
    // md5:size:name  (size is ignored; some databases use '*' for any size)
    let mut parts = line.splitn(3, ':');
    let hash = parts.next()?.trim().to_ascii_lowercase();
    let _size = parts.next()?.trim();
    let name = parts.next()?.trim().to_string();
    if hash.len() != 32 {
        return None;
    }
    Some((
        hash,
        name.clone(),
        Severity::High,
        format!("ClamAV signature: {name}"),
    ))
}

fn parse_csv_line(line: &str) -> Option<ParsedSig> {
    // sha256,name,severity,description
    let mut parts = line.splitn(4, ',');
    let hash = parts.next()?.trim().to_ascii_lowercase();
    let name = parts.next()?.trim().to_string();
    let severity = parts
        .next()
        .map(Severity::from_str_lenient)
        .unwrap_or(Severity::High);
    let description = parts
        .next()
        .unwrap_or("imported signature")
        .trim()
        .to_string();
    if hash.is_empty() || name.is_empty() {
        return None;
    }
    Some((hash, name, severity, description))
}

fn parse_plain_line(line: &str) -> Option<ParsedSig> {
    let mut parts = line.split_whitespace();
    let hash = parts.next()?.trim().to_ascii_lowercase();
    let name = parts
        .next()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "imported-signature".to_string());
    Some((
        hash,
        name.clone(),
        Severity::High,
        format!("community signature: {name}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_and_looks_up_eicar() {
        let storage = Storage::open_in_memory().unwrap();
        let n = seed_storage(&storage).unwrap();
        assert!(n >= 3);
        let hashes = Hashes {
            sha256: builtins::EICAR_SHA256.into(),
            sha1: builtins::EICAR_SHA1.into(),
            md5: builtins::EICAR_MD5.into(),
            size: 68,
        };
        let det = lookup(Some(&Arc::new(storage)), &hashes).unwrap().unwrap();
        assert!(det.name.contains("EICAR"));
        assert_eq!(det.score, 100);
    }

    #[test]
    fn imports_clam_hdb() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("test.hdb");
        std::fs::write(
            &p,
            "# comment\n44d88612fea8a8f36de82e1278abb02f:68:Test.Sig.Name\nbadline\n",
        )
        .unwrap();
        let storage = Storage::open_in_memory().unwrap();
        let n = import_file(&storage, &p, SigFormat::Auto).unwrap();
        assert_eq!(n, 1);
        assert_eq!(storage.signature_count().unwrap(), 1);
    }

    #[test]
    fn imports_csv() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("list.csv");
        std::fs::write(
            &p,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,demo,high,demo sig\n",
        )
        .unwrap();
        let storage = Storage::open_in_memory().unwrap();
        let n = import_file(&storage, &p, SigFormat::Auto).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn imports_plain_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("hashes.txt");
        std::fs::write(
            &p,
            "3395856ce81f2b7382dee72602f798b642f14140 sha1-demo\nzzzz\n",
        )
        .unwrap();
        let storage = Storage::open_in_memory().unwrap();
        let n = import_file(&storage, &p, SigFormat::Auto).unwrap();
        assert_eq!(n, 1);
    }
}
