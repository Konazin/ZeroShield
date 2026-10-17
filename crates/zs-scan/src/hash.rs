//! Streaming file hashing (SHA-256, SHA-1, MD5 in a single pass).

use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha1::Sha1;
use sha2::{Digest, Sha256};

use md5::Md5;
use zs_core::error::{ZsError, ZsResult};
use zs_core::model::Hashes;

const CHUNK: usize = 1024 * 1024;

/// Hash a file, returning all three digests and its size.
pub fn hash_file(path: &Path) -> ZsResult<Hashes> {
    let file = File::open(path).map_err(|e| ZsError::io(path, e))?;
    hash_reader(file, path)
}

pub fn hash_reader<R: Read>(mut reader: R, path: &Path) -> ZsResult<Hashes> {
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut md5 = Md5::new();
    let mut size: u64 = 0;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = reader.read(&mut buf).map_err(|e| ZsError::io(path, e))?;
        if n == 0 {
            break;
        }
        size += n as u64;
        sha256.update(&buf[..n]);
        sha1.update(&buf[..n]);
        md5.update(&buf[..n]);
    }
    Ok(Hashes {
        sha256: hex::encode(sha256.finalize()),
        sha1: hex::encode(sha1.finalize()),
        md5: hex::encode(md5.finalize()),
        size,
    })
}

/// Guess the hash algorithm from the digest length.
pub fn algo_of(hash: &str) -> Option<&'static str> {
    match hash.len() {
        32 => Some("md5"),
        40 => Some("sha1"),
        64 => Some("sha256"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_known_content() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        std::fs::write(&p, b"abc").unwrap();
        let h = hash_file(&p).unwrap();
        assert_eq!(h.size, 3);
        assert_eq!(
            h.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn identifies_algo() {
        assert_eq!(algo_of(&"a".repeat(64)), Some("sha256"));
        assert_eq!(algo_of("zzz"), None);
    }

    #[test]
    fn hashes_eicar() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("eicar.com");
        std::fs::write(&p, crate::builtins::eicar_bytes()).unwrap();
        let h = hash_file(&p).unwrap();
        assert_eq!(h.md5, crate::builtins::EICAR_MD5);
    }
}
