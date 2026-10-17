//! Quarantine store: moves malicious files out of reach (mode 000) keeps
//! metadata in storage and supports restore/purge.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use zs_core::error::{ZsError, ZsResult};
use zs_core::model::{Finding, QuarantineEntry};
use zs_core::storage::Storage;
use zs_core::util::now_secs;

use crate::QUARANTINE_EXT;

pub struct Quarantine {
    dir: PathBuf,
    storage: Arc<Storage>,
}

impl Quarantine {
    pub fn new(dir: PathBuf, storage: Arc<Storage>) -> ZsResult<Self> {
        std::fs::create_dir_all(&dir).map_err(|e| ZsError::io(&dir, e))?;
        set_mode(&dir, 0o700)?;
        Ok(Self { dir, storage })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn list(&self) -> ZsResult<Vec<QuarantineEntry>> {
        self.storage.list_quarantine()
    }

    /// Move a file into quarantine. The file is made unreadable (mode 000).
    pub fn quarantine(&self, path: &Path, finding: &Finding) -> ZsResult<QuarantineEntry> {
        use std::os::unix::fs::MetadataExt;

        let meta = std::fs::symlink_metadata(path).map_err(|e| ZsError::io(path, e))?;
        if !meta.is_file() {
            return Err(ZsError::Scan(format!(
                "cannot quarantine non regular file {}",
                path.display()
            )));
        }
        let original_mode = meta.mode() & 0o7777;

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed")
            .to_string();
        let sha = if finding.hashes.sha256.is_empty() {
            "unknown".to_string()
        } else {
            finding.hashes.sha256.clone()
        };

        let target = self.unique_target(&sha);
        move_file(path, &target)?;
        set_mode(&target, 0o000)?;

        let entry = QuarantineEntry {
            id: 0,
            ts: now_secs(),
            original_path: path.display().to_string(),
            file_name,
            quarantine_path: target.display().to_string(),
            sha256: sha,
            size: meta.len(),
            mode: original_mode,
            detections: finding.detections.clone(),
            restored: false,
        };
        let id = self.storage.insert_quarantine(&entry)?;
        tracing::info!(
            "quarantined {} -> {} (id {})",
            entry.original_path,
            entry.quarantine_path,
            id
        );
        Ok(QuarantineEntry { id, ..entry })
    }

    /// Restore an entry to its original path. Fails if the destination exists.
    pub fn restore(&self, id: i64) -> ZsResult<QuarantineEntry> {
        let entry = self
            .storage
            .get_quarantine(id)?
            .ok_or_else(|| ZsError::NotFound(format!("quarantine entry {id}")))?;
        if entry.restored {
            return Err(ZsError::Scan(format!(
                "quarantine entry {id} was already restored"
            )));
        }
        let qpath = PathBuf::from(&entry.quarantine_path);
        if !qpath.exists() {
            return Err(ZsError::NotFound(format!(
                "quarantined file {}",
                qpath.display()
            )));
        }
        let dest = PathBuf::from(&entry.original_path);
        if dest.exists() {
            return Err(ZsError::Scan(format!(
                "destination {} already exists, refusing to overwrite",
                dest.display()
            )));
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ZsError::io(parent, e))?;
        }
        // Make the file readable again before moving it back.
        set_mode(&qpath, 0o600)?;
        move_file(&qpath, &dest)?;
        set_mode(&dest, entry.mode)?;
        self.storage.mark_restored(id)?;
        tracing::info!(
            "restored {} -> {}",
            entry.quarantine_path,
            entry.original_path
        );
        Ok(entry)
    }

    /// Delete a quarantined file permanently.
    pub fn purge(&self, id: i64) -> ZsResult<()> {
        let entry = self
            .storage
            .get_quarantine(id)?
            .ok_or_else(|| ZsError::NotFound(format!("quarantine entry {id}")))?;
        let qpath = PathBuf::from(&entry.quarantine_path);
        if qpath.exists() {
            // Mode 000 prevents removal? Removal only needs the parent dir.
            std::fs::remove_file(&qpath).map_err(|e| ZsError::io(&qpath, e))?;
        }
        self.storage.delete_quarantine_row(id)?;
        Ok(())
    }

    fn unique_target(&self, sha: &str) -> PathBuf {
        let base = self.dir.join(format!("{sha}.{QUARANTINE_EXT}"));
        if !base.exists() {
            return base;
        }
        for i in 1..10_000 {
            let candidate = self.dir.join(format!("{sha}-{i}.{QUARANTINE_EXT}"));
            if !candidate.exists() {
                return candidate;
            }
        }
        base
    }
}

fn set_mode(path: &Path, mode: u32) -> ZsResult<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| ZsError::io(path, e))
}

/// Move a file, falling back to copy+remove across filesystems.
fn move_file(from: &Path, to: &Path) -> ZsResult<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(from, to).map_err(|e| ZsError::io(to, e))?;
            std::fs::remove_file(from).map_err(|e| ZsError::io(from, e))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zs_core::model::{Detection, Hashes, Severity, Verdict};

    fn setup() -> (tempfile::TempDir, Quarantine, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open_in_memory().unwrap());
        let q = Quarantine::new(dir.path().join("q"), storage).unwrap();
        let file = dir.path().join("evil.bin");
        std::fs::write(&file, b"malicious").unwrap();
        (dir, q, file)
    }

    fn finding() -> Finding {
        Finding {
            path: "/x".into(),
            size: 9,
            hashes: Hashes {
                sha256: "a".repeat(64),
                sha1: "b".repeat(40),
                md5: "c".repeat(32),
                size: 9,
            },
            score: 100,
            severity: Severity::Critical,
            verdict: Verdict::Malicious,
            detections: vec![Detection::new("test", "test/sig", "test", 100)],
            quarantined: false,
        }
    }

    #[test]
    fn quarantine_then_restore() {
        let (_dir, q, file) = setup();
        let entry = q.quarantine(&file, &finding()).unwrap();
        assert!(!file.exists());
        assert!(Path::new(&entry.quarantine_path).exists());

        // mode 000
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&entry.quarantine_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0);

        let restored = q.restore(entry.id).unwrap();
        assert!(file.exists());
        assert_eq!(restored.original_path, file.display().to_string());
        assert!(q.list().unwrap()[0].restored);
    }

    #[test]
    fn restore_refuses_to_overwrite() {
        let (_dir, q, file) = setup();
        let entry = q.quarantine(&file, &finding()).unwrap();
        std::fs::write(&file, b"new file appeared").unwrap();
        assert!(q.restore(entry.id).is_err());
    }

    #[test]
    fn purge_removes_everything() {
        let (_dir, q, file) = setup();
        let entry = q.quarantine(&file, &finding()).unwrap();
        q.purge(entry.id).unwrap();
        assert!(!Path::new(&entry.quarantine_path).exists());
        assert!(q.list().unwrap().is_empty());
    }
}
