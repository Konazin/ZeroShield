//! SQLite backed storage: events, findings, scans, hash cache, clean-file
//! cache, signatures, quarantine metadata and network rules.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{ZsError, ZsResult};
use crate::model::{
    Detection, Finding, FindingRow, Hashes, QuarantineEntry, ScanRow, Severity, SignatureRow,
    StoredEvent, Verdict,
};
use crate::util::now_secs;

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    kind     TEXT    NOT NULL,
    severity TEXT    NOT NULL,
    payload  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);

CREATE TABLE IF NOT EXISTS scans (
    id         TEXT PRIMARY KEY,
    ts         INTEGER NOT NULL,
    target     TEXT NOT NULL,
    files      INTEGER NOT NULL,
    bytes      INTEGER NOT NULL,
    findings   INTEGER NOT NULL,
    max_score  INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  TEXT,
    ts       INTEGER NOT NULL,
    path     TEXT NOT NULL,
    score    INTEGER NOT NULL,
    severity TEXT NOT NULL,
    verdict  TEXT NOT NULL,
    payload  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts DESC);

CREATE TABLE IF NOT EXISTS file_hashes (
    path   TEXT PRIMARY KEY,
    size   INTEGER NOT NULL,
    mtime  INTEGER NOT NULL,
    ino    INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    sha1   TEXT NOT NULL,
    md5    TEXT NOT NULL,
    ts     INTEGER NOT NULL
);

-- Files that were fully scanned with no detections. `version` captures the
-- signature/rules state, so a signature update invalidates every entry.
CREATE TABLE IF NOT EXISTS clean_files (
    path    TEXT PRIMARY KEY,
    size    INTEGER NOT NULL,
    mtime   INTEGER NOT NULL,
    version TEXT NOT NULL,
    ts      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_clean_files_ts ON clean_files(ts);

CREATE TABLE IF NOT EXISTS signatures (
    hash        TEXT PRIMARY KEY,
    algo        TEXT NOT NULL,
    name        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    description TEXT NOT NULL,
    source      TEXT NOT NULL,
    ts          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              INTEGER NOT NULL,
    original_path   TEXT NOT NULL,
    file_name       TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    size            INTEGER NOT NULL,
    mode            INTEGER NOT NULL,
    detections      TEXT NOT NULL,
    restored        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS net_rules (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    kind    TEXT NOT NULL,
    value   TEXT NOT NULL,
    source  TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    ts      INTEGER NOT NULL,
    UNIQUE(kind, value)
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

/// Thread-safe storage handle. Uses a single connection guarded by a mutex;
/// all operations are short, local SQLite statements.
pub struct Storage {
    conn: Mutex<Connection>,
}

impl Storage {
    pub fn open(path: &Path) -> ZsResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ZsError::io(parent, e))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| ZsError::Storage(format!("cannot open {}: {e}", path.display())))?;
        Self::from_conn(conn)
    }

    pub fn open_in_memory() -> ZsResult<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| ZsError::Storage(format!("cannot open in-memory db: {e}")))?;
        Self::from_conn(conn)
    }

    fn from_conn(conn: Connection) -> ZsResult<Self> {
        conn.execute_batch(SCHEMA)
            .map_err(|e| ZsError::Storage(format!("schema migration failed: {e}")))?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.set_meta("schema_version", "2")?;
        Ok(storage)
    }

    fn lock(&self) -> ZsResult<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| ZsError::Storage("storage mutex poisoned".into()))
    }

    // ---------------------------------------------------------------- events

    pub fn record_event(
        &self,
        kind: &str,
        severity: Severity,
        payload: &serde_json::Value,
    ) -> ZsResult<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO events (ts, kind, severity, payload) VALUES (?1, ?2, ?3, ?4)",
            params![
                now_secs(),
                kind,
                severity.as_str(),
                serde_json::to_string(payload)?
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_events(&self, limit: u32) -> ZsResult<Vec<StoredEvent>> {
        self.list_events_since(limit, 0)
    }

    /// List events with `ts >= since` (0 means "no lower bound"), newest first.
    pub fn list_events_since(&self, limit: u32, since: i64) -> ZsResult<Vec<StoredEvent>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, ts, kind, severity, payload FROM events
             WHERE ts >= ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since, limit as i64], |row| {
            let payload: String = row.get(4)?;
            Ok(StoredEvent {
                id: row.get(0)?,
                ts: row.get(1)?,
                kind: row.get(2)?,
                severity: Severity::from_str_lenient(&row.get::<_, String>(3)?),
                payload: serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Event count per severity label (`info`, `low`, ...), for metrics.
    pub fn event_counts_by_severity(&self) -> ZsResult<Vec<(String, u64)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT severity, COUNT(*) FROM events GROUP BY severity")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // ---------------------------------------------------------------- scans

    /// Record a finished scan. Flat by design: one row per scan.
    #[allow(clippy::too_many_arguments)]
    pub fn record_scan(
        &self,
        id: &str,
        target: &str,
        files: u64,
        bytes: u64,
        findings: u64,
        max_score: u32,
        duration_ms: u64,
    ) -> ZsResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO scans (id, ts, target, files, bytes, findings, max_score, duration_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                now_secs(),
                target,
                files as i64,
                bytes as i64,
                findings as i64,
                max_score as i64,
                duration_ms as i64
            ],
        )?;
        Ok(())
    }

    pub fn scan_count(&self) -> ZsResult<u64> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// List scans with `ts >= since` (0 means "no lower bound"), newest first.
    pub fn list_scans(&self, limit: u32, since: i64) -> ZsResult<Vec<ScanRow>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, ts, target, files, bytes, findings, max_score, duration_ms
             FROM scans WHERE ts >= ?1 ORDER BY ts DESC, rowid DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since, limit as i64], |row| {
            Ok(ScanRow {
                id: row.get(0)?,
                ts: row.get(1)?,
                target: row.get(2)?,
                files: row.get::<_, i64>(3)? as u64,
                bytes: row.get::<_, i64>(4)? as u64,
                findings: row.get::<_, i64>(5)? as u64,
                max_score: row.get::<_, i64>(6)? as u32,
                duration_ms: row.get::<_, i64>(7)? as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // ------------------------------------------------------------- findings

    pub fn record_finding(&self, scan_id: Option<&str>, f: &Finding) -> ZsResult<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO findings (scan_id, ts, path, score, severity, verdict, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                scan_id,
                now_secs(),
                f.path,
                f.score as i64,
                f.severity.as_str(),
                f.verdict.as_str(),
                serde_json::to_string(f)?
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Number of recorded threats (findings at or above the suspicious level).
    pub fn threat_count(&self) -> ZsResult<u64> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM findings WHERE verdict IN ('malicious', 'suspicious')",
            [],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    /// Number of recorded findings (any verdict).
    pub fn finding_count(&self) -> ZsResult<u64> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn list_findings(&self, limit: u32) -> ZsResult<Vec<Finding>> {
        Ok(self
            .list_findings_rows(limit, 0)?
            .into_iter()
            .map(|row| row.finding)
            .collect())
    }

    /// List findings with `ts >= since` (0 means "no lower bound"), newest
    /// first, keeping the storage metadata (id, ts, scan_id).
    pub fn list_findings_rows(&self, limit: u32, since: i64) -> ZsResult<Vec<FindingRow>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, ts, scan_id, payload FROM findings
             WHERE ts >= ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since, limit as i64], |row| {
            let payload: String = row.get(3)?;
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                payload,
            ))
        })?;
        let mut out = Vec::new();
        for raw in rows {
            let (id, ts, scan_id, raw) = raw?;
            if let Ok(finding) = serde_json::from_str::<Finding>(&raw) {
                out.push(FindingRow {
                    id,
                    ts,
                    scan_id,
                    finding,
                });
            }
        }
        Ok(out)
    }

    // ----------------------------------------------------------- hash cache

    pub fn get_cached_hashes(&self, path: &str, size: u64, mtime: i64) -> ZsResult<Option<Hashes>> {
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT sha256, sha1, md5 FROM file_hashes
                 WHERE path = ?1 AND size = ?2 AND mtime = ?3",
                params![path, size as i64, mtime],
                |row| {
                    Ok(Hashes {
                        sha256: row.get(0)?,
                        sha1: row.get(1)?,
                        md5: row.get(2)?,
                        size,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn put_cached_hashes(
        &self,
        path: &str,
        size: u64,
        mtime: i64,
        ino: u64,
        hashes: &Hashes,
    ) -> ZsResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO file_hashes (path, size, mtime, ino, sha256, sha1, md5, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(path) DO UPDATE SET
                size = excluded.size, mtime = excluded.mtime, ino = excluded.ino,
                sha256 = excluded.sha256, sha1 = excluded.sha1, md5 = excluded.md5,
                ts = excluded.ts",
            params![
                path,
                size as i64,
                mtime,
                ino as i64,
                hashes.sha256,
                hashes.sha1,
                hashes.md5,
                now_secs()
            ],
        )?;
        Ok(())
    }

    /// Drop hash cache entries older than `ttl` seconds.
    pub fn prune_hash_cache(&self, ttl_secs: u64) -> ZsResult<u64> {
        let conn = self.lock()?;
        let cutoff = now_secs() - ttl_secs as i64;
        let n = conn.execute("DELETE FROM file_hashes WHERE ts < ?1", params![cutoff])?;
        Ok(n as u64)
    }

    pub fn hash_cache_len(&self) -> ZsResult<u64> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM file_hashes", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    // ---------------------------------------------------------- clean cache

    /// Was `path` already fully scanned with no detections at this size/mtime
    /// and under the given signature/rules version?
    pub fn is_clean_file(
        &self,
        path: &str,
        size: u64,
        mtime: i64,
        version: &str,
    ) -> ZsResult<bool> {
        let conn = self.lock()?;
        let hit: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM clean_files
                 WHERE path = ?1 AND size = ?2 AND mtime = ?3 AND version = ?4",
                params![path, size as i64, mtime, version],
                |r| r.get(0),
            )
            .optional()?;
        Ok(hit.is_some())
    }

    /// Remember that `path` was scanned clean.
    pub fn mark_clean_file(
        &self,
        path: &str,
        size: u64,
        mtime: i64,
        version: &str,
    ) -> ZsResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO clean_files (path, size, mtime, version, ts)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(path) DO UPDATE SET
                size = excluded.size, mtime = excluded.mtime,
                version = excluded.version, ts = excluded.ts",
            params![path, size as i64, mtime, version, now_secs()],
        )?;
        Ok(())
    }

    /// Drop clean-file entries older than `ttl` seconds and enforce a maximum
    /// entry count (oldest first). Returns the number of removed rows.
    pub fn prune_clean_files(&self, ttl_secs: u64, max_entries: u64) -> ZsResult<u64> {
        let conn = self.lock()?;
        let cutoff = now_secs() - ttl_secs as i64;
        let mut removed = conn.execute("DELETE FROM clean_files WHERE ts < ?1", params![cutoff])?;
        if max_entries > 0 {
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM clean_files", [], |r| r.get(0))?;
            if n as u64 > max_entries {
                let excess = n as u64 - max_entries;
                removed += conn.execute(
                    "DELETE FROM clean_files WHERE path IN (
                        SELECT path FROM clean_files ORDER BY ts ASC, rowid ASC LIMIT ?1
                     )",
                    params![excess as i64],
                )?;
            }
        }
        Ok(removed as u64)
    }

    pub fn clean_cache_len(&self) -> ZsResult<u64> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM clean_files", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn clear_clean_files(&self) -> ZsResult<u64> {
        let conn = self.lock()?;
        let n = conn.execute("DELETE FROM clean_files", [])?;
        Ok(n as u64)
    }

    /// Fingerprint of the hash signature set (count + newest insertion time).
    /// Any import changes it, invalidating the clean-file cache.
    pub fn signature_fingerprint(&self) -> ZsResult<String> {
        let conn = self.lock()?;
        let (count, newest): (i64, i64) = conn.query_row(
            "SELECT COUNT(*), COALESCE(MAX(ts), 0) FROM signatures",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(format!("{count}-{newest}"))
    }

    // ----------------------------------------------------------- signatures

    pub fn insert_signature(
        &self,
        hash: &str,
        algo: &str,
        name: &str,
        severity: Severity,
        description: &str,
        source: &str,
    ) -> ZsResult<()> {
        let hash = hash.trim().to_ascii_lowercase();
        if hash.is_empty() {
            return Ok(());
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO signatures (hash, algo, name, severity, description, source, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(hash) DO UPDATE SET
                name = excluded.name, severity = excluded.severity,
                description = excluded.description, source = excluded.source",
            params![
                hash,
                algo,
                name,
                severity.as_str(),
                description,
                source,
                now_secs()
            ],
        )?;
        Ok(())
    }

    pub fn lookup_signature(&self, hashes: &Hashes) -> ZsResult<Option<SignatureRow>> {
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT hash, algo, name, severity, description, source FROM signatures
                 WHERE hash IN (?1, ?2, ?3) LIMIT 1",
                params![hashes.sha256, hashes.sha1, hashes.md5],
                |row| {
                    Ok(SignatureRow {
                        hash: row.get(0)?,
                        algo: row.get(1)?,
                        name: row.get(2)?,
                        severity: Severity::from_str_lenient(&row.get::<_, String>(3)?),
                        description: row.get(4)?,
                        source: row.get(5)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn signature_count(&self) -> ZsResult<u64> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM signatures", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    // ---------------------------------------------------------- quarantine

    pub fn insert_quarantine(&self, entry: &QuarantineEntry) -> ZsResult<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO quarantine
               (ts, original_path, file_name, quarantine_path, sha256, size, mode, detections, restored)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.ts,
                entry.original_path,
                entry.file_name,
                entry.quarantine_path,
                entry.sha256,
                entry.size as i64,
                entry.mode as i64,
                serde_json::to_string(&entry.detections)?,
                entry.restored as i64
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_quarantine(&self) -> ZsResult<Vec<QuarantineEntry>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, ts, original_path, file_name, quarantine_path, sha256, size, mode, detections, restored
             FROM quarantine ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([], Self::map_quarantine)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn get_quarantine(&self, id: i64) -> ZsResult<Option<QuarantineEntry>> {
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT id, ts, original_path, file_name, quarantine_path, sha256, size, mode, detections, restored
                 FROM quarantine WHERE id = ?1",
                params![id],
                Self::map_quarantine,
            )
            .optional()?;
        Ok(row)
    }

    pub fn mark_restored(&self, id: i64) -> ZsResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE quarantine SET restored = 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn delete_quarantine_row(&self, id: i64) -> ZsResult<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM quarantine WHERE id = ?1", params![id])?;
        Ok(())
    }

    fn map_quarantine(row: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantineEntry> {
        let detections_raw: String = row.get(8)?;
        Ok(QuarantineEntry {
            id: row.get(0)?,
            ts: row.get(1)?,
            original_path: row.get(2)?,
            file_name: row.get(3)?,
            quarantine_path: row.get(4)?,
            sha256: row.get(5)?,
            size: row.get::<_, i64>(6)? as u64,
            mode: row.get::<_, i64>(7)? as u32,
            detections: serde_json::from_str(&detections_raw)
                .unwrap_or_else(|_| Vec::<Detection>::new()),
            restored: row.get::<_, i64>(9)? != 0,
        })
    }

    // ----------------------------------------------------------- net rules

    pub fn upsert_net_rule(&self, kind: &str, value: &str, source: &str) -> ZsResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO net_rules (kind, value, source, enabled, ts)
             VALUES (?1, ?2, ?3, 1, ?4)
             ON CONFLICT(kind, value) DO UPDATE SET source = excluded.source, enabled = 1",
            params![kind, value, source, now_secs()],
        )?;
        Ok(())
    }

    pub fn list_net_rules(&self, enabled_only: bool) -> ZsResult<Vec<(String, String, String)>> {
        let conn = self.lock()?;
        let sql = if enabled_only {
            "SELECT kind, value, source FROM net_rules WHERE enabled = 1 ORDER BY kind, value"
        } else {
            "SELECT kind, value, source FROM net_rules ORDER BY kind, value"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn set_net_rule_enabled(&self, kind: &str, value: &str, enabled: bool) -> ZsResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE net_rules SET enabled = ?3 WHERE kind = ?1 AND value = ?2",
            params![kind, value, enabled as i64],
        )?;
        Ok(())
    }

    pub fn clear_net_rules(&self, source: Option<&str>) -> ZsResult<u64> {
        let conn = self.lock()?;
        let n = match source {
            Some(s) => conn.execute("DELETE FROM net_rules WHERE source = ?1", params![s])?,
            None => conn.execute("DELETE FROM net_rules", [])?,
        };
        Ok(n as u64)
    }

    pub fn net_rule_count(&self) -> ZsResult<u64> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM net_rules WHERE enabled = 1",
            [],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    // ---------------------------------------------------------------- meta

    pub fn set_meta(&self, key: &str, value: &str) -> ZsResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> ZsResult<Option<String>> {
        let conn = self.lock()?;
        let v = conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(v)
    }
}

/// Convenience: verdict from a payload column (used in tests).
pub fn verdict_of(f: &Finding) -> Verdict {
    f.verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Detection;

    fn store() -> Storage {
        Storage::open_in_memory().unwrap()
    }

    fn sample_finding() -> Finding {
        Finding {
            path: "/tmp/eicar.com".into(),
            size: 68,
            hashes: Hashes {
                sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".into(),
                sha1: "3395856ce81f2b7382dee72602f798b642f14140".into(),
                md5: "44d88612fea8a8f36de82e1278abb02f".into(),
                size: 68,
            },
            score: 100,
            severity: Severity::Critical,
            verdict: Verdict::Malicious,
            detections: vec![Detection::new("signature", "eicar", "EICAR test file", 100)],
            quarantined: false,
        }
    }

    #[test]
    fn events_roundtrip() {
        let s = store();
        let payload = serde_json::json!({"hello": "world"});
        s.record_event("info", Severity::Info, &payload).unwrap();
        let events = s.list_events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "info");
        assert_eq!(events[0].payload["hello"], "world");
    }

    #[test]
    fn event_listing_respects_since() {
        let s = store();
        s.record_event("a", Severity::Info, &serde_json::json!({}))
            .unwrap();
        let now = crate::util::now_secs();
        assert_eq!(s.list_events_since(10, 0).unwrap().len(), 1);
        assert_eq!(s.list_events_since(10, now - 60).unwrap().len(), 1);
        assert!(s.list_events_since(10, now + 60).unwrap().is_empty());
    }

    #[test]
    fn event_counts_group_by_severity() {
        let s = store();
        s.record_event("a", Severity::Info, &serde_json::json!({}))
            .unwrap();
        s.record_event("b", Severity::Critical, &serde_json::json!({}))
            .unwrap();
        s.record_event("c", Severity::Critical, &serde_json::json!({}))
            .unwrap();
        let mut counts = s.event_counts_by_severity().unwrap();
        counts.sort();
        assert_eq!(
            counts,
            vec![("critical".to_string(), 2), ("info".to_string(), 1)]
        );
    }

    #[test]
    fn scan_listing_respects_since() {
        let s = store();
        s.record_scan("s1", "/home", 3, 100, 1, 80, 12).unwrap();
        s.record_scan("s2", "/tmp", 1, 10, 0, 0, 3).unwrap();
        let scans = s.list_scans(10, 0).unwrap();
        assert_eq!(scans.len(), 2);
        assert_eq!(s.scan_count().unwrap(), 2);
        let newest = &scans[0];
        assert_eq!(newest.id, "s2");
        assert_eq!(newest.files, 1);
        assert_eq!(newest.findings, 0);
        let now = crate::util::now_secs();
        assert_eq!(s.list_scans(10, now - 60).unwrap().len(), 2);
        assert!(s.list_scans(10, now + 60).unwrap().is_empty());
        assert_eq!(s.list_scans(1, 0).unwrap().len(), 1);
    }

    #[test]
    fn finding_rows_keep_metadata() {
        let s = store();
        let f = sample_finding();
        let id = s.record_finding(Some("scan-1"), &f).unwrap();
        assert!(id > 0);
        let rows = s.list_findings_rows(10, 0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id);
        assert_eq!(rows[0].scan_id.as_deref(), Some("scan-1"));
        assert_eq!(rows[0].finding.path, "/tmp/eicar.com");
        assert_eq!(rows[0].finding.score, 100);
        assert!(rows[0].ts > 0);
        let now = crate::util::now_secs();
        assert_eq!(s.list_findings_rows(10, now - 60).unwrap().len(), 1);
        assert!(s.list_findings_rows(10, now + 60).unwrap().is_empty());
        // The plain listing still returns bare findings.
        assert_eq!(s.list_findings(10).unwrap().len(), 1);
    }

    #[test]
    fn signature_lookup_any_algo() {
        let s = store();
        s.insert_signature(
            "44d88612fea8a8f36de82e1278abb02f",
            "md5",
            "EICAR-Test-File",
            Severity::Critical,
            "test",
            "builtin",
        )
        .unwrap();
        let h = Hashes {
            md5: "44d88612fea8a8f36de82e1278abb02f".into(),
            ..Default::default()
        };
        let found = s.lookup_signature(&h).unwrap().unwrap();
        assert_eq!(found.name, "EICAR-Test-File");
        assert_eq!(s.signature_count().unwrap(), 1);
    }

    #[test]
    fn hash_cache_respects_mtime() {
        let s = store();
        let h = Hashes {
            sha256: "a".into(),
            sha1: "b".into(),
            md5: "c".into(),
            size: 10,
        };
        s.put_cached_hashes("/x", 10, 1000, 1, &h).unwrap();
        assert!(s.get_cached_hashes("/x", 10, 1000).unwrap().is_some());
        assert!(s.get_cached_hashes("/x", 10, 999).unwrap().is_none());
        assert!(s.get_cached_hashes("/x", 11, 1000).unwrap().is_none());
    }

    #[test]
    fn clean_cache_matches_size_mtime_and_version() {
        let s = store();
        assert!(!s.is_clean_file("/x", 10, 1000, "v1").unwrap());
        s.mark_clean_file("/x", 10, 1000, "v1").unwrap();
        assert!(s.is_clean_file("/x", 10, 1000, "v1").unwrap());
        assert!(!s.is_clean_file("/x", 10, 1000, "v2").unwrap());
        assert!(!s.is_clean_file("/x", 10, 999, "v1").unwrap());
        assert!(!s.is_clean_file("/x", 11, 1000, "v1").unwrap());
        assert_eq!(s.clean_cache_len().unwrap(), 1);
        // Re-marking the same path updates in place.
        s.mark_clean_file("/x", 11, 1000, "v1").unwrap();
        assert_eq!(s.clean_cache_len().unwrap(), 1);
        assert!(s.is_clean_file("/x", 11, 1000, "v1").unwrap());
        assert_eq!(s.clear_clean_files().unwrap(), 1);
        assert_eq!(s.clean_cache_len().unwrap(), 0);
    }

    #[test]
    fn clean_cache_prunes_by_ttl_and_max_entries() {
        let s = store();
        for i in 0..5 {
            s.mark_clean_file(&format!("/f{i}"), 1, 1, "v1").unwrap();
        }
        // ttl of zero removes everything older than "now" (ts < now).
        // Give the first entry an old timestamp explicitly.
        {
            let conn = s.lock().unwrap();
            conn.execute("UPDATE clean_files SET ts = 1 WHERE path = '/f0'", [])
                .unwrap();
        }
        assert_eq!(s.prune_clean_files(3600, 0).unwrap(), 1);
        assert_eq!(s.clean_cache_len().unwrap(), 4);
        // Max-entries enforcement drops the oldest rows.
        assert_eq!(s.prune_clean_files(3600, 2).unwrap(), 2);
        assert_eq!(s.clean_cache_len().unwrap(), 2);
    }

    #[test]
    fn signature_fingerprint_changes_on_import() {
        let s = store();
        let before = s.signature_fingerprint().unwrap();
        s.insert_signature("aa", "md5", "t", Severity::Low, "d", "test")
            .unwrap();
        let after = s.signature_fingerprint().unwrap();
        assert_ne!(before, after);
        // Re-importing the same hash does not change the fingerprint.
        s.insert_signature("aa", "md5", "t", Severity::Low, "d", "test")
            .unwrap();
        assert_eq!(s.signature_fingerprint().unwrap(), after);
    }

    #[test]
    fn findings_and_counts() {
        let s = store();
        s.record_finding(Some("scan-1"), &sample_finding()).unwrap();
        s.record_scan("scan-1", "/tmp", 1, 68, 1, 100, 5).unwrap();
        assert_eq!(s.threat_count().unwrap(), 1);
        assert_eq!(s.scan_count().unwrap(), 1);
        assert_eq!(s.list_findings(10).unwrap().len(), 1);
    }

    #[test]
    fn quarantine_crud() {
        let s = store();
        let entry = QuarantineEntry {
            id: 0,
            ts: now_secs(),
            original_path: "/tmp/eicar.com".into(),
            file_name: "eicar.com".into(),
            quarantine_path: "/data/quarantine/aaa.zsq".into(),
            sha256: "275a...".into(),
            size: 68,
            mode: 0o644,
            detections: vec![],
            restored: false,
        };
        let id = s.insert_quarantine(&entry).unwrap();
        assert_eq!(s.list_quarantine().unwrap().len(), 1);
        s.mark_restored(id).unwrap();
        assert!(s.get_quarantine(id).unwrap().unwrap().restored);
        s.delete_quarantine_row(id).unwrap();
        assert!(s.list_quarantine().unwrap().is_empty());
    }

    #[test]
    fn net_rules_upsert_and_clear() {
        let s = store();
        s.upsert_net_rule("ip", "10.0.0.0/8", "user").unwrap();
        s.upsert_net_rule("ip", "10.0.0.0/8", "user").unwrap();
        s.upsert_net_rule("domain", "evil.example", "feed:test")
            .unwrap();
        assert_eq!(s.net_rule_count().unwrap(), 2);
        s.set_net_rule_enabled("ip", "10.0.0.0/8", false).unwrap();
        assert_eq!(s.net_rule_count().unwrap(), 1);
        assert_eq!(s.clear_net_rules(Some("feed:test")).unwrap(), 1);
        assert_eq!(s.net_rule_count().unwrap(), 0);
    }
}
