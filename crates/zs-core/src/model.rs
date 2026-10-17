//! Shared data models used across crates and serialized over IPC.

use serde::{Deserialize, Serialize};

/// Score at which a target is considered malicious.
pub const SCORE_MALICIOUS: u32 = 70;
/// Score at which a target is considered suspicious.
pub const SCORE_SUSPICIOUS: u32 = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(score: u32) -> Self {
        match score {
            s if s >= 80 => Severity::Critical,
            s if s >= 60 => Severity::High,
            s if s >= 40 => Severity::Medium,
            s if s >= 20 => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn from_str_lenient(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    Error,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Suspicious => "suspicious",
            Verdict::Malicious => "malicious",
            Verdict::Error => "error",
        }
    }

    pub fn from_score(score: u32) -> Self {
        if score >= SCORE_MALICIOUS {
            Verdict::Malicious
        } else if score >= SCORE_SUSPICIOUS {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Cryptographic hashes of a file (hex encoded).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hashes {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub size: u64,
}

/// A single detection contributed by one engine (signature, rule, heuristic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Engine that produced the detection, e.g. `signature`, `yara-like`, `elf-heuristic`.
    pub source: String,
    /// Stable identifier, e.g. `signature/eicar`, `elf/rwx_segment`.
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub score: u32,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Detection {
    pub fn new(
        source: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        score: u32,
    ) -> Self {
        Self {
            source: source.into(),
            name: name.into(),
            description: description.into(),
            severity: Severity::from_score(score),
            score,
            tags: Vec::new(),
        }
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

/// Result of scanning a single file that crossed the reporting threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub path: String,
    pub size: u64,
    pub hashes: Hashes,
    pub score: u32,
    pub severity: Severity,
    pub verdict: Verdict,
    pub detections: Vec<Detection>,
    #[serde(default)]
    pub quarantined: bool,
}

/// Options controlling a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanOptions {
    pub recursive: bool,
    pub follow_symlinks: bool,
    pub max_file_size: u64,
    pub min_report_score: u32,
    pub quarantine: bool,
    pub content_scan: bool,
    pub hash_cache: bool,
    /// Reuse the verdict of files already scanned clean (unchanged size/mtime
    /// and same signature/rules version).
    pub clean_cache: bool,
    /// Persist a row for this scan in the history (disabled for per-file scans
    /// issued by the real-time watcher).
    pub record: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            follow_symlinks: false,
            max_file_size: 512 * 1024 * 1024,
            min_report_score: 20,
            quarantine: false,
            content_scan: true,
            hash_cache: true,
            clean_cache: true,
            record: true,
        }
    }
}

/// Summary of a finished scan (embedded in the `scan_finished` event).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub target: String,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub files_skipped: u64,
    pub errors: u64,
    pub findings: u64,
    pub max_score: u32,
    pub verdict: Verdict,
    pub duration_ms: u64,
    /// Files whose verdict came from the clean-file cache.
    #[serde(default)]
    pub cached: u64,
}

/// Full scan report returned by the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: String,
    pub target: String,
    pub started_at: i64,
    pub duration_ms: u64,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub files_skipped: u64,
    pub errors: u64,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
    pub max_score: u32,
    /// Files whose verdict came from the clean-file cache.
    #[serde(default)]
    pub cached: u64,
}

impl ScanReport {
    pub fn summary(&self) -> ScanSummary {
        ScanSummary {
            scan_id: self.scan_id.clone(),
            target: self.target.clone(),
            files_scanned: self.files_scanned,
            bytes_scanned: self.bytes_scanned,
            files_skipped: self.files_skipped,
            errors: self.errors,
            findings: self.findings.len() as u64,
            max_score: self.max_score,
            verdict: self.verdict,
            duration_ms: self.duration_ms,
            cached: self.cached,
        }
    }
}

/// A running process as seen through `/proc`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub state: char,
    pub cmdline: Vec<String>,
    pub exe: Option<String>,
    pub exe_deleted: bool,
    pub cwd: Option<String>,
    pub uid: u32,
    pub euid: u32,
    pub rss_kb: u64,
    pub threads: u64,
    pub start_time: u64,
    /// Heuristic score (0-100).
    #[serde(default)]
    pub score: u32,
    #[serde(default)]
    pub severity: Severity,
    /// Human readable reasons that contributed to the score.
    #[serde(default)]
    pub reasons: Vec<String>,
}

/// Alert emitted by the process monitor for a newly spawned process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcAlert {
    pub ts: i64,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub cmdline: String,
    pub score: u32,
    pub severity: Severity,
    pub reasons: Vec<String>,
}

/// An entry in the quarantine store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: i64,
    pub ts: i64,
    pub original_path: String,
    pub file_name: String,
    pub quarantine_path: String,
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
    pub detections: Vec<Detection>,
    pub restored: bool,
}

/// A stored signature (hash based).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRow {
    pub hash: String,
    pub algo: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
    pub source: String,
}

/// Event persisted in storage (generic envelope).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub severity: Severity,
    pub payload: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_from_score() {
        assert_eq!(Severity::from_score(0), Severity::Info);
        assert_eq!(Severity::from_score(25), Severity::Low);
        assert_eq!(Severity::from_score(45), Severity::Medium);
        assert_eq!(Severity::from_score(65), Severity::High);
        assert_eq!(Severity::from_score(95), Severity::Critical);
    }

    #[test]
    fn verdict_from_score() {
        assert_eq!(Verdict::from_score(0), Verdict::Clean);
        assert_eq!(Verdict::from_score(SCORE_SUSPICIOUS), Verdict::Suspicious);
        assert_eq!(Verdict::from_score(SCORE_MALICIOUS), Verdict::Malicious);
    }
}
