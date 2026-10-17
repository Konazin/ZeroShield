//! Real-time watch sessions owned by the daemon.
//!
//! Each session runs a [`zs_watch::FileWatcher`] on a dedicated thread. The
//! events it produces are persisted, broadcast to every connected client and
//! surfaced by `zeroshield watch`/`zeroshield events --follow`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use zs_core::error::{ZsError, ZsResult};
use zs_core::event::Event;
use zs_core::model::{ScanOptions, Severity};
use zs_core::module::{Capability, ModuleStatus};
use zs_core::storage::Storage;
use zs_core::util::{now_millis, now_secs};
use zs_scan::{Progress, Scanner};
use zs_watch::mounts::MountInfo;
use zs_watch::{FileWatcher, WatchEvent, WatchOptions};

/// Serialized view of an active session (IPC responses).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchSessionInfo {
    pub paths: Vec<String>,
    pub quarantine: bool,
    pub recursive: bool,
    pub started_at: i64,
    /// Directories currently covered by inotify watches.
    pub watched_dirs: u64,
}

struct WatchSession {
    paths: Vec<PathBuf>,
    stop: Arc<AtomicBool>,
    dirs: Arc<AtomicU64>,
    started_at: i64,
    quarantine: bool,
    recursive: bool,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl WatchSession {
    fn info(&self) -> WatchSessionInfo {
        WatchSessionInfo {
            paths: self.paths.iter().map(|p| p.display().to_string()).collect(),
            quarantine: self.quarantine,
            recursive: self.recursive,
            started_at: self.started_at,
            watched_dirs: self.dirs.load(Ordering::Relaxed),
        }
    }
}

pub struct WatchManager {
    scanner: Arc<Scanner>,
    storage: Arc<Storage>,
    events: tokio::sync::broadcast::Sender<Event>,
    sessions: Mutex<Vec<WatchSession>>,
}

impl WatchManager {
    pub fn new(
        scanner: Arc<Scanner>,
        storage: Arc<Storage>,
        events: tokio::sync::broadcast::Sender<Event>,
    ) -> Self {
        Self {
            scanner,
            storage,
            events,
            sessions: Mutex::new(Vec::new()),
        }
    }

    /// Start a session for `paths`. Sessions may not overlap: asking to watch
    /// a directory that is already covered (or covers one) is an error.
    pub fn start(
        &self,
        paths: Vec<PathBuf>,
        quarantine: bool,
        recursive: bool,
        debounce: Duration,
    ) -> ZsResult<WatchSessionInfo> {
        if paths.is_empty() {
            return Err(ZsError::Config("watch: no paths given".into()));
        }
        if !paths.iter().any(|p| p.is_dir()) {
            return Err(ZsError::Config(
                "watch: none of the given paths is a directory".into(),
            ));
        }

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| ZsError::Config("watch: session lock poisoned".into()))?;

        // Drop sessions whose thread already exited (e.g. after a fatal error).
        sessions.retain(|s| match &s.handle {
            Some(h) => !h.is_finished(),
            None => false,
        });

        for session in sessions.iter() {
            for existing in &session.paths {
                for new in &paths {
                    if new.starts_with(existing) || existing.starts_with(new) {
                        return Err(ZsError::Config(format!(
                            "watch: {} is already covered by an active session",
                            new.display()
                        )));
                    }
                }
            }
        }

        let watcher = FileWatcher::new(
            self.scanner.clone(),
            WatchOptions {
                recursive,
                quarantine,
                debounce,
            },
        );
        let dirs = watcher.watched_dirs();
        let stop = Arc::new(AtomicBool::new(false));
        let events = self.events.clone();
        let storage = self.storage.clone();
        let stop_thread = stop.clone();
        let thread_paths = paths.clone();
        let handle = std::thread::Builder::new()
            .name("zs-watch".into())
            .spawn(move || {
                let mut emit = |ev: WatchEvent| match ev {
                    WatchEvent::Finding(finding) => {
                        if let Err(e) = storage.record_finding(None, &finding) {
                            tracing::warn!("failed to record watch finding: {e}");
                        }
                        let _ = storage.record_event(
                            "watch_finding",
                            finding.severity,
                            &serde_json::to_value(&finding).unwrap_or(serde_json::Value::Null),
                        );
                        let _ = events.send(Event::WatchFinding { finding });
                    }
                    WatchEvent::Error { path, message } => {
                        let _ = events.send(Event::WatchError { path, message });
                    }
                    WatchEvent::Overflow => {
                        let _ = events.send(Event::Warning {
                            message: "inotify queue overflowed: some file events were lost".into(),
                        });
                    }
                };
                if let Err(e) = watcher.run(&thread_paths, &stop_thread, &mut emit) {
                    tracing::warn!("watch session ended: {e}");
                    let _ = events.send(Event::WatchError {
                        path: thread_paths
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                        message: e.to_string(),
                    });
                }
            })
            .map_err(|e| ZsError::Config(format!("watch: cannot spawn thread: {e}")))?;

        // Wait until the initial inotify watches are registered: a file
        // created right after this call must not slip through the startup
        // window. `dirs` starts at 0 and is bumped once the roots are armed.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while dirs.load(Ordering::Relaxed) == 0 && !handle.is_finished() {
            if std::time::Instant::now() >= deadline {
                tracing::warn!("watch: registration took longer than 5s; continuing");
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }

        let session = WatchSession {
            paths: paths.clone(),
            stop,
            dirs,
            started_at: now_secs(),
            quarantine,
            recursive,
            handle: Some(handle),
        };
        let info = session.info();
        sessions.push(session);
        drop(sessions);

        let path_strings: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        let _ = self.storage.record_event(
            "watch_started",
            Severity::Info,
            &serde_json::json!({"paths": path_strings, "quarantine": quarantine, "recursive": recursive}),
        );
        let _ = self.events.send(Event::WatchStarted {
            paths: path_strings,
        });
        tracing::info!("watch session started for {}", info.paths.join(", "));
        Ok(info)
    }

    /// Stop sessions: those overlapping `paths`, or every session when `paths`
    /// is `None`. Returns how many sessions were stopped.
    pub fn stop(&self, paths: Option<&[PathBuf]>) -> usize {
        let mut stopped = Vec::new();
        if let Ok(mut sessions) = self.sessions.lock() {
            let mut keep = Vec::new();
            for session in sessions.drain(..) {
                let hit = match paths {
                    None => true,
                    Some(sel) => sel.iter().any(|want| {
                        session
                            .paths
                            .iter()
                            .any(|have| want.starts_with(have) || have.starts_with(want))
                    }),
                };
                if hit {
                    stopped.push(session);
                } else {
                    keep.push(session);
                }
            }
            *sessions = keep;
        }
        let count = stopped.len();
        for mut session in stopped {
            session.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = session.handle.take() {
                let _ = handle.join();
            }
            let path_strings: Vec<String> = session
                .paths
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            let _ = self.storage.record_event(
                "watch_stopped",
                Severity::Info,
                &serde_json::json!({"paths": path_strings}),
            );
            let _ = self.events.send(Event::WatchStopped {
                paths: path_strings,
            });
        }
        count
    }

    pub fn stop_all(&self) -> usize {
        self.stop(None)
    }

    pub fn list(&self) -> Vec<WatchSessionInfo> {
        match self.sessions.lock() {
            Ok(sessions) => sessions.iter().map(|s| s.info()).collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }

    pub fn watched_dirs_total(&self) -> u64 {
        match self.sessions.lock() {
            Ok(sessions) => sessions
                .iter()
                .map(|s| s.dirs.load(Ordering::Relaxed))
                .sum(),
            Err(_) => 0,
        }
    }

    /// Status shown by `zeroshield status` and `zeroshield modules`.
    pub fn status(&self) -> ModuleStatus {
        let sessions = self.session_count();
        let dirs = self.watched_dirs_total();
        ModuleStatus {
            name: "watch".into(),
            description: "Real-time file watching (inotify) and device scans".into(),
            capabilities: vec![Capability::FileWatch, Capability::DeviceScan],
            healthy: true,
            detail: if sessions == 0 {
                "no active sessions".into()
            } else {
                format!("{sessions} session(s), {dirs} directories watched")
            },
        }
    }
}

/// Scan a freshly mounted device. Runs on a blocking thread; progress and
/// findings are broadcast to every connected client.
pub fn scan_mount(
    scanner: &Scanner,
    storage: &Storage,
    events: &tokio::sync::broadcast::Sender<Event>,
    mount: &MountInfo,
    quarantine: bool,
    min_report_score: u32,
) {
    let target = mount.mountpoint.clone();
    let scan_id = format!("mount-{}-{}", now_millis(), std::process::id());
    let _ = events.send(Event::ScanStarted {
        scan_id: scan_id.clone(),
        target: target.display().to_string(),
    });

    let opts = ScanOptions {
        recursive: true,
        follow_symlinks: false,
        max_file_size: scanner.config().max_file_size,
        min_report_score,
        quarantine,
        content_scan: true,
        hash_cache: scanner.config().hash_cache,
        clean_cache: scanner.config().clean_cache,
        record: true,
    };
    let scan_id_for_progress = scan_id.clone();
    let events_for_progress = events.clone();
    let mut progress = |p: Progress| match p {
        Progress::Finding(finding) => {
            let _ = events_for_progress.send(Event::ScanFinding {
                scan_id: scan_id_for_progress.clone(),
                finding,
            });
        }
        Progress::File { .. } | Progress::Skipped { .. } => {}
    };

    match scanner.scan_named(&scan_id, &target, &opts, &mut progress) {
        Ok(report) => {
            let summary = report.summary();
            let _ = storage.record_event(
                "scan_finished",
                Event::ScanFinished {
                    summary: summary.clone(),
                }
                .severity(),
                &serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null),
            );
            let _ = events.send(Event::ScanFinished { summary });
            tracing::info!(
                "device scan of {} ({}) finished: {} files, verdict {}",
                target.display(),
                mount.device,
                report.files_scanned,
                report.verdict
            );
        }
        Err(e) => {
            tracing::warn!("device scan of {} failed: {e}", target.display());
            let _ = events.send(Event::WatchError {
                path: target.display().to_string(),
                message: format!("device scan failed: {e}"),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> (tempfile::TempDir, WatchManager) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open_in_memory().unwrap());
        zs_scan::signatures::seed_storage(&storage).unwrap();
        let cfg = zs_core::config::ScannerConfig {
            rule_dirs: vec![],
            ..Default::default()
        };
        let scanner = Arc::new(Scanner::new(cfg, Some(storage.clone()), None).unwrap());
        let (events, _) = tokio::sync::broadcast::channel(16);
        (dir, WatchManager::new(scanner, storage, events))
    }

    #[test]
    fn start_list_stop() {
        let (dir, manager) = manager();
        let info = manager
            .start(
                vec![dir.path().to_path_buf()],
                false,
                true,
                Duration::from_millis(50),
            )
            .unwrap();
        assert_eq!(info.paths.len(), 1);
        assert_eq!(manager.session_count(), 1);
        assert_eq!(manager.list().len(), 1);

        // Overlapping sessions are rejected.
        assert!(manager
            .start(
                vec![dir.path().to_path_buf()],
                false,
                true,
                Duration::from_millis(50)
            )
            .is_err());

        assert_eq!(manager.stop(Some(&[dir.path().to_path_buf()])), 1);
        assert_eq!(manager.session_count(), 0);
        assert_eq!(manager.stop_all(), 0);
    }

    #[test]
    fn stop_all_is_idempotent() {
        let (_dir, manager) = manager();
        assert_eq!(manager.stop_all(), 0);
    }

    #[test]
    fn session_is_armed_when_start_returns() {
        let dir = tempfile::tempdir().unwrap();
        let watch_dir = dir.path().join("w");
        std::fs::create_dir(&watch_dir).unwrap();
        let storage = Arc::new(Storage::open_in_memory().unwrap());
        zs_scan::signatures::seed_storage(&storage).unwrap();
        let cfg = zs_core::config::ScannerConfig {
            rule_dirs: vec![],
            ..Default::default()
        };
        let scanner = Arc::new(Scanner::new(cfg, Some(storage.clone()), None).unwrap());
        let (events, mut rx) = tokio::sync::broadcast::channel(16);
        let manager = WatchManager::new(scanner, storage, events);

        manager
            .start(
                vec![watch_dir.clone()],
                false,
                true,
                Duration::from_millis(50),
            )
            .unwrap();

        // No sleep: files written the instant start() returns must be seen.
        std::fs::write(watch_dir.join("boom.com"), zs_scan::builtins::eicar_bytes()).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut found = false;
        while std::time::Instant::now() < deadline {
            match rx.try_recv() {
                Ok(Event::WatchFinding { .. }) => {
                    found = true;
                    break;
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
        manager.stop_all();
        assert!(found, "watch finding was not broadcast");
    }

    #[test]
    fn start_requires_directory() {
        let (_dir, manager) = manager();
        assert!(manager
            .start(
                vec![PathBuf::from("/definitely/not/here")],
                false,
                true,
                Duration::from_millis(50)
            )
            .is_err());
        assert!(manager
            .start(vec![], false, true, Duration::from_millis(50))
            .is_err());
    }

    #[test]
    fn status_reports_sessions() {
        let (dir, manager) = manager();
        let status = manager.status();
        assert_eq!(status.name, "watch");
        assert!(status.detail.contains("no active"));
        manager
            .start(
                vec![dir.path().to_path_buf()],
                false,
                true,
                Duration::from_millis(50),
            )
            .unwrap();
        let status = manager.status();
        assert!(status.detail.contains("1 session"));
        manager.stop_all();
    }
}
