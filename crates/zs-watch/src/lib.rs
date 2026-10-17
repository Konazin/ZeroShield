//! Real-time protection primitives.
//!
//! * [`FileWatcher`]: recursive inotify watching of selected directories with
//!   write debouncing; new or changed files are scanned by the usual pipeline
//!   (signatures, rules, heuristics) and findings surface as [`WatchEvent`]s.
//! * [`mounts::MountWatcher`]: detects removable media appearing in
//!   `/proc/mounts` so the daemon can scan freshly mounted devices.
//!
//! The module is deliberately synchronous and thread friendly: the daemon (or
//! the local CLI) runs `run()` on a dedicated thread and forwards the events
//! to its own consumers.
//!
//! Known limitation: renaming a directory inside a watched tree rebases the
//! recorded paths through the inotify move cookie, but watches registered
//! while a large tree is being moved in may race with the move. Files that
//! exist before the watcher starts are not scanned by it; use
//! `zeroshield scan` for a full pass.

pub mod mounts;

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};

use zs_core::error::{ZsError, ZsResult};
use zs_core::model::{Finding, ScanOptions};
use zs_core::util::now_millis;
use zs_scan::{Progress, Scanner};

/// How often the non-blocking inotify fd is polled when idle.
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const READ_BUFFER_SIZE: usize = 16 * 1024;
/// Safety valve: refuse to register more inotify watches than this.
const MAX_WATCH_DIRS: u64 = 100_000;
const MAX_DEPTH: u32 = 64;

/// Events produced by a running [`FileWatcher`].
#[derive(Debug, Clone)]
pub enum WatchEvent {
    /// A watched file was scanned and crossed the reporting threshold.
    Finding(Finding),
    /// A path could not be watched or scanned (not a threat by itself).
    Error { path: String, message: String },
    /// The kernel dropped events because the queue overflowed: files created
    /// in that window may have been missed.
    Overflow,
}

/// Knobs for a watcher session.
#[derive(Debug, Clone)]
pub struct WatchOptions {
    /// Watch subdirectories of every root.
    pub recursive: bool,
    /// Quarantine malicious files immediately.
    pub quarantine: bool,
    /// Quiet period after the last write before a file is scanned.
    pub debounce: Duration,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            quarantine: false,
            debounce: Duration::from_millis(800),
        }
    }
}

/// A real-time file watcher. `run()` blocks until the stop flag is set.
pub struct FileWatcher {
    scanner: Arc<Scanner>,
    opts: WatchOptions,
    watched_dirs: Arc<AtomicU64>,
}

impl FileWatcher {
    pub fn new(scanner: Arc<Scanner>, opts: WatchOptions) -> Self {
        Self {
            scanner,
            opts,
            watched_dirs: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Shared counter with the number of directories currently watched.
    pub fn watched_dirs(&self) -> Arc<AtomicU64> {
        self.watched_dirs.clone()
    }

    /// Run the watch loop for `roots` until `stop` becomes true.
    ///
    /// Every event is handed to `emit`; the callback must not block for long.
    pub fn run(
        &self,
        roots: &[PathBuf],
        stop: &AtomicBool,
        emit: &mut dyn FnMut(WatchEvent),
    ) -> ZsResult<()> {
        let mut valid: Vec<PathBuf> = Vec::new();
        for root in roots {
            if root.is_dir() {
                valid.push(root.clone());
            } else {
                emit(WatchEvent::Error {
                    path: root.display().to_string(),
                    message: "not a directory (ignored)".into(),
                });
            }
        }
        if valid.is_empty() {
            return Err(ZsError::Config("watch: no valid directory to watch".into()));
        }

        let mut inotify = Inotify::init()
            .map_err(|e| ZsError::Config(format!("watch: cannot initialize inotify: {e}")))?;
        let excludes = self.scanner.config().exclude_dirs.clone();

        let mut wd_paths: HashMap<WatchDescriptor, PathBuf> = HashMap::new();
        let mut dirs: HashSet<PathBuf> = HashSet::new();
        let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
        // inotify move cookie -> old path, so directory renames keep the
        // wd -> path mapping fresh.
        let mut moves: HashMap<u32, PathBuf> = HashMap::new();

        for root in &valid {
            // queue_files = false: existing files are not scanned on startup.
            self.add_tree(
                &inotify,
                root,
                &excludes,
                false,
                &mut wd_paths,
                &mut dirs,
                &mut pending,
                emit,
            );
        }
        self.watched_dirs
            .store(dirs.len() as u64, Ordering::Relaxed);

        let mut buffer = [0u8; READ_BUFFER_SIZE];
        while !stop.load(Ordering::Relaxed) {
            match inotify.read_events(&mut buffer) {
                Ok(events) => {
                    for event in events {
                        self.handle_event(
                            &inotify,
                            &event,
                            &excludes,
                            &mut wd_paths,
                            &mut dirs,
                            &mut pending,
                            &mut moves,
                            emit,
                        );
                    }
                    self.watched_dirs
                        .store(dirs.len() as u64, Ordering::Relaxed);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    emit(WatchEvent::Error {
                        path: valid
                            .first()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                        message: format!("inotify read failed: {e}"),
                    });
                    std::thread::sleep(Duration::from_millis(100));
                }
            }

            // Debounce: scan files that stopped changing.
            if !pending.is_empty() {
                let now = Instant::now();
                let due: Vec<PathBuf> = pending
                    .iter()
                    .filter(|(_, seen)| now.duration_since(**seen) >= self.opts.debounce)
                    .map(|(path, _)| path.clone())
                    .collect();
                for path in due {
                    pending.remove(&path);
                    self.scan_path(&path, emit);
                }
            }

            std::thread::sleep(POLL_INTERVAL);
        }

        self.watched_dirs.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// Process one inotify event.
    #[allow(clippy::too_many_arguments)]
    fn handle_event(
        &self,
        inotify: &Inotify,
        event: &inotify::Event<&OsStr>,
        excludes: &[String],
        wd_paths: &mut HashMap<WatchDescriptor, PathBuf>,
        dirs: &mut HashSet<PathBuf>,
        pending: &mut HashMap<PathBuf, Instant>,
        moves: &mut HashMap<u32, PathBuf>,
        emit: &mut dyn FnMut(WatchEvent),
    ) {
        let mask = event.mask;

        if mask.contains(EventMask::Q_OVERFLOW) {
            emit(WatchEvent::Overflow);
        }
        if mask.intersects(EventMask::IGNORED | EventMask::DELETE_SELF | EventMask::MOVE_SELF) {
            // The watch ended (deleted inode) or the watched directory moved.
            // Drop the recorded path so a recreated directory can be watched
            // again; MOVED_TO on the new parent re-registers the tree when the
            // move stayed inside the watched area.
            if let Some(old) = wd_paths.remove(&event.wd) {
                dirs.remove(&old);
            }
            return;
        }

        let Some(dir) = wd_paths.get(&event.wd).cloned() else {
            return;
        };

        if mask.contains(EventMask::MOVED_FROM) {
            if let Some(name) = event.name {
                let old = dir.join(name);
                // A file was renamed away: its old path is gone.
                pending.remove(&old);
                if mask.contains(EventMask::ISDIR) {
                    moves.insert(event.cookie, old);
                }
            }
            return;
        }

        let Some(name) = event.name else {
            return;
        };
        let path = dir.join(name);
        let is_dir = mask.contains(EventMask::ISDIR);

        if mask.contains(EventMask::MOVED_TO) && is_dir {
            // Directory moved inside the watched area: rebase the recorded
            // paths (watches follow the inode) and queue what came with it.
            if let Some(old_path) = moves.remove(&event.cookie) {
                let rebase = |p: &Path| p.strip_prefix(&old_path).ok().map(|rel| path.join(rel));
                let olds: Vec<PathBuf> = wd_paths.values().cloned().collect();
                for known in wd_paths.values_mut() {
                    if let Some(new) = rebase(known) {
                        *known = new;
                    }
                }
                for old in olds {
                    if let Some(new) = rebase(&old) {
                        dirs.remove(&old);
                        dirs.insert(new);
                    }
                }
            }
            if self.opts.recursive {
                self.add_tree(
                    inotify, &path, excludes, true, wd_paths, dirs, pending, emit,
                );
            }
            return;
        }

        if is_dir {
            if self.opts.recursive && mask.contains(EventMask::CREATE) {
                // A CREATE at a path we already track can only mean the old
                // directory is gone (its IGNORED removed it) or our mapping is
                // stale; refresh it either way.
                dirs.remove(&path);
                self.add_tree(
                    inotify, &path, excludes, false, wd_paths, dirs, pending, emit,
                );
            }
            return;
        }

        let is_write = mask.contains(EventMask::CLOSE_WRITE) || mask.contains(EventMask::MOVED_TO);
        if is_write && path.extension().and_then(|e| e.to_str()) != Some(zs_scan::QUARANTINE_EXT) {
            pending.insert(path, Instant::now());
        }
    }

    /// Register watches for `root` and, when recursive, every subdirectory.
    /// `queue_files` also enqueues regular files found during the walk (used
    /// when a directory tree is moved into the watched area).
    #[allow(clippy::too_many_arguments)]
    fn add_tree(
        &self,
        inotify: &Inotify,
        root: &Path,
        excludes: &[String],
        queue_files: bool,
        wd_paths: &mut HashMap<WatchDescriptor, PathBuf>,
        dirs: &mut HashSet<PathBuf>,
        pending: &mut HashMap<PathBuf, Instant>,
        emit: &mut dyn FnMut(WatchEvent),
    ) {
        let mask = WatchMask::CREATE
            | WatchMask::MOVED_TO
            | WatchMask::CLOSE_WRITE
            | WatchMask::DELETE_SELF
            | WatchMask::MOVE_SELF;

        let mut stack: Vec<(PathBuf, u32)> = vec![(root.to_path_buf(), 0)];
        while let Some((dir, depth)) = stack.pop() {
            if dirs.contains(&dir) {
                continue;
            }
            if dirs.len() as u64 >= MAX_WATCH_DIRS {
                emit(WatchEvent::Error {
                    path: dir.display().to_string(),
                    message: format!("watch limit of {MAX_WATCH_DIRS} directories reached"),
                });
                return;
            }
            match inotify.watches().add(&dir, mask) {
                Ok(wd) => {
                    dirs.insert(dir.clone());
                    wd_paths.insert(wd, dir.clone());
                }
                Err(e) => {
                    emit(WatchEvent::Error {
                        path: dir.display().to_string(),
                        message: format!("cannot watch: {e}"),
                    });
                    continue;
                }
            }
            if !self.opts.recursive || depth >= MAX_DEPTH {
                continue;
            }
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    emit(WatchEvent::Error {
                        path: dir.display().to_string(),
                        message: format!("cannot list: {e}"),
                    });
                    continue;
                }
            };
            for entry in entries.flatten() {
                let file_type = match entry.file_type() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if file_type.is_symlink() {
                    continue;
                }
                let path = entry.path();
                if file_type.is_dir() {
                    if is_excluded_dir(&entry.file_name(), excludes) {
                        continue;
                    }
                    stack.push((path, depth + 1));
                } else if file_type.is_file() && queue_files {
                    pending.insert(path, Instant::now());
                }
            }
        }
    }

    /// Scan one file that settled after a write event.
    fn scan_path(&self, path: &Path, emit: &mut dyn FnMut(WatchEvent)) {
        if !path.is_file() {
            return;
        }
        let cfg = self.scanner.config();
        let opts = ScanOptions {
            recursive: false,
            follow_symlinks: false,
            max_file_size: cfg.max_file_size,
            min_report_score: cfg.min_report_score,
            quarantine: self.opts.quarantine || cfg.quarantine,
            content_scan: true,
            hash_cache: cfg.hash_cache,
            clean_cache: cfg.clean_cache,
            record: false,
        };
        let scan_id = format!("watch-{}-{}", now_millis(), std::process::id());
        let mut progress = |p: Progress| {
            if let Progress::Finding(finding) = p {
                emit(WatchEvent::Finding(finding));
            }
        };
        match self
            .scanner
            .scan_named(&scan_id, path, &opts, &mut progress)
        {
            Ok(report) => tracing::debug!(
                "watch scan of {} finished in {}ms (verdict {})",
                path.display(),
                report.duration_ms,
                report.verdict
            ),
            Err(e) => emit(WatchEvent::Error {
                path: path.display().to_string(),
                message: e.to_string(),
            }),
        }
    }
}

/// Directory names that are never descended into (mirrors the scanner).
fn is_excluded_dir(name: &OsStr, excludes: &[String]) -> bool {
    match name.to_str() {
        Some(n) => excludes.iter().any(|d| d == n),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;
    use zs_core::config::ScannerConfig;
    use zs_scan::Quarantine;

    type Watcher = (
        Arc<AtomicBool>,
        mpsc::Receiver<WatchEvent>,
        std::thread::JoinHandle<()>,
    );

    fn scanner() -> (tempfile::TempDir, Arc<Scanner>) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(zs_core::storage::Storage::open_in_memory().unwrap());
        zs_scan::signatures::seed_storage(&storage).unwrap();
        let quarantine = Arc::new(Quarantine::new(dir.path().join("q"), storage.clone()).unwrap());
        let cfg = ScannerConfig {
            rule_dirs: vec![],
            ..Default::default()
        };
        let scanner = Arc::new(Scanner::new(cfg, Some(storage), Some(quarantine)).unwrap());
        (dir, scanner)
    }

    /// Run a watcher in a thread, returning the stop flag and a receiver.
    fn spawn_watcher(scanner: Arc<Scanner>, root: &Path, opts: WatchOptions) -> Watcher {
        let watcher = FileWatcher::new(scanner, opts);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let (tx, rx) = mpsc::channel();
        let root = root.to_path_buf();
        let handle = std::thread::spawn(move || {
            let mut emit = |ev: WatchEvent| {
                let _ = tx.send(ev);
            };
            if let Err(e) = watcher.run(&[root], &stop_thread, &mut emit) {
                eprintln!("watcher failed: {e}");
            }
        });
        (stop, rx, handle)
    }

    fn recv_finding(rx: &mpsc::Receiver<WatchEvent>, timeout: Duration) -> Option<Finding> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(WatchEvent::Finding(f)) => return Some(f),
                Ok(_) => continue,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
        None
    }

    #[test]
    fn detects_file_written_into_watched_dir() {
        let (dir, scanner) = scanner();
        let watch_dir = dir.path().join("watched");
        std::fs::create_dir(&watch_dir).unwrap();

        let (stop, rx, handle) = spawn_watcher(
            scanner,
            &watch_dir,
            WatchOptions {
                debounce: Duration::from_millis(100),
                ..Default::default()
            },
        );

        // Give the watcher a moment to register the watch.
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(watch_dir.join("suspect.sh"), b"#!/bin/sh\necho hi\n").unwrap();
        std::fs::write(
            watch_dir.join("eicar.com"),
            zs_scan::builtins::eicar_bytes(),
        )
        .unwrap();

        let finding = recv_finding(&rx, Duration::from_secs(10)).expect("no finding seen");
        assert!(finding.path.ends_with("eicar.com"));
        assert!(finding.score >= 90);

        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }

    #[test]
    fn recursive_watch_sees_new_subdirectories() {
        let (dir, scanner) = scanner();
        let watch_dir = dir.path().join("root");
        std::fs::create_dir(&watch_dir).unwrap();

        let (stop, rx, handle) = spawn_watcher(
            scanner,
            &watch_dir,
            WatchOptions {
                debounce: Duration::from_millis(100),
                ..Default::default()
            },
        );
        std::thread::sleep(Duration::from_millis(300));

        let sub = watch_dir.join("incoming");
        std::fs::create_dir(&sub).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        std::fs::write(sub.join("dropped.com"), zs_scan::builtins::eicar_bytes()).unwrap();

        let finding = recv_finding(&rx, Duration::from_secs(10)).expect("no finding seen");
        assert!(finding.path.ends_with("dropped.com"));

        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }

    #[test]
    fn moved_in_tree_is_scanned() {
        let (dir, scanner) = scanner();
        let watch_dir = dir.path().join("root");
        std::fs::create_dir(&watch_dir).unwrap();
        let staging = dir.path().join("staging");
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(
            staging.join("payload.com"),
            zs_scan::builtins::eicar_bytes(),
        )
        .unwrap();

        let (stop, rx, handle) = spawn_watcher(
            scanner,
            &watch_dir,
            WatchOptions {
                debounce: Duration::from_millis(100),
                ..Default::default()
            },
        );
        std::thread::sleep(Duration::from_millis(300));

        std::fs::rename(&staging, watch_dir.join("usb")).unwrap();

        let finding = recv_finding(&rx, Duration::from_secs(10)).expect("no finding seen");
        assert!(finding.path.ends_with("payload.com"));

        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }

    #[test]
    fn stop_flag_ends_the_loop() {
        let (dir, scanner) = scanner();
        let watch_dir = dir.path().join("w");
        std::fs::create_dir(&watch_dir).unwrap();
        let (stop, _rx, handle) = spawn_watcher(scanner, &watch_dir, WatchOptions::default());
        std::thread::sleep(Duration::from_millis(200));
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }

    #[test]
    fn missing_root_is_reported() {
        let (dir, scanner) = scanner();
        let watcher = FileWatcher::new(scanner, WatchOptions::default());
        let stop = AtomicBool::new(false);
        let mut events = Vec::new();
        let result = watcher.run(&[dir.path().join("does-not-exist")], &stop, &mut |ev| {
            events.push(ev)
        });
        assert!(result.is_err());
        assert!(events.iter().any(|e| matches!(e, WatchEvent::Error { .. })));
    }
}
