//! IPC request handling.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::{broadcast, Notify};

use zs_core::config::WatchConfig;
use zs_core::error::{ZsError, ZsResult};
use zs_core::event::Event;
use zs_core::model::{ScanOptions, Severity};
use zs_core::storage::Storage;
use zs_core::util::{human_bytes, now_secs};
use zs_ipc::protocol::{methods, Response};
use zs_ipc::{EventEnvelope, Frame, FrameTx, Handler, PeerCred, Request};
use zs_net::NetGuard;
use zs_proc::ProcMonitor;
use zs_scan::{Progress, Quarantine, Scanner};

use crate::auth::AuthPolicy;
use crate::watch::WatchManager;

pub struct State {
    pub version: String,
    pub started_at: i64,
    pub pid: u32,
    pub socket: PathBuf,
    pub config_file: Option<PathBuf>,
    pub storage: Arc<Storage>,
    pub scanner: Arc<Scanner>,
    pub quarantine: Arc<Quarantine>,
    pub procmon: Arc<ProcMonitor>,
    pub netguard: Arc<NetGuard>,
    pub watches: Arc<WatchManager>,
    /// Defaults for `watch.fs.start` requests.
    pub watch_cfg: WatchConfig,
    pub shutdown: Arc<Notify>,
    /// Daemon-wide event bus: everything sent here reaches watching clients.
    pub events: broadcast::Sender<Event>,
    /// Peer-credentials + polkit authorization for every request (M9-C).
    pub auth: Arc<AuthPolicy>,
}

pub fn build(state: Arc<State>) -> Handler {
    Arc::new(move |req: Request, tx: FrameTx, cred: PeerCred| {
        let state = state.clone();
        Box::pin(async move {
            let id = req.id;
            // Authorization may fork the polkit helper, so it runs on the
            // blocking pool to keep the async workers free.
            let auth = state.auth.clone();
            let method = req.method.clone();
            let decision =
                match tokio::task::spawn_blocking(move || auth.authorize(&cred, &method)).await {
                    Ok(decision) => decision,
                    Err(e) => Err(ZsError::Ipc(format!("authorization task failed: {e}"))),
                };
            if let Err(e) = decision {
                tracing::warn!(
                    "request denied: method={} uid={} gid={} pid={}: {e}",
                    req.method,
                    cred.uid,
                    cred.gid,
                    cred.pid
                );
                return Response::err(id, e.to_string());
            }
            match dispatch(state, &req.method, req.params, tx).await {
                Ok(value) => Response::ok(id, value),
                Err(e) => Response::err(id, e.to_string()),
            }
        })
    })
}

fn frame_event(event: Event) -> Frame {
    Frame::Event(EventEnvelope::new(event))
}

async fn dispatch(state: Arc<State>, method: &str, params: Value, tx: FrameTx) -> ZsResult<Value> {
    match method {
        methods::STATUS => status(&state).await,
        methods::MODULES => modules(&state).await,
        methods::SCAN_RUN => scan_run(&state, params, tx).await,
        methods::PROC_LIST | methods::PROC_AUDIT => proc_list(&state, params).await,
        methods::QUARANTINE_LIST => quarantine_list(&state),
        methods::QUARANTINE_RESTORE => quarantine_restore(&state, params),
        methods::QUARANTINE_PURGE => quarantine_purge(&state, params),
        methods::SIGS_IMPORT => sigs_import(&state, params),
        methods::RULES_LIST => {
            let rules = state.scanner.rules().describe();
            Ok(json!({"rules": rules, "count": rules.len()}))
        }
        methods::EVENTS_LIST => {
            let limit = limit_param(&params, 20);
            let events = state.storage.list_events(limit)?;
            Ok(json!({ "events": events }))
        }
        methods::FINDINGS_LIST => {
            let limit = limit_param(&params, 50);
            let findings = state.storage.list_findings(limit)?;
            Ok(json!({ "findings": findings }))
        }
        methods::NET_STATUS => {
            let status = state.netguard.net_status()?;
            Ok(serde_json::to_value(status)?)
        }
        methods::NET_AUDIT => {
            let targets: Vec<String> = params
                .get("targets")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let results = state.netguard.audit(&targets)?;
            Ok(json!({ "results": results }))
        }
        methods::NET_FEEDS_UPDATE => {
            let force = params
                .get("force")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let netguard = state.netguard.clone();
            let results = tokio::task::spawn_blocking(move || netguard.update_feeds(force))
                .await
                .map_err(|e| ZsError::Net(format!("feed task failed: {e}")))?;
            Ok(json!({ "results": results }))
        }
        methods::NET_APPLY => {
            let dry_run = params
                .get("dry_run")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let netguard = state.netguard.clone();
            let outcome = tokio::task::spawn_blocking(move || netguard.apply(dry_run))
                .await
                .map_err(|e| ZsError::Net(format!("apply task failed: {e}")))??;
            Ok(serde_json::to_value(outcome)?)
        }
        methods::NET_DNS => {
            let install = params
                .get("install")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let path = state.netguard.write_dns(install)?;
            Ok(json!({ "path": path.map(|p| p.display().to_string()) }))
        }
        methods::SHUTDOWN => {
            state.shutdown.notify_waiters();
            Ok(json!({"stopping": true}))
        }
        methods::WATCH => {
            // The connection stays open: daemon-wide broadcast events keep
            // flowing to this client until it disconnects.
            Ok(json!({"watching": true}))
        }
        methods::WATCH_FS_START => watch_fs_start(&state, params),
        methods::WATCH_FS_STOP => watch_fs_stop(&state, params),
        methods::WATCH_FS_LIST => Ok(json!({ "sessions": state.watches.list() })),
        methods::REPORT_GET => report_get(&state, params),
        methods::METRICS_GET => metrics_get(&state),
        other => Err(ZsError::Ipc(format!("unknown method '{other}'"))),
    }
}

fn limit_param(params: &Value, default: u32) -> u32 {
    params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|v| v.min(10_000) as u32)
        .unwrap_or(default)
}

fn watch_fs_start(state: &Arc<State>, params: Value) -> ZsResult<Value> {
    let paths: Vec<PathBuf> = params
        .get("paths")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let paths = if paths.is_empty() {
        state.watch_cfg.paths.clone()
    } else {
        paths
    };

    let quarantine = params
        .get("quarantine")
        .and_then(|v| v.as_bool())
        .unwrap_or(state.watch_cfg.quarantine);
    let recursive = params
        .get("recursive")
        .and_then(|v| v.as_bool())
        .unwrap_or(state.watch_cfg.recursive);
    let debounce_ms = params
        .get("debounce_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(state.watch_cfg.debounce_ms)
        .min(60_000);

    let session = state.watches.start(
        paths,
        quarantine,
        recursive,
        Duration::from_millis(debounce_ms),
    )?;
    Ok(json!({
        "session": session,
        "sessions": state.watches.list(),
    }))
}

fn watch_fs_stop(state: &Arc<State>, params: Value) -> ZsResult<Value> {
    let paths: Vec<PathBuf> = params
        .get("paths")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let selection = match paths.is_empty() {
        true => None,
        false => Some(paths.as_slice()),
    };
    let stopped = state.watches.stop(selection);
    Ok(json!({ "stopped": stopped, "sessions": state.watches.list() }))
}

fn report_get(state: &Arc<State>, params: Value) -> ZsResult<Value> {
    let opts = zs_report::ReportOptions {
        days: params
            .get("days")
            .and_then(|v| v.as_u64())
            .unwrap_or(7)
            .min(3650) as u32,
        limit: params
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000)
            .clamp(1, 10_000) as u32,
    };
    let data = zs_report::collect(&state.storage, &state.version, opts)?;
    Ok(serde_json::to_value(&data)?)
}

fn metrics_get(state: &Arc<State>) -> ZsResult<Value> {
    let storage = &state.storage;
    let input = zs_report::MetricsInput {
        up: true,
        version: state.version.clone(),
        uptime_secs: (now_secs() - state.started_at).max(0) as u64,
        scans_total: storage.scan_count()?,
        threats_total: storage.threat_count()?,
        findings_total: storage.finding_count()?,
        quarantine_entries: state.quarantine.list()?.len() as u64,
        signatures_total: storage.signature_count()?,
        rules_total: state.scanner.rules().len() as u64,
        clean_cache_entries: storage.clean_cache_len().unwrap_or(0),
        watch_sessions: state.watches.session_count() as u64,
        watched_dirs: state.watches.watched_dirs_total(),
        net_rules_total: state.netguard.net_status()?.rule_count,
        procmon_processes: zs_proc::procinfo::list_pids().len() as u64,
        events_by_severity: storage.event_counts_by_severity()?,
    };
    let set = zs_report::collect_metrics(&input);
    Ok(serde_json::to_value(&set)?)
}

async fn modules(state: &Arc<State>) -> ZsResult<Value> {
    use zs_core::module::Module;
    let scanner = state.scanner.status().await;
    let procmon = state.procmon.status().await;
    let netguard = state.netguard.status().await;
    let watches = state.watches.status();
    Ok(json!({ "modules": [scanner, procmon, netguard, watches] }))
}

async fn status(state: &Arc<State>) -> ZsResult<Value> {
    use zs_core::module::Module;
    let scanner = state.scanner.status().await;
    let procmon = state.procmon.status().await;
    let netguard = state.netguard.status().await;
    let watches = state.watches.status();
    let net_status = state.netguard.net_status()?;
    let uptime = now_secs() - state.started_at;

    Ok(json!({
        "version": state.version,
        "pid": state.pid,
        "uptime_secs": uptime,
        "socket": state.socket.display().to_string(),
        "config_file": state.config_file.as_ref().map(|p| p.display().to_string()),
        "scans": state.storage.scan_count()?,
        "threats": state.storage.threat_count()?,
        "rules": state.scanner.rules().len(),
        "signatures": state.storage.signature_count()?,
        "quarantine_entries": state.quarantine.list()?.len(),
        "clean_cache_entries": state.storage.clean_cache_len().unwrap_or(0),
        "watch_sessions": state.watches.session_count(),
        "watched_dirs": state.watches.watched_dirs_total(),
        "net_rules": net_status.rule_count,
        "modules": [scanner, procmon, netguard, watches],
    }))
}

async fn scan_run(state: &Arc<State>, params: Value, tx: FrameTx) -> ZsResult<Value> {
    let target = params
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ZsError::Ipc("scan.run requires a 'target' parameter".into()))?
        .to_string();

    let opts: ScanOptions = match params.get("options") {
        Some(v) if !v.is_null() => serde_json::from_value(v.clone())
            .map_err(|e| ZsError::Config(format!("invalid scan options: {e}")))?,
        _ => ScanOptions {
            recursive: state.scanner.config().recursive,
            follow_symlinks: state.scanner.config().follow_symlinks,
            max_file_size: state.scanner.config().max_file_size,
            min_report_score: state.scanner.config().min_report_score,
            quarantine: state.scanner.config().quarantine,
            content_scan: true,
            hash_cache: state.scanner.config().hash_cache,
            clean_cache: state.scanner.config().clean_cache,
            record: true,
        },
    };

    let scan_id = format!(
        "scan-{}-{}",
        zs_core::util::now_millis(),
        std::process::id()
    );
    let started = Event::ScanStarted {
        scan_id: scan_id.clone(),
        target: target.clone(),
    };
    let _ = state.events.send(started.clone());
    let _ = tx.send(frame_event(started));

    let scanner = state.scanner.clone();
    let scan_id_for_task = scan_id.clone();
    let tx_task = tx.clone();
    let target_for_task = target.clone();
    let events_tx = state.events.clone();

    let report = tokio::task::spawn_blocking(move || {
        let mut progress = |p: Progress| {
            let event = match p {
                Progress::File { path, files, bytes } => Event::ScanProgress {
                    scan_id: scan_id_for_task.clone(),
                    path,
                    files_scanned: files,
                    bytes_scanned: bytes,
                },
                Progress::Finding(finding) => Event::ScanFinding {
                    scan_id: scan_id_for_task.clone(),
                    finding,
                },
                Progress::Skipped { .. } => return,
            };
            // Findings also reach watchers; progress stays on this connection.
            if event.is_persistent() {
                let _ = events_tx.send(event.clone());
            }
            let _ = tx_task.send(frame_event(event));
        };
        scanner.scan_named(
            &scan_id_for_task,
            Path::new(&target_for_task),
            &opts,
            &mut progress,
        )
    })
    .await
    .map_err(|e| ZsError::Scan(format!("scan task failed: {e}")))??;

    let summary = report.summary();
    let _ = state.storage.record_event(
        "scan_finished",
        Event::ScanFinished {
            summary: summary.clone(),
        }
        .severity(),
        &serde_json::to_value(&summary)?,
    );
    let _ = state.events.send(Event::ScanFinished {
        summary: summary.clone(),
    });
    let _ = tx.send(frame_event(Event::ScanFinished { summary }));

    tracing::info!(
        "scan {} finished: {} files ({} scanned) in {}ms, verdict={}",
        report.scan_id,
        report.files_scanned,
        human_bytes(report.bytes_scanned),
        report.duration_ms,
        report.verdict
    );

    serde_json::to_value(&report).map_err(Into::into)
}

async fn proc_list(state: &Arc<State>, params: Value) -> ZsResult<Value> {
    let min_score = params
        .get("min_score")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let procmon = state.procmon.clone();
    let procs = tokio::task::spawn_blocking(move || procmon.audit())
        .await
        .map_err(|e| ZsError::Proc(format!("proc task failed: {e}")))?;
    let filtered: Vec<_> = procs.into_iter().filter(|p| p.score >= min_score).collect();
    Ok(json!({ "processes": filtered }))
}

fn quarantine_list(state: &Arc<State>) -> ZsResult<Value> {
    let entries = state.quarantine.list()?;
    Ok(json!({ "entries": entries }))
}

fn quarantine_restore(state: &Arc<State>, params: Value) -> ZsResult<Value> {
    let id = params
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ZsError::Ipc("quarantine.restore requires 'id'".into()))?;
    let entry = state.quarantine.restore(id)?;
    let _ = state.storage.record_event(
        "quarantine_restored",
        Severity::Info,
        &serde_json::to_value(&entry)?,
    );
    Ok(json!({ "restored": entry.original_path }))
}

fn quarantine_purge(state: &Arc<State>, params: Value) -> ZsResult<Value> {
    let id = params
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ZsError::Ipc("quarantine.purge requires 'id'".into()))?;
    state.quarantine.purge(id)?;
    Ok(json!({ "purged": id }))
}

fn sigs_import(state: &Arc<State>, params: Value) -> ZsResult<Value> {
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ZsError::Ipc("sigs.import requires 'path'".into()))?;
    let imported = zs_scan::signatures::import_file(
        &state.storage,
        Path::new(path),
        zs_scan::signatures::SigFormat::Auto,
    )?;
    let _ = state.storage.record_event(
        "sigs_imported",
        Severity::Info,
        &json!({"path": path, "imported": imported}),
    );
    Ok(json!({ "imported": imported }))
}
