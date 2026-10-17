//! Command implementations. Each command works against the daemon when
//! available and falls back to in-process engines otherwise.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use zs_core::config::Config;
use zs_core::error::{ZsError, ZsResult};
use zs_core::event::Event;
use zs_core::model::{Finding, ProcInfo, ScanOptions, ScanReport, StoredEvent, Verdict};
use zs_core::paths::Paths;
use zs_core::util::{format_ts, human_bytes, human_duration, now_secs};
use zs_ipc::protocol::methods;
use zs_net::guard::{ApplyOutcome, AuditResult, FeedUpdateResult, NetStatus};
use zs_scan::Progress;
use zs_watch::{FileWatcher, WatchEvent, WatchOptions};

use crate::local::Local;
use crate::render::{print_table, truncate, Style};

pub struct Ctx {
    pub paths: Paths,
    pub cfg: Config,
    pub json: bool,
    pub force_local: bool,
    pub style: Style,
}

impl Ctx {
    pub fn load(
        config: Option<PathBuf>,
        json: bool,
        force_local: bool,
        no_color: bool,
    ) -> ZsResult<Self> {
        let mut paths = Paths::resolve();
        if let Some(c) = config {
            paths.config_file = Some(c);
        }
        let (cfg, _) = Config::load(&paths)?;
        Ok(Self {
            paths,
            cfg,
            json,
            force_local,
            style: Style::detect(no_color),
        })
    }

    /// Connect to the daemon, unless local mode was requested.
    pub async fn daemon(&self) -> Option<zs_ipc::Client> {
        if self.force_local {
            return None;
        }
        zs_ipc::Client::connect(&self.paths.socket_path())
            .await
            .ok()
    }

    fn local(&self) -> ZsResult<Local> {
        Local::load(&self.paths, &self.cfg)
    }

    fn from_value<T: DeserializeOwned>(value: Value) -> ZsResult<T> {
        serde_json::from_value(value)
            .map_err(|e| ZsError::Ipc(format!("unexpected daemon response: {e}")))
    }
}

// ---------------------------------------------------------------- printing

fn print_finding(style: &Style, f: &Finding) {
    println!(
        "[{}] score {} {}",
        style.severity(f.severity),
        f.score,
        style.bold(&f.path)
    );
    println!(
        "    {}  sha256 {}",
        human_bytes(f.size),
        style.dim(&f.hashes.sha256)
    );
    for d in &f.detections {
        println!(
            "    - {} {} (+{})",
            style.cyan(&d.name),
            d.description,
            d.score
        );
    }
    if f.quarantined {
        println!("    {}", style.yellow("file quarantined"));
    }
}

fn print_scan_summary(style: &Style, report: &ScanReport) {
    let verdict = style.verdict(report.verdict);
    println!(
        "{} {} — {} files, {} scanned in {}, verdict: {}",
        style.bold("scan"),
        truncate(&report.target, 60),
        report.files_scanned,
        human_bytes(report.bytes_scanned),
        human_duration(report.duration_ms),
        verdict
    );
    if report.files_skipped > 0 || report.errors > 0 {
        println!(
            "    {} skipped, {} errors",
            report.files_skipped, report.errors
        );
    }
    if report.cached > 0 {
        println!(
            "    {} files reused from the clean-file cache",
            report.cached
        );
    }
}

// ------------------------------------------------------------------ status

pub async fn cmd_status(ctx: &Ctx) -> ZsResult<()> {
    if let Some(mut client) = ctx.daemon().await {
        let resp = client.call_simple(methods::STATUS, json!({})).await?;
        let value = resp.into_result()?;
        if ctx.json {
            println!("{}", serde_json::to_string_pretty(&value)?);
            return Ok(());
        }
        let style = &ctx.style;
        println!(
            "{} {} (daemon pid {})",
            style.bold("ZeroShield"),
            value["version"].as_str().unwrap_or("?"),
            value["pid"].as_u64().unwrap_or(0)
        );
        println!(
            "  uptime      {}",
            human_duration(value["uptime_secs"].as_u64().unwrap_or(0) * 1000)
        );
        println!("  socket      {}", value["socket"].as_str().unwrap_or("?"));
        println!(
            "  config      {}",
            value["config_file"]
                .as_str()
                .unwrap_or("(built-in defaults)")
        );
        println!(
            "  scans       {}   threats {}   rules {}   signatures {}",
            value["scans"], value["threats"], value["rules"], value["signatures"]
        );
        println!(
            "  quarantine  {} entries   net rules {}",
            value["quarantine_entries"], value["net_rules"]
        );
        println!(
            "  clean cache {} files   watch: {} session(s), {} dirs",
            value["clean_cache_entries"],
            value["watch_sessions"].as_u64().unwrap_or(0),
            value["watched_dirs"].as_u64().unwrap_or(0),
        );
        if let Some(modules) = value["modules"].as_array() {
            println!("  modules:");
            for m in modules {
                println!(
                    "    - {} {}: {}",
                    m["name"].as_str().unwrap_or("?"),
                    if m["healthy"].as_bool().unwrap_or(false) {
                        style.green("ok")
                    } else {
                        style.red("degraded")
                    },
                    m["detail"].as_str().unwrap_or("")
                );
            }
        }
        return Ok(());
    }

    // Local mode.
    let local = ctx.local()?;
    use zs_core::module::Module;
    let style = &ctx.style;
    let status = local.netguard.net_status()?;
    if ctx.json {
        let value = json!({
            "version": zs_core::VERSION,
            "mode": "local",
            "config_file": ctx.paths.config_file.as_ref().map(|p| p.display().to_string()),
            "socket": ctx.paths.socket_path().display().to_string(),
            "data_dir": ctx.paths.data_dir.display().to_string(),
            "scans": local.storage.scan_count()?,
            "threats": local.storage.threat_count()?,
            "rules": local.scanner.rules().len(),
            "signatures": local.storage.signature_count()?,
            "quarantine_entries": local.quarantine.list()?.len(),
            "clean_cache_entries": local.storage.clean_cache_len().unwrap_or(0),
            "modules": [
                local.scanner.status().await,
                local.procmon.status().await,
                local.netguard.status().await,
            ],
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }

    println!(
        "{} {} {}",
        style.bold("ZeroShield"),
        zs_core::VERSION,
        style.dim("(local mode: daemon not detected)")
    );
    println!("  socket      {}", ctx.paths.socket_path().display());
    println!("  data        {}", ctx.paths.data_dir.display());
    println!(
        "  config      {}",
        ctx.paths
            .config_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(built-in defaults)".into())
    );
    println!(
        "  scans       {}   threats {}   rules {}   signatures {}",
        local.storage.scan_count()?,
        local.storage.threat_count()?,
        local.scanner.rules().len(),
        local.storage.signature_count()?
    );
    println!(
        "  clean cache {} files",
        local.storage.clean_cache_len().unwrap_or(0)
    );
    println!(
        "  netguard    mode={} rules={} nft={}",
        status.mode,
        status.rule_count,
        if status.nft_available {
            "available"
        } else {
            "missing"
        }
    );
    println!(
        "  hint        start the daemon with: {}",
        style.cyan("zeroshieldd")
    );
    Ok(())
}

pub async fn cmd_modules(ctx: &Ctx) -> ZsResult<()> {
    if let Some(mut client) = ctx.daemon().await {
        let resp = client.call_simple(methods::MODULES, json!({})).await?;
        let value = resp.into_result()?;
        if ctx.json {
            println!("{}", serde_json::to_string_pretty(&value)?);
            return Ok(());
        }
        if let Some(modules) = value["modules"].as_array() {
            for m in modules {
                println!(
                    "{} — {}",
                    ctx.style.bold(m["name"].as_str().unwrap_or("?")),
                    m["description"].as_str().unwrap_or("")
                );
                println!("    {}", m["detail"].as_str().unwrap_or(""));
                if let Some(caps) = m["capabilities"].as_array() {
                    let caps: Vec<&str> = caps.iter().filter_map(|c| c.as_str()).collect();
                    println!("    capabilities: {}", caps.join(", "));
                }
            }
        }
        return Ok(());
    }

    let local = ctx.local()?;
    use zs_core::module::Module;
    let statuses = [
        local.scanner.status().await,
        local.procmon.status().await,
        local.netguard.status().await,
    ];
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&statuses)?);
        return Ok(());
    }
    for m in statuses {
        println!("{} — {}", ctx.style.bold(&m.name), m.description);
        println!("    {}", m.detail);
    }
    Ok(())
}

// -------------------------------------------------------------------- scan

pub struct ScanArgs {
    pub recursive: bool,
    pub quarantine: bool,
    pub min_score: Option<u32>,
    pub max_size: Option<u64>,
    pub follow_symlinks: bool,
}

pub async fn cmd_scan(ctx: &Ctx, targets: &[PathBuf], args: ScanArgs) -> ZsResult<bool> {
    let scfg = &ctx.cfg.scanner;
    let opts = ScanOptions {
        recursive: args.recursive,
        follow_symlinks: args.follow_symlinks || scfg.follow_symlinks,
        max_file_size: args.max_size.unwrap_or(scfg.max_file_size),
        min_report_score: args.min_score.unwrap_or(scfg.min_report_score),
        quarantine: args.quarantine || scfg.quarantine,
        content_scan: true,
        hash_cache: scfg.hash_cache,
        clean_cache: scfg.clean_cache,
        record: true,
    };

    let mut threats = false;
    let style = ctx.style;

    if let Some(mut client) = ctx.daemon().await {
        for target in targets {
            let params = json!({
                "target": target.display().to_string(),
                "options": opts,
            });
            let mut last_line = false;
            let json = ctx.json;
            let mut on_event = |event: Event| match event {
                Event::ScanFinding { finding, .. } => {
                    if json {
                        return;
                    }
                    if last_line {
                        println!();
                        last_line = false;
                    }
                    print_finding(&style, &finding);
                }
                Event::ScanProgress {
                    files_scanned,
                    bytes_scanned,
                    ..
                } => {
                    if json || !crate::render::is_tty(1) {
                        return;
                    }
                    print!(
                        "\r  {} {} files ({})",
                        style.dim("scanning..."),
                        files_scanned,
                        human_bytes(bytes_scanned)
                    );
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                    last_line = true;
                }
                _ => {}
            };
            let resp = client
                .call(methods::SCAN_RUN, params, None, &mut on_event)
                .await?;
            if last_line {
                println!();
            }
            let report: ScanReport = Ctx::from_value(resp.into_result()?)?;
            if report.verdict == Verdict::Malicious {
                threats = true;
            }
            if ctx.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_scan_summary(&style, &report);
            }
        }
        return Ok(threats);
    }

    // Local mode.
    let local = ctx.local()?;
    for target in targets {
        let json = ctx.json;
        let style = ctx.style;
        let mut last_line = false;
        let mut on_progress = |p: Progress| match p {
            Progress::Finding(finding) => {
                if json {
                    return;
                }
                if last_line {
                    println!();
                    last_line = false;
                }
                print_finding(&style, &finding);
            }
            Progress::File { path, files, bytes } => {
                if json || !crate::render::is_tty(1) {
                    return;
                }
                let _ = path;
                print!(
                    "\r  {} {} files ({})",
                    style.dim("scanning..."),
                    files,
                    human_bytes(bytes)
                );
                use std::io::Write;
                let _ = std::io::stdout().flush();
                last_line = true;
            }
            Progress::Skipped { path, reason } => {
                tracing::debug!("skipped {path}: {reason}");
            }
        };
        let report = local.scanner.scan(target, &opts, &mut on_progress)?;
        if last_line {
            println!();
        }
        if report.verdict == Verdict::Malicious {
            threats = true;
        }
        if ctx.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print_scan_summary(&style, &report);
        }
    }
    Ok(threats)
}

// --------------------------------------------------------- process monitor

pub async fn cmd_proc_list(ctx: &Ctx, min_score: u32) -> ZsResult<()> {
    let procs: Vec<ProcInfo> = if let Some(mut client) = ctx.daemon().await {
        let resp = client
            .call_simple(methods::PROC_LIST, json!({ "min_score": min_score }))
            .await?;
        let value = resp.into_result()?;
        Ctx::from_value(value["processes"].clone())?
    } else {
        let local = ctx.local()?;
        local
            .procmon
            .audit()
            .into_iter()
            .filter(|p| p.score >= min_score)
            .collect()
    };

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&procs)?);
        return Ok(());
    }
    if procs.is_empty() {
        println!("{}", ctx.style.green("no processes above the given score"));
        return Ok(());
    }

    let rows: Vec<Vec<String>> = procs
        .iter()
        .map(|p| {
            vec![
                p.pid.to_string(),
                p.ppid.to_string(),
                p.score.to_string(),
                p.severity.as_str().to_string(),
                p.euid.to_string(),
                truncate(&p.name, 20),
                truncate(p.exe.as_deref().unwrap_or("-"), 44),
                truncate(p.reasons.first().map(|s| s.as_str()).unwrap_or(""), 52),
            ]
        })
        .collect();
    print_table(
        &ctx.style,
        &[
            "PID",
            "PPID",
            "SCORE",
            "SEVERITY",
            "EUID",
            "NAME",
            "EXE",
            "TOP REASON",
        ],
        &rows,
    );
    let flagged = procs.iter().filter(|p| p.score >= 40).count();
    println!(
        "\n{} processes shown, {} at or above the suspicious threshold",
        procs.len(),
        flagged
    );
    Ok(())
}

pub async fn cmd_proc_watch(ctx: &Ctx) -> ZsResult<()> {
    let style = ctx.style;
    if let Some(mut client) = ctx.daemon().await {
        let resp = client.call_simple(methods::WATCH, json!({})).await?;
        resp.into_result()?;
        println!(
            "{} watching process events from the daemon (Ctrl+C to stop)",
            style.bold("zeroshield:")
        );
        loop {
            match client.next_event(Some(Duration::from_secs(3600))).await {
                Ok(Some(Event::ProcAlert { alert })) => {
                    println!(
                        "{} [{}] pid {} (ppid {}) score {} — {}",
                        style.bold("process alert"),
                        style.severity(alert.severity),
                        alert.pid,
                        alert.ppid,
                        alert.score,
                        truncate(&alert.cmdline, 90)
                    );
                    for reason in &alert.reasons {
                        println!("    {reason}");
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    println!("daemon closed the connection");
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("{e}");
                    return Ok(());
                }
            }
        }
    }

    // Local watch.
    println!(
        "{} watching processes locally every {}s (Ctrl+C to stop)",
        style.bold("zeroshield:"),
        ctx.cfg.procmon.poll_interval_secs
    );
    let mut watcher = zs_proc::ProcWatcher::new(ctx.cfg.procmon.clone());
    watcher.prime();
    let interval = Duration::from_secs(ctx.cfg.procmon.poll_interval_secs.max(1));
    loop {
        tokio::time::sleep(interval).await;
        for alert in watcher.poll() {
            println!(
                "{} [{}] pid {} ({}) score {} — {}",
                style.bold("process alert"),
                style.severity(alert.severity),
                alert.pid,
                truncate(&alert.name, 24),
                alert.score,
                truncate(&alert.cmdline, 80)
            );
            for reason in &alert.reasons {
                println!("    {reason}");
            }
        }
    }
}

// ------------------------------------------------------- real-time watch

pub struct WatchArgs {
    pub paths: Vec<PathBuf>,
    pub quarantine: bool,
    pub recursive: bool,
    pub detach: bool,
    pub list: bool,
    pub stop: bool,
}

pub async fn cmd_watch(ctx: &Ctx, args: WatchArgs) -> ZsResult<()> {
    if args.list && args.stop {
        return Err(ZsError::Config("use either --list or --stop".into()));
    }
    if args.list {
        return cmd_watch_list(ctx).await;
    }
    if args.stop {
        return cmd_watch_stop(ctx, &args.paths).await;
    }

    let paths: Vec<PathBuf> = if args.paths.is_empty() {
        ctx.cfg.watch.paths.clone()
    } else {
        args.paths.clone()
    };
    if paths.is_empty() {
        return Err(ZsError::Config(
            "no directories given; pass paths or set watch.paths in the configuration".into(),
        ));
    }

    match ctx.daemon().await {
        Some(client) => cmd_watch_daemon(ctx, client, &paths, &args).await,
        None => {
            if args.detach {
                return Err(ZsError::Ipc(
                    "--detach requires a running daemon (start zeroshieldd)".into(),
                ));
            }
            cmd_watch_local(ctx, &paths, &args).await
        }
    }
}

async fn cmd_watch_daemon(
    ctx: &Ctx,
    mut client: zs_ipc::Client,
    paths: &[PathBuf],
    args: &WatchArgs,
) -> ZsResult<()> {
    let params = json!({
        "paths": paths,
        "quarantine": args.quarantine || ctx.cfg.watch.quarantine,
        "recursive": args.recursive && ctx.cfg.watch.recursive,
        "debounce_ms": ctx.cfg.watch.debounce_ms,
    });
    let resp = client.call_simple(methods::WATCH_FS_START, params).await?;
    let value = resp.into_result()?;

    if args.detach {
        if ctx.json {
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            println!(
                "{} watching {} in the daemon (detached; stop with 'zeroshield watch --stop')",
                ctx.style.bold("zeroshield:"),
                paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        return Ok(());
    }

    // Keep this connection open: every daemon event is streamed to it.
    let resp = client.call_simple(methods::WATCH, json!({})).await?;
    resp.into_result()?;
    println!(
        "{} watching {} in real time (Ctrl+C to stop)",
        ctx.style.bold("zeroshield:"),
        paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    loop {
        tokio::select! {
            event = client.next_event(Some(Duration::from_secs(3600))) => {
                match event {
                    Ok(Some(event)) => print_live_event(ctx, &event),
                    Ok(None) => {
                        println!("daemon closed the connection");
                        break;
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!();
                break;
            }
        }
    }

    // Stop the session we started (the streaming connection may be gone, so
    // use a fresh one).
    if let Some(mut control) = ctx.daemon().await {
        match control
            .call_simple(methods::WATCH_FS_STOP, json!({ "paths": paths }))
            .await
        {
            Ok(resp) => {
                let _ = resp.into_result();
                println!("{} watch session stopped", ctx.style.bold("zeroshield:"));
            }
            Err(e) => eprintln!("could not stop the watch session: {e}"),
        }
    }
    Ok(())
}

async fn cmd_watch_local(ctx: &Ctx, paths: &[PathBuf], args: &WatchArgs) -> ZsResult<()> {
    let local = ctx.local()?;
    let scanner = Arc::new(local.scanner);
    let opts = WatchOptions {
        recursive: args.recursive && ctx.cfg.watch.recursive,
        quarantine: args.quarantine || ctx.cfg.watch.quarantine,
        debounce: Duration::from_millis(ctx.cfg.watch.debounce_ms.min(60_000)),
    };
    let watcher = FileWatcher::new(scanner, opts);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let thread_paths = paths.to_vec();
    let (tx, rx) = std::sync::mpsc::channel::<WatchEvent>();
    let handle = std::thread::spawn(move || {
        let mut emit = |ev: WatchEvent| {
            let _ = tx.send(ev);
        };
        if let Err(e) = watcher.run(&thread_paths, &stop_thread, &mut emit) {
            eprintln!("watch: {e}");
        }
    });

    println!(
        "{} daemon not reachable: watching locally in this process (Ctrl+C to stop)",
        ctx.style.bold("zeroshield:")
    );
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!();
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                while let Ok(ev) = rx.try_recv() {
                    match ev {
                        WatchEvent::Finding(finding) => {
                            println!("{}", ctx.style.bold("real-time detection"));
                            print_finding(&ctx.style, &finding);
                        }
                        WatchEvent::Error { path, message } => {
                            eprintln!("{} {path}: {message}", ctx.style.yellow("watch error:"));
                        }
                        WatchEvent::Overflow => {
                            eprintln!(
                                "{} kernel event queue overflowed; some files were missed",
                                ctx.style.yellow("watch:")
                            );
                        }
                    }
                }
            }
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    Ok(())
}

async fn cmd_watch_list(ctx: &Ctx) -> ZsResult<()> {
    let Some(mut client) = ctx.daemon().await else {
        return Err(ZsError::Ipc(
            "--list requires a running daemon (sessions live in zeroshieldd)".into(),
        ));
    };
    let resp = client
        .call_simple(methods::WATCH_FS_LIST, json!({}))
        .await?;
    let value = resp.into_result()?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let sessions = value["sessions"].as_array().cloned().unwrap_or_default();
    if sessions.is_empty() {
        println!("no active watch sessions");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = sessions
        .iter()
        .map(|s| {
            let paths = s["paths"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            vec![
                paths,
                s["watched_dirs"].as_u64().unwrap_or(0).to_string(),
                if s["quarantine"].as_bool().unwrap_or(false) {
                    "yes".into()
                } else {
                    "no".into()
                },
                if s["recursive"].as_bool().unwrap_or(true) {
                    "yes".into()
                } else {
                    "no".into()
                },
                format_ts(s["started_at"].as_i64().unwrap_or(0)),
            ]
        })
        .collect();
    print_table(
        &ctx.style,
        &["paths", "dirs", "quarantine", "recursive", "started"],
        &rows,
    );
    Ok(())
}

async fn cmd_watch_stop(ctx: &Ctx, paths: &[PathBuf]) -> ZsResult<()> {
    let Some(mut client) = ctx.daemon().await else {
        return Err(ZsError::Ipc("--stop requires a running daemon".into()));
    };
    let params = if paths.is_empty() {
        json!({})
    } else {
        json!({ "paths": paths })
    };
    let resp = client.call_simple(methods::WATCH_FS_STOP, params).await?;
    let value = resp.into_result()?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let stopped = value["stopped"].as_u64().unwrap_or(0);
    if stopped == 0 {
        println!("no watch session matched");
    } else {
        println!("{stopped} watch session(s) stopped");
    }
    Ok(())
}

// ------------------------------------------------------------- quarantine

pub async fn cmd_quarantine_list(ctx: &Ctx) -> ZsResult<()> {
    let value: Value = if let Some(mut client) = ctx.daemon().await {
        client
            .call_simple(methods::QUARANTINE_LIST, json!({}))
            .await?
            .into_result()?
    } else {
        let local = ctx.local()?;
        json!({ "entries": local.quarantine.list()? })
    };

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let entries = value["entries"].as_array().cloned().unwrap_or_default();
    if entries.is_empty() {
        println!("quarantine is empty");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|e| {
            vec![
                e["id"].as_i64().unwrap_or(0).to_string(),
                format_ts(e["ts"].as_i64().unwrap_or(0)),
                truncate(e["file_name"].as_str().unwrap_or("-"), 28),
                truncate(e["original_path"].as_str().unwrap_or("-"), 50),
                if e["restored"].as_bool().unwrap_or(false) {
                    "restored".into()
                } else {
                    "quarantined".into()
                },
            ]
        })
        .collect();
    print_table(
        &ctx.style,
        &["ID", "WHEN", "FILE", "ORIGINAL PATH", "STATUS"],
        &rows,
    );
    Ok(())
}

pub async fn cmd_quarantine_restore(ctx: &Ctx, id: i64) -> ZsResult<()> {
    let value: Value = if let Some(mut client) = ctx.daemon().await {
        client
            .call_simple(methods::QUARANTINE_RESTORE, json!({ "id": id }))
            .await?
            .into_result()?
    } else {
        let local = ctx.local()?;
        let entry = local.quarantine.restore(id)?;
        json!({ "restored": entry.original_path })
    };
    println!("restored {}", value["restored"].as_str().unwrap_or("file"));
    Ok(())
}

pub async fn cmd_quarantine_purge(ctx: &Ctx, id: i64) -> ZsResult<()> {
    let value: Value = if let Some(mut client) = ctx.daemon().await {
        client
            .call_simple(methods::QUARANTINE_PURGE, json!({ "id": id }))
            .await?
            .into_result()?
    } else {
        let local = ctx.local()?;
        local.quarantine.purge(id)?;
        json!({ "purged": id })
    };
    println!("purged entry {}", value["purged"]);
    Ok(())
}

// ------------------------------------------------------------------- rules

pub async fn cmd_rules_list(ctx: &Ctx) -> ZsResult<()> {
    let value: Value = if let Some(mut client) = ctx.daemon().await {
        client
            .call_simple(methods::RULES_LIST, json!({}))
            .await?
            .into_result()?
    } else {
        let local = ctx.local()?;
        let rules = local.scanner.rules().describe();
        json!({ "rules": rules, "count": rules.len() })
    };

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let rules = value["rules"].as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = rules
        .iter()
        .map(|r| {
            vec![
                truncate(r["name"].as_str().unwrap_or("-"), 40),
                r["severity"].as_str().unwrap_or("-").to_string(),
                r["score"].as_u64().unwrap_or(0).to_string(),
                truncate(r["source"].as_str().unwrap_or("-"), 22),
            ]
        })
        .collect();
    print_table(&ctx.style, &["RULE", "SEVERITY", "SCORE", "SOURCE"], &rows);
    println!("\n{} rules loaded", rules.len());
    Ok(())
}

pub async fn cmd_rules_check(ctx: &Ctx, file: &Path) -> ZsResult<()> {
    let local = ctx.local()?;
    let buf = std::fs::read(file).map_err(|e| ZsError::io(file, e))?;
    let hashes = zs_scan::hash::hash_file(file)?;

    let mut detections = local.scanner.rules().check(&buf, file);
    if let Some(d) = zs_scan::signatures::lookup(Some(&local.storage), &hashes)? {
        detections.push(d);
    }
    if zs_scan::elf::is_elf(&buf) {
        detections.extend(zs_scan::elf::analyze(&buf, file));
    }
    if ctx.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "file": file.display().to_string(),
                "hashes": hashes,
                "detections": detections,
            }))?
        );
        return Ok(());
    }

    println!("{}", ctx.style.bold(&file.display().to_string()));
    println!(
        "  size {}  sha256 {}",
        human_bytes(buf.len() as u64),
        ctx.style.dim(&hashes.sha256)
    );
    if detections.is_empty() {
        println!("  {}", ctx.style.green("no detections"));
        return Ok(());
    }
    for d in &detections {
        println!(
            "  [{}] {} (+{}) — {}",
            ctx.style.severity(d.severity),
            d.name,
            d.score,
            d.description
        );
    }
    let score: u32 = detections.iter().map(|d| d.score).sum::<u32>().min(100);
    println!(
        "  total score {} → verdict {}",
        score,
        ctx.style.verdict(Verdict::from_score(score))
    );
    Ok(())
}

pub async fn cmd_rules_import(ctx: &Ctx, file: &Path, format: &str) -> ZsResult<()> {
    let imported: u64 = if let Some(mut client) = ctx.daemon().await {
        let resp = client
            .call_simple(
                methods::SIGS_IMPORT,
                json!({ "path": file.display().to_string() }),
            )
            .await?;
        let value = resp.into_result()?;
        value["imported"].as_u64().unwrap_or(0)
    } else {
        let local = ctx.local()?;
        let fmt = match format {
            "clam" | "hdb" => zs_scan::signatures::SigFormat::ClamHdb,
            "csv" => zs_scan::signatures::SigFormat::ZeroShieldCsv,
            "plain" => zs_scan::signatures::SigFormat::PlainHashes,
            _ => zs_scan::signatures::SigFormat::Auto,
        };
        zs_scan::signatures::import_file(&local.storage, file, fmt)?
    };
    println!("imported {imported} signatures from {}", file.display());
    Ok(())
}

// --------------------------------------------------------------------- net

pub async fn cmd_net_status(ctx: &Ctx) -> ZsResult<()> {
    let value: Value = if let Some(mut client) = ctx.daemon().await {
        client
            .call_simple(methods::NET_STATUS, json!({}))
            .await?
            .into_result()?
    } else {
        let local = ctx.local()?;
        serde_json::to_value(local.netguard.net_status()?)?
    };
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let status: NetStatus = Ctx::from_value(value)?;
    let style = &ctx.style;
    println!("{}", style.bold("netguard (IPS)"));
    if status.mode == "audit" {
        println!(
            "  mode        {} {}",
            status.mode,
            style.dim("(nothing is blocked: audit only)")
        );
    } else {
        println!("  mode        {}", status.mode);
    }
    println!(
        "  nftables    {} / rules file {}",
        if status.nft_available {
            style.green("available")
        } else {
            style.yellow("missing (install nftables)")
        },
        if status.nft_installed {
            "generated"
        } else {
            "not generated yet"
        }
    );
    println!(
        "  privileges  {}",
        if status.is_root {
            "root"
        } else {
            "unprivileged"
        }
    );
    println!(
        "  rules       {} blocked ({} allowlist / {} blocklist entries in config)",
        status.rule_count, status.allowlist, status.blocklist
    );
    println!(
        "  feeds       {} configured (signatures {})",
        status.feeds,
        if status.feed_signatures {
            "required"
        } else {
            "off"
        }
    );
    println!("  dns mode    {}", status.dns_mode);
    Ok(())
}

pub async fn cmd_net_audit(ctx: &Ctx, targets: &[String]) -> ZsResult<()> {
    if targets.is_empty() {
        return Err(ZsError::Config(
            "net audit requires at least one IP, CIDR, domain or URL".into(),
        ));
    }
    let value: Value = if let Some(mut client) = ctx.daemon().await {
        client
            .call_simple(methods::NET_AUDIT, json!({ "targets": targets }))
            .await?
            .into_result()?
    } else {
        let local = ctx.local()?;
        json!({ "results": local.netguard.audit(targets)? })
    };

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let results: Vec<AuditResult> = Ctx::from_value(value["results"].clone())?;
    let rows: Vec<Vec<String>> = results
        .iter()
        .map(|r| {
            vec![
                truncate(&r.target, 48),
                r.kind.clone(),
                r.decision.to_uppercase(),
                truncate(r.rule.as_deref().unwrap_or("-"), 40),
            ]
        })
        .collect();
    print_table(
        &ctx.style,
        &["TARGET", "KIND", "DECISION", "MATCHED RULE"],
        &rows,
    );
    Ok(())
}

pub async fn cmd_net_feeds_update(ctx: &Ctx, force: bool) -> ZsResult<()> {
    let results: Vec<FeedUpdateResult> = if let Some(mut client) = ctx.daemon().await {
        let resp = client
            .call_simple(methods::NET_FEEDS_UPDATE, json!({ "force": force }))
            .await?;
        let value = resp.into_result()?;
        Ctx::from_value(value["results"].clone())?
    } else {
        let local = ctx.local()?;
        local.netguard.update_feeds(force)
    };

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
        return Ok(());
    }
    let rows: Vec<Vec<String>> = results
        .iter()
        .map(|r| {
            let state = if r.error.is_some() {
                "error"
            } else if r.not_modified {
                "not modified"
            } else if r.skipped {
                "cached"
            } else {
                "downloaded"
            };
            vec![
                truncate(&r.url, 62),
                r.entries.to_string(),
                state.into(),
                if r.verified {
                    "verified".into()
                } else {
                    "-".into()
                },
                truncate(r.error.as_deref().unwrap_or(""), 40),
            ]
        })
        .collect();
    print_table(
        &ctx.style,
        &["FEED", "ENTRIES", "STATE", "GPG", "ERROR"],
        &rows,
    );
    let total: u64 = results.iter().map(|r| r.entries).sum();
    println!("\n{total} indicators ingested");
    Ok(())
}

pub async fn cmd_net_feeds_list(ctx: &Ctx) -> ZsResult<()> {
    let local = ctx.local()?;
    let rules = local.storage.list_net_rules(true)?;
    let mut counts: std::collections::BTreeMap<String, (u64, u64, u64)> = Default::default();
    for (kind, _value, source) in &rules {
        let entry = counts.entry(source.clone()).or_default();
        match kind.as_str() {
            "ip" => entry.0 += 1,
            "cidr" => entry.1 += 1,
            "domain" => entry.2 += 1,
            _ => {}
        }
    }
    if ctx.json {
        let value = json!({ "sources": counts, "total": rules.len() });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let rows: Vec<Vec<String>> = counts
        .iter()
        .map(|(source, (ips, cidrs, domains))| {
            vec![
                truncate(source, 40),
                ips.to_string(),
                cidrs.to_string(),
                domains.to_string(),
            ]
        })
        .collect();
    print_table(&ctx.style, &["SOURCE", "IPs", "CIDRs", "DOMAINS"], &rows);
    println!("\n{} rules stored", rules.len());
    Ok(())
}

pub async fn cmd_net_apply(ctx: &Ctx, yes: bool) -> ZsResult<()> {
    let dry_run = !yes;
    let outcome: ApplyOutcome = if let Some(mut client) = ctx.daemon().await {
        let resp = client
            .call_simple(methods::NET_APPLY, json!({ "dry_run": dry_run }))
            .await?;
        Ctx::from_value(resp.into_result()?)?
    } else {
        let local = ctx.local()?;
        local.netguard.apply(dry_run)?
    };

    let style = &ctx.style;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
        return Ok(());
    }
    println!(
        "{} {} rules, ruleset at {}",
        if outcome.applied {
            style.green("applied")
        } else {
            style.yellow("not applied")
        },
        outcome.rule_count,
        outcome.rules_file
    );
    if !outcome.message.is_empty() {
        println!("  {}", outcome.message);
    }
    if !outcome.applied {
        println!("\n{}", style.bold("generated ruleset (preview)"));
        for line in outcome.ruleset.lines().take(25) {
            println!("  {line}");
        }
        if outcome.ruleset.lines().count() > 25 {
            println!("  {}", style.dim("..."));
        }
    }
    Ok(())
}

pub async fn cmd_net_dns(ctx: &Ctx, install: bool) -> ZsResult<()> {
    let path: Option<String> = if let Some(mut client) = ctx.daemon().await {
        let resp = client
            .call_simple(methods::NET_DNS, json!({ "install": install }))
            .await?;
        let value = resp.into_result()?;
        value["path"].as_str().map(|s| s.to_string())
    } else {
        let local = ctx.local()?;
        local
            .netguard
            .write_dns(install)?
            .map(|p| p.display().to_string())
    };
    match path {
        Some(p) => println!("DNS sinkhole fragment written to {p}"),
        None => println!(
            "dns filtering is off; set netguard.dns_mode = \"dnsmasq\" or \"unbound\" first"
        ),
    }
    Ok(())
}

// ------------------------------------------------------- events / findings

pub async fn cmd_events(ctx: &Ctx, limit: u32, follow: bool) -> ZsResult<()> {
    if follow {
        let Some(mut client) = ctx.daemon().await else {
            return Err(zs_core::error::ZsError::Ipc(
                "events --follow requires a running daemon (start zeroshieldd)".into(),
            ));
        };
        let resp = client.call_simple(methods::WATCH, json!({})).await?;
        resp.into_result()?;
        println!(
            "{} streaming daemon events (Ctrl+C to stop)",
            ctx.style.bold("zeroshield:")
        );
        loop {
            match client.next_event(Some(Duration::from_secs(3600))).await {
                Ok(Some(event)) => print_live_event(ctx, &event),
                Ok(None) => {
                    println!("daemon closed the connection");
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("{e}");
                    return Ok(());
                }
            }
        }
    }

    let events: Vec<StoredEvent> = if let Some(mut client) = ctx.daemon().await {
        let resp = client
            .call_simple(methods::EVENTS_LIST, json!({ "limit": limit }))
            .await?;
        let value = resp.into_result()?;
        Ctx::from_value(value["events"].clone())?
    } else {
        let local = ctx.local()?;
        local.storage.list_events(limit)?
    };

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&events)?);
        return Ok(());
    }
    for e in events.iter().rev() {
        println!(
            "{} [{}] {} {}",
            ctx.style.dim(&format_ts(e.ts)),
            ctx.style.severity(e.severity),
            e.kind,
            truncate(&e.payload.to_string(), 110)
        );
    }
    if events.is_empty() {
        println!("no events recorded yet");
    }
    Ok(())
}

/// Semantic newline rendering for live events.
fn print_live_event(ctx: &Ctx, event: &Event) {
    let style = &ctx.style;
    match event {
        Event::ScanFinding { finding, .. } => {
            print_finding(style, finding);
        }
        Event::WatchFinding { finding } => {
            println!("{}", style.bold("real-time detection"));
            print_finding(style, finding);
        }
        Event::ProcAlert { alert } => {
            println!(
                "{} [{}] pid {} score {} — {}",
                style.bold("process alert"),
                style.severity(alert.severity),
                alert.pid,
                alert.score,
                truncate(&alert.cmdline, 90)
            );
            for reason in &alert.reasons {
                println!("    {reason}");
            }
        }
        other => {
            let detail = match other {
                Event::DaemonStarted { version, pid } => {
                    format!("daemon started v{version} (pid {pid})")
                }
                Event::DaemonStopping => "daemon stopping".to_string(),
                Event::ScanStarted { scan_id, target } => {
                    format!("scan {scan_id} started: {target}")
                }
                Event::ScanProgress {
                    path,
                    files_scanned,
                    ..
                } => format!("scanning {files_scanned} files (at {path})"),
                Event::ScanFinished { summary } => format!(
                    "scan {} finished: {} files, verdict {}",
                    summary.scan_id,
                    summary.files_scanned,
                    summary.verdict.as_str()
                ),
                Event::WatchStarted { paths } => {
                    format!("real-time watch started: {}", paths.join(", "))
                }
                Event::WatchStopped { paths } => {
                    format!("real-time watch stopped: {}", paths.join(", "))
                }
                Event::WatchError { path, message } => {
                    format!("watch error on {path}: {message}")
                }
                Event::DeviceMounted {
                    device, mountpoint, ..
                } => format!("device mounted: {device} on {mountpoint}"),
                Event::NetAlert { message, .. } => format!("net alert: {message}"),
                Event::Info { message } => message.clone(),
                Event::Warning { message } => format!("warning: {message}"),
                Event::Error { message } => format!("error: {message}"),
                Event::ScanFinding { .. }
                | Event::WatchFinding { .. }
                | Event::ProcAlert { .. } => unreachable!(),
            };
            println!(
                "{} [{}] {}",
                style.dim(&format_ts(now_secs())),
                style.severity(other.severity()),
                detail
            );
        }
    }
}

pub async fn cmd_findings(ctx: &Ctx, limit: u32) -> ZsResult<()> {
    let findings: Vec<Finding> = if let Some(mut client) = ctx.daemon().await {
        let resp = client
            .call_simple(methods::FINDINGS_LIST, json!({ "limit": limit }))
            .await?;
        let value = resp.into_result()?;
        Ctx::from_value(value["findings"].clone())?
    } else {
        let local = ctx.local()?;
        local.storage.list_findings(limit)?
    };

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
        return Ok(());
    }
    if findings.is_empty() {
        println!("{}", ctx.style.green("no findings recorded"));
        return Ok(());
    }
    for f in &findings {
        print_finding(&ctx.style, f);
    }
    Ok(())
}

// ------------------------------------------------------- reports / metrics

pub struct ReportArgs {
    pub format: String,
    pub days: u32,
    pub limit: u32,
    pub section: Option<String>,
    pub out: Option<PathBuf>,
}

pub struct MetricsArgs {
    pub format: String,
    pub out: Option<PathBuf>,
}

fn write_output(out: Option<&Path>, text: &str) -> ZsResult<()> {
    match out {
        Some(path) => std::fs::write(path, text)
            .map_err(|e| ZsError::io(path.to_path_buf(), e))
            .map(|_| ()),
        None => {
            print!("{text}");
            Ok(())
        }
    }
}

pub async fn cmd_report(ctx: &Ctx, args: ReportArgs) -> ZsResult<()> {
    if args.format != "csv" && args.section.is_some() {
        return Err(ZsError::Config(
            "--section is only used with --format csv".into(),
        ));
    }
    let opts = zs_report::ReportOptions {
        days: args.days.min(3650),
        limit: args.limit.clamp(1, 10_000),
    };

    let data: zs_report::ReportData = if let Some(mut client) = ctx.daemon().await {
        let resp = client
            .call_simple(
                methods::REPORT_GET,
                json!({ "days": opts.days, "limit": opts.limit }),
            )
            .await?;
        Ctx::from_value(resp.into_result()?)?
    } else {
        let local = ctx.local()?;
        zs_report::collect(&local.storage, zs_core::VERSION, opts)?
    };

    let rendered = match args.format.as_str() {
        "json" => zs_report::render_json(&data)?,
        "csv" => {
            let section = match args.section.as_deref() {
                Some(name) => zs_report::CsvSection::parse(name).ok_or_else(|| {
                    ZsError::Config(format!(
                        "unknown section '{name}' (use findings, scans, events or quarantine)"
                    ))
                })?,
                None => zs_report::CsvSection::Findings,
            };
            zs_report::render_csv(&data, section)
        }
        "html" => zs_report::render_html(&data),
        other => {
            return Err(ZsError::Config(format!(
                "unknown format '{other}' (use json, csv or html)"
            )))
        }
    };

    write_output(args.out.as_deref(), &rendered)?;
    if args.out.is_some() && !ctx.json {
        let summary = &data.summary;
        println!(
            "report written: {} scan(s), {} finding(s) in period, {} threat(s) total, {} quarantine entr(ies)",
            summary.scans_in_period, summary.findings_in_period, summary.threats_total, summary.quarantine_entries
        );
    }
    Ok(())
}

pub async fn cmd_metrics(ctx: &Ctx, args: MetricsArgs) -> ZsResult<()> {
    let set: zs_report::MetricSet = if let Some(mut client) = ctx.daemon().await {
        let resp = client.call_simple(methods::METRICS_GET, json!({})).await?;
        Ctx::from_value(resp.into_result()?)?
    } else {
        let local = ctx.local()?;
        let input = zs_report::MetricsInput {
            up: false,
            version: zs_core::VERSION.to_string(),
            uptime_secs: 0,
            scans_total: local.storage.scan_count()?,
            threats_total: local.storage.threat_count()?,
            findings_total: local.storage.finding_count()?,
            quarantine_entries: local.quarantine.list()?.len() as u64,
            signatures_total: local.storage.signature_count()?,
            rules_total: local.scanner.rules().len() as u64,
            clean_cache_entries: local.storage.clean_cache_len().unwrap_or(0),
            watch_sessions: 0,
            watched_dirs: 0,
            net_rules_total: local.storage.list_net_rules(true)?.len() as u64,
            procmon_processes: 0,
            events_by_severity: local.storage.event_counts_by_severity()?,
        };
        zs_report::collect_metrics(&input)
    };

    let rendered = match args.format.as_str() {
        "prometheus" => zs_report::render_prometheus(&set),
        "journald" => zs_report::render_journald(&set),
        other => {
            return Err(ZsError::Config(format!(
                "unknown format '{other}' (use prometheus or journald)"
            )))
        }
    };
    write_output(args.out.as_deref(), &rendered)
}
