//! `zeroshieldd` — the ZeroShield daemon.
//!
//! Owns the engines (scanner, process monitor, network guard), persists
//! events in SQLite and serves the CLI/GUI over a unix socket.

mod auth;
mod handler;
mod logging;
mod watch;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::Notify;

use zs_core::config::Config;
use zs_core::error::{ZsError, ZsResult};
use zs_core::event::Event;
use zs_core::paths::Paths;
use zs_core::storage::Storage;
use zs_core::util::{euid, is_root, now_secs};
use zs_ipc::protocol::methods;
use zs_ipc::Server;
use zs_net::NetGuard;
use zs_proc::ProcMonitor;
use zs_scan::{Quarantine, Scanner};
use zs_watch::mounts::MountWatcher;

#[derive(Parser, Debug)]
#[command(
    name = "zeroshieldd",
    version,
    about = "ZeroShield daemon: file scanner, process monitor and network guard"
)]
struct Args {
    /// Path to the configuration file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Print the effective configuration as TOML and exit.
    #[arg(long)]
    print_config: bool,

    /// Validate the configuration and exit.
    #[arg(long)]
    check: bool,
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("zeroshieldd: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> ZsResult<()> {
    let mut paths = Paths::resolve();
    if let Some(cfg) = &args.config {
        paths.config_file = Some(cfg.clone());
    }
    let (cfg, cfg_path) = Config::load(&paths)?;

    if args.print_config {
        println!("{}", cfg.to_toml()?);
        return Ok(());
    }
    if args.check {
        println!("configuration is valid");
        if let Some(p) = cfg_path {
            println!("loaded from {}", p.display());
        }
        return Ok(());
    }

    logging::init(&cfg.general.log_level, cfg.general.log_json);
    paths
        .ensure_dirs()
        .map_err(|e| ZsError::io(paths.data_dir.clone(), e))?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| ZsError::Ipc(format!("failed to start runtime: {e}")))?;
    rt.block_on(async_main(paths, cfg, cfg_path))
}

async fn async_main(paths: Paths, cfg: Config, cfg_path: Option<PathBuf>) -> ZsResult<()> {
    let db_path = cfg.storage.path.clone().unwrap_or_else(|| paths.db_path());
    let storage = Arc::new(Storage::open(&db_path)?);
    let seeded = zs_scan::signatures::seed_storage(&storage)?;
    tracing::info!(
        "storage ready at {} ({seeded} built-in signatures)",
        db_path.display()
    );

    // Housekeeping.
    if let Ok(removed) = storage.prune_hash_cache(cfg.scanner.clean_cache_ttl_secs) {
        if removed > 0 {
            tracing::info!("pruned {removed} stale hash cache entries");
        }
    }
    match storage.prune_clean_files(
        cfg.scanner.clean_cache_ttl_secs,
        cfg.scanner.clean_cache_max_entries,
    ) {
        Ok(removed) if removed > 0 => {
            tracing::info!("pruned {removed} stale clean-file cache entries");
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("cannot prune clean-file cache: {e}"),
    }

    let quarantine = Arc::new(Quarantine::new(paths.quarantine_dir(), storage.clone())?);
    let scanner = Arc::new(Scanner::new(
        cfg.scanner.clone(),
        Some(storage.clone()),
        Some(quarantine.clone()),
    )?);
    let procmon = Arc::new(ProcMonitor::new(cfg.procmon.clone()));
    let netguard = Arc::new(NetGuard::new(
        cfg.netguard.clone(),
        storage.clone(),
        paths.cache_dir.clone(),
        paths.data_dir.clone(),
    ));

    let socket_path = paths.socket_path();
    let shutdown = Arc::new(Notify::new());
    let (events_tx, _) = tokio::sync::broadcast::channel::<zs_core::event::Event>(512);
    let watches = Arc::new(watch::WatchManager::new(
        scanner.clone(),
        storage.clone(),
        events_tx.clone(),
    ));
    // Client authorization (M9-C): peer credentials from the kernel plus
    // optional polkit checks for users outside the trust lists.
    let auth = Arc::new(auth::AuthPolicy::new(auth::AuthConfig {
        daemon_uid: euid(),
        client_uids: cfg.daemon.client_uids.clone(),
        client_gids: cfg.daemon.client_gids.clone(),
        polkit_enabled: cfg.daemon.polkit_enabled,
        polkit_helper: cfg.daemon.polkit_helper.clone(),
        polkit_allow_interaction: cfg.daemon.polkit_allow_interaction,
    }));
    tracing::info!("authorization: {}", auth.describe());
    let state = Arc::new(handler::State {
        version: zs_core::VERSION.to_string(),
        started_at: now_secs(),
        pid: std::process::id(),
        socket: socket_path.clone(),
        config_file: cfg_path,
        storage: storage.clone(),
        scanner: scanner.clone(),
        quarantine: quarantine.clone(),
        procmon: procmon.clone(),
        netguard: netguard.clone(),
        watches: watches.clone(),
        watch_cfg: cfg.watch.clone(),
        shutdown: shutdown.clone(),
        events: events_tx.clone(),
        auth,
    });

    let socket_mode = match cfg.daemon.socket_mode_bits() {
        Ok(bits) => bits,
        Err(e) => {
            tracing::warn!("{e}; falling back to 0660 (owner only)");
            0o660
        }
    };
    if socket_mode & 0o007 != 0 {
        tracing::warn!(
            "socket mode {:04o} lets other local users connect: every request is checked \
             against daemon.client_uids/client_gids/polkit",
            socket_mode
        );
    }
    let server = Server::bind_with_events(
        socket_path.clone(),
        handler::build(state.clone()),
        events_tx.clone(),
        socket_mode,
    )?;
    let events = server.events();

    tracing::info!(
        "zeroshieldd {} listening on {} ({})",
        zs_core::VERSION,
        socket_path.display(),
        if is_root() { "root" } else { "unprivileged" }
    );

    let _ = events.send(zs_core::event::Event::DaemonStarted {
        version: zs_core::VERSION.to_string(),
        pid: std::process::id(),
    });
    let _ = storage.record_event(
        "daemon_started",
        zs_core::model::Severity::Info,
        &serde_json::json!({"version": zs_core::VERSION, "pid": std::process::id()}),
    );

    // Process watcher loop.
    if cfg.procmon.enabled {
        let state = state.clone();
        let events = events.clone();
        let storage = storage.clone();
        let interval_secs = cfg.procmon.poll_interval_secs.max(1);
        tokio::spawn(async move {
            let mut watcher = zs_proc::ProcWatcher::new(state.procmon.config().clone());
            watcher.prime();
            tracing::info!("process watcher armed ({} processes)", watcher.seen_count());
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                tick.tick().await;
                let alerts = watcher.poll();
                for alert in alerts {
                    tracing::warn!(
                        "process alert (score {}): {} [{}] {}",
                        alert.score,
                        alert.name,
                        alert.pid,
                        alert.reasons.join("; ")
                    );
                    let _ = storage.record_event(
                        "proc_alert",
                        alert.severity,
                        &serde_json::to_value(&alert).unwrap_or(serde_json::Value::Null),
                    );
                    let _ = events.send(zs_core::event::Event::ProcAlert {
                        alert: alert.clone(),
                    });
                }
            }
        });
    } else {
        tracing::info!("process watcher disabled by configuration");
    }

    // Configured real-time watch sessions (M7).
    if cfg.watch.enabled {
        if cfg.watch.paths.is_empty() {
            tracing::warn!("watch.enabled is true but watch.paths is empty");
        } else {
            match watches.start(
                cfg.watch.paths.clone(),
                cfg.watch.quarantine,
                cfg.watch.recursive,
                std::time::Duration::from_millis(cfg.watch.debounce_ms),
            ) {
                Ok(info) => tracing::info!(
                    "watching {} in real time{}",
                    info.paths.join(", "),
                    if info.quarantine {
                        " (quarantine enabled)"
                    } else {
                        ""
                    }
                ),
                Err(e) => tracing::warn!("cannot start configured watch session: {e}"),
            }
        }
    } else {
        tracing::info!("real-time file watching disabled by configuration");
    }

    // Removable media scanning (M7): poll /proc/mounts for new mounts below
    // the configured roots and scan them in the background.
    if cfg.automount.enabled {
        let state = state.clone();
        let events = events.clone();
        let storage = storage.clone();
        let interval_secs = cfg.automount.poll_interval_secs.clamp(1, 3600);
        let quarantine = cfg.automount.quarantine;
        let roots = cfg.automount.roots.clone();
        tokio::spawn(async move {
            let mut mounts = MountWatcher::new(roots);
            mounts.prime();
            tracing::info!(
                "automount watcher armed ({} mount(s) visible, polling every {interval_secs}s)",
                mounts.visible_count()
            );
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            tick.tick().await; // consume the immediate first tick
            loop {
                tick.tick().await;
                for mount in mounts.poll() {
                    tracing::warn!(
                        "removable media mounted: {} on {} ({})",
                        mount.device,
                        mount.mountpoint.display(),
                        mount.fstype
                    );
                    let event = Event::DeviceMounted {
                        device: mount.device.clone(),
                        mountpoint: mount.mountpoint.display().to_string(),
                        fstype: mount.fstype.clone(),
                    };
                    let _ = storage.record_event(
                        event.kind(),
                        event.severity(),
                        &serde_json::to_value(&event).unwrap_or(serde_json::Value::Null),
                    );
                    let _ = events.send(event);

                    let scanner = state.scanner.clone();
                    let storage = storage.clone();
                    let events = events.clone();
                    let mount_for_task = mount.clone();
                    let min_report_score = state.scanner.config().min_report_score;
                    tokio::task::spawn_blocking(move || {
                        watch::scan_mount(
                            &scanner,
                            &storage,
                            &events,
                            &mount_for_task,
                            quarantine,
                            min_report_score,
                        );
                    });
                }
            }
        });
    } else {
        tracing::info!("removable media scanning disabled by configuration");
    }

    // Shutdown on SIGINT/SIGTERM or daemon.shutdown request.
    let shutdown_signal = {
        let notify = shutdown.clone();
        async move {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            let term = async {
                let mut sig =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("install SIGTERM handler");
                sig.recv().await;
            };
            #[cfg(not(unix))]
            let term = std::future::pending::<()>();

            tokio::select! {
                _ = ctrl_c => {}
                _ = term => {}
                _ = notify.notified() => {}
            }
        }
    };

    tokio::select! {
        result = server.run(shutdown_signal) => {
            result?;
        }
    }

    let stopped = watches.stop_all();
    if stopped > 0 {
        tracing::info!("stopped {stopped} watch session(s)");
    }

    let _ = events.send(zs_core::event::Event::DaemonStopping);
    let _ = storage.record_event(
        "daemon_stopping",
        zs_core::model::Severity::Info,
        &serde_json::json!({}),
    );
    tracing::info!("zeroshieldd stopped");
    let _ = methods::STATUS; // keep the methods module linked for docs
    Ok(())
}
