//! ZeroShield terminal user interface (ratatui).
//!
//! A daemon client for servers: overview, live events, findings, quarantine,
//! processes and IPS status, plus actions (scan, restore/purge). The daemon is
//! required; when the socket is unreachable the UI shows an offline screen and
//! keeps retrying in the background.

mod app;
mod data;
mod ui;

use std::path::PathBuf;
use std::time::Duration;

use zs_core::error::{ZsError, ZsResult};

use crate::app::{Action, App};
use crate::data::Tasks;

/// Run the TUI against the daemon socket. The terminal is restored on exit
/// (including on panic, via the hook installed by [`ratatui::try_init`]).
pub async fn run(socket: PathBuf) -> ZsResult<()> {
    let mut terminal = ratatui::try_init().map_err(|e| ZsError::io("<terminal>", e))?;
    let result = run_loop(&mut terminal, socket).await;
    ratatui::restore();
    result
}

async fn run_loop(terminal: &mut ratatui::DefaultTerminal, socket: PathBuf) -> ZsResult<()> {
    let mut app = App::new(socket.display().to_string());
    let mut tasks = data::spawn(socket);
    tasks.set_active_tab(app.tab_index());

    // Terminal input is blocking: read keys on a dedicated thread and forward
    // them into the async loop.
    let (key_tx, mut key_rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        use ratatui::crossterm::event::{read, Event};
        loop {
            match read() {
                Ok(Event::Key(key)) => {
                    if key_tx.send(key).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    let mut tick = tokio::time::interval(Duration::from_millis(500));
    terminal
        .draw(|frame| ui::render(frame, &mut app))
        .map_err(ZsError::from)?;

    while !app.should_quit {
        tokio::select! {
            _ = tick.tick() => {
                app.tick = app.tick.wrapping_add(1);
            }
            Some(update) = tasks.updates.recv() => app.apply(update),
            Some(key) = key_rx.recv() => {
                let previous = app.tab_index();
                if let Some(action) = app.on_key(key) {
                    handle_action(action, &mut app, &tasks);
                }
                if app.tab_index() != previous {
                    tasks.set_active_tab(app.tab_index());
                    tasks.refresh_now();
                }
            }
        }
        terminal
            .draw(|frame| ui::render(frame, &mut app))
            .map_err(ZsError::from)?;
    }
    Ok(())
}

fn handle_action(action: Action, app: &mut App, tasks: &Tasks) {
    match action {
        Action::Quit => app.should_quit = true,
        Action::Refresh => tasks.refresh_now(),
        Action::Scan(target) => {
            app.scan_running = Some(target.clone());
            tasks.start_scan(target);
        }
        Action::RestoreQuarantine(id) => tasks.restore(id),
        Action::PurgeQuarantine(id) => tasks.purge(id),
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use serde_json::json;

    use zs_core::model::{
        Detection, Finding, Hashes, ProcInfo, QuarantineEntry, Severity, StoredEvent, Verdict,
    };

    use crate::app::{App, StatusView};

    pub fn status() -> StatusView {
        StatusView::from_value(&json!({
            "version": "0.1.0-test",
            "pid": 1234,
            "uptime_secs": 90,
            "socket": "/run/zeroshield/zeroshieldd.sock",
            "scans": 4,
            "threats": 2,
            "rules": 12,
            "signatures": 3,
            "quarantine_entries": 1,
            "clean_cache_entries": 7,
            "watch_sessions": 1,
            "watched_dirs": 2,
            "net_rules": 0,
            "modules": [
                {
                    "name": "scanner",
                    "description": "file scanner",
                    "healthy": true,
                    "detail": "12 rules, 3 signatures",
                    "capabilities": ["file_scan", "quarantine"]
                },
                {
                    "name": "procmon",
                    "description": "process monitor",
                    "healthy": true,
                    "detail": "480 processes visible",
                    "capabilities": ["process_audit"]
                }
            ]
        }))
    }

    pub fn event() -> StoredEvent {
        StoredEvent {
            id: 7,
            ts: 1_700_000_000,
            kind: "scan_finding".into(),
            severity: Severity::Critical,
            payload: json!({"path": "/tmp/eicar.com", "score": 100}),
        }
    }

    pub fn finding() -> Finding {
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
            quarantined: true,
        }
    }

    pub fn quarantine_entry() -> QuarantineEntry {
        QuarantineEntry {
            id: 1,
            ts: 1_700_000_100,
            original_path: "/tmp/eicar.com".into(),
            file_name: "eicar.com".into(),
            quarantine_path: "/var/lib/zeroshield/quarantine/eicar.com".into(),
            sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".into(),
            size: 68,
            mode: 0,
            detections: finding().detections,
            restored: false,
        }
    }

    pub fn process() -> ProcInfo {
        ProcInfo {
            pid: 4242,
            name: "evil".into(),
            score: 90,
            severity: Severity::Critical,
            cmdline: vec!["evil".into(), "--flag".into()],
            reasons: vec!["deleted executable".into()],
            ..Default::default()
        }
    }

    pub fn full_app() -> App {
        let mut app = App::new("test.sock".into());
        app.connected = true;
        app.status = status();
        app.events = vec![event()];
        app.findings = vec![finding()];
        app.quarantine = vec![quarantine_entry()];
        app.processes = vec![process()];
        app.net_lines = vec![
            ("mode".into(), "audit".into()),
            ("rules".into(), "0".into()),
        ];
        app.clamp_all();
        app
    }
}
