//! Background tasks: poll the daemon for section data, follow the event
//! stream, run scans and perform quarantine actions.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

use zs_core::error::{ZsError, ZsResult};
use zs_core::event::Event;
use zs_core::model::{Finding, ProcInfo, QuarantineEntry, ScanReport, StoredEvent};
use zs_core::util::human_bytes;
use zs_ipc::client::Client;
use zs_ipc::protocol::methods;

use crate::app::{StatusView, Update};

/// How often inactive sections are re-polled.
const POLL_INTERVAL: Duration = Duration::from_secs(3);
/// Minimum gap between two refreshes triggered by live events.
const MIN_GAP: Duration = Duration::from_millis(1000);
/// Maximum rows requested per section.
const ROW_LIMIT: u32 = 500;

pub struct ScanRequest {
    pub target: String,
}

/// Handles to the background tasks, owned by the run loop.
pub struct Tasks {
    pub updates: mpsc::UnboundedReceiver<Update>,
    tx: mpsc::UnboundedSender<Update>,
    notify: Arc<Notify>,
    active_tab: Arc<AtomicUsize>,
    scan_tx: mpsc::UnboundedSender<ScanRequest>,
    socket: PathBuf,
}

impl Tasks {
    /// Ask the poller to refresh immediately.
    pub fn refresh_now(&self) {
        self.notify.notify_one();
    }

    /// Tell the poller which tab is visible (heavier sections are only
    /// refreshed while their tab is open).
    pub fn set_active_tab(&self, index: usize) {
        self.active_tab.store(index, Ordering::Relaxed);
    }

    pub fn start_scan(&self, target: String) {
        let _ = self.scan_tx.send(ScanRequest { target });
    }

    pub fn restore(&self, id: i64) {
        self.spawn_quarantine(methods::QUARANTINE_RESTORE, id);
    }

    pub fn purge(&self, id: i64) {
        self.spawn_quarantine(methods::QUARANTINE_PURGE, id);
    }

    fn spawn_quarantine(&self, method: &'static str, id: i64) {
        let socket = self.socket.clone();
        let tx = self.tx.clone();
        let notify = self.notify.clone();
        tokio::spawn(async move {
            let result = async {
                let mut client = Client::connect(&socket).await?;
                let resp = client.call_simple(method, json!({ "id": id })).await?;
                resp.into_result()
            }
            .await;
            match result {
                Ok(value) => {
                    let text = value
                        .get("restored")
                        .and_then(Value::as_str)
                        .map(|s| format!("restored {s}"))
                        .or_else(|| value.get("purged").map(|v| format!("purged #{v}")))
                        .unwrap_or_else(|| format!("quarantine #{id}: done"));
                    let _ = tx.send(Update::Message { text, ok: true });
                    notify.notify_one();
                }
                Err(err) => {
                    let _ = tx.send(Update::Message {
                        text: format!("quarantine action failed: {err}"),
                        ok: false,
                    });
                }
            }
        });
    }
}

/// Spawn every background task. Returns the receiver side used by the UI.
pub fn spawn(socket: PathBuf) -> Tasks {
    let (tx, rx) = mpsc::unbounded_channel();
    let notify = Arc::new(Notify::new());
    let active_tab = Arc::new(AtomicUsize::new(0));

    {
        let socket = socket.clone();
        let tx = tx.clone();
        let notify = notify.clone();
        let active_tab = active_tab.clone();
        tokio::spawn(async move { poller(socket, tx, notify, active_tab).await });
    }
    {
        let socket = socket.clone();
        let tx = tx.clone();
        let notify = notify.clone();
        tokio::spawn(async move { streamer(socket, tx, notify).await });
    }

    let (scan_tx, mut scan_rx) = mpsc::unbounded_channel::<ScanRequest>();
    {
        let socket = socket.clone();
        let tx = tx.clone();
        let notify = notify.clone();
        tokio::spawn(async move {
            while let Some(request) = scan_rx.recv().await {
                run_scan(&socket, &tx, request).await;
                notify.notify_one();
            }
        });
    }

    Tasks {
        updates: rx,
        tx,
        notify,
        active_tab,
        scan_tx,
        socket,
    }
}

async fn poller(
    socket: PathBuf,
    tx: mpsc::UnboundedSender<Update>,
    notify: Arc<Notify>,
    active_tab: Arc<AtomicUsize>,
) {
    let mut client: Option<Client> = None;
    let mut connected = false;
    let mut last = Instant::now() - POLL_INTERVAL;
    loop {
        let next = last + POLL_INTERVAL;
        tokio::select! {
            _ = tokio::time::sleep_until(next) => {}
            _ = notify.notified() => {}
        }
        // Coalesce bursts: never refresh more than once per second.
        let now = Instant::now();
        if now < last + MIN_GAP {
            tokio::time::sleep(last + MIN_GAP - now).await;
        }
        last = Instant::now();

        match refresh(
            &mut client,
            &socket,
            &tx,
            active_tab.load(Ordering::Relaxed),
        )
        .await
        {
            Ok(()) => {
                if !connected {
                    connected = true;
                    let _ = tx.send(Update::Connected(true));
                }
            }
            Err(err) => {
                client = None;
                if connected {
                    connected = false;
                    let _ = tx.send(Update::Connected(false));
                }
                let _ = tx.send(Update::Message {
                    text: format!("daemon not reachable: {err}"),
                    ok: false,
                });
            }
        }
    }
}

/// One refresh pass: always status (cheap) plus the active tab's section.
async fn refresh(
    client: &mut Option<Client>,
    socket: &Path,
    tx: &mpsc::UnboundedSender<Update>,
    active_tab: usize,
) -> ZsResult<()> {
    if client.is_none() {
        *client = Some(Client::connect(socket).await?);
    }
    let client = client.as_mut().expect("client was just connected");

    let status = client.call_simple(methods::STATUS, json!({})).await?;
    let _ = tx.send(Update::Status(Box::new(StatusView::from_value(
        &status.into_result()?,
    ))));

    // The events tail is cheap and keeps the header/footer live.
    let events: Vec<StoredEvent> = parse_field(
        client
            .call_simple(methods::EVENTS_LIST, json!({ "limit": ROW_LIMIT }))
            .await?
            .into_result()?,
        "events",
    )?;
    let _ = tx.send(Update::Events(events));

    match active_tab {
        2 => {
            let findings: Vec<Finding> = parse_field(
                client
                    .call_simple(methods::FINDINGS_LIST, json!({ "limit": ROW_LIMIT }))
                    .await?
                    .into_result()?,
                "findings",
            )?;
            let _ = tx.send(Update::Findings(findings));
        }
        3 => {
            let entries: Vec<QuarantineEntry> = parse_field(
                client
                    .call_simple(methods::QUARANTINE_LIST, json!({}))
                    .await?
                    .into_result()?,
                "entries",
            )?;
            let _ = tx.send(Update::Quarantine(entries));
        }
        4 => {
            let procs: Vec<ProcInfo> = parse_field(
                client
                    .call_simple(methods::PROC_LIST, json!({ "min_score": 0 }))
                    .await?
                    .into_result()?,
                "processes",
            )?;
            let _ = tx.send(Update::Processes(procs));
        }
        5 => {
            let value = client.call_simple(methods::NET_STATUS, json!({})).await?;
            let _ = tx.send(Update::Net(flatten(&value.into_result()?)));
        }
        _ => {}
    }
    Ok(())
}

/// Follow the daemon-wide event stream (`watch.start` keeps the connection
/// open). Each event nudges the poller so lists stay current.
async fn streamer(socket: PathBuf, tx: mpsc::UnboundedSender<Update>, notify: Arc<Notify>) {
    loop {
        let mut client = match Client::connect(&socket).await {
            Ok(client) => client,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
        };
        let mut on_event = |event: Event| {
            let _ = tx.send(Update::LiveEvent(event.kind().to_string()));
            notify.notify_one();
        };
        let _ = client
            .call(methods::WATCH, json!({}), None, &mut on_event)
            .await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Run a scan on a dedicated connection so the connection-only progress
/// events reach the footer.
async fn run_scan(socket: &Path, tx: &mpsc::UnboundedSender<Update>, request: ScanRequest) {
    let _ = tx.send(Update::ScanNote(format!("scanning {}…", request.target)));
    let result = async {
        let mut client = Client::connect(socket).await?;
        let target = request.target.clone();
        let progress_tx = tx.clone();
        let mut on_event = |event: Event| {
            if let Event::ScanProgress {
                files_scanned,
                bytes_scanned,
                ..
            } = event
            {
                let _ = progress_tx.send(Update::ScanNote(format!(
                    "scanning {}… {} files ({})",
                    target,
                    files_scanned,
                    human_bytes(bytes_scanned)
                )));
            }
        };
        let resp = client
            .call(
                methods::SCAN_RUN,
                json!({ "target": request.target }),
                None,
                &mut on_event,
            )
            .await?;
        let report: ScanReport = serde_json::from_value(resp.into_result()?)?;
        Ok::<_, ZsError>(report)
    }
    .await;

    let _ = tx.send(Update::ScanNote(String::new()));
    let _ = tx.send(Update::ScanFinished);
    match result {
        Ok(report) => {
            let _ = tx.send(Update::Message {
                text: format!(
                    "scan {} done: {} files, {} finding(s), verdict {}",
                    report.target,
                    report.files_scanned,
                    report.findings.len(),
                    report.verdict.as_str()
                ),
                ok: report.verdict != zs_core::model::Verdict::Malicious,
            });
        }
        Err(err) => {
            let _ = tx.send(Update::Message {
                text: format!("scan failed: {err}"),
                ok: false,
            });
        }
    }
}

fn parse_field<T: DeserializeOwned>(value: Value, field: &str) -> ZsResult<T> {
    let inner = value.get(field).cloned().unwrap_or(Value::Null);
    serde_json::from_value(inner).map_err(|e| ZsError::Serialization(format!("{field}: {e}")))
}

/// Flatten a JSON object into display lines (single level).
fn flatten(value: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Value::Object(map) = value {
        for (key, val) in map {
            let text = match val {
                Value::String(s) => s.clone(),
                Value::Null => "-".to_string(),
                other => {
                    let raw = other.to_string();
                    if raw.chars().count() > 160 {
                        format!("{}…", raw.chars().take(160).collect::<String>())
                    } else {
                        raw
                    }
                }
            };
            out.push((key.clone(), text));
        }
    }
    out
}
