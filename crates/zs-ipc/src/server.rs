//! IPC server used by `zeroshieldd`.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc};

use zs_core::error::{ZsError, ZsResult};
use zs_core::event::Event;

use crate::protocol::{EventEnvelope, Frame, Request, Response};

/// Sender for frames on a single connection (used to stream events while a
/// request is being handled).
pub type FrameTx = mpsc::UnboundedSender<Frame>;

pub type HandlerFuture = Pin<Box<dyn Future<Output = Response> + Send>>;
pub type Handler = Arc<dyn Fn(Request, FrameTx) -> HandlerFuture + Send + Sync + 'static>;

pub struct Server {
    listener: UnixListener,
    path: PathBuf,
    handler: Handler,
    events: broadcast::Sender<Event>,
}

impl Server {
    /// Bind the socket. Removes a stale socket file if no daemon answers.
    pub fn bind(path: impl Into<PathBuf>, handler: Handler) -> ZsResult<Self> {
        let (events, _) = broadcast::channel(512);
        Self::bind_with_events(path, handler, events)
    }

    /// Like [`Server::bind`], but reusing a caller-provided broadcast channel
    /// so other components of the daemon can publish their own events.
    pub fn bind_with_events(
        path: impl Into<PathBuf>,
        handler: Handler,
        events: broadcast::Sender<Event>,
    ) -> ZsResult<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ZsError::io(parent, e))?;
        }
        if path.exists() {
            // Is someone listening? Then refuse to start a second daemon.
            let alive = std::os::unix::net::UnixStream::connect(&path).is_ok();
            if alive {
                return Err(ZsError::Ipc(format!(
                    "another daemon is already listening on {}",
                    path.display()
                )));
            }
            std::fs::remove_file(&path).map_err(|e| ZsError::io(&path, e))?;
        }
        let listener = UnixListener::bind(&path).map_err(|e| ZsError::io(&path, e))?;
        restrict_permissions(&path)?;
        Ok(Self {
            listener,
            path,
            handler,
            events,
        })
    }

    /// Broadcast channel for daemon-wide events (process alerts, etc).
    pub fn events(&self) -> broadcast::Sender<Event> {
        self.events.clone()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serve until `shutdown` resolves.
    pub async fn run<F>(self, shutdown: F) -> ZsResult<()>
    where
        F: Future<Output = ()> + Send,
    {
        let Server {
            listener,
            path,
            handler,
            events,
        } = self;

        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _addr)) => {
                            let handler = handler.clone();
                            let events = events.clone();
                            tokio::spawn(async move {
                                if let Err(e) = serve_connection(stream, handler, events).await {
                                    tracing::debug!("connection ended with error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("accept failed: {e}");
                        }
                    }
                }
            }
        }

        // Cleanup: unix sockets are not removed automatically.
        let _ = std::fs::remove_file(&path);
        Ok(())
    }
}

fn restrict_permissions(path: &Path) -> ZsResult<()> {
    use std::os::unix::fs::PermissionsExt;
    // Owner + group only. A system (root) daemon is reachable to root, while
    // user daemons live inside a 0700 runtime directory.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| ZsError::io(path, e))
}

async fn serve_connection(
    stream: UnixStream,
    handler: Handler,
    events: broadcast::Sender<Event>,
) -> ZsResult<()> {
    let (rd, mut wr) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();

    // Writer task: drains outgoing frames (responses + streamed events).
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            let line = match frame.to_line() {
                Ok(l) => l,
                Err(_) => continue,
            };
            if wr.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    // Forward daemon-wide broadcast events to this client.
    let ev_tx = tx.clone();
    let mut ev_rx = events.subscribe();
    let forwarder = tokio::spawn(async move {
        loop {
            match ev_rx.recv().await {
                Ok(event) => {
                    if ev_tx.send(Frame::Event(EventEnvelope::new(event))).is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Reader loop: one task per request so slow scans do not block the socket.
    let mut reader = BufReader::new(rd);
    let mut line_buf = String::new();
    loop {
        line_buf.clear();
        match reader.read_line(&mut line_buf).await {
            Ok(0) => break, // client disconnected
            Ok(_) => {}
            Err(e) => {
                tracing::debug!("read error: {e}");
                break;
            }
        }
        let raw = line_buf.trim();
        if raw.is_empty() {
            continue;
        }
        let request = match serde_json::from_str::<Request>(raw) {
            Ok(r) => r,
            Err(e) => {
                let _ = tx.send(Frame::Response(Response::err(
                    0,
                    format!("malformed request: {e}"),
                )));
                continue;
            }
        };
        let handler = handler.clone();
        let tx_req = tx.clone();
        tokio::spawn(async move {
            let id = request.id;
            let mut response = handler(request, tx_req.clone()).await;
            if response.id != id {
                response.id = id;
            }
            let _ = tx_req.send(Frame::Response(response));
        });
    }

    drop(tx);
    forwarder.abort();
    // Give the aborted forwarder a chance to drop its sender clone so the
    // writer task can finish.
    tokio::task::yield_now().await;
    let _ = writer.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;
    use zs_core::model::Severity;

    fn echo_handler() -> Handler {
        Arc::new(|req: Request, tx: FrameTx| {
            Box::pin(async move {
                // Stream one info event, then answer.
                let _ = tx.send(Frame::Event(EventEnvelope::new(Event::Info {
                    message: format!("handling {}", req.method),
                })));
                if req.method == "fail" {
                    Response::err(req.id, "boom")
                } else {
                    Response::ok(req.id, serde_json::json!({"echo": req.params}))
                }
            })
        })
    }

    #[tokio::test]
    async fn server_client_roundtrip_with_events() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");

        let server = Server::bind(&sock, echo_handler()).unwrap();
        let shutdown = {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            // keep tx alive; drop after test via leak-free guard
            std::mem::forget(tx);
            async move {
                let _ = rx.await;
            }
        };
        let server_task = tokio::spawn(async move { server.run(shutdown).await });

        let mut client = Client::connect(&sock).await.unwrap();
        let mut events = Vec::new();
        let resp = client
            .call(
                "hello",
                serde_json::json!({"x": 1}),
                Some(std::time::Duration::from_secs(5)),
                &mut |ev| events.push(ev),
            )
            .await
            .unwrap();
        assert!(resp.ok);
        assert_eq!(resp.into_result().unwrap()["echo"]["x"], 1);
        assert!(events.iter().any(|e| e.kind() == "info"));

        // Error responses propagate.
        let resp = client
            .call_simple("fail", serde_json::json!({}))
            .await
            .unwrap();
        assert!(!resp.ok);
        assert_eq!(
            resp.into_result().unwrap_err().to_string(),
            "ipc error: boom"
        );

        // A second server on the same socket must be refused.
        assert!(Server::bind(&sock, echo_handler()).is_err());

        // Broadcast events reach connected clients.
        let mut client2 = Client::connect(&sock).await.unwrap();
        let resp = client2
            .call_simple("hello", serde_json::json!({}))
            .await
            .unwrap();
        assert!(resp.ok);

        drop(client);
        drop(client2);
        server_task.abort();
    }

    #[tokio::test]
    async fn broadcast_reaches_client() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("b.sock");
        let server = Server::bind(&sock, echo_handler()).unwrap();
        let events = server.events();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            server
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await
        });

        let mut client = Client::connect(&sock).await.unwrap();
        // trigger a broadcast from "outside"; the server may not have
        // subscribed the fresh connection yet, so retry briefly.
        let event = Event::NetAlert {
            message: "blocked".into(),
            severity: Severity::High,
        };
        for _ in 0..100 {
            match events.send(event.clone()) {
                Ok(_) => break,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        }

        let mut seen = Vec::new();
        // The broadcast event may arrive while waiting for this call.
        let _ = client
            .call(
                "hello",
                serde_json::json!({}),
                Some(std::time::Duration::from_secs(5)),
                &mut |ev| seen.push(ev),
            )
            .await
            .unwrap();
        // There is a race: if the event arrives after the response, wait a bit.
        if seen.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let _ = client
                .call(
                    "hello",
                    serde_json::json!({}),
                    Some(std::time::Duration::from_secs(5)),
                    &mut |ev| seen.push(ev),
                )
                .await
                .unwrap();
        }
        assert!(seen.iter().any(|e| e.kind() == "net_alert"));

        let _ = stop_tx.send(());
        server_task.abort();
    }
}
