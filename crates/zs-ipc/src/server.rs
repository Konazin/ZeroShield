//! IPC server used by `zeroshieldd`.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc};

use zs_core::error::{ZsError, ZsResult};
use zs_core::event::Event;

use crate::protocol::{
    EventEnvelope, Frame, Request, Response, MAX_FRAME_BYTES, MAX_INFLIGHT_REQUESTS,
};

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
    serve_connection_with_limits(
        stream,
        handler,
        events,
        MAX_FRAME_BYTES,
        MAX_INFLIGHT_REQUESTS,
    )
    .await
}

/// Connection loop with explicit limits.
///
/// Split from [`serve_connection`] so tests can exercise the frame-size and
/// in-flight caps with tiny values instead of megabyte buffers.
async fn serve_connection_with_limits(
    stream: UnixStream,
    handler: Handler,
    events: broadcast::Sender<Event>,
    max_frame_bytes: usize,
    max_inflight: usize,
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
    // Two caps protect the daemon from a hostile or buggy client:
    //   * `max_frame_bytes` bounds how much memory a single frame can use;
    //   * `max_inflight` bounds how many request tasks one connection spawns.
    let mut reader = BufReader::new(rd);
    let mut line_buf = String::new();
    let inflight = Arc::new(tokio::sync::Semaphore::new(max_inflight.max(1)));
    let read_limit = max_frame_bytes.saturating_add(1) as u64;
    loop {
        line_buf.clear();
        // `take` caps the bytes buffered for a single line: an endless line
        // can never grow `line_buf` beyond `read_limit` bytes.
        match (&mut reader)
            .take(read_limit)
            .read_line(&mut line_buf)
            .await
        {
            Ok(0) => break, // client disconnected
            Ok(_) => {}
            Err(e) => {
                tracing::debug!("read error: {e}");
                break;
            }
        }
        if !line_buf.ends_with('\n') {
            if line_buf.len() as u64 >= read_limit {
                let _ = tx.send(Frame::Response(Response::err(
                    0,
                    format!("frame exceeds the {max_frame_bytes} byte limit"),
                )));
                tracing::debug!("closing connection: oversized frame");
            } else if !line_buf.is_empty() {
                // EOF in the middle of a frame: nothing sensible to answer.
                tracing::debug!("closing connection: partial frame at end of stream");
            }
            break;
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
        // Backpressure: wait for a free slot before spawning the task so a
        // single connection cannot queue unbounded work.
        let permit = match inflight.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
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
            drop(permit);
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

    fn slow_handler() -> Handler {
        Arc::new(|req: Request, _tx: FrameTx| {
            Box::pin(async move {
                if req.method == "slow" {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Response::ok(req.id, serde_json::json!({"echo": req.params}))
            })
        })
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_and_closed() {
        let (server_side, mut client) = UnixStream::pair().unwrap();
        let events = broadcast::channel(8).0;
        let task = tokio::spawn(serve_connection_with_limits(
            server_side,
            echo_handler(),
            events,
            512,
            4,
        ));

        // One frame without a newline, well above the 512 byte cap.
        client.write_all("x".repeat(600).as_bytes()).await.unwrap();

        let mut reader = BufReader::new(&mut client);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        match Frame::parse(&line).unwrap() {
            Frame::Response(resp) => {
                assert!(!resp.ok);
                assert!(resp.error.unwrap().contains("512"));
            }
            other => panic!("expected response frame, got {other:?}"),
        }

        // The connection is closed right after the error frame.
        line.clear();
        assert_eq!(reader.read_line(&mut line).await.unwrap(), 0);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn partial_frame_at_eof_closes_silently() {
        let (server_side, mut client) = UnixStream::pair().unwrap();
        let events = broadcast::channel(8).0;
        let task = tokio::spawn(serve_connection_with_limits(
            server_side,
            echo_handler(),
            events,
            512,
            4,
        ));

        client.write_all(b"{\"id\":1,").await.unwrap();
        client.shutdown().await.unwrap();

        let mut reader = BufReader::new(&mut client);
        let mut line = String::new();
        assert_eq!(reader.read_line(&mut line).await.unwrap(), 0);
        assert!(line.is_empty());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn inflight_limit_backpressures_without_deadlock() {
        let (server_side, mut client) = UnixStream::pair().unwrap();
        let events = broadcast::channel(8).0;
        let task = tokio::spawn(serve_connection_with_limits(
            server_side,
            slow_handler(),
            events,
            4096,
            2,
        ));

        // Six slow requests pipelined through a limit of two in flight: the
        // reader must block on the semaphore, then drain everything.
        let request = "{\"id\":7,\"method\":\"slow\",\"params\":{}}\n";
        for _ in 0..6 {
            client.write_all(request.as_bytes()).await.unwrap();
        }

        let mut reader = BufReader::new(&mut client);
        let responses = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut responses = 0;
            let mut line = String::new();
            while responses < 6 {
                line.clear();
                if reader.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                assert!(matches!(Frame::parse(&line).unwrap(), Frame::Response(_)));
                responses += 1;
            }
            responses
        })
        .await
        .expect("server deadlocked under backpressure");
        assert_eq!(responses, 6);

        drop(reader);
        drop(client);
        task.await.unwrap().unwrap();
    }
}
