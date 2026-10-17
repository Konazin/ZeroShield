//! IPC client used by the CLI (and GUI).

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

use zs_core::error::{ZsError, ZsResult};
use zs_core::event::Event;

use crate::protocol::{Frame, Request, Response};

pub struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next_id: u64,
    line_buf: String,
}

impl Client {
    pub async fn connect(path: &Path) -> ZsResult<Self> {
        let stream = UnixStream::connect(path).await.map_err(|e| {
            ZsError::Ipc(format!(
                "cannot connect to daemon socket {}: {e}",
                path.display()
            ))
        })?;
        let (rd, wr) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(rd),
            writer: wr,
            next_id: 1,
            line_buf: String::new(),
        })
    }

    /// Returns true if a daemon is listening on `path`.
    pub async fn ping(path: &Path) -> bool {
        UnixStream::connect(path).await.is_ok()
    }

    /// Send a request and wait for the matching response.
    ///
    /// `on_event` receives every `event` frame that arrives while waiting
    /// (streamed progress of this call plus daemon-wide broadcasts).
    pub async fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
        timeout: Option<Duration>,
        on_event: &mut dyn FnMut(Event),
    ) -> ZsResult<Response> {
        let id = self.next_id;
        self.next_id += 1;

        let req = Request::new(id, method, params);
        let mut line = serde_json::to_string(&req)?;
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .await
            .map_err(|e| ZsError::Ipc(format!("failed to send request: {e}")))?;
        self.writer
            .flush()
            .await
            .map_err(|e| ZsError::Ipc(format!("failed to flush request: {e}")))?;

        loop {
            self.line_buf.clear();
            let read = self.reader.read_line(&mut self.line_buf);
            let result = match timeout {
                Some(t) => tokio::time::timeout(t, read)
                    .await
                    .map_err(|_| ZsError::Ipc("daemon request timed out".into()))?,
                None => read.await,
            };
            let n = result.map_err(|e| ZsError::Ipc(format!("daemon connection lost: {e}")))?;
            if n == 0 {
                return Err(ZsError::Ipc("daemon closed the connection".into()));
            }
            match Frame::parse(&self.line_buf) {
                Ok(Frame::Event(envelope)) => on_event(envelope.event),
                Ok(Frame::Response(resp)) => {
                    if resp.id == id {
                        return Ok(resp);
                    }
                    // Stale response for another call; ignore.
                }
                Err(_) => continue,
            }
        }
    }

    /// Convenience wrapper without event handling.
    pub async fn call_simple(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> ZsResult<Response> {
        self.call(method, params, Some(Duration::from_secs(10)), &mut |_| {})
            .await
    }

    /// Read frames until an event arrives. Returns `Ok(None)` when the daemon
    /// closes the connection. Used by `zeroshield proc watch`.
    pub async fn next_event(&mut self, timeout: Option<Duration>) -> ZsResult<Option<Event>> {
        loop {
            self.line_buf.clear();
            let read = self.reader.read_line(&mut self.line_buf);
            let result = match timeout {
                Some(t) => tokio::time::timeout(t, read)
                    .await
                    .map_err(|_| ZsError::Ipc("timed out waiting for daemon events".into()))?,
                None => read.await,
            };
            let n = result.map_err(|e| ZsError::Ipc(format!("daemon connection lost: {e}")))?;
            if n == 0 {
                return Ok(None);
            }
            match Frame::parse(&self.line_buf) {
                Ok(Frame::Event(envelope)) => return Ok(Some(envelope.event)),
                Ok(Frame::Response(_)) => continue,
                Err(_) => continue,
            }
        }
    }
}
