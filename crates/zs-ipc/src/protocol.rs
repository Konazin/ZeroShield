//! Wire protocol types.

use serde::{Deserialize, Serialize};

use zs_core::error::{ZsError, ZsResult};
use zs_core::event::Event;

/// Request method names understood by the daemon.
pub mod methods {
    pub const STATUS: &str = "status";
    pub const MODULES: &str = "modules";
    pub const SCAN_RUN: &str = "scan.run";
    pub const PROC_LIST: &str = "proc.list";
    pub const PROC_AUDIT: &str = "proc.audit";
    pub const QUARANTINE_LIST: &str = "quarantine.list";
    pub const QUARANTINE_RESTORE: &str = "quarantine.restore";
    pub const QUARANTINE_PURGE: &str = "quarantine.purge";
    pub const SIGS_IMPORT: &str = "sigs.import";
    pub const RULES_LIST: &str = "rules.list";
    pub const EVENTS_LIST: &str = "events.list";
    pub const FINDINGS_LIST: &str = "findings.list";
    pub const NET_STATUS: &str = "net.status";
    pub const NET_AUDIT: &str = "net.audit";
    pub const NET_FEEDS_UPDATE: &str = "net.feeds.update";
    pub const NET_APPLY: &str = "net.apply";
    pub const NET_DNS: &str = "net.dns";
    pub const SHUTDOWN: &str = "daemon.shutdown";
    /// Keeps the connection open and streams events (process alerts, ...).
    pub const WATCH: &str = "watch.start";
    /// Start a real-time directory watch session (`watch.fs.start`).
    pub const WATCH_FS_START: &str = "watch.fs.start";
    /// Stop watch sessions (`watch.fs.stop`).
    pub const WATCH_FS_STOP: &str = "watch.fs.stop";
    /// List active watch sessions (`watch.fs.list`).
    pub const WATCH_FS_LIST: &str = "watch.fs.list";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

impl Request {
    pub fn new(id: u64, method: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            id,
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn ok(id: u64, result: serde_json::Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: u64, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(message.into()),
        }
    }

    /// Extract the result, converting a daemon error into `ZsError`.
    pub fn into_result(self) -> ZsResult<serde_json::Value> {
        if self.ok {
            Ok(self.result.unwrap_or(serde_json::Value::Null))
        } else {
            Err(ZsError::Ipc(
                self.error.unwrap_or_else(|| "unknown daemon error".into()),
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event: Event,
}

impl EventEnvelope {
    pub fn new(event: Event) -> Self {
        Self { event }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Frame {
    Response(Response),
    Event(EventEnvelope),
}

impl Frame {
    pub fn to_line(&self) -> ZsResult<String> {
        let mut line = serde_json::to_string(self)?;
        line.push('\n');
        Ok(line)
    }

    pub fn parse(line: &str) -> ZsResult<Frame> {
        serde_json::from_str(line.trim()).map_err(|e| ZsError::Ipc(format!("invalid frame: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zs_core::model::Severity;

    #[test]
    fn response_frame_roundtrip() {
        let frame = Frame::Response(Response::ok(7, serde_json::json!({"a": 1})));
        let line = frame.to_line().unwrap();
        match Frame::parse(&line).unwrap() {
            Frame::Response(r) => {
                assert_eq!(r.id, 7);
                assert!(r.ok);
                assert_eq!(r.result.unwrap()["a"], 1);
            }
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[test]
    fn event_frame_roundtrip() {
        let frame = Frame::Event(EventEnvelope::new(Event::NetAlert {
            message: "blocked 1.2.3.4".into(),
            severity: Severity::High,
        }));
        let line = frame.to_line().unwrap();
        match Frame::parse(&line).unwrap() {
            Frame::Event(e) => assert_eq!(e.event.kind(), "net_alert"),
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[test]
    fn error_response_into_result() {
        let resp = Response::err(1, "boom");
        assert!(resp.into_result().is_err());
    }
}
