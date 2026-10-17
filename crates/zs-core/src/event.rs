//! Event bus payloads.
//!
//! Events are emitted by engines, persisted in storage and broadcast over IPC
//! so that CLI/TUI/GUI clients can display live activity.

use serde::{Deserialize, Serialize};

use crate::model::{Finding, ProcAlert, ScanSummary, Severity, Verdict};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    DaemonStarted {
        version: String,
        pid: u32,
    },
    DaemonStopping,
    ScanStarted {
        scan_id: String,
        target: String,
    },
    ScanProgress {
        scan_id: String,
        path: String,
        files_scanned: u64,
        bytes_scanned: u64,
    },
    ScanFinding {
        scan_id: String,
        finding: Finding,
    },
    ScanFinished {
        summary: ScanSummary,
    },
    ProcAlert {
        alert: ProcAlert,
    },
    NetAlert {
        message: String,
        severity: Severity,
    },
    Info {
        message: String,
    },
    Warning {
        message: String,
    },
    Error {
        message: String,
    },
}

impl Event {
    /// Stable kind string, used as the storage `kind` column.
    pub fn kind(&self) -> &'static str {
        match self {
            Event::DaemonStarted { .. } => "daemon_started",
            Event::DaemonStopping => "daemon_stopping",
            Event::ScanStarted { .. } => "scan_started",
            Event::ScanProgress { .. } => "scan_progress",
            Event::ScanFinding { .. } => "scan_finding",
            Event::ScanFinished { .. } => "scan_finished",
            Event::ProcAlert { .. } => "proc_alert",
            Event::NetAlert { .. } => "net_alert",
            Event::Info { .. } => "info",
            Event::Warning { .. } => "warning",
            Event::Error { .. } => "error",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Event::DaemonStarted { .. } | Event::DaemonStopping => Severity::Info,
            Event::ScanStarted { .. } | Event::ScanProgress { .. } => Severity::Info,
            Event::ScanFinding { finding, .. } => finding.severity,
            Event::ScanFinished { summary } => match summary.verdict {
                Verdict::Malicious => Severity::High,
                Verdict::Suspicious => Severity::Medium,
                _ => Severity::Info,
            },
            Event::ProcAlert { alert } => alert.severity,
            Event::NetAlert { severity, .. } => *severity,
            Event::Info { .. } => Severity::Info,
            Event::Warning { .. } => Severity::Medium,
            Event::Error { .. } => Severity::High,
        }
    }

    /// Whether this event should be persisted (progress events are too noisy).
    pub fn is_persistent(&self) -> bool {
        !matches!(self, Event::ScanProgress { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_roundtrip() {
        let ev = Event::Info {
            message: "hello".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"type\":\"info\""));
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind(), "info");
    }

    #[test]
    fn progress_is_not_persistent() {
        let ev = Event::ScanProgress {
            scan_id: "s".into(),
            path: "/x".into(),
            files_scanned: 1,
            bytes_scanned: 2,
        };
        assert!(!ev.is_persistent());
    }
}
