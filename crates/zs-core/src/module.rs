//! Module contract.
//!
//! Every capability of ZeroShield (file scanning, process monitoring, network
//! guard, ...) is implemented as a module exposing this contract. The daemon
//! owns the module instances and dispatches IPC requests to them.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FileScan,
    FileWatch,
    DeviceScan,
    ProcessScan,
    NetworkAudit,
    NetworkFilter,
    DnsFilter,
    Quarantine,
    SignatureUpdate,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::FileScan => "file-scan",
            Capability::FileWatch => "file-watch",
            Capability::DeviceScan => "device-scan",
            Capability::ProcessScan => "process-scan",
            Capability::NetworkAudit => "network-audit",
            Capability::NetworkFilter => "network-filter",
            Capability::DnsFilter => "dns-filter",
            Capability::Quarantine => "quarantine",
            Capability::SignatureUpdate => "signature-update",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatus {
    pub name: String,
    pub description: String,
    pub capabilities: Vec<Capability>,
    pub healthy: bool,
    pub detail: String,
}

#[async_trait]
pub trait Module: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn capabilities(&self) -> Vec<Capability>;

    /// Health/status snapshot, shown by `zeroshield modules`.
    async fn status(&self) -> ModuleStatus;
}
