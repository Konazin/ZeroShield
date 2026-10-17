//! ZeroShield network guard.
//!
//! Scope of v0.1:
//!   * ingest threat feeds (IP/CIDR/domain lists) and store them as rules
//!   * audit mode: explain what *would* be blocked, without touching the
//!     firewall
//!   * block mode (opt-in, requires root + nftables): install an isolated
//!     `inet` table that drops outbound traffic to blocked addresses
//!   * generate DNS sinkhole fragments for dnsmasq/Unbound
//!
//! Everything fails safe: without root or without `nft` the module only
//! reports what it would do.

pub mod blocklist;
pub mod dns;
pub mod feeds;
pub mod guard;
pub mod nft;

pub use blocklist::{Blocklist, Decision};
pub use guard::{ApplyOutcome, AuditResult, FeedUpdateResult, NetGuard, NetStatus};

use async_trait::async_trait;
use zs_core::module::{Capability, Module, ModuleStatus};
use zs_core::util::is_root;

#[async_trait]
impl Module for NetGuard {
    fn name(&self) -> &'static str {
        "netguard"
    }

    fn description(&self) -> &'static str {
        "Network guard (IPS): threat feeds, nftables outbound blocking, DNS sinkhole"
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::NetworkAudit,
            Capability::NetworkFilter,
            Capability::DnsFilter,
        ]
    }

    async fn status(&self) -> ModuleStatus {
        let detail = match self.net_status() {
            Ok(s) => format!(
                "mode={}, rules={}, nft={}, root={}",
                s.mode,
                s.rule_count,
                if s.nft_available { "yes" } else { "no" },
                if is_root() { "yes" } else { "no" }
            ),
            Err(e) => format!("status error: {e}"),
        };
        ModuleStatus {
            name: self.name().to_string(),
            description: self.description().to_string(),
            capabilities: self.capabilities(),
            healthy: true,
            detail,
        }
    }
}
