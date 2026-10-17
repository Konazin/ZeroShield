//! ZeroShield process monitor.
//!
//! v0.1 uses `/proc` polling: portable, needs no privileges beyond what the
//! user already has, and works on every kernel. eBPF based real-time tracing
//! (aya) lands behind the `ebpf` feature in a follow-up milestone and will
//! feed the same heuristics with `execve`/`fork`/`connect` events.

pub mod heuristics;
pub mod procinfo;
pub mod watcher;

use async_trait::async_trait;
use zs_core::config::ProcMonConfig;
use zs_core::module::{Capability, Module, ModuleStatus};
use zs_core::util::is_root;

pub use heuristics::Evaluation;
pub use procinfo::{list_processes, read_proc};
pub use watcher::ProcWatcher;

pub struct ProcMonitor {
    cfg: ProcMonConfig,
}

impl ProcMonitor {
    pub fn new(cfg: ProcMonConfig) -> Self {
        Self { cfg }
    }

    pub fn config(&self) -> &ProcMonConfig {
        &self.cfg
    }

    /// Evaluate every visible process, sorted by score (highest first).
    pub fn audit(&self) -> Vec<zs_core::model::ProcInfo> {
        let mut procs = list_processes();
        for p in procs.iter_mut() {
            let evaluation = heuristics::evaluate(p, &self.cfg);
            p.score = evaluation.score;
            p.severity = evaluation.severity;
            p.reasons = evaluation.reason_strings();
        }
        procs.sort_by(|a, b| b.score.cmp(&a.score).then(a.pid.cmp(&b.pid)));
        procs
    }
}

#[async_trait]
impl Module for ProcMonitor {
    fn name(&self) -> &'static str {
        "procmon"
    }

    fn description(&self) -> &'static str {
        "Process monitor: enumerates /proc and scores potentially malicious processes"
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::ProcessScan]
    }

    async fn status(&self) -> ModuleStatus {
        let count = procinfo::list_pids().len();
        ModuleStatus {
            name: self.name().to_string(),
            description: self.description().to_string(),
            capabilities: self.capabilities(),
            healthy: true,
            detail: format!(
                "{} processes visible ({}), poll every {}s",
                count,
                if is_root() { "root" } else { "user" },
                self.cfg.poll_interval_secs
            ),
        }
    }
}
