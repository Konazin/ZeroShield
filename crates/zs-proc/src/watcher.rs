//! Polling based process watcher.
//!
//! Keeps a set of known pids and reports newly appeared processes that score
//! above `procmon.alert_score`.

use std::collections::HashSet;

use zs_core::config::ProcMonConfig;
use zs_core::model::{ProcAlert, Severity};
use zs_core::util::now_secs;

use crate::heuristics;
use crate::procinfo::{self, cmdline_string};

pub struct ProcWatcher {
    cfg: ProcMonConfig,
    seen: HashSet<u32>,
}

impl ProcWatcher {
    pub fn new(cfg: ProcMonConfig) -> Self {
        Self {
            cfg,
            seen: HashSet::new(),
        }
    }

    /// Mark every currently running process as known. Call once at startup so
    /// the daemon does not alert about the whole system.
    pub fn prime(&mut self) {
        self.seen = procinfo::list_pids().into_iter().collect();
    }

    pub fn seen_count(&self) -> usize {
        self.seen.len()
    }

    /// Check for new processes, returning alerts.
    pub fn poll(&mut self) -> Vec<ProcAlert> {
        let pids = procinfo::list_pids();
        let mut alerts = Vec::new();

        for &pid in &pids {
            if self.seen.contains(&pid) {
                continue;
            }
            let Some(info) = procinfo::read_proc(pid) else {
                continue;
            };
            let evaluation = heuristics::evaluate(&info, &self.cfg);
            let interesting = evaluation.score >= self.cfg.alert_score;
            if interesting || self.cfg.report_all_new {
                let severity = if interesting {
                    evaluation.severity
                } else {
                    Severity::Info
                };
                alerts.push(ProcAlert {
                    ts: now_secs(),
                    pid: info.pid,
                    ppid: info.ppid,
                    name: info.name.clone(),
                    exe: info.exe.clone(),
                    cmdline: cmdline_string(&info),
                    score: evaluation.score,
                    severity,
                    reasons: evaluation.reason_strings(),
                });
            }
        }

        // Refresh the seen set (drops dead pids).
        self.seen = pids.into_iter().collect();
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prime_then_poll_is_quiet() {
        let mut w = ProcWatcher::new(ProcMonConfig::default());
        w.prime();
        let alerts = w.poll();
        // Between prime and poll only our own test threads could appear; the
        // default alert score (40) rejects them anyway.
        assert!(alerts.iter().all(|a| a.score >= 40));
    }

    #[test]
    fn detects_new_process() {
        let mut w = ProcWatcher::new(ProcMonConfig {
            poll_interval_secs: 1,
            alert_score: 0,
            report_all_new: true,
            ..Default::default()
        });
        w.prime();

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        // Give the kernel a moment to fully set up /proc/<pid>.
        std::thread::sleep(std::time::Duration::from_millis(200));

        let alerts = w.poll();
        let found = alerts.iter().any(|a| a.pid == child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert!(found, "expected an alert for the spawned process");
    }
}
