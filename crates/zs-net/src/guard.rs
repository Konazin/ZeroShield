//! NetGuard orchestration: feeds → rules → nftables/DNS.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use zs_core::config::{DnsMode, NetGuardConfig, NetMode};
use zs_core::error::ZsResult;
use zs_core::storage::Storage;
use zs_core::util::{is_root, now_secs};

use crate::blocklist::{Blocklist, Decision};
use crate::dns::{self, DnsBackend};
use crate::feeds;
use crate::nft;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetStatus {
    pub enabled: bool,
    pub mode: String,
    pub nft_available: bool,
    pub nft_installed: bool,
    pub is_root: bool,
    pub rule_count: u64,
    pub feeds: usize,
    pub dns_mode: String,
    pub allowlist: usize,
    pub blocklist: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    pub target: String,
    pub kind: String,
    pub decision: String,
    pub rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedUpdateResult {
    pub url: String,
    pub source: String,
    pub entries: u64,
    pub skipped: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyOutcome {
    pub applied: bool,
    pub rules_file: String,
    pub rule_count: usize,
    pub ruleset: String,
    pub message: String,
}

pub struct NetGuard {
    cfg: NetGuardConfig,
    storage: Arc<Storage>,
    cache_dir: PathBuf,
    data_dir: PathBuf,
}

impl NetGuard {
    pub fn new(
        cfg: NetGuardConfig,
        storage: Arc<Storage>,
        cache_dir: PathBuf,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            cfg,
            storage,
            cache_dir,
            data_dir,
        }
    }

    pub fn config(&self) -> &NetGuardConfig {
        &self.cfg
    }

    pub fn net_status(&self) -> ZsResult<NetStatus> {
        let (rules_file, nft_installed) = {
            let path = nft::default_ruleset_path(&self.data_dir);
            let installed = path.exists();
            (path, installed)
        };
        let _ = rules_file;
        Ok(NetStatus {
            enabled: self.cfg.enabled,
            mode: match self.cfg.mode {
                NetMode::Audit => "audit".into(),
                NetMode::Block => "block".into(),
            },
            nft_available: nft::nft_available(),
            nft_installed,
            is_root: is_root(),
            rule_count: self.storage.net_rule_count()?,
            feeds: self.cfg.feed_urls.len(),
            dns_mode: match self.cfg.dns_mode {
                DnsMode::Off => "off".into(),
                DnsMode::Dnsmasq => "dnsmasq".into(),
                DnsMode::Unbound => "unbound".into(),
            },
            allowlist: self.cfg.allowlist.len(),
            blocklist: self.cfg.blocklist.len(),
        })
    }

    /// Build the effective block/allow lists.
    pub fn build_blocklist(&self) -> ZsResult<Blocklist> {
        let mut bl = Blocklist::default();
        // Whitelist first so it always wins.
        for entry in &self.cfg.allowlist {
            add_config_entry(&mut bl, entry, true);
        }
        for entry in &self.cfg.blocklist {
            add_config_entry(&mut bl, entry, false);
        }
        for (kind, value, _source) in self.storage.list_net_rules(true)? {
            if !bl.add(&kind, &value, false) {
                tracing::warn!("ignoring invalid stored rule {kind}:{value}");
            }
        }
        Ok(bl)
    }

    /// Explain the verdict for each target (IP, CIDR, domain or URL).
    pub fn audit(&self, targets: &[String]) -> ZsResult<Vec<AuditResult>> {
        let bl = self.build_blocklist()?;
        let mut out = Vec::new();
        for target in targets {
            let t = target.trim();
            let (kind, decision) = if Blocklist::is_ip(t) {
                ("ip".to_string(), bl.decision_ip(t))
            } else if let Some(host) = host_of_url(t) {
                ("domain".to_string(), bl.decision_domain(&host))
            } else if let Some((addr, _prefix)) = t.split_once('/') {
                if Blocklist::is_ip(addr) {
                    ("cidr".to_string(), audit_cidr(&bl, addr, t))
                } else {
                    ("unknown".to_string(), Decision::Unknown)
                }
            } else if t.contains('.') {
                ("domain".to_string(), bl.decision_domain(t))
            } else {
                ("unknown".to_string(), Decision::Unknown)
            };
            out.push(AuditResult {
                target: target.clone(),
                kind,
                decision: decision.as_str().to_string(),
                rule: decision.rule().map(|s| s.to_string()),
            });
        }
        Ok(out)
    }

    /// Download and ingest every configured feed (respecting the cache TTL).
    pub fn update_feeds(&self, force: bool) -> Vec<FeedUpdateResult> {
        std::fs::create_dir_all(&self.cache_dir).ok();
        let mut results = Vec::new();
        for url in &self.cfg.feed_urls {
            let name = feed_name(url);
            let dest = self.cache_dir.join(format!("{name}.txt"));
            let mut result = FeedUpdateResult {
                url: url.clone(),
                source: format!("feed:{name}"),
                entries: 0,
                skipped: false,
                error: None,
            };

            let fresh = !force && is_fresh(&dest, self.cfg.feed_cache_ttl_secs);
            if fresh {
                result.skipped = true;
            } else if let Err(e) = download(url, &dest) {
                result.error = Some(e);
                results.push(result);
                continue;
            }

            if !dest.exists() {
                result.error = Some("feed file missing and could not be downloaded".into());
                results.push(result);
                continue;
            }

            match feeds::load_feed_file(&dest, &result.source) {
                Ok(entries) => {
                    // Replace the previous content of this feed.
                    let _ = self.storage.clear_net_rules(Some(&result.source));
                    for entry in &entries {
                        if let Err(e) =
                            self.storage
                                .upsert_net_rule(&entry.kind, &entry.value, &result.source)
                        {
                            tracing::warn!("failed to store rule {}: {e}", entry.value);
                        }
                    }
                    result.entries = entries.len() as u64;
                }
                Err(e) => result.error = Some(e.to_string()),
            }
            results.push(result);
        }
        tracing::info!("feed update finished ({} feeds)", results.len());
        results
    }

    /// Generate (and optionally install) nftables rules. Never applies
    /// anything unless the config explicitly enables block mode and this
    /// process is root.
    pub fn apply(&self, dry_run: bool) -> ZsResult<ApplyOutcome> {
        let bl = self.build_blocklist()?;
        let ips = bl.blocked_net_strings();
        let ruleset = nft::generate_ruleset(&self.cfg.nft_table, &ips);
        let path = nft::default_ruleset_path(&self.data_dir);
        nft::write_ruleset(&path, &ruleset)?;

        let mut outcome = ApplyOutcome {
            applied: false,
            rules_file: path.display().to_string(),
            rule_count: ips.len(),
            ruleset,
            message: String::new(),
        };

        if dry_run {
            outcome.message = "dry-run: ruleset generated but not applied".into();
            return Ok(outcome);
        }
        if !self.cfg.enabled {
            outcome.message = "netguard is disabled (netguard.enabled = false)".into();
            return Ok(outcome);
        }
        if self.cfg.mode != NetMode::Block {
            outcome.message =
                "netguard is in audit mode; set netguard.mode = \"block\" to apply".into();
            return Ok(outcome);
        }
        if !is_root() {
            outcome.message = "applying nftables rules requires root".into();
            return Ok(outcome);
        }

        nft::flush(&self.cfg.nft_table)?;
        let out = nft::apply_file(&path)?;
        outcome.applied = true;
        outcome.message = if out.is_empty() {
            format!("applied {} rules", outcome.rule_count)
        } else {
            out
        };
        Ok(outcome)
    }

    /// Write the DNS sinkhole fragment; install it when possible.
    pub fn write_dns(&self, install: bool) -> ZsResult<Option<PathBuf>> {
        let backend = match self.cfg.dns_mode {
            DnsMode::Off => return Ok(None),
            DnsMode::Dnsmasq => DnsBackend::Dnsmasq,
            DnsMode::Unbound => DnsBackend::Unbound,
        };
        let domains = self.build_blocklist()?.blocked_domain_strings();
        let fragment = dns::write_fragment(&self.data_dir, backend, &domains)?;
        if install {
            let target_dir = match backend {
                DnsBackend::Dnsmasq => self.cfg.dnsmasq_dir.clone(),
                DnsBackend::Unbound => self.cfg.unbound_dir.clone(),
            };
            let installed = dns::install(&fragment, &target_dir, backend)?;
            return Ok(Some(installed));
        }
        Ok(Some(fragment))
    }
}

fn add_config_entry(bl: &mut Blocklist, entry: &str, allowed: bool) {
    let e = entry.trim();
    if e.is_empty() {
        return;
    }
    let (kind, value) = if let Some((addr, _)) = e.split_once('/') {
        if Blocklist::is_ip(addr) {
            ("cidr", e)
        } else if let Some(host) = host_of_url(e) {
            let _ = host;
            ("domain", e)
        } else {
            ("domain", e)
        }
    } else if Blocklist::is_ip(e) {
        ("ip", e)
    } else {
        ("domain", e)
    };
    if !bl.add(kind, value, allowed) {
        tracing::warn!("invalid netguard config entry ignored: {entry}");
    }
}

fn audit_cidr(bl: &Blocklist, addr: &str, full: &str) -> Decision {
    let mask = match full.split_once('/').and_then(|(_, p)| p.parse::<u8>().ok()) {
        Some(m) => m,
        None => return Decision::Unknown,
    };
    // Audit the network address and the last address of the range.
    let mut decision = bl.decision_ip(addr);
    if matches!(decision, Decision::Unknown) && mask < 32 {
        let Some(base) = crate::blocklist::parse_ipv4_u32(addr) else {
            return Decision::Unknown;
        };
        let broadcast = base | (u32::MAX >> mask);
        decision = bl.decision_ip(&crate::blocklist::u32_to_ip(broadcast));
    }
    decision
}

fn host_of_url(s: &str) -> Option<String> {
    let rest = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))?;
    let host = rest
        .split(['/', '?', '#'])
        .next()?
        .split(':')
        .next()?
        .to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn feed_name(url: &str) -> String {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host_path = after_scheme.replace(['/', '?', '&', '='], "_");
    let cleaned: String = host_path
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "feed".into()
    } else {
        trimmed.chars().take(80).collect()
    }
}

fn is_fresh(path: &Path, ttl_secs: u64) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let age = match std::time::SystemTime::now().duration_since(modified) {
        Ok(age) => age,
        Err(_) => return false,
    };
    age < Duration::from_secs(ttl_secs)
}

fn download(url: &str, dest: &Path) -> Result<(), String> {
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "60",
            "--proto",
            "=https",
            "--tlsv1.2",
            "-o",
        ])
        .arg(dest)
        .arg(url)
        .output()
        .map_err(|e| format!("failed to run curl: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Timestamp helper used by callers that log feed updates.
pub fn last_update_ts() -> i64 {
    now_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> (tempfile::TempDir, NetGuard) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open_in_memory().unwrap());
        let cfg = NetGuardConfig {
            // keep the test hermetic: no network feeds
            feed_urls: vec![],
            allowlist: vec!["10.1.1.1".into(), "trusted.example".into()],
            ..Default::default()
        };
        let guard = NetGuard::new(
            cfg,
            storage,
            dir.path().join("cache"),
            dir.path().join("data"),
        );
        (dir, guard)
    }

    #[test]
    fn audit_ip_and_domain() {
        let (_d, guard) = guard();
        guard
            .storage
            .upsert_net_rule("cidr", "203.0.113.0/24", "test")
            .unwrap();
        guard
            .storage
            .upsert_net_rule("domain", "evil.example", "test")
            .unwrap();

        let results = guard
            .audit(&[
                "203.0.113.9".into(),
                "sub.evil.example".into(),
                "10.1.1.1".into(),
                "https://evil.example/payload".into(),
                "8.8.8.8".into(),
            ])
            .unwrap();

        assert_eq!(results[0].decision, "blocked");
        assert_eq!(results[1].decision, "blocked");
        assert_eq!(results[2].decision, "allowed"); // allowlist wins
        assert_eq!(results[3].decision, "blocked"); // URL host extracted
        assert_eq!(results[4].decision, "unknown");
    }

    #[test]
    fn apply_dry_run_generates_ruleset() {
        let (_d, guard) = guard();
        guard
            .storage
            .upsert_net_rule("ip", "198.51.100.7", "test")
            .unwrap();
        let outcome = guard.apply(true).unwrap();
        assert!(!outcome.applied);
        assert_eq!(outcome.rule_count, 1);
        assert!(outcome.ruleset.contains("198.51.100.7"));
        assert!(Path::new(&outcome.rules_file).exists());
    }

    #[test]
    fn apply_respects_disabled_and_audit() {
        let (_d, guard) = guard();
        // enabled=false by default
        let outcome = guard.apply(false).unwrap();
        assert!(!outcome.applied);
        assert!(outcome.message.contains("disabled"));
    }

    #[test]
    fn status_reports_config() {
        let (_d, guard) = guard();
        let status = guard.net_status().unwrap();
        assert_eq!(status.mode, "audit");
        assert_eq!(status.dns_mode, "off");
        assert_eq!(status.allowlist, 2);
    }

    #[test]
    fn dns_fragment_is_written_from_rules() {
        let (_d, mut guard) = guard();
        guard.cfg.dns_mode = DnsMode::Dnsmasq;
        guard
            .storage
            .upsert_net_rule("domain", "evil.example", "test")
            .unwrap();
        let path = guard.write_dns(false).unwrap().unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains("evil.example"));
    }

    #[test]
    fn dns_fragment_includes_config_blocklist() {
        let (_d, mut guard) = guard();
        guard.cfg.dns_mode = DnsMode::Dnsmasq;
        guard.cfg.blocklist = vec!["malware.example".into(), "trusted.example".into()];
        let path = guard.write_dns(false).unwrap().unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains("address=/malware.example/0.0.0.0"));
        // The allowlist wins: trusted.example must not be sinkholed.
        assert!(!text.contains("trusted.example"));
    }

    #[test]
    fn feed_name_is_sanitized() {
        assert_eq!(
            feed_name("https://example.com/a/b.txt"),
            "example.com_a_b.txt"
        );
        assert!(!feed_name("").is_empty());
    }
}
