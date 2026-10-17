//! Configuration loading and defaults.
//!
//! Configuration is TOML. Lookup order:
//!   1. `$ZS_CONFIG` (explicit path)
//!   2. `/etc/zeroshield/config.toml` (system installs, preferred when root)
//!   3. `$XDG_CONFIG_HOME/zeroshield/config.toml` (usually `~/.config/zeroshield`)
//!
//! Missing files are not an error: built-in defaults are used.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{ZsError, ZsResult};
use crate::paths::Paths;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub general: GeneralConfig,
    pub scanner: ScannerConfig,
    pub procmon: ProcMonConfig,
    pub netguard: NetGuardConfig,
    pub watch: WatchConfig,
    pub automount: AutomountConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// tracing filter, e.g. `info`, `debug`, `zeroshield=debug`.
    pub log_level: String,
    /// Emit JSON logs (useful for journald/ELK).
    pub log_json: bool,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: "info".into(),
            log_json: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScannerConfig {
    pub recursive: bool,
    pub follow_symlinks: bool,
    /// Files larger than this are skipped (bytes).
    pub max_file_size: u64,
    /// Minimum score for a file to be reported as a finding.
    pub min_report_score: u32,
    /// Automatically quarantine malicious files found during a scan.
    pub quarantine: bool,
    pub hash_cache: bool,
    /// Reuse the verdict of files already scanned clean (unchanged size/mtime
    /// and same signature/rules version) without reading them again.
    pub clean_cache: bool,
    /// Upper bound for the clean-file cache (oldest entries are pruned).
    pub clean_cache_max_entries: u64,
    /// How long a clean file may stay in the hash cache (seconds).
    pub clean_cache_ttl_secs: u64,
    /// Maximum number of bytes inspected for content rules per file.
    pub content_scan_max_bytes: u64,
    /// Extra directories with `.toml` rule files.
    pub rule_dirs: Vec<PathBuf>,
    /// Directory names that are never descended into.
    pub exclude_dirs: Vec<String>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            recursive: true,
            follow_symlinks: false,
            max_file_size: 512 * 1024 * 1024,
            min_report_score: 20,
            quarantine: false,
            hash_cache: true,
            clean_cache: true,
            clean_cache_max_entries: 200_000,
            clean_cache_ttl_secs: 7 * 24 * 3600,
            content_scan_max_bytes: 16 * 1024 * 1024,
            rule_dirs: vec![PathBuf::from("/usr/share/zeroshield/rules")],
            exclude_dirs: vec![".git".into(), "node_modules".into(), "__pycache__".into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcMonConfig {
    pub enabled: bool,
    /// Poll interval of the process watcher (seconds).
    pub poll_interval_secs: u64,
    /// Minimum score for a process to generate an alert.
    pub alert_score: u32,
    /// Report every new process, not only suspicious ones (debugging).
    pub report_all_new: bool,
}

impl Default for ProcMonConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: 5,
            alert_score: 40,
            report_all_new: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WatchConfig {
    /// Start watchers for `paths` automatically when the daemon boots.
    pub enabled: bool,
    /// Directories monitored in real time (new and changed files).
    pub paths: Vec<PathBuf>,
    /// Quarantine malicious files detected by the watcher.
    pub quarantine: bool,
    /// Watch subdirectories as well.
    pub recursive: bool,
    /// Wait this long after the last write before scanning a file, so that
    /// partially written files are not scanned mid-copy.
    pub debounce_ms: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            paths: Vec::new(),
            quarantine: false,
            recursive: true,
            debounce_ms: 800,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AutomountConfig {
    /// Scan removable media automatically when it is mounted.
    pub enabled: bool,
    /// Poll interval for `/proc/mounts` (seconds).
    pub poll_interval_secs: u64,
    /// Mount points below these prefixes are treated as removable media.
    pub roots: Vec<PathBuf>,
    /// Quarantine malicious files found on mounted media.
    pub quarantine: bool,
}

impl Default for AutomountConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_interval_secs: 5,
            roots: vec![
                PathBuf::from("/media"),
                PathBuf::from("/run/media"),
                PathBuf::from("/mnt"),
            ],
            quarantine: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetMode {
    /// Only log what *would* be blocked. Always the safe default.
    Audit,
    /// Actually install nftables rules.
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    Off,
    Dnsmasq,
    Unbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetGuardConfig {
    pub enabled: bool,
    pub mode: NetMode,
    /// Name of the isolated nftables table.
    pub nft_table: String,
    pub feed_urls: Vec<String>,
    /// Feed cache lifetime (seconds).
    pub feed_cache_ttl_secs: u64,
    pub dns_mode: DnsMode,
    pub dnsmasq_dir: PathBuf,
    pub unbound_dir: PathBuf,
    /// Never blocked, always allowed (IPs, CIDRs or domains).
    pub allowlist: Vec<String>,
    /// Always blocked (IPs, CIDRs or domains).
    pub blocklist: Vec<String>,
}

impl Default for NetGuardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: NetMode::Audit,
            nft_table: "zeroshield".into(),
            feed_urls: vec![
                "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".into(),
                "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt".into(),
                "https://rules.emergingthreats.net/blockrules/compromised-ips.txt".into(),
                "https://urlhaus.abuse.ch/downloads/text/".into(),
            ],
            feed_cache_ttl_secs: 6 * 3600,
            dns_mode: DnsMode::Off,
            dnsmasq_dir: PathBuf::from("/etc/dnsmasq.d"),
            unbound_dir: PathBuf::from("/etc/unbound/unbound.conf.d"),
            allowlist: Vec::new(),
            blocklist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct StorageConfig {
    /// Override database path (default: `<data_dir>/zeroshield.db`).
    pub path: Option<PathBuf>,
}

impl Config {
    /// Load the configuration, falling back to defaults.
    pub fn load(paths: &Paths) -> ZsResult<(Self, Option<PathBuf>)> {
        match &paths.config_file {
            Some(file) => {
                let cfg = Self::load_file(file)?;
                Ok((cfg, Some(file.clone())))
            }
            None => Ok((Self::default(), None)),
        }
    }

    pub fn load_file(path: &Path) -> ZsResult<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| ZsError::io(path.to_path_buf(), e))?;
        let cfg: Config = toml::from_str(&text)
            .map_err(|e| ZsError::Config(format!("failed to parse {}: {e}", path.display())))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse and validate TOML text without any file I/O (used by tests and
    /// fuzz targets).
    pub fn parse_toml(text: &str) -> ZsResult<Self> {
        let cfg: Config = toml::from_str(text)
            .map_err(|e| ZsError::Config(format!("failed to parse config: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> ZsResult<()> {
        if self.scanner.min_report_score > 100 {
            return Err(ZsError::Config(
                "scanner.min_report_score must be <= 100".into(),
            ));
        }
        if self.procmon.alert_score > 100 {
            return Err(ZsError::Config("procmon.alert_score must be <= 100".into()));
        }
        if self.netguard.nft_table.is_empty()
            || !self
                .netguard
                .nft_table
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(ZsError::Config(
                "netguard.nft_table must be a plain identifier".into(),
            ));
        }
        if self.scanner.max_file_size == 0 {
            return Err(ZsError::Config("scanner.max_file_size must be > 0".into()));
        }
        if self.scanner.clean_cache_max_entries == 0 {
            return Err(ZsError::Config(
                "scanner.clean_cache_max_entries must be > 0".into(),
            ));
        }
        if self.watch.debounce_ms > 60_000 {
            return Err(ZsError::Config("watch.debounce_ms must be <= 60000".into()));
        }
        if self.watch.enabled && self.watch.paths.is_empty() {
            return Err(ZsError::Config(
                "watch.paths must not be empty when watch.enabled = true".into(),
            ));
        }
        if self.automount.enabled && self.automount.roots.is_empty() {
            return Err(ZsError::Config(
                "automount.roots must not be empty when automount.enabled = true".into(),
            ));
        }
        if self.automount.poll_interval_secs == 0 {
            return Err(ZsError::Config(
                "automount.poll_interval_secs must be > 0".into(),
            ));
        }
        Ok(())
    }

    pub fn to_toml(&self) -> ZsResult<String> {
        toml::to_string_pretty(self)
            .map_err(|e| ZsError::Config(format!("failed to serialize config: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn parses_partial_toml() {
        let text = r#"
[scanner]
min_report_score = 50
recursive = false

[netguard]
mode = "block"
dns_mode = "dnsmasq"

[watch]
enabled = true
paths = ["/home", "/tmp"]
quarantine = true
debounce_ms = 1500

[automount]
enabled = true
poll_interval_secs = 10
roots = ["/media"]
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        assert_eq!(cfg.scanner.min_report_score, 50);
        assert!(!cfg.scanner.recursive);
        assert_eq!(cfg.netguard.mode, NetMode::Block);
        assert_eq!(cfg.netguard.dns_mode, DnsMode::Dnsmasq);
        assert!(cfg.watch.enabled);
        assert_eq!(cfg.watch.paths.len(), 2);
        assert!(cfg.watch.quarantine);
        assert_eq!(cfg.watch.debounce_ms, 1500);
        assert!(cfg.watch.recursive, "untouched keys keep defaults");
        assert!(cfg.automount.enabled);
        assert_eq!(cfg.automount.poll_interval_secs, 10);
        // untouched sections keep defaults
        assert_eq!(cfg.procmon.poll_interval_secs, 5);
        cfg.validate().unwrap();
    }

    #[test]
    fn watch_enabled_requires_paths() {
        let text = r#"
[watch]
enabled = true
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn automount_enabled_requires_roots() {
        let mut cfg = Config::default();
        cfg.automount.enabled = true;
        cfg.automount.roots.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_invalid_config() {
        let mut cfg = Config::default();
        cfg.scanner.min_report_score = 101;
        assert!(cfg.validate().is_err());
    }
}
