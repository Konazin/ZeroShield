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
    pub daemon: DaemonConfig,
    pub scanner: ScannerConfig,
    pub procmon: ProcMonConfig,
    pub netguard: NetGuardConfig,
    pub watch: WatchConfig,
    pub automount: AutomountConfig,
    pub storage: StorageConfig,
}

/// Client authorization for the daemon socket (M9-C).
///
/// The daemon always trusts root and its own user; everyone else is either
/// listed here or (when reachable at all, i.e. with a permissive
/// `socket_mode`) checked through polkit per request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    /// Extra UIDs with full access (no polkit prompt).
    pub client_uids: Vec<u32>,
    /// Extra GIDs with full access (primary or supplementary group).
    pub client_gids: Vec<u32>,
    /// Ask polkit (via `polkit_helper`) for untrusted local users instead of
    /// denying them outright.
    pub polkit_enabled: bool,
    /// Binary used for the polkit check (`pkcheck` compatible).
    pub polkit_helper: String,
    /// Pass `--allow-user-interaction` so an authentication agent can prompt
    /// (useful for the GUI; keeps `pkcheck` from blocking otherwise).
    pub polkit_allow_interaction: bool,
    /// Socket mode as an octal string. `"0660"` (default) keeps the socket
    /// owner-only; `"0666"` lets any local user connect, with every
    /// untrusted request checked individually.
    pub socket_mode: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            client_uids: Vec::new(),
            client_gids: Vec::new(),
            polkit_enabled: true,
            polkit_helper: "pkcheck".into(),
            polkit_allow_interaction: false,
            socket_mode: "0660".into(),
        }
    }
}

impl DaemonConfig {
    /// Parse `socket_mode` (octal) into a Unix permission bits value.
    pub fn socket_mode_bits(&self) -> ZsResult<u32> {
        let bits = u32::from_str_radix(self.socket_mode.trim(), 8).map_err(|_| {
            ZsError::Config(format!(
                "daemon.socket_mode must be an octal mode like \"0660\" (got {:?})",
                self.socket_mode
            ))
        })?;
        if bits == 0 || bits > 0o777 {
            return Err(ZsError::Config(format!(
                "daemon.socket_mode must be between 0001 and 0777 (got {:?})",
                self.socket_mode
            )));
        }
        Ok(bits)
    }
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
    /// Require a detached GPG signature (`<feed_url>.asc`) for every feed
    /// before it may replace the cache. Recommended; disabled by default
    /// for easy migration.
    pub feed_signature_required: bool,
    /// Public keyring (binary, as exported by `gpg --export`) used by
    /// `gpgv` to verify feed signatures.
    pub feed_keyring: PathBuf,
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
            feed_signature_required: false,
            feed_keyring: PathBuf::from("/etc/zeroshield/feeds.gpg"),
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
        // Reject a malformed daemon.socket_mode early (the daemon would
        // otherwise have to fall back to the restrictive default).
        self.daemon.socket_mode_bits()?;
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
    fn feed_signatures_default_to_off() {
        let cfg = NetGuardConfig::default();
        assert!(!cfg.feed_signature_required, "opt-in, migration-friendly");
        assert_eq!(cfg.feed_keyring, PathBuf::from("/etc/zeroshield/feeds.gpg"));
    }

    #[test]
    fn socket_mode_defaults_to_owner_only() {
        let cfg = DaemonConfig::default();
        assert_eq!(cfg.socket_mode_bits().unwrap(), 0o660);
        assert!(cfg.client_uids.is_empty());
        assert!(cfg.client_gids.is_empty());
    }

    #[test]
    fn socket_mode_validation_rejects_garbage() {
        let mut cfg = Config::default();
        cfg.daemon.socket_mode = "660".into(); // octal without the 0 prefix
        assert_eq!(cfg.daemon.socket_mode_bits().unwrap(), 0o660);
        for bad in ["08", "07777", "0000", "rw-", ""] {
            cfg.daemon.socket_mode = bad.into();
            assert!(cfg.validate().is_err(), "{bad:?} must be rejected");
        }
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
feed_signature_required = true
feed_keyring = "/tmp/feeds.gpg"

[daemon]
client_uids = [1000, 1001]
client_gids = [984]
socket_mode = "0666"

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
        assert!(cfg.netguard.feed_signature_required);
        assert_eq!(cfg.netguard.feed_keyring, PathBuf::from("/tmp/feeds.gpg"));
        assert_eq!(cfg.daemon.client_uids, vec![1000, 1001]);
        assert_eq!(cfg.daemon.client_gids, vec![984]);
        assert!(cfg.daemon.polkit_enabled, "on by default");
        assert_eq!(cfg.daemon.polkit_helper, "pkcheck");
        assert!(!cfg.daemon.polkit_allow_interaction);
        assert_eq!(cfg.daemon.socket_mode_bits().unwrap(), 0o666);
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
