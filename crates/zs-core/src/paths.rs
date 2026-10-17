//! Filesystem location resolution (XDG aware, root aware).

use std::env;
use std::path::{Path, PathBuf};

use crate::util;

/// Resolved paths used by the CLI and daemon.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Configuration file that was found on disk (if any).
    pub config_file: Option<PathBuf>,
    /// Directories to search for a configuration file (in order).
    pub config_candidates: Vec<PathBuf>,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub runtime_dir: PathBuf,
}

impl Paths {
    pub fn resolve() -> Self {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/root"));
        let root = util::is_root();

        let xdg = |key: &str, fallback: PathBuf| -> PathBuf {
            env::var_os(key)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or(fallback)
        };

        let system_config = PathBuf::from("/etc/zeroshield/config.toml");
        let user_config_dir = xdg("XDG_CONFIG_HOME", home.join(".config")).join("zeroshield");
        let user_config = user_config_dir.join("config.toml");

        // Daemon runs as root on installed systems: prefer /etc + /var/lib.
        // User runs (dev, tests) use XDG paths.
        let config_candidates = if let Some(explicit) = env::var_os("ZS_CONFIG") {
            vec![PathBuf::from(explicit)]
        } else if root && Path::new("/etc/zeroshield").exists() {
            vec![system_config.clone(), user_config.clone()]
        } else {
            vec![user_config.clone(), system_config.clone()]
        };

        let config_file = config_candidates.iter().find(|p| p.is_file()).cloned();
        let config_dir = config_file
            .as_ref()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| {
                if root && Path::new("/etc/zeroshield").exists() {
                    PathBuf::from("/etc/zeroshield")
                } else {
                    user_config_dir.clone()
                }
            });

        let data_dir = if let Some(dir) = env::var_os("ZS_DATA_DIR") {
            PathBuf::from(dir)
        } else if root && Path::new("/var/lib/zeroshield").exists() {
            PathBuf::from("/var/lib/zeroshield")
        } else {
            xdg("XDG_DATA_HOME", home.join(".local/share")).join("zeroshield")
        };

        let cache_dir = xdg("XDG_CACHE_HOME", home.join(".cache")).join("zeroshield");

        let runtime_dir = env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .map(|p| p.join("zeroshield"))
            .unwrap_or_else(|| {
                if root {
                    PathBuf::from("/run/zeroshield")
                } else {
                    PathBuf::from(format!("/tmp/zeroshield-{}", util::euid()))
                }
            });

        Self {
            config_file,
            config_candidates,
            config_dir,
            data_dir,
            cache_dir,
            runtime_dir,
        }
    }

    /// Unix socket used by the daemon.
    pub fn socket_path(&self) -> PathBuf {
        if let Some(p) = env::var_os("ZS_SOCKET") {
            return PathBuf::from(p);
        }
        self.runtime_dir.join("zeroshieldd.sock")
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("zeroshield.db")
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        self.data_dir.join("quarantine")
    }

    pub fn feeds_dir(&self) -> PathBuf {
        self.cache_dir.join("feeds")
    }

    pub fn log_path(&self) -> PathBuf {
        self.data_dir.join("zeroshieldd.log")
    }

    /// Create the directories the daemon needs (best effort, 0700 for runtime).
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(self.quarantine_dir())?;
        std::fs::create_dir_all(&self.cache_dir)?;
        std::fs::create_dir_all(self.feeds_dir())?;
        std::fs::create_dir_all(&self.runtime_dir)?;
        set_mode(&self.runtime_dir, 0o700)?;
        set_mode(&self.data_dir, 0o700)?;
        set_mode(&self.quarantine_dir(), 0o700)?;
        Ok(())
    }
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_paths() {
        let paths = Paths::resolve();
        assert!(paths.data_dir.is_absolute());
        assert!(paths.socket_path().is_absolute());
    }
}
