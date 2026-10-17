//! Local (in-process) engine assembly, used when no daemon is running.

use std::sync::Arc;

use zs_core::config::Config;
use zs_core::error::{ZsError, ZsResult};
use zs_core::paths::Paths;
use zs_core::storage::Storage;
use zs_net::NetGuard;
use zs_proc::ProcMonitor;
use zs_scan::{Quarantine, Scanner};

pub struct Local {
    pub storage: Arc<Storage>,
    pub scanner: Scanner,
    pub procmon: ProcMonitor,
    pub netguard: NetGuard,
    pub quarantine: Arc<Quarantine>,
}

impl Local {
    pub fn load(paths: &Paths, cfg: &Config) -> ZsResult<Self> {
        paths
            .ensure_dirs()
            .map_err(|e| ZsError::io(paths.data_dir.clone(), e))?;
        let db_path = cfg.storage.path.clone().unwrap_or_else(|| paths.db_path());
        let storage = Arc::new(Storage::open(&db_path)?);
        zs_scan::signatures::seed_storage(&storage)?;

        let quarantine = Arc::new(Quarantine::new(paths.quarantine_dir(), storage.clone())?);
        let scanner = Scanner::new(
            cfg.scanner.clone(),
            Some(storage.clone()),
            Some(quarantine.clone()),
        )?;
        let procmon = ProcMonitor::new(cfg.procmon.clone());
        let netguard = NetGuard::new(
            cfg.netguard.clone(),
            storage.clone(),
            paths.cache_dir.clone(),
            paths.data_dir.clone(),
        );

        Ok(Self {
            storage,
            scanner,
            procmon,
            netguard,
            quarantine,
        })
    }
}
