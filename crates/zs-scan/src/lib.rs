//! ZeroShield file scanner.
//!
//! Pipeline per file:
//!   1. (cached) SHA-256/SHA-1/MD5 hashing
//!   2. hash signature lookup (local DB + built-ins)
//!   3. content rules (native pattern engine, YARA-style use cases)
//!   4. ELF heuristics (packing, RWX segments, suspicious strings/imports)
//!   5. scoring → verdict → optional quarantine

pub mod builtins;
pub mod elf;
pub mod engine;
pub mod hash;
pub mod quarantine;
pub mod rules;
pub mod signatures;

pub use engine::{Progress, Scanner};
pub use quarantine::Quarantine;
pub use rules::RuleSet;

use async_trait::async_trait;
use zs_core::module::{Capability, Module, ModuleStatus};

#[async_trait]
impl Module for Scanner {
    fn name(&self) -> &'static str {
        "scanner"
    }

    fn description(&self) -> &'static str {
        "File scanner: hash signatures, content rules and ELF heuristics"
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::FileScan,
            Capability::Quarantine,
            Capability::SignatureUpdate,
        ]
    }

    async fn status(&self) -> ModuleStatus {
        let signatures = match &self.storage {
            Some(s) => s.signature_count().unwrap_or(0),
            None => 0,
        };
        ModuleStatus {
            name: self.name().to_string(),
            description: self.description().to_string(),
            capabilities: self.capabilities(),
            healthy: true,
            detail: format!(
                "{} content rules, {} hash signatures, quarantine {}",
                self.rules().len(),
                signatures,
                if self.quarantine.is_some() {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
        }
    }
}

/// File extensions used by the quarantine store.
pub const QUARANTINE_EXT: &str = "zsq";
