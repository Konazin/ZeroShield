//! ZeroShield core library.
//!
//! Everything that is shared between the daemon, the CLI, the GUI and the
//! scanner/process/network engines lives here: configuration, shared data
//! models, the event bus payloads, persistent storage (SQLite) and the module
//! contract.

pub mod config;
pub mod error;
pub mod event;
pub mod model;
pub mod module;
pub mod paths;
pub mod storage;
pub mod util;

pub use error::{ZsError, ZsResult};

/// Application name (used for XDG paths, sockets, etc).
pub const APP_NAME: &str = "zeroshield";

/// Version reported by the daemon and CLI.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
