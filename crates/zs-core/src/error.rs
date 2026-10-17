use std::path::PathBuf;

/// Errors produced by ZeroShield crates.
#[derive(Debug, thiserror::Error)]
pub enum ZsError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("scan error: {0}")]
    Scan(String),

    #[error("process error: {0}")]
    Proc(String),

    #[error("network error: {0}")]
    Net(String),

    #[error("ipc error: {0}")]
    Ipc(String),

    #[error("permission denied: {0}")]
    Permission(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type ZsResult<T> = Result<T, ZsError>;

impl ZsError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        ZsError::Io {
            path: path.into(),
            source,
        }
    }
}

impl From<std::io::Error> for ZsError {
    fn from(source: std::io::Error) -> Self {
        ZsError::Io {
            path: PathBuf::new(),
            source,
        }
    }
}

impl From<serde_json::Error> for ZsError {
    fn from(e: serde_json::Error) -> Self {
        ZsError::Serialization(e.to_string())
    }
}

impl From<rusqlite::Error> for ZsError {
    fn from(e: rusqlite::Error) -> Self {
        ZsError::Storage(e.to_string())
    }
}
