//! Error types for proxychains

use std::io;
use thiserror::Error;

/// Main error type for proxychains operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Proxy connection failed: {0}")]
    ProxyConnection(String),

    #[error("Proxy authentication failed: {0}")]
    AuthFailed(String),

    #[error("Chain error: {0}")]
    Chain(String),

    #[error("DNS resolution failed: {0}")]
    Dns(String),

    #[error("Socket error: {0}")]
    Socket(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Blocked by proxy")]
    Blocked,

    #[error("Chain is empty")]
    ChainEmpty,

    #[error("Memory allocation failed")]
    MemoryFail,

    #[error("Socket error")]
    SocketError,

    #[error("Chain is down")]
    ChainDown,

    #[error("Invalid address")]
    InvalidAddress,

    #[error("Nix error: {0}")]
    Nix(#[from] nix::Error),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Result type alias for proxychains operations
pub type Result<T> = std::result::Result<T, Error>;

impl From<std::ffi::NulError> for Error {
    fn from(e: std::ffi::NulError) -> Self {
        Error::Config(e.to_string())
    }
}
