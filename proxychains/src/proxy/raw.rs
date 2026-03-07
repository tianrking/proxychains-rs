//! Raw proxy type - direct connection without protocol
//!
//! This is used for direct connections in a proxy chain,
//! where no protocol transformation is needed.

use std::io::{Read, Write};
use std::time::Duration;

use crate::config::ProxyData;
use crate::error::Result;

/// Raw connector - does nothing, just passes through
pub struct RawConnector<'a> {
    _proxy: &'a ProxyData,
    _timeout: Duration,
}

impl<'a> RawConnector<'a> {
    /// Create a new raw connector
    pub fn new(proxy: &'a ProxyData, timeout: Duration) -> Self {
        Self {
            _proxy: proxy,
            _timeout: timeout,
        }
    }

    /// "Connect" - does nothing for raw type
    pub fn connect<T: Read + Write>(&self, _stream: &mut T) -> Result<()> {
        // Raw type doesn't send any protocol data
        // The connection is already established
        Ok(())
    }
}

/// Raw "connect" - does nothing
pub fn raw_connect<T: Read + Write>(
    _stream: &mut T,
    _proxy: &ProxyData,
    _timeout: Duration,
) -> Result<()> {
    // Raw type doesn't send any protocol data
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_connect() {
        let proxy = ProxyData::default();
        let connector = RawConnector::new(&proxy, Duration::from_secs(5));
        // Raw connector should always succeed
        // (no actual stream needed for this test)
    }
}
