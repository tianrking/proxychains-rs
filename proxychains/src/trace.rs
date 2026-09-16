//! Best-effort JSONL connection tracing for transparent hook diagnostics.
//!
//! Tracing is disabled unless `PROXYCHAINS_LOG_FILE` is set. Events never
//! include proxy credentials or payload bytes. A contended logger is skipped
//! so an application thread is not serialized behind a slow file reader.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ConnectionEvent<'a> {
    pub schema_version: &'static str,
    pub timestamp_ms: u128,
    pub pid: u32,
    pub event: &'a str,
    pub protocol: &'a str,
    pub target: &'a str,
    pub port: u16,
    pub stage: &'a str,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'a str>,
}

static WRITER: OnceLock<Option<Mutex<std::fs::File>>> = OnceLock::new();

pub fn init_from_env() {
    let _ = writer();
}

fn writer() -> Option<&'static Mutex<std::fs::File>> {
    WRITER
        .get_or_init(|| {
            let path = std::env::var_os("PROXYCHAINS_LOG_FILE")?;
            if path.is_empty() {
                return None;
            }
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(file) => Some(Mutex::new(file)),
                Err(error) => {
                    eprintln!("proxychains: cannot open connection log: {error}");
                    None
                }
            }
        })
        .as_ref()
}

pub fn record(event: ConnectionEvent<'_>) {
    let Some(writer) = writer() else { return };
    let Some(mut writer) = writer.try_lock() else { return };
    let mut line = match serde_json::to_vec(&event) {
        Ok(line) => line,
        Err(_) => return,
    };
    line.push(b'\n');
    let _ = writer.write_all(&line);
    let _ = writer.flush();
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

pub fn process_id() -> u32 {
    std::process::id()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serializes_without_sensitive_fields() {
        let event = ConnectionEvent {
            schema_version: "1.0",
            timestamp_ms: 1,
            pid: 2,
            event: "connect",
            protocol: "tcp",
            target: "example.test",
            port: 443,
            stage: "target",
            ok: true,
            elapsed_ms: Some(3),
            error: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("example.test"));
        assert!(!json.contains("password"));
    }
}
