//! Best-effort JSONL connection tracing for transparent hook diagnostics.
//!
//! Tracing is disabled unless `PROXYCHAINS_LOG_FILE` is set. Events never
//! include proxy credentials or payload bytes. A contended logger is skipped
//! so an application thread is not serialized behind a slow file reader.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::atomic::{AtomicU64, Ordering};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ConnectionEvent<'a> {
    pub schema_version: &'static str,
    pub timestamp_ms: u128,
    pub pid: u32,
    pub process: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub event: &'a str,
    pub protocol: &'a str,
    pub target: &'a str,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    pub stage: &'a str,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'a str>,
}

struct AsyncWriter {
    sender: SyncSender<Vec<u8>>,
    pid: u32,
}
static WRITER: OnceLock<Option<AsyncWriter>> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);
const QUEUE_CAPACITY: usize = 256;
const MAX_EVENT_BYTES: usize = 16 * 1024;

/// Events lost to overload, oversized records or an unavailable writer.
pub fn dropped_events() -> u64 { DROPPED.load(Ordering::Relaxed) }

fn start_writer<W: Write + Send + 'static>(mut output: W) -> Option<AsyncWriter> {
    let (sender, receiver) = sync_channel::<Vec<u8>>(QUEUE_CAPACITY);
    std::thread::Builder::new().name("proxychains-log".into()).spawn(move || {
        for line in receiver {
            if output.write_all(&line).is_err() {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }).ok()?;
    Some(AsyncWriter { sender, pid: std::process::id() })
}

pub fn init_from_env() {
    let _ = writer();
}

fn writer() -> Option<&'static AsyncWriter> {
    WRITER
        .get_or_init(|| {
            let path = std::env::var_os("PROXYCHAINS_LOG_FILE")?;
            if path.is_empty() {
                return None;
            }
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(file) => start_writer(file),
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
    // A fork does not copy the worker thread. Never touch the inherited queue
    // in that child; exec creates a fresh logger. Logging stays best-effort.
    if writer.pid != std::process::id() {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut line = match serde_json::to_vec(&event) {
        Ok(line) => line,
        Err(_) => return,
    };
    line.push(b'\n');
    if line.len() > MAX_EVENT_BYTES || writer.sender.try_send(line).is_err() {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

pub fn process_id() -> u32 {
    std::process::id()
}

pub fn process_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn session_id() -> Option<String> {
    std::env::var("PROXYCHAINS_SESSION_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_sink_cannot_block_producers_and_queue_is_bounded() {
        struct SlowSink(std::sync::mpsc::Receiver<()>);
        impl Write for SlowSink {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                let _ = self.0.recv();
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let (release, gate) = sync_channel(0);
        let writer = start_writer(SlowSink(gate)).unwrap();
        let mut rejected = 0;
        for _ in 0..QUEUE_CAPACITY + 2 {
            if writer.sender.try_send(vec![b'x']).is_err() { rejected += 1; }
        }
        assert!(rejected > 0);
        drop(release);
        drop(writer);
    }

    #[test]
    fn event_serializes_without_sensitive_fields() {
        let event = ConnectionEvent {
            schema_version: "1.0",
            timestamp_ms: 1,
            pid: 2,
            process: "fixture.exe".to_string(),
            session_id: Some("session-1".to_string()),
            event: "connect",
            protocol: "tcp",
            target: "example.test",
            port: 443,
            proxy: Some("127.0.0.1:1080".to_string()),
            stage: "target",
            ok: true,
            elapsed_ms: Some(3),
            error: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("example.test"));
        assert!(json.contains("127.0.0.1:1080"));
        assert!(!json.contains("password"));
    }
}
