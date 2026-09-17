//! A loopback-friendly SOCKS5 CONNECT listener backed by a proxychains route.
//!
//! The listener deliberately supports only TCP CONNECT. It never falls back to
//! a direct target connection: every successful request has completed the
//! configured proxy chain first. UDP belongs to the explicit UDP forwarder and
//! transparent hook paths, where SOCKS5 UDP ASSOCIATE lifecycle can be tracked.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tracing::debug;

use crate::{ChainManager, Config, Error, ProxyType, Result};

const SOCKS5_VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const USERPASS_AUTH: u8 = 2;
const NO_ACCEPTABLE_AUTH: u8 = 0xff;
const CONNECT: u8 = 1;
const COMMAND_UNSUPPORTED: u8 = 7;
const GENERAL_FAILURE: u8 = 1;
const ADDRESS_TYPE_UNSUPPORTED: u8 = 8;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Optional username/password credentials required by the local listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalSocks5Credentials {
    pub username: String,
    pub password: String,
}

impl LocalSocks5Credentials {
    /// Validate credentials against SOCKS5 username/password framing limits.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Result<Self> {
        let credentials = Self {
            username: username.into(),
            password: password.into(),
        };
        if credentials.username.is_empty()
            || credentials.password.is_empty()
            || credentials.username.len() > u8::MAX as usize
            || credentials.password.len() > u8::MAX as usize
        {
            return Err(Error::Config(
                "local SOCKS5 credentials must be non-empty UTF-8 values of at most 255 bytes"
                    .to_string(),
            ));
        }
        Ok(credentials)
    }
}

/// Local SOCKS5 CONNECT service which always uses its configured proxy chain.
pub struct LocalSocks5Server {
    chain: Arc<ChainManager>,
    credentials: Option<LocalSocks5Credentials>,
    max_clients: usize,
}

impl LocalSocks5Server {
    /// Build a listener service from one already-selected proxychains config.
    /// `raw` is rejected because it is not an upstream proxy protocol.
    pub fn new(
        config: Config,
        credentials: Option<LocalSocks5Credentials>,
        max_clients: usize,
    ) -> Result<Self> {
        if config.proxies.is_empty() {
            return Err(Error::ChainEmpty);
        }
        if config
            .proxies
            .iter()
            .any(|proxy| proxy.proxy_type == ProxyType::Raw)
        {
            return Err(Error::Config(
                "local SOCKS5 service requires SOCKS4, SOCKS5, or HTTP upstream proxies; raw is not an upstream proxy"
                    .to_string(),
            ));
        }
        if max_clients == 0 {
            return Err(Error::Config(
                "local SOCKS5 max_clients must be greater than zero".to_string(),
            ));
        }
        Ok(Self {
            chain: Arc::new(ChainManager::new(config)),
            credentials,
            max_clients,
        })
    }

    /// Serve until `shutdown` is set. The caller retains listener ownership and
    /// should bind it to a loopback address unless remote clients are intended.
    pub fn serve(self, listener: TcpListener, shutdown: Arc<AtomicBool>) -> Result<()> {
        listener.set_nonblocking(true)?;
        let active = Arc::new(AtomicUsize::new(0));
        while !shutdown.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, peer)) => {
                    // Accepted descriptors inherit nonblocking mode on some
                    // platforms. Each worker uses blocking I/O with explicit
                    // handshake timeouts, so normalize before handing it off.
                    if let Err(error) = stream.set_nonblocking(false) {
                        debug!("local SOCKS5 rejected {peer}: cannot configure socket: {error}");
                        continue;
                    }
                    let Some(permit) = ClientPermit::acquire(active.clone(), self.max_clients)
                    else {
                        debug!("local SOCKS5 rejected {peer}: client limit reached");
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    };
                    let chain = self.chain.clone();
                    let credentials = self.credentials.clone();
                    if let Err(error) = thread::Builder::new()
                        .name("proxychains-socks5-client".to_string())
                        .spawn(move || {
                            let _permit = permit;
                            if let Err(error) = handle_client(stream, chain, credentials) {
                                debug!("local SOCKS5 client {peer} ended: {error}");
                            }
                        })
                    {
                        debug!("local SOCKS5 could not start worker for {peer}: {error}");
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

struct ClientPermit(Arc<AtomicUsize>);

impl ClientPermit {
    fn acquire(active: Arc<AtomicUsize>, maximum: usize) -> Option<Self> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < maximum).then_some(current + 1)
            })
            .ok()
            .map(|_| Self(active))
    }
}

impl Drop for ClientPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

enum Target {
    Ip(IpAddr),
    Domain(String),
}

fn handle_client(
    mut client: TcpStream,
    chain: Arc<ChainManager>,
    credentials: Option<LocalSocks5Credentials>,
) -> Result<()> {
    client.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    client.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    authenticate(&mut client, credentials.as_ref())?;

    let mut request = [0; 4];
    client.read_exact(&mut request)?;
    if request[0] != SOCKS5_VERSION || request[2] != 0 {
        return Err(Error::Protocol(
            "invalid local SOCKS5 request header".to_string(),
        ));
    }
    if request[1] != CONNECT {
        write_reply(&mut client, COMMAND_UNSUPPORTED)?;
        return Ok(());
    }
    let target = match read_target(&mut client, request[3]) {
        Ok(target) => target,
        Err(Error::Protocol(_)) => {
            write_reply(&mut client, ADDRESS_TYPE_UNSUPPORTED)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let mut port = [0; 2];
    client.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);

    let upstream = match target {
        Target::Ip(address) => chain.connect_proxy_chain(address, port, None),
        // SOCKS4a/SOCKS5/HTTP CONNECT choose the domain in TargetAddress; the
        // placeholder prevents the local listener from resolving client names.
        Target::Domain(domain) => {
            chain.connect_proxy_chain(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port, Some(&domain))
        }
    };
    let upstream = match upstream {
        Ok(stream) => stream,
        Err(error) => {
            debug!("local SOCKS5 upstream chain rejected request: {error}");
            write_reply(&mut client, GENERAL_FAILURE)?;
            return Ok(());
        }
    };
    write_reply(&mut client, 0)?;
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    relay(client, upstream)
}

fn authenticate(
    client: &mut TcpStream,
    credentials: Option<&LocalSocks5Credentials>,
) -> Result<()> {
    let mut header = [0; 2];
    client.read_exact(&mut header)?;
    if header[0] != SOCKS5_VERSION {
        return Err(Error::Protocol(
            "local SOCKS5 client sent an unsupported version".to_string(),
        ));
    }
    let mut methods = vec![0; header[1] as usize];
    client.read_exact(&mut methods)?;
    let selected = match credentials {
        Some(_) if methods.contains(&USERPASS_AUTH) => USERPASS_AUTH,
        None if methods.contains(&NO_AUTH) => NO_AUTH,
        _ => NO_ACCEPTABLE_AUTH,
    };
    client.write_all(&[SOCKS5_VERSION, selected])?;
    if selected == NO_ACCEPTABLE_AUTH {
        return Err(Error::AuthFailed(
            "local SOCKS5 client did not offer an accepted authentication method".to_string(),
        ));
    }
    if let Some(expected) = credentials {
        let mut version = [0; 1];
        client.read_exact(&mut version)?;
        if version[0] != 1 {
            return Err(Error::AuthFailed(
                "local SOCKS5 username/password version is unsupported".to_string(),
            ));
        }
        let username = read_userpass_field(client)?;
        let password = read_userpass_field(client)?;
        let accepted = constant_time_eq(username.as_bytes(), expected.username.as_bytes())
            & constant_time_eq(password.as_bytes(), expected.password.as_bytes());
        client.write_all(&[1, if accepted { 0 } else { 1 }])?;
        if !accepted {
            return Err(Error::AuthFailed(
                "local SOCKS5 credentials were rejected".to_string(),
            ));
        }
    }
    Ok(())
}

fn read_userpass_field(client: &mut TcpStream) -> Result<String> {
    let mut length = [0; 1];
    client.read_exact(&mut length)?;
    if length[0] == 0 {
        return Err(Error::AuthFailed(
            "local SOCKS5 credentials must not be empty".to_string(),
        ));
    }
    let mut bytes = vec![0; length[0] as usize];
    client.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(Error::from)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let maximum = left.len().max(right.len());
    for index in 0..maximum {
        difference |= left.get(index).copied().unwrap_or(0) as usize
            ^ right.get(index).copied().unwrap_or(0) as usize;
    }
    difference == 0
}

fn read_target(client: &mut TcpStream, address_type: u8) -> Result<Target> {
    match address_type {
        1 => {
            let mut bytes = [0; 4];
            client.read_exact(&mut bytes)?;
            Ok(Target::Ip(IpAddr::from(bytes)))
        }
        3 => {
            let mut length = [0; 1];
            client.read_exact(&mut length)?;
            if length[0] == 0 {
                return Err(Error::Protocol("empty SOCKS5 domain name".to_string()));
            }
            let mut bytes = vec![0; length[0] as usize];
            client.read_exact(&mut bytes)?;
            let domain = String::from_utf8(bytes)?;
            if domain.contains('\0') {
                return Err(Error::Protocol("invalid SOCKS5 domain name".to_string()));
            }
            Ok(Target::Domain(domain))
        }
        4 => {
            let mut bytes = [0; 16];
            client.read_exact(&mut bytes)?;
            Ok(Target::Ip(IpAddr::from(bytes)))
        }
        _ => Err(Error::Protocol(
            "unsupported SOCKS5 address type".to_string(),
        )),
    }
}

fn write_reply(client: &mut TcpStream, status: u8) -> Result<()> {
    client.write_all(&[SOCKS5_VERSION, status, 0, 1, 0, 0, 0, 0, 0, 0])?;
    Ok(())
}

fn relay(mut client: TcpStream, mut upstream: TcpStream) -> Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;
    let upload = thread::spawn(move || {
        let result = io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(Shutdown::Write);
        result
    });
    let download = io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let upload = upload
        .join()
        .map_err(|_| Error::Chain("local SOCKS5 relay worker panicked".to_string()))?;
    download?;
    upload?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_reject_empty_or_oversized_values() {
        assert!(LocalSocks5Credentials::new("", "password").is_err());
        assert!(LocalSocks5Credentials::new("user", "").is_err());
        assert!(LocalSocks5Credentials::new("x".repeat(256), "password").is_err());
    }

    #[test]
    fn constant_time_comparison_requires_identical_values() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"different"));
        assert!(!constant_time_eq(b"same", b"sam"));
    }
}
