//! Explicit fixed-destination UDP forwarding; this is not application interception.
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{mpsc, Arc, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use clap::Parser;
use proxychains::{ConfigParser, config::{ProxyData, ProxyType}, proxy::{TargetAddress, UdpAssociation}};

#[derive(Parser)]
#[command(author = "tianrking", version, about = "Forward a loopback UDP port through one SOCKS5 proxy to a fixed IP endpoint")]
struct Args {
    #[arg(short = 'f', long)]
    config: std::path::PathBuf,
    #[arg(long, default_value = "127.0.0.1:1053")]
    listen: SocketAddr,
    #[arg(long)]
    target: SocketAddr,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    anyhow::ensure!(args.listen.ip().is_loopback(), "listen address must be loopback");
    anyhow::ensure!(args.target.port() != 0 && !args.target.ip().is_unspecified(), "target must be a concrete IP and nonzero port");
    let config = ConfigParser::new().with_path(args.config).parse()?;
    anyhow::ensure!(config.proxies.len() == 1 && config.proxies[0].proxy_type == ProxyType::Socks5,
        "UDP forwarding requires exactly one SOCKS5 proxy; chains are not supported");
    let socket = Arc::new(UdpSocket::bind(args.listen)?);
    eprintln!("UDP {} -> {} through SOCKS5; maximum 64 clients, 60s idle expiry", socket.local_addr()?, args.target);
    run(socket, config.proxies[0].clone(), args.target, &AtomicBool::new(false))
}

struct Client { sender: mpsc::SyncSender<Vec<u8>>, seen: Instant }

fn run(socket: Arc<UdpSocket>, proxy: ProxyData, target: SocketAddr, stop: &AtomicBool) -> anyhow::Result<()> {
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut clients: HashMap<SocketAddr, Client> = HashMap::new();
    let mut packet = vec![0; 65535];
    while !stop.load(Ordering::Relaxed) {
        clients.retain(|_, client| client.seen.elapsed() < Duration::from_secs(60));
        let (size, peer) = match socket.recv_from(&mut packet) {
            Ok(value) => value,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
            Err(e) => return Err(e.into()),
        };
        if !peer.ip().is_loopback() { continue; }
        if !clients.contains_key(&peer) {
            if clients.len() >= 64 { continue; }
            let (sender, receiver) = mpsc::sync_channel(64);
            let proxy = proxy.clone(); let socket = socket.clone();
            std::thread::Builder::new().name("socks5-udp-client".into()).spawn(move || {
                if let Err(e) = session(socket, peer, proxy, target, receiver) {
                    eprintln!("UDP client {peer} closed: {e}");
                }
            })?;
            clients.insert(peer, Client { sender, seen: Instant::now() });
        }
        let client = clients.get_mut(&peer).unwrap();
        client.seen = Instant::now();
        match client.sender.try_send(packet[..size].to_vec()) {
            Ok(()) | Err(mpsc::TrySendError::Full(_)) => (), // UDP overload drops packets; never direct-connect.
            Err(mpsc::TrySendError::Disconnected(_)) => { clients.remove(&peer); }
        }
    }
    Ok(())
}

fn session(socket: Arc<UdpSocket>, peer: SocketAddr, proxy: ProxyData, target: SocketAddr, receiver: mpsc::Receiver<Vec<u8>>) -> anyhow::Result<()> {
    // Each local source owns a separate control channel and relay socket. Replies
    // can therefore never be delivered to another client with the same DNS ID.
    let association = UdpAssociation::connect(&proxy, Duration::from_secs(3), Duration::from_secs(3))?;
    association.set_read_timeout(Some(Duration::from_millis(50)))?;
    let destination = TargetAddress::from_ip(target.ip());
    loop {
        for _ in 0..32 {
            match receiver.try_recv() {
                Ok(data) => { association.send_to(&destination, target.port(), &data)?; }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
            }
        }
        match association.recv_from() {
            Ok((source, port, data)) if source.ip() == Some(&target.ip()) && port == target.port() => { socket.send_to(&data, peer)?; }
            Ok(_) => (), // Ignore datagrams claiming an unrelated remote endpoint.
            Err(proxychains::Error::Io(e)) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => (),
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn two_clients_have_independent_relay_sessions() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy = ProxyData::new("127.0.0.1".parse().unwrap(), listener.local_addr().unwrap().port(), ProxyType::Socks5);
        let mock = std::thread::spawn(move || {
            let mut workers = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(5);
            while workers.len() < 2 {
                let (mut control, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10)); continue;
                    }
                    Err(e) => panic!("missing UDP association: {e}"),
                };
                workers.push(std::thread::spawn(move || {
                    control.set_nonblocking(false).unwrap();
                    control.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut greeting = [0;3]; control.read_exact(&mut greeting).unwrap(); assert_eq!(greeting, [5,1,0]);
                    control.write_all(&[5,0]).unwrap();
                    let mut request = [0;10]; control.read_exact(&mut request).unwrap(); assert_eq!(request[1], 3);
                    let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
                    relay.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    let mut reply = vec![5,0,0,1,127,0,0,1]; reply.extend(relay.local_addr().unwrap().port().to_be_bytes());
                    control.write_all(&reply).unwrap();
                    let mut packet = [0;1024]; let (size, peer) = relay.recv_from(&mut packet).unwrap();
                    relay.send_to(&packet[..size], peer).unwrap();
                    assert_eq!(control.read(&mut [0]).unwrap(), 0, "shutdown releases association");
                }));
            }
            for worker in workers { worker.join().unwrap(); }
        });
        let local = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let addr = local.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false)); let worker_stop = stop.clone();
        let forward = std::thread::spawn(move || run(local, proxy, "192.0.2.53:53".parse().unwrap(), &worker_stop).unwrap());
        let a = UdpSocket::bind("127.0.0.1:0").unwrap(); let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        for client in [&a, &b] { client.set_read_timeout(Some(Duration::from_secs(3))).unwrap(); }
        a.send_to(b"same-id:client-a", addr).unwrap(); b.send_to(b"same-id:client-b", addr).unwrap();
        let mut buf = [0;128]; let (size, _) = a.recv_from(&mut buf).unwrap(); assert_eq!(&buf[..size], b"same-id:client-a");
        let (size, _) = b.recv_from(&mut buf).unwrap(); assert_eq!(&buf[..size], b"same-id:client-b");
        stop.store(true, Ordering::Relaxed); forward.join().unwrap(); mock.join().unwrap();
    }
}
