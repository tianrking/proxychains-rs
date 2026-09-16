use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

pub fn run(mode: &str) {
    let destination: SocketAddr = match mode {
        "udp-domain" => ("udp.test.invalid", 443)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap(),
        "udp-ipv6" | "udp-v6relay" => "[2001:db8::123]:443".parse().unwrap(),
        _ => "192.0.2.123:443".parse().unwrap(),
    };
    if mode == "udp-failure" {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(socket.send_to(b"must-not-go-direct", destination).is_err());
        return;
    }
    if mode == "udp-control-closed" {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        socket.send_to(b"first", destination).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert!(socket.send_to(b"after-close", destination).is_err());
        assert!(socket.recv_from(&mut [0; 64]).is_err());
        return;
    }
    for _ in 0..2 {
        let socket = UdpSocket::bind(if mode == "udp-v6relay" {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        })
        .unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let local = socket.local_addr().unwrap();
        let mut payload = local.port().to_be_bytes().to_vec();
        payload.extend_from_slice(b"native-udp-payload");
        let connected = mode == "udp-connected";
        if connected {
            socket.connect(destination).unwrap();
            assert_eq!(socket.peer_addr().unwrap(), destination);
        }
        for round in 0..4 {
            let data = if round == 1 {
                &[][..]
            } else {
                payload.as_slice()
            };
            if round == 3 {
                socket.set_nonblocking(true).unwrap();
                assert_eq!(
                    socket.recv_from(&mut [0; 32]).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
            let n = if mode == "udp-iocp" && round == 0 {
                iocp_send_to(&socket, data, destination)
            } else if mode == "udp-vectored" {
                vectored_send(&socket, data, destination)
            } else if connected {
                socket.send(data).unwrap()
            } else {
                socket.send_to(data, destination).unwrap()
            };
            assert_eq!(n, data.len());
            assert_eq!(socket.local_addr().unwrap(), local);
            assert_eq!(socket.read_timeout().unwrap(), Some(Duration::from_secs(3)));
            let mut buffer = [0; 64];
            if round == 0 {
                let (n, from) = socket.peek_from(&mut buffer).unwrap();
                assert_eq!(&buffer[..n], data);
                assert_eq!(from, destination);
            }
            if round == 2 {
                let result = socket.recv_from(&mut buffer[..3]);
                #[cfg(windows)]
                assert_eq!(result.unwrap_err().raw_os_error(), Some(10040));
                #[cfg(unix)]
                assert_eq!(result.unwrap(), (3, destination));
                assert_eq!(&buffer[..3], &data[..3]);
            } else {
                let deadline = Instant::now() + Duration::from_secs(3);
                let (n, source) = loop {
                    let result = if mode == "udp-vectored" {
                        vectored_recv(&socket, &mut buffer)
                    } else if connected {
                        socket.recv(&mut buffer).map(|n| (n, destination))
                    } else {
                        socket.recv_from(&mut buffer)
                    };
                    match result {
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        result => break result.unwrap(),
                    }
                };
                assert_eq!(&buffer[..n], data);
                assert_eq!(source, destination);
            }
        }
        #[cfg(windows)]
        if mode != "udp-iocp" {
            reject_overlapped(&socket, destination);
        }
    }
}

#[cfg(windows)]
fn vectored_send(socket: &UdpSocket, data: &[u8], destination: SocketAddr) -> usize {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{WSASendTo, SOCKET, WSABUF};
    let split = data.len().min(2);
    let buffers = [
        WSABUF {
            len: split as u32,
            buf: windows::core::PSTR(data.as_ptr().cast_mut()),
        },
        WSABUF {
            len: (data.len() - split) as u32,
            buf: windows::core::PSTR(unsafe { data.as_ptr().add(split).cast_mut() }),
        },
    ];
    let destination = socket2::SockAddr::from(destination);
    let mut sent = 0;
    unsafe {
        assert_eq!(
            WSASendTo(
                SOCKET(socket.as_raw_socket() as usize),
                &buffers,
                Some(&mut sent),
                0,
                Some(destination.as_ptr().cast()),
                destination.len(),
                None,
                None
            ),
            0
        );
    }
    sent as usize
}
#[cfg(windows)]
fn vectored_recv(socket: &UdpSocket, data: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{WSAGetLastError, WSARecvFrom, SOCKET, WSABUF};
    let buffers = [
        WSABUF {
            len: 2,
            buf: windows::core::PSTR(data.as_mut_ptr()),
        },
        WSABUF {
            len: (data.len() - 2) as u32,
            buf: windows::core::PSTR(unsafe { data.as_mut_ptr().add(2) }),
        },
    ];
    let mut received = 0;
    let mut flags = 0;
    let (_, address) = unsafe {
        socket2::SockAddr::try_init(|storage, len| {
            let result = WSARecvFrom(
                SOCKET(socket.as_raw_socket() as usize),
                &buffers,
                Some(&mut received),
                &mut flags,
                Some(storage.cast()),
                Some(len.cast()),
                None,
                None,
            );
            if result == 0 {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(WSAGetLastError().0))
            }
        })?
    };
    Ok((received as usize, address.as_socket().unwrap()))
}
#[cfg(windows)]
fn reject_overlapped(socket: &UdpSocket, destination: SocketAddr) {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{
        WSAGetLastError, WSASendTo, SOCKET, WSABUF, WSAEOPNOTSUPP,
    };
    let mut data = [1];
    let buffers = [WSABUF {
        len: 1,
        buf: windows::core::PSTR(data.as_mut_ptr()),
    }];
    let mut overlapped = windows::Win32::System::IO::OVERLAPPED::default();
    let destination = socket2::SockAddr::from(destination);
    unsafe {
        assert!(
            WSASendTo(
                SOCKET(socket.as_raw_socket() as usize),
                &buffers,
                None,
                0,
                Some(destination.as_ptr().cast()),
                destination.len(),
                Some(&mut overlapped),
                None
            ) == -1
        );
        assert_eq!(WSAGetLastError(), WSAEOPNOTSUPP);
    }
}
#[cfg(windows)]
fn iocp_send_to(socket: &UdpSocket, data: &[u8], destination: SocketAddr) -> usize {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Networking::WinSock::{WSAGetLastError, WSASendTo, SOCKET, WSABUF, WSA_IO_PENDING};
    use windows::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED};
    let port = unsafe {
        CreateIoCompletionPort(
            HANDLE(-1),
            HANDLE::default(),
            0x51,
            1,
        ).expect("CreateIoCompletionPort")
    };
    let socket_handle = HANDLE(socket.as_raw_socket() as isize);
    unsafe {
        CreateIoCompletionPort(socket_handle, port, 0x51, 1).expect("associate UDP socket with IOCP");
    }
    let destination = socket2::SockAddr::from(destination);
    let mut sent = 0;
    let mut overlapped = OVERLAPPED::default();
    let buffer = WSABUF {
        len: data.len() as u32,
        buf: windows::core::PSTR(data.as_ptr().cast_mut()),
    };
    let result = unsafe {
        WSASendTo(
            SOCKET(socket.as_raw_socket() as usize),
            std::slice::from_ref(&buffer),
            None,
            0,
            Some(destination.as_ptr().cast()),
            destination.len(),
            Some(&mut overlapped),
            None,
        )
    };
    assert_eq!(result, -1);
    assert_eq!(unsafe { WSAGetLastError() }, WSA_IO_PENDING);
    let mut bytes = 0;
    let mut key = 0;
    let mut completed = std::ptr::null_mut();
    unsafe {
        GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut completed, 5000)
            .expect("UDP IOCP completion");
    }
    assert_eq!(key, 0x51);
    assert!(std::ptr::eq(completed, &mut overlapped));
    assert_eq!(bytes as usize, data.len());
    sent = bytes;
    sent as usize
}
#[cfg(not(windows))]
fn iocp_send_to(socket: &UdpSocket, data: &[u8], destination: SocketAddr) -> usize {
    socket.send_to(data, destination).unwrap()
}
#[cfg(unix)]
fn vectored_send(socket: &UdpSocket, data: &[u8], destination: SocketAddr) -> usize {
    use std::os::fd::AsRawFd;
    let split = data.len().min(2);
    let mut iov = [
        libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: split,
        },
        libc::iovec {
            iov_base: unsafe { data.as_ptr().add(split).cast_mut().cast() },
            iov_len: data.len() - split,
        },
    ];
    let destination = socket2::SockAddr::from(destination);
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = destination.as_ptr().cast_mut().cast();
        msg.msg_namelen = destination.len();
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = 2;
        let n = libc::sendmsg(socket.as_raw_fd(), &msg, 0);
        assert!(n >= 0, "sendmsg: {}", std::io::Error::last_os_error());
        n as usize
    }
}
#[cfg(unix)]
fn vectored_recv(socket: &UdpSocket, data: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    use std::os::fd::AsRawFd;
    let mut iov = [
        libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: 2,
        },
        libc::iovec {
            iov_base: unsafe { data.as_mut_ptr().add(2).cast() },
            iov_len: data.len() - 2,
        },
    ];
    let (n, address) = unsafe {
        socket2::SockAddr::try_init(|storage, len| {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_name = storage.cast();
            msg.msg_namelen = *len;
            msg.msg_iov = iov.as_mut_ptr();
            msg.msg_iovlen = 2;
            let n = libc::recvmsg(socket.as_raw_fd(), &mut msg, 0);
            *len = msg.msg_namelen;
            if n >= 0 {
                Ok(n)
            } else {
                Err(std::io::Error::last_os_error())
            }
        })?
    };
    Ok((n as usize, address.as_socket().unwrap()))
}
