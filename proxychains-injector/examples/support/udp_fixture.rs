use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};
use bytes::Buf;

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
    if mode == "udp-failover" {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket.send_to(b"udp-failover", destination).unwrap();
        let mut buffer = [0; 64];
        let (n, source) = socket.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..n], b"udp-failover");
        assert_eq!(source, destination);
        return;
    }
    if mode == "quic" {
        run_quic(destination);
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
    if mode == "udp-dup" {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        #[cfg(target_os = "macos")]
        let clone = unsafe {
            use std::os::fd::{AsRawFd, FromRawFd};
            let fd = libc::dup(socket.as_raw_fd());
            assert!(fd >= 0);
            // A failed replacement must leave the destination session intact.
            assert_eq!(libc::dup2(-1, fd), -1);
            UdpSocket::from_raw_fd(fd)
        };
        #[cfg(not(target_os = "macos"))]
        let clone = socket.try_clone().unwrap();
        socket.send_to(b"dup-original", destination).unwrap();
        clone.send_to(b"dup-clone", destination).unwrap();
        let mut buffer = [0; 64];
        let mut received = Vec::new();
        for _ in 0..2 {
            let (n, source) = socket.recv_from(&mut buffer).unwrap();
            assert_eq!(source, destination);
            received.push(buffer[..n].to_vec());
        }
        received.sort();
        assert_eq!(
            received,
            vec![b"dup-clone".to_vec(), b"dup-original".to_vec()]
        );
        return;
    }
    #[cfg(target_os = "linux")]
    if mode == "udp-recvmmsg-timeout" {
        use std::os::fd::AsRawFd;
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.send_to(b"batch-timeout", destination).unwrap();
        let mut payload = [0u8; 64];
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut message: libc::mmsghdr = unsafe { std::mem::zeroed() };
        message.msg_hdr.msg_iov = &mut iov;
        message.msg_hdr.msg_iovlen = 1;
        let mut timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        let received =
            unsafe { libc::recvmmsg(socket.as_raw_fd(), &mut message, 2, 0, &mut timeout) };
        assert_eq!(received, 1);
        assert_eq!(message.msg_len as usize, b"batch-timeout".len());
        assert_eq!(&payload[..message.msg_len as usize], b"batch-timeout");
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
            } else if mode == "udp-iocp-sendmsg" && round == 0 {
                iocp_sendmsg_to(&socket, data, destination)
            } else if mode == "udp-completion" && round == 0 {
                completion_send_recv(&socket, data, destination);
                data.len()
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
            if mode == "udp-iocp-recv" && round == 0 {
                let n = iocp_recv_from(&socket, data);
                assert_eq!(n, data.len());
                continue;
            }
            if mode == "udp-recvmsg" && round == 0 {
                let n = recvmsg_from(&socket, data);
                assert_eq!(n, data.len());
                continue;
            }
            if mode == "udp-iocp-recvmsg" && round == 0 {
                let n = iocp_recvmsg_from(&socket, data);
                assert_eq!(n, data.len());
                continue;
            }
            if mode == "udp-completion" && round == 0 {
                continue;
            }
            if mode == "udp-iocp-cancel" && round == 0 {
                iocp_cancel_recv(&socket);
                return;
            }
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
        if !mode.starts_with("udp-iocp") {
            reject_overlapped(&socket, destination);
        }
    }
}

#[cfg(windows)]
fn completion_send_recv(socket: &UdpSocket, data: &[u8], destination: SocketAddr) {
    use std::os::windows::io::AsRawSocket;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use windows::Win32::Networking::WinSock::{
        WSAGetLastError, WSARecvFrom, WSASendTo, SOCKET, WSABUF, WSA_IO_PENDING,
    };
    use windows::Win32::System::IO::OVERLAPPED;

    static CALLED: AtomicBool = AtomicBool::new(false);
    static ERROR: AtomicU32 = AtomicU32::new(u32::MAX);
    static BYTES: AtomicU32 = AtomicU32::new(0);
    static OVERLAPPED_PTR: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "system" fn completion(
        error: u32,
        bytes: u32,
        overlapped: *mut OVERLAPPED,
        _flags: u32,
    ) {
        ERROR.store(error, Ordering::Release);
        BYTES.store(bytes, Ordering::Release);
        OVERLAPPED_PTR.store(overlapped as usize, Ordering::Release);
        CALLED.store(true, Ordering::Release);
    }
    let raw = SOCKET(socket.as_raw_socket() as usize);
    let destination = socket2::SockAddr::from(destination);
    let mut buffer = WSABUF {
        len: data.len() as u32,
        buf: windows::core::PSTR(data.as_ptr().cast_mut()),
    };
    let mut overlapped = OVERLAPPED::default();
    CALLED.store(false, Ordering::Release);
    ERROR.store(u32::MAX, Ordering::Release);
    let result = unsafe {
        WSASendTo(
            raw,
            std::slice::from_mut(&mut buffer),
            None,
            0,
            Some(destination.as_ptr().cast()),
            destination.len() as i32,
            Some(&mut overlapped),
            Some(completion),
        )
    };
    assert_eq!(result, -1);
    assert_eq!(unsafe { WSAGetLastError() }, WSA_IO_PENDING);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !CALLED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(CALLED.load(Ordering::Acquire), "WSASendTo completion not called");
    assert_eq!(ERROR.load(Ordering::Acquire), 0);
    assert_eq!(BYTES.load(Ordering::Acquire) as usize, data.len());
    assert_eq!(OVERLAPPED_PTR.load(Ordering::Acquire), &mut overlapped as *mut _ as usize);

    let mut payload = vec![0u8; data.len().max(64)];
    let mut recv_buffer = WSABUF {
        len: payload.len() as u32,
        buf: windows::core::PSTR(payload.as_mut_ptr()),
    };
    let mut flags = 0;
    let mut source = [0u8; 128];
    let mut source_len = source.len() as i32;
    let mut recv_overlapped = OVERLAPPED::default();
    CALLED.store(false, Ordering::Release);
    ERROR.store(u32::MAX, Ordering::Release);
    let result = unsafe {
        WSARecvFrom(
            raw,
            std::slice::from_mut(&mut recv_buffer),
            None,
            &mut flags,
            Some(source.as_mut_ptr().cast()),
            Some(&mut source_len),
            Some(&mut recv_overlapped),
            Some(completion),
        )
    };
    assert_eq!(result, -1);
    assert_eq!(unsafe { WSAGetLastError() }, WSA_IO_PENDING);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !CALLED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(CALLED.load(Ordering::Acquire), "WSARecvFrom completion not called");
    assert_eq!(ERROR.load(Ordering::Acquire), 0);
    assert_eq!(BYTES.load(Ordering::Acquire) as usize, data.len());
    assert_eq!(OVERLAPPED_PTR.load(Ordering::Acquire), &mut recv_overlapped as *mut _ as usize);
    assert_eq!(&payload[..data.len()], data);
}

#[cfg(not(windows))]
fn completion_send_recv(_socket: &UdpSocket, _data: &[u8], _destination: SocketAddr) {
    unreachable!("Windows completion routines are only available on Windows");
}

fn run_quic(destination: SocketAddr) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async move {
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];
        endpoint.set_default_client_config(quinn::ClientConfig::new(std::sync::Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
        )));
        let connection = endpoint
            .connect(destination, "localhost")
            .unwrap()
            .await
            .expect("quic connect");
        let (mut driver, mut client) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .expect("http3 client init");
        let request = async move {
            let mut stream = client
                .send_request(http::Request::get("https://proxychains.test/quic").body(()).unwrap())
                .await
                .expect("http3 request");
            let response = stream.recv_response().await.expect("http3 response");
            assert_eq!(response.status(), http::StatusCode::OK);
            let body = stream
                .recv_data()
                .await
                .expect("http3 response body")
                .expect("http3 response data");
            assert_eq!(body.chunk(), b"http3-proxy-response");
            connection.close(0u32.into(), b"done");
        };
        let drive = async move {
            std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        };
        tokio::join!(request, drive);
        endpoint.wait_idle().await;
    });
}

#[derive(Debug)]
struct SkipServerVerification(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        )))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
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
    use windows::Win32::Networking::WinSock::{
        WSAGetLastError, WSASendTo, SOCKET, WSABUF, WSA_IO_PENDING,
    };
    use windows::Win32::System::IO::{
        CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
    };
    let port = unsafe {
        CreateIoCompletionPort(HANDLE(-1), HANDLE::default(), 0x51, 1)
            .expect("CreateIoCompletionPort")
    };
    let socket_handle = HANDLE(socket.as_raw_socket() as isize);
    unsafe {
        CreateIoCompletionPort(socket_handle, port, 0x51, 1)
            .expect("associate UDP socket with IOCP");
    }
    let destination = socket2::SockAddr::from(destination);
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
    bytes as usize
}
#[cfg(windows)]
fn iocp_sendmsg_to(socket: &UdpSocket, data: &[u8], destination: SocketAddr) -> usize {
    use std::ffi::c_void;
    use std::mem::transmute;
    use std::os::windows::io::AsRawSocket;
    use windows::core::GUID;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Networking::WinSock::{
        WSAGetLastError, WSAIoctl, LPWSAOVERLAPPED_COMPLETION_ROUTINE, SOCKET, WSABUF,
        WSAID_WSASENDMSG, WSAMSG, WSA_IO_PENDING,
    };
    use windows::Win32::System::IO::{
        CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
    };
    const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
    type SendMsg = unsafe extern "system" fn(
        SOCKET,
        *const WSAMSG,
        u32,
        *mut u32,
        *mut OVERLAPPED,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> i32;
    let port = unsafe {
        CreateIoCompletionPort(HANDLE(-1), HANDLE::default(), 0x54, 1)
            .expect("CreateIoCompletionPort")
    };
    let raw = SOCKET(socket.as_raw_socket() as usize);
    unsafe {
        CreateIoCompletionPort(HANDLE(socket.as_raw_socket() as isize), port, 0x54, 1)
            .expect("associate UDP socket with IOCP");
    }
    let mut function: *mut c_void = std::ptr::null_mut();
    let mut returned = 0;
    let result = unsafe {
        WSAIoctl(
            raw,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            Some((&WSAID_WSASENDMSG as *const GUID).cast()),
            std::mem::size_of::<GUID>() as u32,
            Some((&mut function as *mut *mut c_void).cast()),
            std::mem::size_of::<*mut c_void>() as u32,
            &mut returned,
            None,
            None,
        )
    };
    assert_eq!(result, 0);
    let sendmsg: SendMsg = unsafe { transmute(function) };
    let mut buffer = WSABUF {
        len: data.len() as u32,
        buf: windows::core::PSTR(data.as_ptr().cast_mut()),
    };
    let destination = socket2::SockAddr::from(destination);
    let message = WSAMSG {
        name: destination.as_ptr().cast_mut().cast(),
        namelen: destination.len(),
        lpBuffers: &mut buffer,
        dwBufferCount: 1,
        Control: WSABUF {
            len: 0,
            buf: windows::core::PSTR(std::ptr::null_mut()),
        },
        dwFlags: 0,
    };
    let mut overlapped = OVERLAPPED::default();
    assert_eq!(
        unsafe {
            sendmsg(
                raw,
                &message,
                0,
                std::ptr::null_mut(),
                &mut overlapped,
                None,
            )
        },
        -1
    );
    assert_eq!(unsafe { WSAGetLastError() }, WSA_IO_PENDING);
    let mut bytes = 0;
    let mut key = 0;
    let mut completed = std::ptr::null_mut();
    unsafe {
        GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut completed, 5000)
            .expect("UDP IOCP WSASendMsg completion");
    }
    assert_eq!(key, 0x54);
    assert!(std::ptr::eq(completed, &mut overlapped));
    assert_eq!(bytes as usize, data.len());
    bytes as usize
}
#[cfg(not(windows))]
fn iocp_sendmsg_to(socket: &UdpSocket, data: &[u8], destination: SocketAddr) -> usize {
    socket.send_to(data, destination).unwrap()
}
#[cfg(windows)]
fn iocp_recv_from(socket: &UdpSocket, expected: &[u8]) -> usize {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Networking::WinSock::{
        WSAGetLastError, WSARecvFrom, SOCKET, WSABUF, WSA_IO_PENDING,
    };
    use windows::Win32::System::IO::{
        CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
    };
    let port = unsafe {
        CreateIoCompletionPort(HANDLE(-1), HANDLE::default(), 0x52, 1)
            .expect("CreateIoCompletionPort")
    };
    let socket_handle = HANDLE(socket.as_raw_socket() as isize);
    unsafe {
        CreateIoCompletionPort(socket_handle, port, 0x52, 1)
            .expect("associate UDP socket with IOCP");
    }
    let mut payload = vec![0u8; expected.len().max(64)];
    let buffer = WSABUF {
        len: payload.len() as u32,
        buf: windows::core::PSTR(payload.as_mut_ptr()),
    };
    let mut flags = 0;
    let mut storage = [0u8; 128];
    let mut storage_len = storage.len() as i32;
    let mut overlapped = OVERLAPPED::default();
    let result = unsafe {
        WSARecvFrom(
            SOCKET(socket.as_raw_socket() as usize),
            std::slice::from_ref(&buffer),
            None,
            &mut flags,
            Some(storage.as_mut_ptr().cast()),
            Some(&mut storage_len),
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
            .expect("UDP IOCP receive completion");
    }
    assert_eq!(key, 0x52);
    assert!(std::ptr::eq(completed, &mut overlapped));
    assert_eq!(bytes as usize, expected.len());
    assert_eq!(&payload[..bytes as usize], expected);
    bytes as usize
}
#[cfg(not(windows))]
fn iocp_recv_from(socket: &UdpSocket, expected: &[u8]) -> usize {
    let mut payload = vec![0u8; expected.len().max(64)];
    let (n, _) = socket.recv_from(&mut payload).unwrap();
    assert_eq!(&payload[..n], expected);
    n
}
#[cfg(windows)]
fn iocp_cancel_recv(socket: &UdpSocket) {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Networking::WinSock::{
        closesocket, WSAGetLastError, WSARecvFrom, SOCKET, WSABUF, WSA_IO_PENDING,
        WSA_OPERATION_ABORTED,
    };
    use windows::Win32::System::IO::{
        CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
    };
    let port = unsafe {
        CreateIoCompletionPort(HANDLE(-1), HANDLE::default(), 0x53, 1)
            .expect("CreateIoCompletionPort")
    };
    let raw = SOCKET(socket.as_raw_socket() as usize);
    unsafe {
        CreateIoCompletionPort(HANDLE(socket.as_raw_socket() as isize), port, 0x53, 1)
            .expect("associate UDP socket with IOCP");
    }
    let mut payload = [0u8; 64];
    let buffer = WSABUF {
        len: payload.len() as u32,
        buf: windows::core::PSTR(payload.as_mut_ptr()),
    };
    let mut flags = 0;
    let mut storage = [0u8; 128];
    let mut storage_len = storage.len() as i32;
    let mut overlapped = OVERLAPPED::default();
    let result = unsafe {
        WSARecvFrom(
            raw,
            std::slice::from_ref(&buffer),
            None,
            &mut flags,
            Some(storage.as_mut_ptr().cast()),
            Some(&mut storage_len),
            Some(&mut overlapped),
            None,
        )
    };
    assert_eq!(result, -1);
    assert_eq!(unsafe { WSAGetLastError() }, WSA_IO_PENDING);
    assert_eq!(unsafe { closesocket(raw) }, 0);
    let mut bytes = 0;
    let mut key = 0;
    let mut completed = std::ptr::null_mut();
    unsafe {
        GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut completed, 5000)
            .expect("cancelled UDP IOCP completion");
    }
    assert_eq!(bytes, 0);
    assert_eq!(key, 0x53);
    assert!(std::ptr::eq(completed, &mut overlapped));
    assert_eq!(overlapped.Internal, WSA_OPERATION_ABORTED.0 as usize);
}
#[cfg(not(windows))]
fn iocp_cancel_recv(_socket: &UdpSocket) {}
#[cfg(windows)]
fn recvmsg_from(socket: &UdpSocket, expected: &[u8]) -> usize {
    use std::ffi::c_void;
    use std::mem::transmute;
    use std::os::windows::io::AsRawSocket;
    use windows::core::GUID;
    use windows::Win32::Networking::WinSock::{
        WSAIoctl, LPWSAOVERLAPPED_COMPLETION_ROUTINE, SOCKET, WSABUF, WSAMSG,
    };
    const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
    const WSAID_WSARECVMSG: GUID = GUID::from_u128(0xf689d7c8_6f1f_436b_8a53_e54fe351c322);
    type RecvMsg = unsafe extern "system" fn(
        SOCKET,
        *mut WSAMSG,
        *mut u32,
        *mut windows::Win32::System::IO::OVERLAPPED,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> i32;
    let raw = SOCKET(socket.as_raw_socket() as usize);
    let mut function: *mut c_void = std::ptr::null_mut();
    let mut returned = 0;
    let result = unsafe {
        WSAIoctl(
            raw,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            Some((&WSAID_WSARECVMSG as *const GUID).cast()),
            std::mem::size_of::<GUID>() as u32,
            Some((&mut function as *mut *mut c_void).cast()),
            std::mem::size_of::<*mut c_void>() as u32,
            &mut returned,
            None,
            None,
        )
    };
    assert_eq!(result, 0);
    let recvmsg: RecvMsg = unsafe { transmute(function) };
    let mut payload = vec![0u8; expected.len().max(64)];
    let mut buffer = WSABUF {
        len: payload.len() as u32,
        buf: windows::core::PSTR(payload.as_mut_ptr()),
    };
    let mut storage = [0u8; 128];
    let mut message = WSAMSG {
        name: storage.as_mut_ptr().cast(),
        namelen: storage.len() as i32,
        lpBuffers: &mut buffer,
        dwBufferCount: 1,
        Control: WSABUF {
            len: 0,
            buf: windows::core::PSTR(std::ptr::null_mut()),
        },
        dwFlags: 0,
    };
    let mut received = 0;
    assert_eq!(
        unsafe { recvmsg(raw, &mut message, &mut received, std::ptr::null_mut(), None) },
        0
    );
    assert_eq!(received as usize, expected.len());
    assert_eq!(&payload[..received as usize], expected);
    received as usize
}
#[cfg(not(windows))]
fn recvmsg_from(socket: &UdpSocket, expected: &[u8]) -> usize {
    let mut payload = vec![0u8; expected.len().max(64)];
    let (n, _) = socket.recv_from(&mut payload).unwrap();
    assert_eq!(&payload[..n], expected);
    n
}
#[cfg(windows)]
fn iocp_recvmsg_from(socket: &UdpSocket, expected: &[u8]) -> usize {
    use std::ffi::c_void;
    use std::mem::transmute;
    use std::os::windows::io::AsRawSocket;
    use windows::core::GUID;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Networking::WinSock::{
        WSAGetLastError, WSAIoctl, LPWSAOVERLAPPED_COMPLETION_ROUTINE, SOCKET, WSABUF,
        WSAID_WSARECVMSG, WSAMSG, WSA_IO_PENDING,
    };
    use windows::Win32::System::IO::{
        CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
    };
    const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
    type RecvMsg = unsafe extern "system" fn(
        SOCKET,
        *mut WSAMSG,
        *mut u32,
        *mut OVERLAPPED,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> i32;
    let port = unsafe {
        CreateIoCompletionPort(HANDLE(-1), HANDLE::default(), 0x55, 1)
            .expect("CreateIoCompletionPort")
    };
    let raw = SOCKET(socket.as_raw_socket() as usize);
    unsafe {
        CreateIoCompletionPort(HANDLE(socket.as_raw_socket() as isize), port, 0x55, 1)
            .expect("associate UDP socket with IOCP");
    }
    let mut function: *mut c_void = std::ptr::null_mut();
    let mut returned = 0;
    assert_eq!(
        unsafe {
            WSAIoctl(
                raw,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                Some((&WSAID_WSARECVMSG as *const GUID).cast()),
                std::mem::size_of::<GUID>() as u32,
                Some((&mut function as *mut *mut c_void).cast()),
                std::mem::size_of::<*mut c_void>() as u32,
                &mut returned,
                None,
                None,
            )
        },
        0
    );
    let recvmsg: RecvMsg = unsafe { transmute(function) };
    let mut payload = vec![0u8; expected.len().max(64)];
    let mut buffer = WSABUF {
        len: payload.len() as u32,
        buf: windows::core::PSTR(payload.as_mut_ptr()),
    };
    let mut storage = [0u8; 128];
    let mut message = WSAMSG {
        name: storage.as_mut_ptr().cast(),
        namelen: storage.len() as i32,
        lpBuffers: &mut buffer,
        dwBufferCount: 1,
        Control: WSABUF {
            len: 0,
            buf: windows::core::PSTR(std::ptr::null_mut()),
        },
        dwFlags: 0,
    };
    let mut overlapped = OVERLAPPED::default();
    assert_eq!(
        unsafe {
            recvmsg(
                raw,
                &mut message,
                std::ptr::null_mut(),
                &mut overlapped,
                None,
            )
        },
        -1
    );
    assert_eq!(unsafe { WSAGetLastError() }, WSA_IO_PENDING);
    let mut bytes = 0;
    let mut key = 0;
    let mut completed = std::ptr::null_mut();
    unsafe {
        GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut completed, 5000)
            .expect("UDP IOCP WSARecvMsg completion");
    }
    assert_eq!(key, 0x55);
    assert!(std::ptr::eq(completed, &mut overlapped));
    assert_eq!(bytes as usize, expected.len());
    assert_eq!(&payload[..bytes as usize], expected);
    bytes as usize
}
#[cfg(not(windows))]
fn iocp_recvmsg_from(socket: &UdpSocket, expected: &[u8]) -> usize {
    recvmsg_from(socket, expected)
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
