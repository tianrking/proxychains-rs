#[path = "support/udp_fixture.rs"]
mod udp_fixture;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args
        .get(1)
        .is_some_and(|s| (s.starts_with("udp") && s != "udp-rio") || s == "quic")
    {
        udp_fixture::run(&args[1]);
        std::process::exit(23);
    }
    if args.get(1).map(String::as_str) == Some("tcp") {
        use std::io::{Read, Write};
        let mut stream = match std::net::TcpStream::connect(&args[2]) {
            Ok(stream) => stream,
            Err(_) => std::process::exit(24),
        };
        assert_eq!(
            stream.read_timeout().unwrap(),
            None,
            "hook must restore application timeout"
        );
        assert_eq!(
            stream.write_timeout().unwrap(),
            None,
            "hook must restore application timeout"
        );
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        stream.write_all(b"fixture-request").unwrap();
        let mut response = [0; 14];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"proxy-response");
        std::process::exit(23);
    }
    if matches!(
        args.get(1).map(String::as_str),
        Some(
            "tcp-connectex"
                | "tcp-connectex-iocp"
                | "tcp-connectex-cancel"
                | "tcp-connectex-cancel-iocp",
        )
    ) {
        #[cfg(windows)]
        if args[1].starts_with("tcp-connectex-cancel") {
            run_tcp_connectex_cancel(&args[2], args[1].ends_with("-iocp"));
        } else {
            run_tcp_connectex(&args[2], args[1] == "tcp-connectex-iocp");
        }
        #[cfg(not(windows))]
        std::process::exit(24);
        std::process::exit(23);
    }
    if args.get(1).map(String::as_str) == Some("dns-exa") {
        #[cfg(windows)]
        run_dns_exa();
        #[cfg(not(windows))]
        std::process::exit(24);
        std::process::exit(23);
    }
    if args.get(1).map(String::as_str) == Some("dns-queryex") {
        #[cfg(windows)]
        run_dns_queryex();
        #[cfg(not(windows))]
        std::process::exit(24);
        std::process::exit(23);
    }
    if args.get(1).map(String::as_str) == Some("udp-rio") {
        #[cfg(windows)]
        run_udp_rio_probe();
        #[cfg(not(windows))]
        std::process::exit(24);
        std::process::exit(23);
    }
    if args.get(1).map(String::as_str) == Some("sleep") {
        std::thread::sleep(std::time::Duration::from_secs(60));
        return;
    }
    if let Some(marker) = args.get(1) {
        std::fs::write(marker, b"started").unwrap();
    }
    std::process::exit(23);
}

#[cfg(windows)]
fn run_udp_rio_probe() {
    use std::os::windows::io::AsRawSocket;
    use windows::core::GUID;
    use windows::Win32::Networking::WinSock::{WSAIoctl, SOCKET};
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    const SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0024;
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("RIO probe socket");
    let raw = SOCKET(socket.as_raw_socket() as usize);
    let rio = GUID::from_u128(0x8509e08196dd4005b1659e2ee8c79e3f);
    #[repr(C)]
    struct RioTable {
        cb_size: u32,
        _padding: u32,
        functions: [usize; 13],
    }
    let mut table = RioTable {
        cb_size: 0,
        _padding: 0,
        functions: [0; 13],
    };
    let mut returned = 0;
    let result = unsafe {
        WSAIoctl(
            raw,
            SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
            Some((&rio as *const GUID).cast()),
            std::mem::size_of::<GUID>() as u32,
            Some((&mut table as *mut RioTable).cast()),
            std::mem::size_of::<RioTable>() as u32,
            &mut returned,
            None,
            None,
        )
    };
    assert_eq!(result, 0, "RIO extension table must be available");
    assert_eq!(returned as usize, std::mem::size_of::<RioTable>());
    assert!(table.cb_size >= std::mem::size_of::<RioTable>() as u32);

    type CreateCq = unsafe extern "system" fn(u32, *mut std::ffi::c_void) -> usize;
    type CloseCq = unsafe extern "system" fn(usize);
    type Notify = unsafe extern "system" fn(usize) -> i32;
    type CreateRq = unsafe extern "system" fn(
        usize,
        u32,
        u32,
        u32,
        u32,
        usize,
        usize,
        *mut std::ffi::c_void,
    ) -> usize;
    type Register = unsafe extern "system" fn(*mut i8, u32) -> usize;
    type Deregister = unsafe extern "system" fn(usize);
    type SendEx = unsafe extern "system" fn(
        usize,
        *const RioBuf,
        u32,
        *const RioBuf,
        *const RioBuf,
        *const RioBuf,
        *const RioBuf,
        u32,
        *mut std::ffi::c_void,
    ) -> i32;
    type ReceiveEx = unsafe extern "system" fn(
        usize,
        *const RioBuf,
        u32,
        *const RioBuf,
        *const RioBuf,
        *const RioBuf,
        *const RioBuf,
        u32,
        *mut std::ffi::c_void,
    ) -> i32;
    type Dequeue = unsafe extern "system" fn(usize, *mut RioResult, u32) -> u32;
    #[repr(C)]
    struct RioBuf {
        buffer_id: usize,
        offset: u32,
        length: u32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RioNotification {
        kind: i32,
        _padding: u32,
        payload: [usize; 3],
    }
    #[repr(C)]
    #[derive(Default)]
    struct RioResult {
        status: i32,
        bytes_transferred: u32,
        socket_context: u64,
        request_context: u64,
    }
    let create_cq: CreateCq = unsafe { std::mem::transmute(table.functions[5]) };
    let close_cq: CloseCq = unsafe { std::mem::transmute(table.functions[4]) };
    let notify: Notify = unsafe { std::mem::transmute(table.functions[9]) };
    let create_rq: CreateRq = unsafe { std::mem::transmute(table.functions[6]) };
    let register: Register = unsafe { std::mem::transmute(table.functions[10]) };
    let deregister: Deregister = unsafe { std::mem::transmute(table.functions[8]) };
    let send_ex: SendEx = unsafe { std::mem::transmute(table.functions[3]) };
    let receive_ex: ReceiveEx = unsafe { std::mem::transmute(table.functions[1]) };
    let dequeue: Dequeue = unsafe { std::mem::transmute(table.functions[7]) };
    let event = unsafe { CreateEventW(None, true, false, None).expect("RIO completion event") };
    let mut notification = RioNotification {
        kind: 1,
        _padding: 0,
        payload: [event.0 as usize, 1, 0],
    };
    let cq = unsafe { create_cq(8, (&mut notification as *mut RioNotification).cast()) };
    assert_ne!(cq, 0, "RIO completion queue creation");
    let rq = unsafe {
        create_rq(
            socket.as_raw_socket() as usize,
            8,
            8,
            8,
            8,
            cq,
            cq,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(rq, 0, "RIO request queue creation");
    let mut payload = [0u8; 16];
    let buffer = unsafe { register(payload.as_mut_ptr().cast(), payload.len() as u32) };
    assert_ne!(buffer, usize::MAX, "RIO buffer registration");
    let descriptor = RioBuf {
        buffer_id: buffer,
        offset: 0,
        length: payload.len() as u32,
    };
    let invalid_descriptor = RioBuf {
        buffer_id: 1,
        offset: 0,
        length: payload.len() as u32,
    };
    assert_eq!(
        unsafe {
            send_ex(
                rq,
                &invalid_descriptor,
                1,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            )
        },
        0,
        "RIO must reject an unregistered buffer id"
    );
    let remote = socket2::SockAddr::from(
        "192.0.2.123:443"
            .parse::<std::net::SocketAddr>()
            .expect("RIO target address"),
    );
    let remote_bytes = unsafe {
        std::slice::from_raw_parts(remote.as_ptr().cast::<u8>(), remote.len() as usize)
    };
    let remote_id = unsafe {
        register(
            remote_bytes.as_ptr().cast_mut().cast(),
            remote_bytes.len() as u32,
        )
    };
    assert_ne!(remote_id, usize::MAX, "RIO remote buffer registration");
    let remote_descriptor = RioBuf {
        buffer_id: remote_id,
        offset: 0,
        length: remote_bytes.len() as u32,
    };
    assert_eq!(
        unsafe {
            send_ex(
                rq,
                &descriptor,
                1,
                std::ptr::null(),
                &remote_descriptor,
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            )
        },
        1
    );
    assert_eq!(unsafe { notify(cq) }, 0);
    assert_eq!(unsafe { WaitForSingleObject(event, 1000) }, WAIT_OBJECT_0);
    let mut completion = RioResult::default();
    assert_eq!(unsafe { dequeue(cq, &mut completion, 1) }, 1);
    payload.fill(0);
    assert_eq!(
        unsafe {
            receive_ex(
                rq,
                &descriptor,
                1,
                std::ptr::null(),
                &remote_descriptor,
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            )
        },
        1
    );
    completion = RioResult::default();
    assert_eq!(unsafe { dequeue(cq, &mut completion, 1) }, 1);
    assert_eq!(completion.bytes_transferred, payload.len() as u32);
    unsafe {
        deregister(remote_id);
        deregister(buffer);
        close_cq(cq);
        let _ = CloseHandle(event);
    }
}

#[cfg(windows)]
fn run_tcp_connectex_cancel(target: &str, use_iocp: bool) {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::ffi::c_void;
    use std::mem::{forget, transmute};
    use std::net::SocketAddr;
    use std::os::windows::io::AsRawSocket;
    use windows::core::GUID;
    use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows::Win32::Networking::WinSock::{
        closesocket, WSAGetLastError, WSAIoctl, SOCKET, WSAID_CONNECTEX, WSA_IO_PENDING,
        WSA_OPERATION_ABORTED,
    };
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
    use windows::Win32::System::IO::{
        CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
    };

    type ConnectEx = unsafe extern "system" fn(
        SOCKET,
        *const c_void,
        i32,
        *const c_void,
        u32,
        *mut u32,
        *mut OVERLAPPED,
    ) -> i32;

    let target: SocketAddr = target.parse().expect("ConnectEx cancellation target");
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )
    .expect("ConnectEx cancellation socket");
    socket
        .bind(&SockAddr::from(SocketAddr::new(
            if target.is_ipv4() { "0.0.0.0" } else { "::" }
                .parse()
                .unwrap(),
            0,
        )))
        .expect("ConnectEx cancellation bind");
    let raw = SOCKET(socket.as_raw_socket() as usize);
    let mut function: *mut c_void = std::ptr::null_mut();
    let mut returned = 0;
    assert_eq!(
        unsafe {
            WSAIoctl(
                raw,
                0xC800_0006,
                Some((&WSAID_CONNECTEX as *const GUID).cast()),
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
    let connect_ex: ConnectEx = unsafe { transmute(function) };
    let event = if use_iocp {
        HANDLE::default()
    } else {
        unsafe { CreateEventW(None, true, false, None).expect("ConnectEx cancellation event") }
    };
    let port = if use_iocp {
        let port = unsafe {
            CreateIoCompletionPort(HANDLE(-1), HANDLE::default(), 0x57, 1)
                .expect("ConnectEx cancellation IOCP")
        };
        unsafe {
            CreateIoCompletionPort(HANDLE(raw.0 as isize), port, 0x57, 1)
                .expect("associate cancellation socket")
        };
        Some(port)
    } else {
        None
    };
    let mut overlapped = OVERLAPPED {
        hEvent: event,
        ..Default::default()
    };
    let destination = SockAddr::from(target);
    let mut sent = 0;
    let result = unsafe {
        connect_ex(
            raw,
            destination.as_ptr().cast(),
            destination.len(),
            std::ptr::null(),
            0,
            &mut sent,
            &mut overlapped,
        )
    };
    assert_eq!(result, 0);
    assert_eq!(unsafe { WSAGetLastError() }, WSA_IO_PENDING);
    // Let the worker establish the proxy TCP connection before cancellation;
    // the mock proxy then keeps the HTTP handshake pending.
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert_eq!(unsafe { closesocket(raw) }, 0);
    forget(socket);

    let mut completed_bytes = 0;
    let mut key = 0;
    let mut completed = std::ptr::null_mut();
    if let Some(port) = port {
        unsafe {
            let _ = GetQueuedCompletionStatus(
                port,
                &mut completed_bytes,
                &mut key,
                &mut completed,
                10_000,
            );
        }
        assert_eq!(key, 0x57);
        assert!(std::ptr::eq(completed, &mut overlapped));
    } else {
        assert_eq!(unsafe { WaitForSingleObject(event, 10_000) }, WAIT_OBJECT_0);
    }
    assert_eq!(completed_bytes, 0);
    assert_eq!(overlapped.Internal, WSA_OPERATION_ABORTED.0 as usize);
}

#[cfg(windows)]
fn run_tcp_connectex(target: &str, use_iocp: bool) {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::ffi::c_void;
    use std::io::Read;
    use std::mem::transmute;
    use std::net::SocketAddr;
    use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket};
    use windows::core::GUID;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Networking::WinSock::{
        WSAGetLastError, WSAIoctl, SIO_GET_EXTENSION_FUNCTION_POINTER, SOCKET, WSAID_CONNECTEX,
        WSA_IO_PENDING,
    };
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
    use windows::Win32::System::IO::{
        CreateIoCompletionPort, GetOverlappedResult, GetQueuedCompletionStatus, OVERLAPPED,
    };

    type ConnectEx = unsafe extern "system" fn(
        SOCKET,
        *const c_void,
        i32,
        *const c_void,
        u32,
        *mut u32,
        *mut OVERLAPPED,
    ) -> i32;

    let target: SocketAddr = target.parse().expect("ConnectEx target");
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )
    .expect("ConnectEx socket");
    socket
        .bind(&SockAddr::from(SocketAddr::new(
            if target.is_ipv4() { "0.0.0.0" } else { "::" }
                .parse()
                .unwrap(),
            0,
        )))
        .expect("ConnectEx bind");
    let raw = SOCKET(socket.as_raw_socket() as usize);
    let mut function: *mut c_void = std::ptr::null_mut();
    let mut returned = 0;
    let result = unsafe {
        WSAIoctl(
            raw,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            Some((&WSAID_CONNECTEX as *const GUID).cast()),
            std::mem::size_of::<GUID>() as u32,
            Some((&mut function as *mut *mut c_void).cast()),
            std::mem::size_of::<*mut c_void>() as u32,
            &mut returned,
            None,
            None,
        )
    };
    assert_eq!(result, 0);
    let connect_ex: ConnectEx = unsafe { transmute(function) };
    let event = if use_iocp {
        HANDLE::default()
    } else {
        unsafe { CreateEventW(None, true, false, None).expect("ConnectEx event") }
    };
    let port = if use_iocp {
        let port = unsafe {
            CreateIoCompletionPort(HANDLE(-1), HANDLE::default(), 0x56, 1).expect("ConnectEx IOCP")
        };
        unsafe {
            CreateIoCompletionPort(HANDLE(raw.0 as isize), port, 0x56, 1)
                .expect("associate ConnectEx socket")
        };
        Some(port)
    } else {
        None
    };
    let mut overlapped = OVERLAPPED {
        hEvent: event,
        ..Default::default()
    };
    let initial = b"connectex-request";
    let mut sent = 0;
    let destination = SockAddr::from(target);
    let result = unsafe {
        connect_ex(
            raw,
            destination.as_ptr().cast(),
            destination.len(),
            initial.as_ptr().cast(),
            initial.len() as u32,
            &mut sent,
            &mut overlapped,
        )
    };
    assert_eq!(result, 0);
    assert_eq!(unsafe { WSAGetLastError() }, WSA_IO_PENDING);
    if let Some(port) = port {
        let mut completed_bytes = 0;
        let mut key = 0;
        let mut completed = std::ptr::null_mut();
        unsafe {
            GetQueuedCompletionStatus(port, &mut completed_bytes, &mut key, &mut completed, 10_000)
                .expect("ConnectEx IOCP completion");
        }
        assert_eq!(key, 0x56);
        assert!(std::ptr::eq(completed, &mut overlapped));
        assert_eq!(completed_bytes, initial.len() as u32);
    } else {
        assert_eq!(
            unsafe { WaitForSingleObject(event, 10_000) },
            windows::Win32::Foundation::WAIT_OBJECT_0
        );
    }
    let mut completed = 0;
    unsafe {
        GetOverlappedResult(
            HANDLE(raw.0 as isize),
            &mut overlapped,
            &mut completed,
            true,
        )
        .expect("ConnectEx completion");
    }
    assert_eq!(completed, initial.len() as u32);
    assert_eq!(sent, initial.len() as u32);
    let mut stream = unsafe { std::net::TcpStream::from_raw_socket(socket.into_raw_socket()) };
    let mut response = [0; 14];
    stream
        .read_exact(&mut response)
        .expect("ConnectEx response");
    assert_eq!(&response, b"proxy-response");
}

#[cfg(windows)]
fn run_dns_exa() {
    use std::ffi::{c_void, CString};
    use std::mem::transmute;
    use windows::core::PCSTR;
    use windows::Win32::Networking::WinSock::{WSACleanup, WSAStartup, WSADATA};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    type GetAddrInfoExA = unsafe extern "system" fn(
        *const i8,
        *const i8,
        u32,
        *mut c_void,
        *const c_void,
        *mut *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
    ) -> i32;
    let module = unsafe { GetModuleHandleA(PCSTR(b"ws2_32.dll\0".as_ptr())) }.expect("ws2_32");
    let mut wsa_data = WSADATA::default();
    assert_eq!(unsafe { WSAStartup(0x202, &mut wsa_data) }, 0);
    let get_proc = unsafe { GetProcAddress(module, PCSTR(b"GetAddrInfoExA\0".as_ptr())) }
        .expect("GetAddrInfoExA");
    let get: GetAddrInfoExA = unsafe { transmute(get_proc) };
    let hostname = CString::new("proxychains-remote-dns.invalid").unwrap();
    let mut result = std::ptr::null_mut();
    let code = unsafe {
        get(
            hostname.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut result,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(code, 0, "GetAddrInfoExA returned {code}");
    assert!(!result.is_null(), "GetAddrInfoExA returned no result");
    assert_eq!(unsafe { WSACleanup() }, 0);
}

#[cfg(windows)]
fn run_dns_queryex() {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::NetworkManagement::Dns::{
        DnsFree, DnsFreeRecordList, DnsQueryEx, DNS_QUERY_REQUEST, DNS_QUERY_REQUEST_VERSION1,
        DNS_QUERY_RESULT, DNS_QUERY_RESULTS_VERSION1, DNS_TYPE_A,
    };

    static CALLED: AtomicBool = AtomicBool::new(false);
    static CONTEXT: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "system" fn callback(context: *const c_void, results: *mut DNS_QUERY_RESULT) {
        CONTEXT.store(context as usize, Ordering::Release);
        if !results.is_null() {
            let result = &mut *results;
            if !result.pQueryRecords.is_null() {
                DnsFree(Some(result.pQueryRecords.cast()), DnsFreeRecordList);
                result.pQueryRecords = std::ptr::null_mut();
            }
        }
        CALLED.store(true, Ordering::Release);
    }

    CALLED.store(false, Ordering::Release);
    CONTEXT.store(0, Ordering::Release);
    // localhost is intentionally used here because Windows may complete a
    // numeric/fake DNS answer synchronously without invoking the callback.
    // The proxy-DNS fake-name path is covered by the hook unit tests; this
    // native fixture validates the real callback ABI and context lifetime.
    let name: Vec<u16> = "localhost"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let request = DNS_QUERY_REQUEST {
        Version: DNS_QUERY_REQUEST_VERSION1.0,
        QueryName: PCWSTR(name.as_ptr()),
        QueryType: DNS_TYPE_A.0,
        pQueryCompletionCallback: Some(callback),
        pQueryContext: 0x1234usize as *mut c_void,
        ..Default::default()
    };
    let mut result = DNS_QUERY_RESULT {
        Version: DNS_QUERY_RESULTS_VERSION1.0,
        ..Default::default()
    };
    let code = unsafe { DnsQueryEx(&request, &mut result, None) };
    assert!(
        code == ERROR_SUCCESS.0 as i32 || code == 9506,
        "DnsQueryEx returned {code}"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !CALLED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    // Windows may satisfy cached queries synchronously without invoking the
    // completion routine. When it does invoke the routine, the hook must
    // restore the application's original context before forwarding it.
    if CALLED.load(Ordering::Acquire) {
        assert_eq!(CONTEXT.load(Ordering::Acquire), 0x1234);
    } else {
        assert_eq!(code, ERROR_SUCCESS.0 as i32);
    }
}
