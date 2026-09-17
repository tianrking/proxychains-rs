//! Small RIO compatibility layer for transparent UDP sockets.
//!
//! RIO uses registered buffers and opaque request/completion queue handles,
//! so it does not pass through the ordinary Winsock send/receive hooks.  The
//! wrappers below preserve those semantics while routing the actual datagram
//! through the existing SOCKS5 UDP implementation.

use super::udp;
use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::ptr;
use std::sync::{Mutex, OnceLock};
use windows::Win32::Foundation::BOOL;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::IO::{PostQueuedCompletionStatus, OVERLAPPED};
use windows::Win32::System::Threading::SetEvent;

pub type BufferId = *mut RioBuffer;
pub type CompletionQueue = *mut RioCompletionQueue;
pub type RequestQueue = *mut RioRequestQueue;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RioResult {
    pub status: i32,
    pub bytes_transferred: u32,
    pub socket_context: u64,
    pub request_context: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RioBuf {
    pub buffer_id: BufferId,
    pub offset: u32,
    pub length: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RioNotificationCompletion {
    pub kind: i32,
    pub payload: [usize; 3],
}

pub struct RioBuffer {
    _token: u8,
}

pub struct RioCompletionQueue {
    results: Mutex<VecDeque<RioResult>>,
    notification: Option<RioNotificationCompletion>,
    _capacity: u32,
}

pub struct RioRequestQueue {
    socket: usize,
    receive: CompletionQueue,
    send: CompletionQueue,
    context: u64,
}

static REQUEST_QUEUES: OnceLock<Mutex<HashMap<usize, Vec<usize>>>> = OnceLock::new();
static BUFFERS: OnceLock<Mutex<HashMap<usize, (usize, usize)>>> = OnceLock::new();

fn request_queues() -> &'static Mutex<HashMap<usize, Vec<usize>>> {
    REQUEST_QUEUES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn buffers() -> &'static Mutex<HashMap<usize, (usize, usize)>> {
    BUFFERS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[repr(C)]
pub struct ExtensionFunctionTable {
    pub cb_size: u32,
    pub receive: *const c_void,
    pub receive_ex: *const c_void,
    pub send: *const c_void,
    pub send_ex: *const c_void,
    pub close_completion_queue: *const c_void,
    pub create_completion_queue: *const c_void,
    pub create_request_queue: *const c_void,
    pub dequeue_completion: *const c_void,
    pub deregister_buffer: *const c_void,
    pub notify: *const c_void,
    pub register_buffer: *const c_void,
    pub resize_completion_queue: *const c_void,
    pub resize_request_queue: *const c_void,
}

pub fn extension_table() -> ExtensionFunctionTable {
    ExtensionFunctionTable {
        cb_size: std::mem::size_of::<ExtensionFunctionTable>() as u32,
        receive: receive as *const c_void,
        receive_ex: receive_ex as *const c_void,
        send: send as *const c_void,
        send_ex: send_ex as *const c_void,
        close_completion_queue: close_completion_queue as *const c_void,
        create_completion_queue: create_completion_queue as *const c_void,
        create_request_queue: create_request_queue as *const c_void,
        dequeue_completion: dequeue as *const c_void,
        deregister_buffer: deregister_buffer as *const c_void,
        notify: notify as *const c_void,
        register_buffer: register_buffer as *const c_void,
        resize_completion_queue: resize_completion_queue as *const c_void,
        resize_request_queue: resize_request_queue as *const c_void,
    }
}

unsafe impl Send for RioBuffer {}
unsafe impl Sync for RioBuffer {}
unsafe impl Send for RioCompletionQueue {}
unsafe impl Sync for RioCompletionQueue {}
unsafe impl Send for RioRequestQueue {}
unsafe impl Sync for RioRequestQueue {}

pub unsafe extern "system" fn register_buffer(data: *mut i8, length: u32) -> BufferId {
    if data.is_null() || length == 0 {
        return usize::MAX as BufferId;
    }
    let buffer = Box::into_raw(Box::new(RioBuffer { _token: 0 }));
    if let Ok(mut registered) = buffers().lock() {
        registered.insert(buffer as usize, (data as usize, length as usize));
        buffer
    } else {
        drop(Box::from_raw(buffer));
        usize::MAX as BufferId
    }
}

pub unsafe extern "system" fn deregister_buffer(id: BufferId) {
    if !id.is_null()
        && id as usize != usize::MAX
        && buffers()
            .lock()
            .ok()
            .and_then(|mut registered| registered.remove(&(id as usize)))
            .is_some()
    {
        drop(Box::from_raw(id));
    }
}

pub unsafe extern "system" fn create_completion_queue(
    size: u32,
    _notification: *mut RioNotificationCompletion,
) -> CompletionQueue {
    if size == 0 {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new(RioCompletionQueue {
        results: Mutex::new(VecDeque::with_capacity(size.min(4096) as usize)),
        notification: if _notification.is_null() {
            None
        } else {
            Some(*_notification)
        },
        _capacity: size,
    }))
}

pub unsafe extern "system" fn close_completion_queue(queue: CompletionQueue) {
    if !queue.is_null() {
        drop(Box::from_raw(queue));
    }
}

pub unsafe extern "system" fn create_request_queue(
    socket: usize,
    _max_outstanding_receive: u32,
    _max_receive_data_buffers: u32,
    _max_outstanding_send: u32,
    _max_send_data_buffers: u32,
    receive: CompletionQueue,
    send: CompletionQueue,
    context: *mut c_void,
) -> RequestQueue {
    if receive.is_null() || send.is_null() || socket == 0 {
        return ptr::null_mut();
    }
    let queue = Box::into_raw(Box::new(RioRequestQueue {
        socket,
        receive,
        send,
        context: context as usize as u64,
    }));
    if let Ok(mut queues) = request_queues().lock() {
        queues.entry(socket).or_default().push(queue as usize);
    }
    queue
}

/// Reclaim request queues when the owning Winsock socket is closed.
pub unsafe fn forget_socket(socket: usize) {
    let queues = request_queues()
        .lock()
        .ok()
        .and_then(|mut queues| queues.remove(&socket));
    if let Some(queues) = queues {
        for queue in queues {
            drop(Box::from_raw(queue as RequestQueue));
        }
    }
}

unsafe fn signal(queue: &RioCompletionQueue) {
    let Some(notification) = queue.notification else {
        return;
    };
    match notification.kind {
        1 => {
            let _ = SetEvent(HANDLE(notification.payload[0] as isize));
        }
        2 => {
            let _ = PostQueuedCompletionStatus(
                HANDLE(notification.payload[0] as isize),
                0,
                notification.payload[1],
                Some(notification.payload[2] as *mut OVERLAPPED),
            );
        }
        _ => {}
    }
}

pub unsafe extern "system" fn notify(queue: CompletionQueue) -> i32 {
    if queue.is_null() {
        return -1;
    }
    if (*queue).results.lock().is_ok_and(|results| !results.is_empty()) {
        signal(&*queue);
    }
    0
}

pub unsafe extern "system" fn resize_completion_queue(_queue: CompletionQueue, _size: u32) -> i32 {
    1
}

pub unsafe extern "system" fn resize_request_queue(
    _queue: RequestQueue,
    _max_receive: u32,
    _max_send: u32,
) -> i32 {
    1
}

unsafe fn gather(descriptors: *const RioBuf, count: u32) -> Option<Vec<u8>> {
    if descriptors.is_null() || count == 0 || count > 1024 {
        return None;
    }
    let mut output = Vec::new();
    for item in std::slice::from_raw_parts(descriptors, count as usize) {
        if item.buffer_id.is_null() || item.buffer_id as usize == usize::MAX {
            return None;
        }
        let (base, length) = buffers()
            .lock()
            .ok()
            .and_then(|registered| registered.get(&(item.buffer_id as usize)).copied())?;
        let end = (item.offset as usize).checked_add(item.length as usize)?;
        if end > length {
            return None;
        }
        let part = std::slice::from_raw_parts(
            (base as *const u8).add(item.offset as usize),
            item.length as usize,
        );
        output.extend_from_slice(part);
    }
    Some(output)
}

unsafe fn scatter(descriptors: *const RioBuf, count: u32, payload: &[u8]) -> Option<u32> {
    if descriptors.is_null() || count == 0 || count > 1024 {
        return None;
    }
    let mut copied = 0usize;
    for item in std::slice::from_raw_parts(descriptors, count as usize) {
        if item.buffer_id.is_null() || item.buffer_id as usize == usize::MAX {
            return None;
        }
        let (base, length) = buffers()
            .lock()
            .ok()
            .and_then(|registered| registered.get(&(item.buffer_id as usize)).copied())?;
        let end = (item.offset as usize).checked_add(item.length as usize)?;
        if end > length {
            return None;
        }
        let amount = (item.length as usize).min(payload.len().saturating_sub(copied));
        if amount != 0 {
            ptr::copy_nonoverlapping(
                payload.as_ptr().add(copied),
                (base as *mut u8).add(item.offset as usize),
                amount,
            );
            copied += amount;
        }
        if copied == payload.len() {
            break;
        }
    }
    Some(copied as u32)
}

unsafe fn push(queue: CompletionQueue, result: RioResult) {
    if !queue.is_null() {
        if let Ok(mut results) = (*queue).results.lock() {
            results.push_back(result);
        }
    }
}

pub unsafe extern "system" fn send(
    queue: RequestQueue,
    buffers: *const RioBuf,
    count: u32,
    flags: u32,
    context: *mut c_void,
) -> i32 {
    send_with_address(queue, buffers, count, flags, context, None)
}

unsafe fn send_with_address(
    queue: RequestQueue,
    buffers: *const RioBuf,
    count: u32,
    flags: u32,
    context: *mut c_void,
    address: Option<std::net::SocketAddr>,
) -> i32 {
    if queue.is_null() {
        return 0;
    }
    let request = &*queue;
    let data = match gather(buffers, count) {
        Some(data) => data,
        None => return 0,
    };
    let result = match udp::send(request.socket, &data, address, flags as i32) {
        Some(Ok(bytes)) => RioResult {
            status: 0,
            bytes_transferred: bytes as u32,
            socket_context: request.context,
            request_context: context as usize as u64,
        },
        Some(Err(error)) => RioResult {
            status: error.raw_os_error().unwrap_or(10053),
            bytes_transferred: 0,
            socket_context: request.context,
            request_context: context as usize as u64,
        },
        None => RioResult {
            status: 10045,
            bytes_transferred: 0,
            socket_context: request.context,
            request_context: context as usize as u64,
        },
    };
    push(request.send, result);
    BOOL(1).0
}

pub unsafe extern "system" fn send_ex(
    queue: RequestQueue,
    buffers: *const RioBuf,
    count: u32,
    _local: *const RioBuf,
    _remote: *const RioBuf,
    _control: *const RioBuf,
    _flags: *const RioBuf,
    flags: u32,
    context: *mut c_void,
) -> i32 {
    let address = if _remote.is_null() {
        None
    } else {
        let bytes = match gather(_remote, 1) {
            Some(bytes) => bytes,
            None => return 0,
        };
        udp::parse_address(bytes.as_ptr().cast(), bytes.len())
    };
    send_with_address(queue, buffers, count, flags, context, address)
}

pub unsafe extern "system" fn receive(
    queue: RequestQueue,
    buffers: *const RioBuf,
    count: u32,
    flags: u32,
    context: *mut c_void,
) -> i32 {
    receive_with_address(queue, buffers, count, flags, context, None)
}

unsafe fn receive_with_address(
    queue: RequestQueue,
    buffers: *const RioBuf,
    count: u32,
    flags: u32,
    context: *mut c_void,
    remote: Option<*const RioBuf>,
) -> i32 {
    if queue.is_null() {
        return 0;
    }
    let request = &*queue;
    let result = match udp::receive(request.socket, flags as i32) {
        Some(Ok(received)) => match scatter(buffers, count, &received.payload) {
            Some(bytes) => {
                let address_ok = remote.is_none_or(|remote| {
                    let address = socket2::SockAddr::from(received.source);
                    scatter(
                        remote,
                        1,
                        std::slice::from_raw_parts(
                            address.as_ptr().cast::<u8>(),
                            address.len() as usize,
                        ),
                    )
                    .is_some()
                });
                RioResult {
                    status: if address_ok { 0 } else { 10014 },
                    bytes_transferred: if address_ok { bytes } else { 0 },
                    socket_context: request.context,
                    request_context: context as usize as u64,
                }
            }
            None => RioResult {
                status: 10014,
                bytes_transferred: 0,
                socket_context: request.context,
                request_context: context as usize as u64,
            },
        },
        Some(Err(error)) => RioResult {
            status: error.raw_os_error().unwrap_or(10053),
            bytes_transferred: 0,
            socket_context: request.context,
            request_context: context as usize as u64,
        },
        None => RioResult {
            status: 10045,
            bytes_transferred: 0,
            socket_context: request.context,
            request_context: context as usize as u64,
        },
    };
    push(request.receive, result);
    BOOL(1).0
}

pub unsafe extern "system" fn receive_ex(
    queue: RequestQueue,
    buffers: *const RioBuf,
    count: u32,
    _local: *const RioBuf,
    _remote: *const RioBuf,
    _control: *const RioBuf,
    _flags: *const RioBuf,
    flags: u32,
    context: *mut c_void,
) -> i32 {
    receive_with_address(
        queue,
        buffers,
        count,
        flags,
        context,
        (!_remote.is_null()).then_some(_remote),
    )
}

pub unsafe extern "system" fn dequeue(
    queue: CompletionQueue,
    output: *mut RioResult,
    count: u32,
) -> u32 {
    if queue.is_null() || output.is_null() || count == 0 {
        return 0;
    }
    let Ok(mut results) = (*queue).results.lock() else {
        return 0;
    };
    let mut copied = 0;
    while copied < count {
        let Some(result) = results.pop_front() else {
            break;
        };
        *output.add(copied as usize) = result;
        copied += 1;
    }
    copied
}
