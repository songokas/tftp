use core::cell::Cell;
use core::net::SocketAddr;
use core::time::Duration;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;

use log::trace;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket as Socket2;
use socket2::Type;
use tftp_dus::config::MAX_CLIENTS;
use tftp_dus::error::BoxedResult;
use tftp_dus::socket::BoundSocket;
use tftp_dus::socket::Socket;
use tftp_dus::socket::SocketRawFd;
use tftp_dus::socket::ToSocketId;
use tftp_dus::std_compat::io;
use tftp_dus::types::DataBuffer;

use crate::error::from_io_err;
use crate::poller::wait_readable;
use crate::poller::Poller;

// every client holds a socket and a file open, plus the process's own descriptors
const FD_SET_WORDS: usize = {
    let needed = (MAX_CLIENTS as usize * 2 + 64) / u64::BITS as usize + 1;
    if needed < 16 {
        16
    } else {
        needed
    }
};
const FD_SET_BITS: i32 = (FD_SET_WORDS * u64::BITS as usize) as i32;

/// Notified sockets are tracked by file descriptor, not socket id: ids grow
/// forever, while a closed descriptor's stale bit is cleared when it is reused.
struct FdSet {
    words: [Cell<u64>; FD_SET_WORDS],
}

impl FdSet {
    fn new() -> Self {
        Self {
            words: core::array::from_fn(|_| Cell::new(0)),
        }
    }

    fn position(fd: i32) -> Option<(usize, u64)> {
        (0..FD_SET_BITS).contains(&fd).then(|| {
            (
                (fd as usize) / u64::BITS as usize,
                1 << (fd as u32 % u64::BITS),
            )
        })
    }

    fn insert(&self, fd: i32) {
        if let Some((word, bit)) = Self::position(fd) {
            self.words[word].set(self.words[word].get() | bit);
        }
    }

    fn remove(&self, fd: i32) {
        if let Some((word, bit)) = Self::position(fd) {
            self.words[word].set(self.words[word].get() & !bit);
        }
    }

    #[cfg_attr(feature = "multi_thread", allow(dead_code))]
    fn contains(&self, fd: i32) -> bool {
        Self::position(fd).is_some_and(|(word, bit)| self.words[word].get() & bit != 0)
    }
}

fn new_socket(address: SocketAddr, reuse: bool) -> io::Result<Socket2> {
    let socket = Socket2::new(
        Domain::for_address(address),
        Type::DGRAM,
        Protocol::UDP.into(),
    )
    .map_err(from_io_err)?;
    socket.set_reuse_address(reuse).map_err(from_io_err)?;
    socket.set_reuse_port(reuse).map_err(from_io_err)?;
    Ok(socket)
}

pub fn create_socket(
    address: SocketAddr,
    socket_id: usize,
    reuse: bool,
    _capacity: usize,
) -> BoxedResult<UdpUnboundSocket> {
    let socket = new_socket(address, reuse)?;
    socket.bind(&address.into()).map_err(from_io_err)?;
    socket.set_nonblocking(true).map_err(from_io_err)?;

    let socket = UdpUnboundSocket {
        socket: socket.into(),
        poller: Poller::new()?,
        socket_id,
        notified: FdSet::new(),
    };
    socket.poller.add(socket.fd())?;
    Ok(socket)
}

pub fn create_bound_socket(
    listen: SocketAddr,
    socket_id: usize,
    endpoint: SocketAddr,
) -> BoxedResult<UdpBoundSocket> {
    let socket = new_socket(endpoint, true)?;
    socket.bind(&listen.into()).map_err(from_io_err)?;
    socket.set_nonblocking(true).map_err(from_io_err)?;
    socket.connect(&endpoint.into()).map_err(from_io_err)?;
    Ok(UdpBoundSocket {
        socket: socket.into(),
        socket_id,
    })
}

pub struct UdpUnboundSocket {
    socket: UdpSocket,
    poller: Poller,
    socket_id: usize,
    notified: FdSet,
}

impl UdpUnboundSocket {
    fn fd(&self) -> i32 {
        AsRawFd::as_raw_fd(&self.socket)
    }
}

impl Socket for UdpUnboundSocket {
    fn recv_from(
        &mut self,
        buff: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> io::Result<(usize, SocketAddr)> {
        self.modify_interest(self.socket_id, self.fd())?;
        self.poller.wait(wait_for.unwrap_or(Duration::ZERO), |fd| {
            self.notified.insert(fd)
        })?;
        let (size, client) = self.socket.recv_from(buff).map_err(from_io_err)?;
        trace!("Received from {client} {size} {:x?}", buff);
        Ok((size, client))
    }

    fn send_to(&self, buff: &mut DataBuffer, client: SocketAddr) -> io::Result<usize> {
        trace!("Send to {client} {} {:x?}", buff.len(), buff);
        self.socket.send_to(buff, client).map_err(from_io_err)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr().map_err(from_io_err)
    }

    #[cfg(not(feature = "multi_thread"))]
    fn notified(&self, socket: &impl ToSocketId) -> bool {
        self.notified.contains(socket.as_raw_fd())
    }

    #[cfg(not(feature = "multi_thread"))]
    fn add_interest(&self, socket: &impl ToSocketId) -> io::Result<()> {
        let fd = socket.as_raw_fd();
        if FdSet::position(fd).is_none() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        self.notified.remove(fd);
        self.poller.add(fd)
    }

    fn modify_interest(&mut self, _socket_id: usize, raw_fd: SocketRawFd) -> io::Result<()> {
        self.notified.remove(raw_fd);
        self.poller.rearm(raw_fd)
    }
}

impl ToSocketId for UdpUnboundSocket {
    fn as_raw_fd(&self) -> SocketRawFd {
        self.fd()
    }

    fn socket_id(&self) -> usize {
        self.socket_id
    }
}

pub struct UdpBoundSocket {
    socket: UdpSocket,
    socket_id: usize,
}

impl BoundSocket for UdpBoundSocket {
    fn recv(&mut self, buff: &mut DataBuffer, wait_for: Option<Duration>) -> io::Result<usize> {
        if let Some(wait) = wait_for {
            wait_readable(AsRawFd::as_raw_fd(&self.socket), wait)?;
        }
        self.socket.recv(buff).map_err(from_io_err)
    }

    fn send(&self, buff: &mut DataBuffer) -> io::Result<usize> {
        self.socket.send(buff).map_err(from_io_err)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr().map_err(from_io_err)
    }
}

impl ToSocketId for UdpBoundSocket {
    fn as_raw_fd(&self) -> SocketRawFd {
        AsRawFd::as_raw_fd(&self.socket)
    }

    fn socket_id(&self) -> usize {
        self.socket_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fd_set() {
        let set = FdSet::new();
        for fd in [0, 63, 64, FD_SET_BITS - 1] {
            assert!(!set.contains(fd));
            set.insert(fd);
            assert!(set.contains(fd));
            set.remove(fd);
            assert!(!set.contains(fd));
        }
    }

    #[test]
    fn test_fd_set_ignores_out_of_range() {
        let set = FdSet::new();
        for fd in [-1, FD_SET_BITS] {
            set.insert(fd);
            assert!(!set.contains(fd));
            assert!(FdSet::position(fd).is_none());
        }
    }
}
