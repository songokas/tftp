//! The library's socket traits on top of `std::net`.

use std::io;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::time::Duration;

use tftp_dus::error::BoxedResult;
use tftp_dus::socket::BoundSocket;
use tftp_dus::socket::Socket;
use tftp_dus::socket::SocketRawFd;
use tftp_dus::socket::ToSocketId;
use tftp_dus::types::DataBuffer;

/// lwIP truncates timeouts to milliseconds and treats 0 as waiting forever.
const MIN_WAIT: Duration = Duration::from_millis(1);

/// Applies a wait to the socket, skipping the system calls when it is unchanged.
struct Waiter {
    current: Option<Duration>,
}

impl Waiter {
    fn new(socket: &UdpSocket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self { current: None })
    }

    fn apply(&mut self, socket: &UdpSocket, wait_for: Option<Duration>) -> io::Result<()> {
        let wait_for = wait_for.filter(|d| !d.is_zero()).map(|d| d.max(MIN_WAIT));
        if wait_for == self.current {
            return Ok(());
        }
        match wait_for {
            Some(_) => {
                socket.set_read_timeout(wait_for)?;
                if self.current.is_none() {
                    socket.set_nonblocking(false)?;
                }
            }
            None => socket.set_nonblocking(true)?,
        }
        self.current = wait_for;
        Ok(())
    }
}

pub struct UdpListenSocket {
    socket: UdpSocket,
    socket_id: usize,
    waiter: Waiter,
}

pub struct UdpClientSocket {
    socket: UdpSocket,
    socket_id: usize,
    waiter: Waiter,
}

pub fn create_socket(listen: SocketAddr, socket_id: usize) -> BoxedResult<UdpListenSocket> {
    let socket = UdpSocket::bind(listen)?;
    let waiter = Waiter::new(&socket)?;
    Ok(UdpListenSocket {
        socket,
        socket_id,
        waiter,
    })
}

pub fn create_bound_socket(
    listen: SocketAddr,
    socket_id: usize,
    client: SocketAddr,
) -> BoxedResult<UdpClientSocket> {
    let socket = UdpSocket::bind(listen)?;
    socket.connect(client)?;
    let waiter = Waiter::new(&socket)?;
    Ok(UdpClientSocket {
        socket,
        socket_id,
        waiter,
    })
}

impl Socket for UdpListenSocket {
    fn recv_from(
        &mut self,
        buffer: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> io::Result<(usize, SocketAddr)> {
        self.waiter.apply(&self.socket, wait_for)?;
        self.socket.recv_from(buffer)
    }

    fn send_to(&self, buffer: &mut DataBuffer, address: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buffer, address)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    // Only the single threaded server polls sockets
    fn modify_interest(&mut self, _socket_id: usize, _raw_fd: SocketRawFd) -> io::Result<()> {
        Ok(())
    }
}

impl BoundSocket for UdpClientSocket {
    fn recv(&mut self, buffer: &mut DataBuffer, wait_for: Option<Duration>) -> io::Result<usize> {
        self.waiter.apply(&self.socket, wait_for)?;
        self.socket.recv(buffer)
    }

    fn send(&self, buffer: &mut DataBuffer) -> io::Result<usize> {
        self.socket.send(buffer)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl ToSocketId for UdpListenSocket {
    fn as_raw_fd(&self) -> SocketRawFd {
        self.socket.as_raw_fd()
    }

    fn socket_id(&self) -> usize {
        self.socket_id
    }
}

impl ToSocketId for UdpClientSocket {
    fn as_raw_fd(&self) -> SocketRawFd {
        self.socket.as_raw_fd()
    }

    fn socket_id(&self) -> usize {
        self.socket_id
    }
}
