use core::time::Duration;
use std::net::UdpSocket;

#[cfg(not(target_family = "windows"))]
use std::os::fd::{AsFd, AsRawFd, RawFd};
#[cfg(target_family = "windows")]
use std::os::windows::io::{AsRawSocket, RawSocket};

use log::{info, trace};
use polling::{Event, Poller, Source};
use socket2::{Domain, Protocol, SockAddr, Type};
use tftp::{
    config::ConnectionOptions,
    encryption::EncryptionLevel,
    error::BoxedResult,
    socket::*,
    std_compat::{io, net::SocketAddr},
    types::DataBuffer,
};

use crate::{
    cli::{BinError, BinResult, ClientCliConfig},
    io::from_io_err,
};

pub fn create_socket(listen: &str, socket_id: usize, reuse: bool) -> BoxedResult<impl Socket> {
    let address: std::net::SocketAddr = listen
        .parse()
        .map_err(|_| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
    let socket = socket2::Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Protocol::UDP.into(),
    )
    .map_err(from_io_err)?;

    socket.set_reuse_address(reuse).map_err(from_io_err)?;
    #[cfg(not(target_family = "windows"))]
    socket.set_reuse_port(reuse).map_err(from_io_err)?;
    socket.bind(&address.into()).map_err(from_io_err)?;

    let socket: UdpSocket = socket.into();
    socket.set_nonblocking(true).map_err(from_io_err)?;

    let poller = Poller::new().map_err(from_io_err)?;
    poller
        .add(&socket, Event::readable(socket_id))
        .map_err(from_io_err)?;
    let socket = StdSocket {
        socket,
        poller,
        socket_id,
        events: Vec::new(),
    };
    Ok(socket)
}

pub fn create_bound_socket(
    listen: &str,
    socket_id: usize,
    endpoint: SocketAddr,
) -> BoxedResult<impl BoundSocket> {
    let endpoint = socket_addr_to_std(endpoint);
    let socket = socket2::Socket::new(
        Domain::for_address(endpoint),
        Type::DGRAM,
        Protocol::UDP.into(),
    )
    .map_err(from_io_err)?;

    socket.set_reuse_address(true).map_err(from_io_err)?;
    #[cfg(not(target_family = "windows"))]
    socket.set_reuse_port(true).map_err(from_io_err)?;

    let address: std::net::SocketAddr = listen
        .parse()
        .map_err(|_| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
    socket.bind(&address.into()).unwrap();

    let socket: UdpSocket = socket.into();
    socket.set_nonblocking(true).map_err(from_io_err)?;
    socket.connect(endpoint).map_err(from_io_err)?;
    let poller = Poller::new().map_err(from_io_err)?;
    poller
        .add(&socket, Event::readable(socket_id))
        .map_err(from_io_err)?;
    let socket = StdBoundSocket {
        socket,
        poller,
        socket_id,
    };
    Ok(socket)
}

pub struct StdSocket {
    socket: UdpSocket,
    poller: Poller,
    socket_id: usize,
    // TODO alloc in stack
    events: Vec<Event>,
}

impl Socket for StdSocket {
    fn recv_from(
        &mut self,
        buff: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> io::Result<(usize, SocketAddr)> {
        self.modify_interest(self.socket_id(), self.as_raw_fd())?;
        self.poller
            .wait(&mut self.events, wait_for.or_else(|| Duration::ZERO.into()))
            .map_err(from_io_err)?;

        #[cfg(feature = "std")]
        let result = self.socket.recv_from(buff);
        #[cfg(not(feature = "std"))]
        let result = self
            .socket
            .recv_from(buff)
            .map(|(b, s)| (b, std_to_socket_addr(s)))
            .map_err(from_io_err);
        if let Ok((size, client)) = result.as_ref() {
            trace!("Received from {client} {size} {:x?}", buff);
        }
        result
    }

    fn send_to(&self, buff: &mut DataBuffer, client: SocketAddr) -> io::Result<usize> {
        #[cfg(feature = "std")]
        let result = self.socket.send_to(buff, client);
        #[cfg(not(feature = "std"))]
        let result = self
            .socket
            .send_to(&buff, socket_addr_to_std(client))
            .map_err(from_io_err);
        trace!("Send to {client} {} {:x?}", buff.len(), buff);
        result
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        #[cfg(feature = "std")]
        return self.socket.local_addr();
        #[cfg(not(feature = "std"))]
        self.socket
            .local_addr()
            .map(|s| std_to_socket_addr(s))
            .map_err(from_io_err)
    }

    fn notified(&self, socket: &impl ToSocketId) -> bool {
        self.events.iter().any(|e| e.key == socket.socket_id())
    }

    fn add_interest(&self, socket: &impl ToSocketId) -> io::Result<()> {
        self.poller
            .add(
                RawCInt(socket.as_raw_fd()),
                Event::readable(socket.socket_id()),
            )
            .map_err(from_io_err)
    }

    fn modify_interest(&mut self, socket_id: usize, raw_fd: SocketRawFd) -> io::Result<()> {
        self.events.retain(|e| e.key != socket_id);
        self.poller
            .modify(RawCInt(raw_fd), Event::readable(socket_id))
            .map_err(from_io_err)
    }
}

#[cfg(target_family = "windows")]
struct RawCInt(u64);

#[cfg(target_family = "windows")]
impl Source for RawCInt {
    fn raw(&self) -> RawSocket {
        self.0 as RawSocket
    }
}

#[cfg(not(target_family = "windows"))]
struct RawCInt(i32);

#[cfg(not(target_family = "windows"))]
impl Source for RawCInt {
    fn raw(&self) -> RawFd {
        self.0 as RawFd
    }
}

impl ToSocketId for StdSocket {
    fn as_raw_fd(&self) -> SocketRawFd {
        #[cfg(target_family = "windows")]
        return self.socket.as_raw_socket();
        #[cfg(not(target_family = "windows"))]
        self.socket.as_fd().as_raw_fd()
    }

    fn socket_id(&self) -> usize {
        self.socket_id
    }
}

pub struct StdBoundSocket {
    socket: UdpSocket,
    poller: Poller,
    socket_id: usize,
}

impl BoundSocket for StdBoundSocket {
    fn recv(&self, buff: &mut DataBuffer, wait_for: Option<Duration>) -> io::Result<usize> {
        if let Some(d) = wait_for {
            self.poller
                .modify(&self.socket, Event::readable(self.socket_id))
                .map_err(from_io_err)?;
            // TODO alloc in stack
            let mut events = Vec::new();
            self.poller
                .wait(&mut events, d.into())
                .map_err(from_io_err)?;
        }
        self.socket.recv(buff).map_err(from_io_err)
    }

    fn send(&self, buff: &mut DataBuffer) -> io::Result<usize> {
        self.socket.send(buff).map_err(from_io_err)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        #[cfg(feature = "std")]
        return self.socket.local_addr();
        #[cfg(not(feature = "std"))]
        self.socket
            .local_addr()
            .map(|s| std_to_socket_addr(s))
            .map_err(from_io_err)
    }
}

impl ToSocketId for StdBoundSocket {
    fn as_raw_fd(&self) -> SocketRawFd {
        #[cfg(target_family = "windows")]
        return self.socket.as_raw_socket();
        #[cfg(not(target_family = "windows"))]
        self.socket.as_fd().as_raw_fd()
    }

    fn socket_id(&self) -> usize {
        self.socket_id
    }
}

#[cfg(not(feature = "std"))]
pub fn std_to_socket_addr(addr: std::net::SocketAddr) -> SocketAddr {
    match addr {
        std::net::SocketAddr::V4(a) => SocketAddr {
            ip: tftp::std_compat::net::IpVersion::Ipv4(a.ip().octets()),
            port: a.port(),
        },
        std::net::SocketAddr::V6(a) => SocketAddr {
            ip: tftp::std_compat::net::IpVersion::Ipv6(a.ip().octets()),
            port: a.port(),
        },
    }
}

pub fn socket_addr_to_std(addr: SocketAddr) -> std::net::SocketAddr {
    #[cfg(feature = "std")]
    return addr;
    #[cfg(not(feature = "std"))]
    match addr.ip {
        tftp::std_compat::net::IpVersion::Ipv4(b) => std::net::SocketAddr::V4(
            std::net::SocketAddrV4::new(std::net::Ipv4Addr::from(b), addr.port),
        ),
        tftp::std_compat::net::IpVersion::Ipv6(b) => std::net::SocketAddr::V6(
            std::net::SocketAddrV6::new(std::net::Ipv6Addr::from(b), addr.port, 0, 0),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn test_receive_wait_for() {
        let mut socket_r = create_socket("127.0.0.1:9000", 1, false).unwrap();
        let socket_s = create_socket("127.0.0.1:0", 0, false).unwrap();
        let mut buf = DataBuffer::new();
        #[allow(unused_must_use)]
        {
            buf.resize(100, 0);
        }

        let now = Instant::now();
        let wait_for = Duration::from_millis(30);
        let result = socket_r.recv_from(&mut buf, wait_for.into());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(now.elapsed() >= wait_for);

        let now = Instant::now();
        let wait_for = Duration::from_micros(30);
        let result = socket_r.recv_from(&mut buf, wait_for.into());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(now.elapsed() >= wait_for);

        let now = Instant::now();
        let wait_for = Duration::from_micros(30);
        let result = socket_r.recv_from(&mut buf, None);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(now.elapsed() < wait_for);

        let mut send_buf = DataBuffer::new();
        let addr: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();
        #[cfg(not(feature = "std"))]
        let addr = std_to_socket_addr(addr);
        socket_s.send_to(&mut send_buf, addr).unwrap();
        let now = Instant::now();
        let wait_for = Duration::from_secs(2);
        let result = socket_r.recv_from(&mut buf, wait_for.into());
        assert!(result.is_ok());
        assert!(now.elapsed() < wait_for);

        let now = Instant::now();
        let wait_for = Duration::from_micros(15);
        let result = socket_r.recv_from(&mut buf, None);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(now.elapsed() < wait_for);
    }
}
