use core::num::NonZeroUsize;
use core::time::Duration;
use std::collections::HashSet;
use std::net::SocketAddr as StdSocketAddr;
use std::net::ToSocketAddrs;
use std::net::UdpSocket;
#[cfg(not(target_family = "windows"))]
use std::os::fd::AsFd;
#[cfg(not(target_family = "windows"))]
use std::os::fd::AsRawFd;
#[cfg(target_family = "windows")]
use std::os::windows::io::AsRawSocket;

use log::*;
use polling::Event;
use polling::Events;
use polling::Poller;
// use polling::Source;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket as Socket2;
use socket2::Type;
use tftp::error::BoxedResult;
use tftp::socket::*;
use tftp::std_compat::io;
use tftp::std_compat::net::SocketAddr;
use tftp::types::DataBuffer;

use crate::macros::cfg_no_std;
use crate::std_compat::io::from_io_err;

cfg_no_std! {
    use tftp::std_compat::net::IpVersion;
    use std::net::SocketAddrV4;
    use std::net::SocketAddrV6;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;
}

pub fn create_socket(
    listen: &str,
    socket_id: usize,
    reuse: bool,
    capacity: usize,
) -> BoxedResult<impl Socket> {
    let address: StdSocketAddr = listen
        .to_socket_addrs()
        .map_err(|e| {
            error!("Socket parse error: {e}");
            io::Error::from(io::ErrorKind::AddrNotAvailable)
        })?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
    let socket = Socket2::new(
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
    unsafe {
        poller
            .add(&socket, Event::readable(socket_id))
            .map_err(from_io_err)?;
    }

    let events = Events::with_capacity(NonZeroUsize::new(capacity).expect("not empty capacity"));
    let notified = HashSet::with_capacity(capacity);

    let socket = UdpUnboundSocket {
        socket,
        poller,
        socket_id,
        events,
        notified,
    };
    Ok(socket)
}

pub fn create_bound_socket(
    listen: &str,
    socket_id: usize,
    endpoint: SocketAddr,
) -> BoxedResult<impl BoundSocket> {
    let endpoint = socket_addr_to_std(endpoint);
    let socket = Socket2::new(
        Domain::for_address(endpoint),
        Type::DGRAM,
        Protocol::UDP.into(),
    )
    .map_err(from_io_err)?;

    socket.set_reuse_address(true).map_err(from_io_err)?;
    #[cfg(not(target_family = "windows"))]
    socket.set_reuse_port(true).map_err(from_io_err)?;

    let address: StdSocketAddr = listen
        .parse()
        .map_err(|_| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
    socket.bind(&address.into()).map_err(from_io_err)?;

    let socket: UdpSocket = socket.into();
    socket.set_nonblocking(true).map_err(from_io_err)?;
    socket.connect(endpoint).map_err(from_io_err)?;
    let poller = Poller::new().map_err(from_io_err)?;
    unsafe {
        poller
            .add(&socket, Event::readable(socket_id))
            .map_err(from_io_err)?;
    }
    let socket = UdpBoundSocket {
        socket,
        poller,
        socket_id,
        // TODO alloc in stack
        events: Events::with_capacity(NonZeroUsize::new(1).unwrap()),
    };
    Ok(socket)
}

pub struct UdpUnboundSocket {
    socket: UdpSocket,
    poller: Poller,
    socket_id: usize,
    // TODO alloc in stack
    events: Events,
    notified: HashSet<usize>,
    //
}

impl Socket for UdpUnboundSocket {
    fn recv_from(
        &mut self,
        buff: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> io::Result<(usize, SocketAddr)> {
        self.events.clear();
        self.modify_interest(self.socket_id(), self.as_raw_fd())?;
        self.poller
            .wait(&mut self.events, wait_for.or_else(|| Duration::ZERO.into()))
            .map_err(from_io_err)?;
        self.notified.extend(self.events.iter().map(|e| e.key));

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

    #[cfg(not(feature = "multi_thread"))]
    fn notified(&self, socket: &impl ToSocketId) -> bool {
        self.notified.contains(&socket.socket_id())
    }

    #[cfg(not(feature = "multi_thread"))]
    fn add_interest(&self, socket: &impl ToSocketId) -> io::Result<()> {
        unsafe {
            self.poller
                .add(socket.as_raw_fd(), Event::readable(socket.socket_id()))
                .map_err(from_io_err)
        }
    }

    fn modify_interest(&mut self, socket_id: usize, raw_fd: SocketRawFd) -> io::Result<()> {
        self.notified.remove(&socket_id);
        self.poller
            .modify(
                #[cfg(target_family = "windows")]
                unsafe {
                    std::os::windows::io::BorrowedSocket::borrow_raw(raw_fd)
                },
                #[cfg(not(target_family = "windows"))]
                unsafe {
                    std::os::fd::BorrowedFd::borrow_raw(raw_fd.as_raw_fd())
                },
                Event::readable(socket_id),
            )
            .map_err(from_io_err)
    }
}

impl ToSocketId for UdpUnboundSocket {
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

pub struct UdpBoundSocket {
    socket: UdpSocket,
    poller: Poller,
    socket_id: usize,
    events: Events,
}

impl BoundSocket for UdpBoundSocket {
    fn recv(&mut self, buff: &mut DataBuffer, wait_for: Option<Duration>) -> io::Result<usize> {
        if let Some(d) = wait_for {
            self.poller
                .modify(&self.socket, Event::readable(self.socket_id))
                .map_err(from_io_err)?;
            self.events.clear();
            self.poller
                .wait(&mut self.events, d.into())
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

impl ToSocketId for UdpBoundSocket {
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
pub fn std_to_socket_addr(addr: StdSocketAddr) -> SocketAddr {
    match addr {
        StdSocketAddr::V4(a) => SocketAddr {
            ip: IpVersion::Ipv4(a.ip().octets()),
            port: a.port(),
        },
        StdSocketAddr::V6(a) => SocketAddr {
            ip: IpVersion::Ipv6(a.ip().octets()),
            port: a.port(),
        },
    }
}

pub fn socket_addr_to_std(addr: SocketAddr) -> StdSocketAddr {
    #[cfg(feature = "std")]
    return addr;
    #[cfg(not(feature = "std"))]
    match addr.ip {
        IpVersion::Ipv4(b) => StdSocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(b), addr.port)),
        IpVersion::Ipv6(b) => {
            StdSocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(b), addr.port, 0, 0))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn test_receive_wait_for() {
        let mut socket_r = create_socket("127.0.0.1:9000", 1, false, 1).unwrap();
        let socket_s = create_socket("127.0.0.1:0", 0, false, 1).unwrap();
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
