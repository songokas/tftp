use core::net::IpAddr;
use core::net::Ipv4Addr;
use core::net::Ipv6Addr;
use core::net::SocketAddr;
use core::num::NonZeroUsize;
use core::time::Duration;
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
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket as Socket2;
use socket2::Type;
use tftp_dus::config::MAX_CLIENTS;
use tftp_dus::error::BoxedResult;
use tftp_dus::map::Map;
use tftp_dus::socket::*;
use tftp_dus::std_compat::io;
use tftp_dus::types::DataBuffer;

use crate::std_compat::io::from_io_err;

pub fn obtain_listen_socket(listen: &str) -> BoxedResult<SocketAddr> {
    let address = listen
        .to_socket_addrs()
        .map_err(|e| {
            error!("Socket parse error: {e}");
            io::Error::from(io::ErrorKind::AddrNotAvailable)
        })?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
    Ok(address)
}

pub fn obtain_listen_socket_based_on_endpoint(endpoint: &str) -> BoxedResult<SocketAddr> {
    let endpoints_addresses = endpoint.to_socket_addrs().map_err(|e| {
        error!("Invalid endpoint address={endpoint}: {e}");
        io::Error::from(io::ErrorKind::AddrNotAvailable)
    })?;

    for listen in endpoints_addresses {
        if listen.is_ipv4() {
            return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        }
        if listen.is_ipv6() {
            return Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0));
        }
    }
    error!("Could not find listen address based on endpoint={endpoint}");
    Err(io::Error::from(io::ErrorKind::AddrNotAvailable).into())
}

pub fn create_socket(
    address: SocketAddr,
    socket_id: usize,
    _reuse: bool,
    capacity: usize,
) -> BoxedResult<impl Socket> {
    let socket = Socket2::new(
        Domain::for_address(address),
        Type::DGRAM,
        Protocol::UDP.into(),
    )
    .map_err(from_io_err)?;

    #[cfg(not(target_family = "windows"))]
    socket.set_reuse_address(_reuse).map_err(from_io_err)?;
    #[cfg(not(target_family = "windows"))]
    socket.set_reuse_port(_reuse).map_err(from_io_err)?;
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

    let socket = UdpUnboundSocket {
        socket,
        poller,
        socket_id,
        events,
        notified: Map::new(),
    };
    Ok(socket)
}

pub fn create_bound_socket(
    listen: SocketAddr,
    socket_id: usize,
    endpoint: SocketAddr,
) -> BoxedResult<impl BoundSocket> {
    let socket = Socket2::new(
        Domain::for_address(endpoint),
        Type::DGRAM,
        Protocol::UDP.into(),
    )
    .map_err(from_io_err)?;

    #[cfg(not(target_family = "windows"))]
    socket.set_reuse_address(true).map_err(from_io_err)?;
    #[cfg(not(target_family = "windows"))]
    socket.set_reuse_port(true).map_err(from_io_err)?;

    socket.bind(&listen.into()).map_err(from_io_err)?;

    // let socket: UdpSocket = socket.into();
    socket.set_nonblocking(true).map_err(from_io_err)?;
    socket.connect(&endpoint.into()).map_err(from_io_err)?;
    let poller = Poller::new().map_err(from_io_err)?;
    unsafe {
        poller
            .add(&socket, Event::readable(socket_id))
            .map_err(from_io_err)?;
    }
    let socket = UdpBoundSocket {
        socket: socket.into(),
        poller,
        socket_id,
        // polling allocates the event list once, when the socket is created
        events: Events::with_capacity(NonZeroUsize::new(1).unwrap()),
    };
    Ok(socket)
}

/// Each client uses a socket and the descriptors of its own poller.
const MAX_NOTIFIED_SOCKETS: usize = MAX_CLIENTS as usize * 8;

/// Notified sockets are tracked by descriptor, not socket id: ids grow forever,
/// while the entry of a closed descriptor is replaced when the descriptor is reused.
fn poller_key(raw_fd: SocketRawFd) -> usize {
    raw_fd as usize
}

const WSAEMSGSIZE: i32 = 10040;

/// Windows fails a read of a datagram larger than the buffer and discards the
/// datagram, where other systems cut it to the buffer size. Such a datagram is
/// never valid, so it must not end the transfer or the server.
fn ignore_oversized_datagram<T>(result: std::io::Result<T>) -> std::io::Result<T> {
    match result {
        Err(e) if cfg!(target_family = "windows") && e.raw_os_error() == Some(WSAEMSGSIZE) => {
            debug!("Ignoring a datagram larger than the receive buffer");
            Err(std::io::ErrorKind::WouldBlock.into())
        }
        result => result,
    }
}

pub struct UdpUnboundSocket {
    socket: UdpSocket,
    poller: Poller,
    socket_id: usize,
    // polling allocates the event list once, when the socket is created
    events: Events,
    notified: Map<usize, (), MAX_NOTIFIED_SOCKETS>,
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
        for event in self.events.iter() {
            let _ = self.notified.insert(event.key, ());
        }

        let result = ignore_oversized_datagram(self.socket.recv_from(buff));
        if let Ok((size, client)) = result.as_ref() {
            trace!("Received from {client} {size} {:x?}", buff);
        }
        result
    }

    fn send_to(&self, buff: &mut DataBuffer, client: SocketAddr) -> io::Result<usize> {
        let result = self.socket.send_to(buff, client);
        trace!("Send to {client} {} {:x?}", buff.len(), buff);
        result
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    #[cfg(not(feature = "multi_thread"))]
    fn notified(&self, socket: &impl ToSocketId) -> bool {
        // polling a socket that has no data is harmless, missing one that has is not
        self.notified.len() >= MAX_NOTIFIED_SOCKETS
            || self.notified.contains_key(&poller_key(socket.as_raw_fd()))
    }

    #[cfg(not(feature = "multi_thread"))]
    fn add_interest(&self, socket: &impl ToSocketId) -> io::Result<()> {
        unsafe {
            self.poller
                .add(
                    socket.as_raw_fd(),
                    Event::readable(poller_key(socket.as_raw_fd())),
                )
                .map_err(from_io_err)
        }
    }

    fn modify_interest(&mut self, _socket_id: usize, raw_fd: SocketRawFd) -> io::Result<()> {
        let key = poller_key(raw_fd);
        self.notified.remove(&key);
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
                Event::readable(key),
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
        ignore_oversized_datagram(self.socket.recv(buff)).map_err(from_io_err)
    }

    fn send(&self, buff: &mut DataBuffer) -> io::Result<usize> {
        self.socket.send(buff).map_err(from_io_err)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
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

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[cfg(not(feature = "multi_thread"))]
    #[test]
    fn test_client_socket_is_notified_until_interest_is_modified() {
        let mut server = create_socket("127.0.0.1:0".parse().unwrap(), 0, false, 4).unwrap();
        let client = create_bound_socket(
            "127.0.0.1:0".parse().unwrap(),
            1,
            server.local_addr().unwrap(),
        )
        .unwrap();
        server.add_interest(&client).unwrap();
        assert!(!server.notified(&client));

        let mut buf = DataBuffer::new();
        #[allow(unused_must_use)]
        {
            buf.resize(100, 0);
        }
        // a connected socket only accepts packets from the address it is connected to
        server
            .send_to(&mut buf, client.local_addr().unwrap())
            .unwrap();
        let _ = server.recv_from(&mut buf, Duration::from_millis(100).into());

        assert!(server.notified(&client));
        server
            .modify_interest(client.socket_id(), client.as_raw_fd())
            .unwrap();
        assert!(!server.notified(&client));
    }

    #[test]
    fn test_receive_wait_for() {
        let mut socket_r = create_socket("127.0.0.1:9000".parse().unwrap(), 1, false, 1).unwrap();
        let socket_s = create_socket("127.0.0.1:0".parse().unwrap(), 0, false, 1).unwrap();
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
        let wait_for = Duration::from_millis(30);
        let result = socket_r.recv_from(&mut buf, None);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(now.elapsed() < wait_for);

        let mut send_buf = DataBuffer::new();
        let addr: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();
        socket_s.send_to(&mut send_buf, addr).unwrap();
        let now = Instant::now();
        let wait_for = Duration::from_secs(2);
        let result = socket_r.recv_from(&mut buf, wait_for.into());
        assert!(result.is_ok());
        assert!(now.elapsed() < wait_for);

        let now = Instant::now();
        let wait_for = Duration::from_millis(30);
        let result = socket_r.recv_from(&mut buf, None);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(now.elapsed() < wait_for);
    }
}
