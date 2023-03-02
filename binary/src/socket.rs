use core::time::Duration;

use log::info;
use polling::{Event, Poller};
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

pub fn create_socket(listen: &str, socket_id: usize) -> BoxedResult<impl Socket> {
    let socket = std::net::UdpSocket::bind(listen).map_err(from_io_err)?;
    socket.set_nonblocking(true).map_err(from_io_err)?;
    let local_addr = socket.local_addr().map_err(from_io_err)?;
    let poller = if socket_id > 0 {
        let poller = Poller::new().map_err(from_io_err)?;
        poller
            .add(&socket, Event::readable(socket_id))
            .map_err(from_io_err)?;
        poller.into()
    } else {
        None
    };
    let socket = StdSocket {
        socket,
        poller,
        socket_id,
    };
    Ok(socket)
}

pub struct StdSocket {
    socket: std::net::UdpSocket,
    poller: Option<Poller>,
    socket_id: usize,
}

impl Socket for StdSocket {
    fn recv_from(
        &self,
        buf: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> io::Result<(usize, SocketAddr)> {
        if let (Some(d), Some(poller)) = (wait_for, &self.poller) {
            poller
                .modify(&self.socket, Event::readable(self.socket_id))
                .map_err(from_io_err)?;
            // TODO alloc in stack
            let mut events = Vec::new();
            poller.wait(&mut events, d.into()).map_err(from_io_err)?;
        }

        #[cfg(feature = "std")]
        let result = self.socket.recv_from(buf);
        #[cfg(not(feature = "std"))]
        let result = self
            .socket
            .recv_from(buf)
            .map(|(b, s)| (b, std_to_socket_addr(s)))
            .map_err(from_io_err);
        result
    }

    fn send_to(&self, buff: &mut DataBuffer, addr: SocketAddr) -> io::Result<usize> {
        #[cfg(feature = "std")]
        return self.socket.send_to(&buff, addr);
        #[cfg(not(feature = "std"))]
        self.socket
            .send_to(&buff, socket_addr_to_std(addr))
            .map_err(from_io_err)
    }

    fn try_clone(&self) -> io::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            #[cfg(feature = "std")]
            socket: self.socket.try_clone()?,
            #[cfg(not(feature = "std"))]
            socket: self.socket.try_clone().map_err(from_io_err)?,
            poller: None,
            socket_id: 0,
        })
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

#[cfg(not(feature = "std"))]
pub fn socket_addr_to_std(addr: SocketAddr) -> std::net::SocketAddr {
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
        let socket_r = create_socket("127.0.0.1:9000", 1).unwrap();
        let socket_s = create_socket("127.0.0.1:0", 0).unwrap();
        let mut buf = DataBuffer::new();
        #[allow(unused_must_use)]
        {
            buf.resize(100, 0);
        }

        let now = Instant::now();
        let wait_for = Duration::from_millis(15);
        let result = socket_r.recv_from(&mut buf, wait_for.into());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(now.elapsed() >= wait_for);

        let now = Instant::now();
        let wait_for = Duration::from_micros(15);
        let result = socket_r.recv_from(&mut buf, wait_for.into());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(now.elapsed() >= wait_for);

        let now = Instant::now();
        let wait_for = Duration::from_micros(15);
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
