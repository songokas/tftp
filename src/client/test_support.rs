//! Doubles that drive a client transfer one datagram at a time.

use core::net::IpAddr;
use core::net::Ipv4Addr;
use core::net::SocketAddr;
use core::time::Duration;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::vec::Vec;

use crate::client::ClientConfig;
use crate::error::BoxedResult;
use crate::socket::BoundSocket;
use crate::socket::Socket;
use crate::socket::SocketRawFd;
use crate::socket::ToSocketId;
use crate::std_compat::io;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::io::Read;
use crate::std_compat::io::Seek;
use crate::std_compat::io::SeekFrom;
use crate::std_compat::io::Write;
use crate::types::DataBuffer;

/// State shared between a test and a double that a server may require to be `Send`.
#[derive(Default)]
pub struct Cell<T>(Mutex<T>);

impl<T> Cell<T> {
    pub fn borrow(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap()
    }

    pub fn borrow_mut(&self) -> MutexGuard<'_, T> {
        self.borrow()
    }
}

pub type Shared<T> = Arc<Cell<T>>;

pub fn server_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6969)
}

pub fn other_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 6969)
}

pub fn client_config() -> ClientConfig {
    ClientConfig {
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        endpoint: server_address(),
        request_timeout: Duration::from_secs(60),
        max_file_size: 1 << 20,
        private_key: None,
        remote_public_key: None,
        allow_server_port_change: false,
        prefer_seek: false,
        encryption_key: None,
    }
}

pub fn data_packet(block: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 3];
    packet.extend_from_slice(&block.to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

pub fn ack_packet(block: u16) -> Vec<u8> {
    let mut packet = vec![0, 4];
    packet.extend_from_slice(&block.to_be_bytes());
    packet
}

/// True when a transfer ended because its request timeout expired, rather than
/// by running out of scripted datagrams.
pub fn timed_out<T>(result: &BoxedResult<T>) -> bool {
    matches!(result, Err(e) if format!("{e}").contains("Timeout"))
}

/// True when a data packet went out, with any encryption applied or not.
pub fn sent_data(sent: &Shared<Vec<Vec<u8>>>) -> bool {
    sent.borrow().iter().any(|p| p.starts_with(&[0, 3]))
}

pub enum Incoming {
    Datagram(Vec<u8>, SocketAddr),
    Idle,
}

/// Replays `incoming`, then fails, which ends a transfer that is still waiting.
pub struct ScriptedSocket {
    pub incoming: VecDeque<Incoming>,
    pub sent: Shared<Vec<Vec<u8>>>,
    /// Time each receive takes, to let timeouts expire.
    pub delay: Duration,
}

impl ScriptedSocket {
    pub fn new(incoming: impl IntoIterator<Item = Incoming>) -> Self {
        Self {
            incoming: incoming.into_iter().collect(),
            sent: Default::default(),
            delay: Duration::ZERO,
        }
    }

    pub fn from_server(datagrams: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self::new(
            datagrams
                .into_iter()
                .map(|d| Incoming::Datagram(d, server_address())),
        )
    }
}

impl ToSocketId for ScriptedSocket {
    fn as_raw_fd(&self) -> SocketRawFd {
        0
    }

    fn socket_id(&self) -> usize {
        0
    }
}

impl Socket for ScriptedSocket {
    fn recv_from(
        &mut self,
        buffer: &mut DataBuffer,
        _wait_for: Option<Duration>,
    ) -> io::Result<(usize, SocketAddr)> {
        std::thread::sleep(self.delay);
        match self.incoming.pop_front() {
            Some(Incoming::Datagram(data, from)) => {
                // like a real socket, drops what does not fit
                let size = data.len().min(buffer.len());
                buffer[..size].copy_from_slice(&data[..size]);
                Ok((size, from))
            }
            Some(Incoming::Idle) => Err(ErrorKind::WouldBlock.into()),
            None => Err(ErrorKind::Other.into()),
        }
    }

    fn send_to(&self, buffer: &mut DataBuffer, _addr: SocketAddr) -> io::Result<usize> {
        self.sent.borrow_mut().push(buffer.to_vec());
        Ok(buffer.len())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000))
    }

    fn modify_interest(&mut self, _socket_id: usize, _raw_fd: SocketRawFd) -> io::Result<()> {
        Ok(())
    }

    #[cfg(not(feature = "multi_thread"))]
    fn notified(&self, _to_socket_id: &impl ToSocketId) -> bool {
        true
    }

    #[cfg(not(feature = "multi_thread"))]
    fn add_interest(&self, _to_socket_id: &impl ToSocketId) -> io::Result<()> {
        Ok(())
    }
}

impl BoundSocket for ScriptedSocket {
    fn recv(&mut self, buffer: &mut DataBuffer, wait_for: Option<Duration>) -> io::Result<usize> {
        self.recv_from(buffer, wait_for).map(|(size, _)| size)
    }

    fn send(&self, buffer: &mut DataBuffer) -> io::Result<usize> {
        self.send_to(buffer, server_address())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Socket::local_addr(self)
    }
}

/// A local file kept in memory, so a test can read what a transfer stored.
#[derive(Clone, Default)]
pub struct MemoryFile(pub Shared<Vec<u8>>);

impl Write for MemoryFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn write_fmt(&mut self, _fmt: core::fmt::Arguments<'_>) -> io::Result<()> {
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A local file to send.
pub struct MemoryReader {
    pub data: Vec<u8>,
    pub position: usize,
}

impl MemoryReader {
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            position: 0,
        }
    }
}

impl Read for MemoryReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let size = buffer.len().min(self.data.len() - self.position);
        buffer[..size].copy_from_slice(&self.data[self.position..self.position + size]);
        self.position += size;
        Ok(size)
    }
}

impl Seek for MemoryReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if let SeekFrom::Start(start) = position {
            self.position = start as usize;
        }
        Ok(self.position as u64)
    }
}
