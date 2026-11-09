//! `tftp-dus` sockets on top of `smoltcp`, with all memory reserved up front.

use core::cell::RefCell;
use core::net::Ipv4Addr;
use core::net::SocketAddr;
use core::net::SocketAddrV4;
use core::time::Duration;

use log::info;
use smoltcp::iface::Config;
use smoltcp::iface::Interface;
use smoltcp::iface::SocketHandle;
use smoltcp::iface::SocketSet;
use smoltcp::iface::SocketStorage;
use smoltcp::phy::Device;
use smoltcp::socket::dhcpv4;
use smoltcp::socket::udp;
use smoltcp::socket::udp::PacketMetadata;
use smoltcp::time::Instant as NetInstant;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::HardwareAddress;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpCidr;
use smoltcp::wire::IpEndpoint;
use smoltcp::wire::IpListenEndpoint;
use smoltcp::wire::Ipv4Cidr;
use tftp_dus::config::MAX_BLOCKS_FOR_MULTI_READER;
use tftp_dus::config::MAX_BUFFER_SIZE;
use tftp_dus::config::MAX_CLIENTS;
use tftp_dus::error::BoxedResult;
use tftp_dus::socket::BoundSocket;
use tftp_dus::socket::Socket;
use tftp_dus::socket::SocketRawFd;
use tftp_dus::socket::ToSocketId;
use tftp_dus::std_compat::io;
use tftp_dus::types::DataBuffer;

/// One socket per client plus the listening socket.
const UDP_SOCKETS: usize = MAX_CLIENTS as usize + 1;
/// The UDP sockets plus DHCP.
const SOCKET_ENTRIES: usize = UDP_SOCKETS + 1;
/// A full window of data and the packet that follows it.
const PACKETS: usize = MAX_BLOCKS_FOR_MULTI_READER as usize + 1;
const PAYLOAD: usize = PACKETS * MAX_BUFFER_SIZE as usize;
const FIRST_DYNAMIC_PORT: u16 = 49152;
const SEND_ATTEMPTS: u32 = 1000;

/// Everything the network layer needs, intended to live in a `static`.
pub struct Memory {
    entries: [SocketStorage<'static>; SOCKET_ENTRIES],
    rx_metadata: [[PacketMetadata; PACKETS]; UDP_SOCKETS],
    tx_metadata: [[PacketMetadata; PACKETS]; UDP_SOCKETS],
    rx_payload: [[u8; PAYLOAD]; UDP_SOCKETS],
    tx_payload: [[u8; PAYLOAD]; UDP_SOCKETS],
}

impl Memory {
    pub const fn new() -> Self {
        Self {
            entries: [SocketStorage::EMPTY; SOCKET_ENTRIES],
            rx_metadata: [[PacketMetadata::EMPTY; PACKETS]; UDP_SOCKETS],
            tx_metadata: [[PacketMetadata::EMPTY; PACKETS]; UDP_SOCKETS],
            rx_payload: [[0; PAYLOAD]; UDP_SOCKETS],
            tx_payload: [[0; PAYLOAD]; UDP_SOCKETS],
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

fn to_endpoint(address: SocketAddr) -> io::Result<IpEndpoint> {
    match address {
        SocketAddr::V4(address) => Ok(address.into()),
        SocketAddr::V6(_) => Err(io::ErrorKind::AddrNotAvailable.into()),
    }
}

fn to_socket_address(endpoint: IpEndpoint) -> SocketAddr {
    let IpAddress::Ipv4(ip) = endpoint.addr;
    SocketAddr::V4(SocketAddrV4::new(ip, endpoint.port))
}

pub enum Address {
    Static(Ipv4Cidr),
    Dhcp,
}

struct Inner<D: Device> {
    device: D,
    interface: Interface,
    sockets: SocketSet<'static>,
    handles: heapless::Vec<SocketHandle, UDP_SOCKETS>,
    in_use: [bool; UDP_SOCKETS],
    next_port: u16,
    dhcp: Option<SocketHandle>,
}

/// Not locked: the example only touches the network from the server loop, and
/// keeping interrupts on while polling is required by the Wi-Fi driver.
pub struct NetStack<D: Device> {
    inner: RefCell<Inner<D>>,
    clock: fn() -> u64,
}

impl<D: Device> Inner<D> {
    fn poll(&mut self, now: NetInstant) {
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        let Some(handle) = self.dhcp else {
            return;
        };
        match self.sockets.get_mut::<dhcpv4::Socket>(handle).poll() {
            None => (),
            Some(dhcpv4::Event::Configured(lease)) => {
                info!("Received address {}", lease.address);
                self.interface.update_ip_addrs(|addresses| {
                    addresses.clear();
                    let _ = addresses.push(IpCidr::Ipv4(lease.address));
                });
                let routes = self.interface.routes_mut();
                routes.remove_default_ipv4_route();
                if let Some(router) = lease.router {
                    let _ = routes.add_default_ipv4_route(router);
                }
            }
            Some(dhcpv4::Event::Deconfigured) => {
                self.interface
                    .update_ip_addrs(|addresses| addresses.clear());
                self.interface.routes_mut().remove_default_ipv4_route();
            }
        }
    }

    fn udp(&mut self, slot: usize) -> &mut udp::Socket<'static> {
        self.sockets.get_mut::<udp::Socket>(self.handles[slot])
    }

    fn allocate_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = self.next_port.checked_add(1).unwrap_or(FIRST_DYNAMIC_PORT);
        port
    }
}

impl<D: Device + 'static> NetStack<D> {
    /// `clock` returns monotonic microseconds, `seed` randomizes smoltcp.
    pub fn new(
        mut device: D,
        mac: [u8; 6],
        address: Address,
        memory: &'static mut Memory,
        clock: fn() -> u64,
        seed: u64,
    ) -> Self {
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        config.random_seed = seed;
        let now = NetInstant::from_micros(clock() as i64);
        let mut interface = Interface::new(config, &mut device, now);

        let Memory {
            entries,
            rx_metadata,
            tx_metadata,
            rx_payload,
            tx_payload,
        } = memory;
        let mut sockets = SocketSet::new(&mut entries[..]);
        let mut handles = heapless::Vec::new();
        let buffers = rx_metadata
            .iter_mut()
            .zip(rx_payload.iter_mut())
            .zip(tx_metadata.iter_mut().zip(tx_payload.iter_mut()));
        for ((rx_meta, rx_data), (tx_meta, tx_data)) in buffers {
            let socket = udp::Socket::new(
                udp::PacketBuffer::new(&mut rx_meta[..], &mut rx_data[..]),
                udp::PacketBuffer::new(&mut tx_meta[..], &mut tx_data[..]),
            );
            let _ = handles.push(sockets.add(socket));
        }

        let dhcp = match address {
            Address::Static(cidr) => {
                interface.update_ip_addrs(|addresses| {
                    let _ = addresses.push(IpCidr::Ipv4(cidr));
                });
                None
            }
            Address::Dhcp => Some(sockets.add(dhcpv4::Socket::new())),
        };

        Self {
            inner: RefCell::new(Inner {
                device,
                interface,
                sockets,
                handles,
                in_use: [false; UDP_SOCKETS],
                next_port: FIRST_DYNAMIC_PORT,
                dhcp,
            }),
            clock,
        }
    }

    fn now(&self) -> NetInstant {
        NetInstant::from_micros((self.clock)() as i64)
    }

    pub fn poll(&self) {
        let now = self.now();
        self.inner.borrow_mut().poll(now);
    }

    pub fn address(&self) -> Option<Ipv4Addr> {
        self.inner.borrow().interface.ipv4_addr()
    }

    /// Runs the network until an address is configured, by DHCP for example.
    pub fn wait_for_address(&self) -> Ipv4Addr {
        loop {
            self.poll();
            if let Some(address) = self.address() {
                return address;
            }
            core::hint::spin_loop();
        }
    }

    fn open(&self, requested_port: u16) -> io::Result<usize> {
        let inner = &mut *self.inner.borrow_mut();
        let slot = inner
            .in_use
            .iter()
            .position(|used| !used)
            .ok_or(io::Error::from(io::ErrorKind::OutOfMemory))?;
        let port = match requested_port {
            0 => inner.allocate_port(),
            port => port,
        };
        inner
            .udp(slot)
            .bind(IpListenEndpoint { addr: None, port })
            .map_err(|_| io::Error::from(io::ErrorKind::AddrInUse))?;
        inner.in_use[slot] = true;
        Ok(slot)
    }

    fn close(&self, slot: usize) {
        let mut inner = self.inner.borrow_mut();
        inner.udp(slot).close();
        inner.in_use[slot] = false;
    }

    fn take_packet(
        &self,
        slot: usize,
        buffer: &mut [u8],
        peer: Option<IpEndpoint>,
    ) -> Option<(usize, IpEndpoint)> {
        let mut inner = self.inner.borrow_mut();
        let socket = inner.udp(slot);
        while socket.can_recv() {
            let Ok((size, metadata)) = socket.recv_slice(buffer) else {
                continue;
            };
            if peer.is_none_or(|peer| peer == metadata.endpoint) {
                return Some((size, metadata.endpoint));
            }
        }
        None
    }

    fn receive(
        &self,
        slot: usize,
        buffer: &mut [u8],
        peer: Option<IpEndpoint>,
        wait: Duration,
    ) -> io::Result<(usize, IpEndpoint)> {
        let deadline = (self.clock)().saturating_add(wait.as_micros() as u64);
        loop {
            self.poll();
            if let Some(received) = self.take_packet(slot, buffer, peer) {
                return Ok(received);
            }
            if (self.clock)() >= deadline {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            core::hint::spin_loop();
        }
    }

    fn send(&self, slot: usize, data: &[u8], destination: IpEndpoint) -> io::Result<usize> {
        for _ in 0..SEND_ATTEMPTS {
            let sent = self
                .inner
                .borrow_mut()
                .udp(slot)
                .send_slice(data, destination);
            match sent {
                Ok(()) => {
                    self.poll();
                    return Ok(data.len());
                }
                Err(udp::SendError::BufferFull) => self.poll(),
                Err(_) => return Err(io::ErrorKind::InvalidInput.into()),
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn has_packet(&self, slot: usize) -> bool {
        self.inner.borrow_mut().udp(slot).can_recv()
    }

    fn local_address(&self, slot: usize) -> SocketAddr {
        let mut inner = self.inner.borrow_mut();
        let port = inner.udp(slot).endpoint().port;
        let ip = inner.interface.ipv4_addr().unwrap_or(Ipv4Addr::UNSPECIFIED);
        SocketAddr::V4(SocketAddrV4::new(ip, port))
    }

    pub fn create_socket(
        &'static self,
        address: SocketAddr,
        socket_id: usize,
    ) -> BoxedResult<UdpSocket<D>> {
        let slot = self.open(address.port())?;
        Ok(UdpSocket {
            stack: self,
            slot,
            socket_id,
        })
    }

    /// The local port is chosen here when `listen` has port 0. smoltcp can not
    /// share a port between sockets, so servers need `require_server_port_change`.
    pub fn create_bound_socket(
        &'static self,
        listen: SocketAddr,
        socket_id: usize,
        peer: SocketAddr,
    ) -> BoxedResult<UdpBoundSocket<D>> {
        let slot = self.open(listen.port())?;
        Ok(UdpBoundSocket {
            stack: self,
            slot,
            socket_id,
            peer: to_endpoint(peer)?,
        })
    }
}

pub struct UdpSocket<D: Device + 'static> {
    stack: &'static NetStack<D>,
    slot: usize,
    socket_id: usize,
}

impl<D: Device + 'static> Drop for UdpSocket<D> {
    fn drop(&mut self) {
        self.stack.close(self.slot);
    }
}

impl<D: Device + 'static> ToSocketId for UdpSocket<D> {
    fn as_raw_fd(&self) -> SocketRawFd {
        self.slot as SocketRawFd
    }

    fn socket_id(&self) -> usize {
        self.socket_id
    }
}

impl<D: Device + 'static> Socket for UdpSocket<D> {
    fn recv_from(
        &mut self,
        buf: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> io::Result<(usize, SocketAddr)> {
        let wait = wait_for.unwrap_or(Duration::ZERO);
        let (size, from) = self.stack.receive(self.slot, buf, None, wait)?;
        Ok((size, to_socket_address(from)))
    }

    fn send_to(&self, buf: &mut DataBuffer, addr: SocketAddr) -> io::Result<usize> {
        self.stack.send(self.slot, buf, to_endpoint(addr)?)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.stack.local_address(self.slot))
    }

    fn modify_interest(&mut self, _socket_id: usize, _raw_fd: SocketRawFd) -> io::Result<()> {
        Ok(())
    }

    fn notified(&self, socket: &impl ToSocketId) -> bool {
        self.stack.has_packet(socket.as_raw_fd() as usize)
    }

    fn add_interest(&self, _socket: &impl ToSocketId) -> io::Result<()> {
        Ok(())
    }
}

pub struct UdpBoundSocket<D: Device + 'static> {
    stack: &'static NetStack<D>,
    slot: usize,
    socket_id: usize,
    peer: IpEndpoint,
}

// SAFETY: the library requires Send for its multi threaded server. The example
// uses the single threaded server, so these never leave the network thread.
unsafe impl<D: Device + 'static> Send for UdpBoundSocket<D> {}

impl<D: Device + 'static> Drop for UdpBoundSocket<D> {
    fn drop(&mut self) {
        self.stack.close(self.slot);
    }
}

impl<D: Device + 'static> ToSocketId for UdpBoundSocket<D> {
    fn as_raw_fd(&self) -> SocketRawFd {
        self.slot as SocketRawFd
    }

    fn socket_id(&self) -> usize {
        self.socket_id
    }
}

impl<D: Device + 'static> BoundSocket for UdpBoundSocket<D> {
    fn recv(&mut self, buff: &mut DataBuffer, wait_for: Option<Duration>) -> io::Result<usize> {
        let wait = wait_for.unwrap_or(Duration::ZERO);
        let (size, _) = self.stack.receive(self.slot, buff, Some(self.peer), wait)?;
        Ok(size)
    }

    fn send(&self, buff: &mut DataBuffer) -> io::Result<usize> {
        self.stack.send(self.slot, buff, self.peer)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.stack.local_address(self.slot))
    }
}
