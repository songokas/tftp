use core::time::Duration;

use crate::std_compat::io::Result;
use crate::std_compat::net::SocketAddr;
use crate::types::DataBuffer;

pub trait Socket: ToSocketId {
    fn recv_from(
        &mut self,
        buf: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> Result<(usize, SocketAddr)>;
    fn send_to(&self, buf: &mut DataBuffer, addr: SocketAddr) -> Result<usize>;
    fn local_addr(&self) -> Result<SocketAddr>;

    fn notified(&self, to_socket_id: &impl ToSocketId) -> bool;
    fn add_interest(&self, to_socket_id: &impl ToSocketId) -> Result<()>;
    fn modify_interest(&mut self, socket_id: usize, raw_fd: SocketRawFd) -> Result<()>;
}

pub trait BoundSocket: ToSocketId {
    fn recv(&mut self, buff: &mut DataBuffer, wait_for: Option<Duration>) -> Result<usize>;
    fn send(&self, buff: &mut DataBuffer) -> Result<usize>;
    fn local_addr(&self) -> Result<SocketAddr>;
}

pub trait ToSocketId {
    fn as_raw_fd(&self) -> SocketRawFd;
    fn socket_id(&self) -> usize;
}

#[cfg(target_family = "windows")]
pub type SocketRawFd = u64;
#[cfg(not(target_family = "windows"))]
pub type SocketRawFd = i32;
