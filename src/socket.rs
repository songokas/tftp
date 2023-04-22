use core::time::Duration;

use crate::{
    config::ConnectionOptions,
    encryption::{overwrite_data_packet, EncryptionKeys, EncryptionLevel, Encryptor, PublicKey},
    std_compat::{
        io::{Error, ErrorKind, Result},
        net::SocketAddr,
    },
    types::DataBuffer,
};

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
    fn recv(&self, buff: &mut DataBuffer, wait_for: Option<Duration>) -> Result<usize>;
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

#[cfg(feature = "encryption")]
pub struct EncryptionBoundSocket<S> {
    pub socket: S,
    pub encryptor: Option<Encryptor>,
    pub encryption_level: EncryptionLevel,
    pub public_key: Option<PublicKey>,
}

#[cfg(feature = "encryption")]
impl<S> EncryptionBoundSocket<S> {
    pub fn new(
        socket: S,
        encryptor: Option<Encryptor>,
        public_key: PublicKey,
        encryption_level: EncryptionLevel,
    ) -> Self {
        Self {
            socket,
            encryptor,
            encryption_level,
            public_key: public_key.into(),
        }
    }

    pub fn wrap(socket: S) -> Self {
        Self {
            socket,
            encryptor: None,
            encryption_level: EncryptionLevel::None,
            public_key: None,
        }
    }
}

#[cfg(feature = "encryption")]
impl<S> Socket for EncryptionBoundSocket<S>
where
    S: Socket,
{
    fn recv_from(
        &mut self,
        buff: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> Result<(usize, SocketAddr)> {
        let (received_length, s) = self.socket.recv_from(buff, wait_for)?;
        buff.truncate(received_length);
        match (self.encryption_level, &self.encryptor) {
            (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) => {
                encryptor
                    .decrypt(buff)
                    .map_err(|_| Error::from(ErrorKind::InvalidData))?;
            }
            (EncryptionLevel::Data, Some(encryptor)) => {
                overwrite_data_packet(buff, |buff| encryptor.decrypt(buff))
                    .map_err(|_| Error::from(ErrorKind::InvalidData))?;
            }
            _ => (),
        }
        Ok((buff.len(), s))
    }

    fn send_to(&self, buff: &mut DataBuffer, endpoint: SocketAddr) -> Result<usize> {
        use crate::packet::PacketType;
        match (self.encryption_level, &self.encryptor) {
            (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) => {
                let packet_type = PacketType::from_bytes(buff);
                encryptor
                    .encrypt(buff)
                    .map_err(|_| Error::from(ErrorKind::InvalidData))?;
                // encrypt initial packet
                if let Ok(PacketType::Read | PacketType::Write) = packet_type {
                    *buff = PacketType::InitialEncryption
                        .to_bytes()
                        .into_iter()
                        .chain(self.public_key.unwrap().as_bytes().iter().copied())
                        .chain(encryptor.nonce.into_iter())
                        .chain(buff.iter().copied())
                        .collect();
                }
            }
            (EncryptionLevel::Data, Some(encryptor)) => {
                overwrite_data_packet(buff, |buff| encryptor.encrypt(buff))
                    .map_err(|_| Error::from(ErrorKind::InvalidData))?;
            }
            _ => (),
        }
        self.socket.send_to(buff, endpoint)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn add_interest(&self, to_socket_id: &impl ToSocketId) -> Result<()> {
        unimplemented!()
    }

    fn modify_interest(&mut self, socket_id: usize, raw_fd: SocketRawFd) -> Result<()> {
        unimplemented!()
    }

    fn notified(&self, to_socket_id: &impl ToSocketId) -> bool {
        unimplemented!()
    }
}

#[cfg(feature = "encryption")]
impl<S> ToSocketId for EncryptionBoundSocket<S>
where
    S: ToSocketId,
{
    fn as_raw_fd(&self) -> SocketRawFd {
        unimplemented!()
    }

    fn socket_id(&self) -> usize {
        unimplemented!()
    }
}
