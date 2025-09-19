use core::net::SocketAddr;
use core::time::Duration;

use log::error;
use rand::CryptoRng;
use rand::RngCore;

use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::encrypted_packet::EncryptedDataPacket;
use crate::encrypted_packet::EncryptedPacket;
use crate::encrypted_packet::InitialPacket;
use crate::encryption::EncryptionLevel;
use crate::encryption::Encryptor;
use crate::encryption::PublicKey;
use crate::packet::PacketType;
use crate::socket::Socket;
use crate::socket::SocketRawFd;
use crate::socket::ToSocketId;
use crate::std_compat::io::Error;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::io::Result;
use crate::types::DataBuffer;

pub struct EncryptionBoundSocket<S, Rng> {
    pub socket: S,
    pub connection_encryptor: Option<Encryptor<Rng>>,
    pub encryption_level: EncryptionLevel,
    pub public_key: Option<PublicKey>,
    pub block_size: u16,
}

impl<S, Rng> EncryptionBoundSocket<S, Rng> {
    pub fn new(
        socket: S,
        connection_encryptor: Option<Encryptor<Rng>>,
        public_key: PublicKey,
        encryption_level: EncryptionLevel,
        block_size: u16,
    ) -> Self {
        Self {
            socket,
            connection_encryptor,
            encryption_level,
            public_key: public_key.into(),
            block_size,
        }
    }

    pub fn wrap(socket: S, block_size: u16) -> Self {
        Self {
            socket,
            connection_encryptor: None,
            encryption_level: EncryptionLevel::None,
            public_key: None,
            block_size,
        }
    }
}

impl<S, Rng> Socket for EncryptionBoundSocket<S, Rng>
where
    S: Socket,
    Rng: CryptoRng + RngCore + Copy,
{
    fn recv_from(
        &mut self,
        buff: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> Result<(usize, SocketAddr)> {
        let (received_length, s) = self.socket.recv_from(buff, wait_for)?;
        buff.truncate(received_length);

        match (self.encryption_level, &self.connection_encryptor) {
            (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) => {
                EncryptedPacket::decrypt(encryptor, buff).map_err(|e| {
                    error!("Failed to decrypt data {e}");
                    Error::from(ErrorKind::InvalidData)
                })?;
            }
            (EncryptionLevel::Data, Some(encryptor))
                if matches!(PacketType::from_bytes(buff), Ok(PacketType::Data)) =>
            {
                EncryptedDataPacket::decrypt(encryptor, buff).map_err(|e| {
                    error!("Failed to decrypt data {e}");
                    Error::from(ErrorKind::InvalidData)
                })?;
            }
            _ => (),
        }
        Ok((buff.len(), s))
    }

    fn send_to(&self, buff: &mut DataBuffer, endpoint: SocketAddr) -> Result<usize> {
        let packet_type = PacketType::from_bytes(buff);
        match (self.encryption_level, &self.connection_encryptor) {
            (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) => {
                // encrypt initial packet
                if let Ok(PacketType::Read | PacketType::Write) = packet_type {
                    InitialPacket::encrypt(
                        encryptor,
                        buff,
                        self.block_size + DATA_PACKET_HEADER_SIZE as u16,
                        &self
                            .public_key
                            .expect("Public key must be set for initial packet"),
                    )
                    .map_err(|e| {
                        error!("Failed to encrypt data {e}");
                        Error::from(ErrorKind::InvalidData)
                    })?;
                } else {
                    EncryptedPacket::encrypt(
                        encryptor,
                        buff,
                        self.block_size + DATA_PACKET_HEADER_SIZE as u16,
                    )
                    .map_err(|e| {
                        error!("Failed to encrypt data {e}");
                        Error::from(ErrorKind::InvalidData)
                    })?;
                }
            }
            (EncryptionLevel::Data, Some(encryptor))
                if matches!(packet_type, Ok(PacketType::Data)) =>
            {
                EncryptedDataPacket::encrypt(encryptor, buff).map_err(|e| {
                    error!("Failed to encrypt data {e}");
                    Error::from(ErrorKind::InvalidData)
                })?;
            }
            _ => (),
        }
        self.socket.send_to(buff, endpoint)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr()
    }

    #[cfg(not(feature = "multi_thread"))]
    fn add_interest(&self, _to_socket_id: &impl ToSocketId) -> Result<()> {
        unimplemented!()
    }

    fn modify_interest(&mut self, _socket_id: usize, _raw_fd: SocketRawFd) -> Result<()> {
        unimplemented!()
    }

    #[cfg(not(feature = "multi_thread"))]
    fn notified(&self, _to_socket_id: &impl ToSocketId) -> bool {
        unimplemented!()
    }
}

#[cfg(feature = "encryption")]
impl<S, R> ToSocketId for EncryptionBoundSocket<S, R>
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
