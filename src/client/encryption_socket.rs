use core::mem::size_of;
use core::time::Duration;

use log::error;

use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::config::ENCRYPTION_PADDING;
use crate::config::ENCRYPTION_TAG_SIZE;
use crate::encryption::apply_bit_padding;
use crate::encryption::overwrite_data_packet;
use crate::encryption::remove_bit_padding;
use crate::encryption::EncryptionLevel;
use crate::encryption::Encryptor;
use crate::encryption::Nonce;
use crate::encryption::PublicKey;
use crate::packet::PacketType;
use crate::socket::Socket;
use crate::socket::SocketRawFd;
use crate::socket::ToSocketId;
use crate::std_compat::io::Error;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::io::Result;
use crate::std_compat::net::SocketAddr;
use crate::types::DataBuffer;

const FULLY_ENCODED_HEADER_SIZE: usize = size_of::<PacketType>()
    + size_of::<PublicKey>()
    + size_of::<Nonce>()
    + ENCRYPTION_TAG_SIZE as usize
    + ENCRYPTION_PADDING as usize;

pub struct EncryptionBoundSocket<S> {
    pub socket: S,
    pub encryptor: Option<Encryptor>,
    pub encryption_level: EncryptionLevel,
    pub public_key: Option<PublicKey>,
    pub block_size: usize,
}

impl<S> EncryptionBoundSocket<S> {
    pub fn new(
        socket: S,
        encryptor: Option<Encryptor>,
        public_key: PublicKey,
        encryption_level: EncryptionLevel,
        block_size: usize,
    ) -> Self {
        Self {
            socket,
            encryptor,
            encryption_level,
            public_key: public_key.into(),
            block_size,
        }
    }

    pub fn wrap(socket: S, block_size: usize) -> Self {
        Self {
            socket,
            encryptor: None,
            encryption_level: EncryptionLevel::None,
            public_key: None,
            block_size,
        }
    }
}

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
                encryptor.decrypt(buff).map_err(|e| {
                    error!("Failed to decrypt data {e}");
                    Error::from(ErrorKind::InvalidData)
                })?;
                remove_bit_padding(buff).map_err(|e| {
                    error!("Failed to remove padding {e}");
                    Error::from(ErrorKind::InvalidData)
                })?;
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
        match (self.encryption_level, &self.encryptor) {
            (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) => {
                let packet_type = PacketType::from_bytes(buff);

                // encrypt initial packet
                if let Ok(PacketType::Read | PacketType::Write) = packet_type {
                    apply_bit_padding(
                        buff,
                        self.block_size + DATA_PACKET_HEADER_SIZE as usize
                            - FULLY_ENCODED_HEADER_SIZE,
                    )
                    .map_err(|e| {
                        error!("Failed to apply padding {e}");
                        Error::from(ErrorKind::InvalidData)
                    })?;

                    encryptor.encrypt(buff).map_err(|e| {
                        error!("Failed to encrypt data {e}");
                        Error::from(ErrorKind::InvalidData)
                    })?;
                    *buff = PacketType::InitialEncryption
                        .to_bytes()
                        .into_iter()
                        .chain(
                            self.public_key
                                .expect("Public key must be set for initial packet")
                                .as_bytes()
                                .iter()
                                .copied(),
                        )
                        .chain(encryptor.nonce)
                        .chain(buff.iter().copied())
                        .collect();
                } else {
                    apply_bit_padding(buff, self.block_size + DATA_PACKET_HEADER_SIZE as usize)
                        .map_err(|e| {
                            error!("Failed to apply padding {e}");
                            Error::from(ErrorKind::InvalidData)
                        })?;

                    encryptor.encrypt(buff).map_err(|e| {
                        error!("Failed to encrypt data {e}");
                        Error::from(ErrorKind::InvalidData)
                    })?;
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

    fn add_interest(&self, _to_socket_id: &impl ToSocketId) -> Result<()> {
        unimplemented!()
    }

    fn modify_interest(&mut self, _socket_id: usize, _raw_fd: SocketRawFd) -> Result<()> {
        unimplemented!()
    }

    fn notified(&self, _to_socket_id: &impl ToSocketId) -> bool {
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
