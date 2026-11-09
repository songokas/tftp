use core::cmp::min;
use core::fmt::Display;
use core::net::SocketAddr;
use core::time::Duration;

use log::debug;
use log::error;
use rand::CryptoRng;
use rand::RngCore;

use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::config::DEFAULT_DATA_BLOCK_SIZE;
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

/// Anyone can send a datagram to the client's port, so one that fails to decrypt
/// must not end the transfer: callers treat it as if nothing arrived.
fn ignore_datagram(error: impl Display, from: SocketAddr) -> Error {
    debug!("Ignoring datagram from {from} that failed to decrypt {error}");
    ErrorKind::WouldBlock.into()
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
                EncryptedPacket::decrypt(encryptor, buff).map_err(|e| ignore_datagram(e, s))?;
            }
            (EncryptionLevel::Data, Some(encryptor))
                if matches!(PacketType::from_bytes(buff), Ok(PacketType::Data)) =>
            {
                EncryptedDataPacket::decrypt(encryptor, buff).map_err(|e| ignore_datagram(e, s))?;
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
                    // the server has not agreed to any block size yet
                    InitialPacket::encrypt(
                        encryptor,
                        buff,
                        min(self.block_size, DEFAULT_DATA_BLOCK_SIZE)
                            + DATA_PACKET_HEADER_SIZE as u16,
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

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use rand::rngs::OsRng;

    use super::*;
    use crate::client::test_support::*;
    use crate::encryption::create_encryptor_with_auth_keys;
    use crate::encryption::SigningKey;
    use crate::encryption::VerifyingKey;

    fn encrypted_socket(
        level: EncryptionLevel,
        datagrams: [Vec<u8>; 1],
    ) -> EncryptionBoundSocket<ScriptedSocket, OsRng> {
        let server_key = VerifyingKey::from(&SigningKey::from([3; 32]));
        let (encryptor, public_key) = create_encryptor_with_auth_keys(OsRng, &server_key).unwrap();
        EncryptionBoundSocket::new(
            ScriptedSocket::from_server(datagrams),
            Some(encryptor),
            public_key,
            level,
            512,
        )
    }

    fn encrypted_request_size(block_size: u16) -> usize {
        let server_key = VerifyingKey::from(&SigningKey::from([3; 32]));
        let (encryptor, public_key) = create_encryptor_with_auth_keys(OsRng, &server_key).unwrap();
        let socket = ScriptedSocket::from_server([]);
        let sent = socket.sent.clone();
        let socket = EncryptionBoundSocket::new(
            socket,
            Some(encryptor),
            public_key,
            EncryptionLevel::Full,
            block_size,
        );
        let mut request = DataBuffer::new();
        let _ = crate::buffer::extend_from_slice(&mut request, b"\0\x01file\0octet\0", ());

        socket.send_to(&mut request, server_address()).unwrap();

        let size = sent.borrow()[0].len();
        size
    }

    #[test]
    fn test_initial_request_fits_a_server_with_default_block_size() {
        assert_eq!(encrypted_request_size(1400), 516);
    }

    #[test]
    fn test_initial_request_is_not_padded_past_a_small_block_size() {
        assert_eq!(encrypted_request_size(256), 260);
    }

    #[test]
    fn test_undecryptable_datagram_is_reported_as_nothing_received() {
        let junk = data_packet(1, &[7; 80]);
        for level in [
            EncryptionLevel::Data,
            EncryptionLevel::Protocol,
            EncryptionLevel::Full,
        ] {
            let mut socket = encrypted_socket(level, [junk.clone()]);
            let mut buffer = crate::buffer::create_max_buffer(512);

            let error = socket.recv_from(&mut buffer, None).unwrap_err();

            assert_eq!(error.kind(), ErrorKind::WouldBlock, "{level}");
        }
    }
}
