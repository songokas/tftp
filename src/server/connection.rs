use core::num::NonZeroU16;
use core::time::Duration;

use log::debug;
use log::error;
use rand::CryptoRng;
use rand::RngCore;

use crate::buffer::resize_buffer;
use crate::config::ConnectionOptions;

use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::encryption::*;
use crate::macros::cfg_encryption;
use crate::packet::ByteConverter;
use crate::packet::Packet;
use crate::packet::PacketType;
use crate::socket::BoundSocket;
use crate::std_compat::io;
use crate::std_compat::net::SocketAddr;
use crate::std_compat::time::Instant;
use crate::types::DataBuffer;

cfg_encryption! {
    use crate::encrypted_packet::EncryptedDataPacket;
    use crate::encrypted_packet::EncryptedPacket;
}

pub enum ClientType<R, W> {
    Reader(R),
    Writer(W),
}

pub enum ConnectionType {
    Read,
    Write,
}

pub struct Connection<B, Rng> {
    pub socket: B,
    pub options: ConnectionOptions,
    pub encryptor: Option<Encryptor<Rng>>,
    // connection last updated: valid block received, valid block acknowledged
    pub last_updated: Instant,
    /// last block index acknowledged
    pub last_acknowledged: u64,
    // total file size transferred
    pub transfer: usize,
    // multiplier for retry_packet_after_timeout
    pub retry_packet_multiplier: NonZeroU16,
    pub endpoint: SocketAddr,
    pub finished: bool,
    pub invalid: bool,
}

impl<B: BoundSocket, Rng: CryptoRng + RngCore + Copy> Connection<B, Rng> {
    pub fn recv(
        &mut self,
        buffer: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> io::Result<usize> {
        self.socket.recv(buffer, wait_for)
    }

    pub fn decrypt_packet(&self, _buffer: &mut DataBuffer) -> bool {
        #[cfg(feature = "encryption")]
        if let (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) =
            (self.options.encryption_level, &self.encryptor)
        {
            if EncryptedPacket::decrypt(encryptor, _buffer).is_err() {
                debug!(
                    "Failed to decrypt packet from {} {} {:?}",
                    self.endpoint,
                    &_buffer.len(),
                    &_buffer
                );
                return false;
            }
        }

        #[cfg(feature = "encryption")]
        if let (Ok(PacketType::Data), EncryptionLevel::Data, Some(encryptor)) = (
            PacketType::from_bytes(_buffer),
            self.options.encryption_level,
            &self.encryptor,
        ) {
            if EncryptedDataPacket::decrypt(encryptor, _buffer).is_err() {
                debug!(
                    "Failed to decrypt data from {} {} {:x?}",
                    self.endpoint,
                    &_buffer.len(),
                    &_buffer
                );
                return false;
            }
        }

        true
    }

    pub fn send_packet(&self, packet: Packet, buffer: &mut DataBuffer) -> bool {
        let packet_name = packet.packet_type();
        match &packet {
            Packet::Data(d) => debug!("Send {} {} to {}", packet_name, d.block, self.endpoint),
            Packet::Ack(d) => debug!("Send {} {} to {}", packet_name, d.block, self.endpoint),
            _ => debug!("Send {} to {}", packet_name, self.endpoint),
        };

        // ensure min buffer size
        let expected_min_buffer_size =
            DATA_PACKET_HEADER_SIZE as usize + self.options.block_size as usize;
        if buffer.len() < expected_min_buffer_size {
            resize_buffer(buffer, expected_min_buffer_size);
        }

        let Some(s) = packet.to_buffer(buffer) else {
            return false;
        };
        buffer.truncate(s);
        self.send_bytes(packet_name, buffer)
    }

    pub fn send_bytes(&self, packet_name: PacketType, data: &mut DataBuffer) -> bool {
        #[cfg(feature = "encryption")]
        if let (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) =
            (self.options.encryption_level, &self.encryptor)
        {
            if EncryptedPacket::encrypt(
                encryptor,
                data,
                self.options.block_size_with_encryption() + DATA_PACKET_HEADER_SIZE as u16,
            )
            .is_err()
            {
                error!("Failed to encrypt data {:x?}", data);
                return false;
            }
        }
        #[cfg(feature = "encryption")]
        if let (EncryptionLevel::Data, Some(encryptor), PacketType::Data) =
            (self.options.encryption_level, &self.encryptor, packet_name)
        {
            if EncryptedDataPacket::encrypt(encryptor, data).is_err() {
                error!("Failed to encrypt data {:x?}", data);
                return false;
            }
        }
        if let Err(e) = self.socket.send(data) {
            error!("Failed to send {} to {} {}", packet_name, self.endpoint, e);
            return false;
        }
        true
    }
}
