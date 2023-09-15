use core::num::NonZeroU16;
use core::time::Duration;

use log::debug;
use log::error;

use crate::config::ConnectionOptions;
use crate::encryption::*;
use crate::macros::cfg_encryption;
use crate::packet::ByteConverter;
use crate::packet::Packet;
use crate::socket::BoundSocket;
use crate::std_compat::io;
use crate::std_compat::net::SocketAddr;
use crate::std_compat::time::Instant;
use crate::types::DataBuffer;

cfg_encryption! {
    use crate::packet::PacketType;
}

pub enum ClientType<R, W> {
    Reader(R),
    Writer(W),
}

pub enum ConnectionType {
    Read,
    Write,
}

pub struct Connection<B> {
    pub socket: B,
    pub options: ConnectionOptions,
    pub encryptor: Option<Encryptor>,
    // conection last updated: valid block received, valid block acknoledged
    pub last_updated: Instant,
    /// last block index acknoledged
    pub last_acknoledged: u64,
    // total file size transferred
    pub transfer: usize,
    // multiplier for retry_packet_after_timeout
    pub retry_packet_multiplier: NonZeroU16,
    pub endpoint: SocketAddr,
    pub finished: bool,
    pub invalid: bool,
}

impl<B: BoundSocket> Connection<B> {
    pub fn recv(&self, buffer: &mut DataBuffer, wait_for: Option<Duration>) -> io::Result<usize> {
        self.socket.recv(buffer, wait_for)
    }

    pub fn decrypt_packet(&self, _buffer: &mut DataBuffer) -> bool {
        #[cfg(feature = "encryption")]
        if let (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) =
            (self.options.encryption_level, &self.encryptor)
        {
            if encryptor.decrypt(_buffer).is_err() {
                debug!(
                    "Failed to decrypt packet from {} {} {:x?}",
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
            if overwrite_data_packet(_buffer, |buf| encryptor.decrypt(buf)).is_err() {
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

    pub fn send_packet(&self, packet: Packet) -> bool {
        let packet_name = packet.packet_type();
        match &packet {
            Packet::Data(d) => debug!("Send {} {} to {}", packet_name, d.block, self.endpoint),
            Packet::Ack(d) => debug!("Send {} {} to {}", packet_name, d.block, self.endpoint),
            _ => debug!("Send {} to {}", packet_name, self.endpoint),
        };

        let mut data = packet.to_bytes();

        #[cfg(feature = "encryption")]
        if let (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) =
            (self.options.encryption_level, &self.encryptor)
        {
            if encryptor.encrypt(&mut data).is_err() {
                error!("Failed to encrypt data {:x?}", &data);
                return false;
            }
        }
        #[cfg(feature = "encryption")]
        if let (EncryptionLevel::Data, Some(encryptor)) =
            (self.options.encryption_level, &self.encryptor)
        {
            if overwrite_data_packet(&mut data, |buf| encryptor.encrypt(buf)).is_err() {
                error!("Failed to encrypt data {:x?}", &data);
                return false;
            }
        }
        if let Err(e) = self.socket.send(&mut data) {
            error!("Failed to send {} to {} {}", packet_name, self.endpoint, e);
            return false;
        }
        true
    }
}
