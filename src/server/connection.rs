use core::net::SocketAddr;
use core::num::NonZeroU8;
use core::time::Duration;

use log::*;
use rand::CryptoRng;
use rand::RngCore;

use crate::buffer::resize_buffer;
use crate::config::ConnectionOptions;
use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::encryption::*;
use crate::flow_control::RateControl;
use crate::metrics::counter;
use crate::metrics::histogram;
use crate::packet::ByteConverter;
use crate::packet::ErrorPacket;
use crate::packet::Packet;
use crate::packet::PacketType;
use crate::server::session_encryption;
use crate::socket::BoundSocket;
use crate::std_compat::io;
use crate::std_compat::time::Instant;
use crate::types::DataBuffer;

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
    #[allow(unused)]
    pub encryptor: Option<Encryptor<Rng>>,
    // connection last updated: valid block received, valid block acknowledged
    pub last_updated: Instant,
    /// last block index acknowledged
    pub last_acknowledged: u64,
    pub started: Instant,
    // total file size transferred
    pub transfer: usize,
    // multiplier for retry_packet_after_timeout
    pub retry_packet_multiplier: NonZeroU8,

    pub endpoint: SocketAddr,
    pub finished: bool,
    pub invalid: Option<Instant>,
    pub writer: bool,
    pub rate_control: RateControl,
    pub packets_to_send: u32,
    pub rate_period: Instant,
    pub window_sent_at: Option<Instant>,
    pub fast_retransmit: bool,
}

impl<B: BoundSocket, Rng: CryptoRng + RngCore + Copy> Connection<B, Rng> {
    pub fn recv(
        &mut self,
        buffer: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> io::Result<usize> {
        self.socket.recv(buffer, wait_for)
    }

    pub fn decrypt_packet(&self, buffer: &mut DataBuffer) -> bool {
        session_encryption::decrypt_packet(&self.options, &self.encryptor, self.endpoint, buffer)
    }

    /// A finished connection stays for retransmissions. After one retry interval
    /// a request from this address is new, not a late copy of the first one.
    #[cfg(not(feature = "multi_thread"))]
    pub fn can_be_replaced(&self) -> bool {
        (self.finished || self.invalid.is_some())
            && self.last_updated.elapsed() >= self.options.retry_packet_after_timeout
    }

    /// Sends an error to the client. Every error of a connection goes through
    /// here, so that its message fits what the client can receive.
    pub fn reply_with_error(&self, mut error: ErrorPacket, buffer: &mut DataBuffer) -> bool {
        let encrypted = self.encryptor.is_some() && self.options.encrypts_protocol_packets();
        error.limit_message(self.options.max_error_message_size(encrypted));
        self.send_packet(Packet::Error(error), buffer)
    }

    pub fn send_packet(&self, packet: Packet, buffer: &mut DataBuffer) -> bool {
        let packet_name = packet.packet_type();
        match &packet {
            Packet::Data(d) => trace!("Send {} {} to {}", packet_name, d.block, self.endpoint),
            Packet::Ack(d) => trace!("Send {} {} to {}", packet_name, d.block, self.endpoint),
            _ => trace!("Send {} to {}", packet_name, self.endpoint),
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
        if !session_encryption::encrypt_packet(&self.options, &self.encryptor, packet_name, data) {
            return false;
        }
        if let Err(e) = self.socket.send(data) {
            error!("Failed to send {} to {} {}", packet_name, self.endpoint, e);
            return false;
        }
        true
    }
}

impl<B, Rng> Drop for Connection<B, Rng> {
    fn drop(&mut self) {
        let _connection_type = if self.writer { "write" } else { "read" };
        let _error = if self.invalid.is_some() {
            "true"
        } else {
            "false"
        };
        counter!("tftp.server.connection.transfer.size", "connection_type" => _connection_type, "error" => _error)
            .increment(self.transfer as u64);
        histogram!("tftp.server.connection.duration",  "connection_type" => _connection_type, "error" =>_error)
            .record(self.started.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    use crate::client::test_support::*;
    use crate::packet::ErrorCode;
    use crate::string::format_str;
    use crate::time::test_now as instant;

    const OVERSIZED_SEND_BUFFER: usize = 64;

    fn connection(
        socket: ScriptedSocket,
        options: ConnectionOptions,
        encryptor: Option<Encryptor<OsRng>>,
    ) -> Connection<ScriptedSocket, OsRng> {
        Connection {
            socket,
            options,
            encryptor,
            last_updated: instant(),
            last_acknowledged: 0,
            started: instant(),
            transfer: 0,
            retry_packet_multiplier: NonZeroU8::new(1).unwrap(),
            endpoint: server_address(),
            finished: false,
            invalid: None,
            writer: false,
            rate_control: RateControl::new(instant),
            packets_to_send: u32::MAX,
            rate_period: instant(),
            window_sent_at: None,
            fast_retransmit: false,
        }
    }

    fn error_packet(size: usize) -> ErrorPacket {
        let message = "x".repeat(size);
        ErrorPacket::new(
            ErrorCode::Undefined,
            format_str!(DefaultString, "{message}"),
        )
    }

    fn send_error(
        options: ConnectionOptions,
        encryptor: Option<Encryptor<OsRng>>,
        message_size: usize,
    ) -> std::vec::Vec<u8> {
        let socket = ScriptedSocket::from_server([]);
        let sent = socket.sent.clone();
        let connection = connection(socket, options, encryptor);
        let mut buffer = crate::buffer::new_buffer(OVERSIZED_SEND_BUFFER);

        assert!(connection.reply_with_error(error_packet(message_size), &mut buffer));

        let sent = sent.borrow();
        assert_eq!(sent.len(), 1);
        sent[0].clone()
    }

    #[test]
    fn test_plain_error_message_is_cut_to_the_negotiated_block_size() {
        let options = ConnectionOptions::default().with_block_size(16);

        let sent = send_error(options, None, 40);

        assert_eq!(&sent[..4], &[0, 5, 0, 0]);
        assert_eq!(&sent[4..sent.len() - 1], "x".repeat(15).as_bytes());
        assert_eq!(sent[sent.len() - 1], 0);
    }

    #[test]
    fn test_plain_error_message_that_fits_the_block_size_is_kept() {
        let options = ConnectionOptions::default().with_block_size(16);

        let sent = send_error(options, None, 15);

        assert_eq!(&sent[4..sent.len() - 1], "x".repeat(15).as_bytes());
    }

    #[cfg(feature = "encryption")]
    mod encrypted {
        use chacha20poly1305::aead::KeyInit;
        use chacha20poly1305::XChaCha20Poly1305;

        use super::*;
        use crate::encrypted_packet::EncryptedPacket;

        fn encryptor(role: Role) -> Encryptor<OsRng> {
            Encryptor {
                cipher: XChaCha20Poly1305::new(&[5; 32].into()),
                rng: OsRng,
                role,
                context: [7; 32],
            }
        }

        fn options(encryption_level: EncryptionLevel) -> ConnectionOptions {
            ConnectionOptions {
                encryption_level,
                ..ConnectionOptions::default().with_block_size(64)
            }
        }

        #[test]
        fn test_encrypted_error_message_is_cut_to_the_negotiated_block_size() {
            let sent = send_error(
                options(EncryptionLevel::Full),
                Some(encryptor(Role::Server)),
                40,
            );

            assert_eq!(sent.len(), 68);
            let mut packet: DataBuffer = sent.into_iter().collect();
            EncryptedPacket::decrypt(&encryptor(Role::Client), &mut packet).unwrap();
            let Ok(Packet::Error(received)) = Packet::from_bytes(&packet) else {
                panic!("expected an error packet");
            };
            assert_eq!(received.message.as_str(), "x".repeat(22));
        }

        #[test]
        fn test_error_message_is_not_shortened_for_encryption_it_does_not_get() {
            let sent = send_error(
                options(EncryptionLevel::Data),
                Some(encryptor(Role::Server)),
                40,
            );

            assert_eq!(&sent[4..sent.len() - 1], "x".repeat(40).as_bytes());
        }
    }
}
