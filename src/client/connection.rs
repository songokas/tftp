use core::cmp::min;
use core::net::SocketAddr;
use core::time::Duration;

use log::debug;
use log::error;

use super::extensions::ensure_block_size_fits;
use super::extensions::parse_extensions;
use super::extensions::validate_extensions;
use super::ClientConfig;
use crate::buffer::resize_buffer;
use crate::config::ConnectionOptions;
use crate::config::DEFAULT_DATA_BLOCK_SIZE;
use crate::config::EXTENSION_WINDOW_SIZE_MIN;
use crate::encryption::EncryptionLevel;
use crate::encryption::PublicKeyPair;
use crate::error::BoxedResult;
use crate::error::DefaultBoxedResult;
use crate::error::ExtensionError;
use crate::error::PacketError;
use crate::packet::ByteConverter;
use crate::packet::ErrorCode;
use crate::packet::ErrorPacket;
use crate::packet::Mode;
use crate::packet::Packet;
use crate::packet::PacketExtensions;
use crate::packet::PacketType;
use crate::packet::RequestPacket;
use crate::socket::Socket;
use crate::std_compat::io::ErrorKind;
use crate::string::format_str;
use crate::time::InstantCallback;
use crate::types::DataBuffer;
use crate::types::FilePath;

pub struct QueryResult {
    pub received_length: Option<usize>,
    pub acknowledge: bool,
    pub options: ConnectionOptions,
    pub endpoint: SocketAddr,
    pub remote_session_public_keys: Option<PublicKeyPair>,
}

pub struct QueryOptions<'a> {
    pub file_path: &'a FilePath,
    pub options: ConnectionOptions,
    pub config: &'a ClientConfig,
    pub extensions: PacketExtensions,
}

pub fn query_server<'a>(
    socket: &mut impl Socket,
    buffer: &mut DataBuffer,
    create_packet: impl Fn(RequestPacket) -> Packet<'a>,
    instant: InstantCallback,
    query_options: QueryOptions,
) -> BoxedResult<QueryResult> {
    let QueryOptions {
        file_path,
        options,
        config,
        mut extensions,
    } = query_options;
    let mut used_extensions = extensions.clone();
    let mut initial = true;

    let request_timeout = config.request_timeout;
    let buffer_size = buffer.len();

    loop {
        let request_packet = RequestPacket {
            file_name: file_path.clone(),
            mode: Mode::Octet,
            extensions,
        };
        let packet = create_packet(request_packet);
        let packet_type = packet.packet_type();

        resize_buffer(buffer, buffer_size);

        let (length, endpoint) = wait_for_initial_packet(
            socket,
            config.endpoint,
            packet,
            buffer,
            request_timeout,
            instant,
            options.retry_packet_after_timeout,
        )?;
        if config.endpoint != endpoint {
            if !config.allow_server_port_change {
                error!("Server is using a new port, however configuration does not allow it. Pass allow-server-port-change");
                return Err(PacketError::Invalid.into());
            } else {
                debug!("Using new endpoint {}", endpoint);
            }
        }

        let data = &mut buffer[..length];
        match (packet_type, Packet::from_bytes(data)) {
            (_, Ok(Packet::OptionalAck(p))) => {
                if let Err(e) = validate_extensions(&p.extensions, &used_extensions) {
                    let message = e.message.clone();
                    reply_with_error(&*socket, endpoint, &options, e)?;
                    return Err(PacketError::RemoteError(message).into());
                }
                let (conn, remote_session_public_keys) = parse_extensions(p.extensions, options)?;
                // if we know server public key and server should reply with one it must match
                if conn.encryption_level != EncryptionLevel::None
                    && config.private_key.is_some()
                    && config.remote_public_key.is_some()
                    && config.remote_public_key.as_ref()
                        != remote_session_public_keys
                            .as_ref()
                            .and_then(|k| k.auth.as_ref())
                {
                    return Err(PacketError::RemoteError(format_str!(
                        DefaultString,
                        "Unexpected remote public key received"
                    ))
                    .into());
                }
                return Ok(QueryResult {
                    received_length: None,
                    acknowledge: true,
                    options: conn,
                    endpoint,
                    remote_session_public_keys,
                });
            }
            (PacketType::Write, Ok(Packet::Ack(_))) => {
                // server disregards extensions
                return Ok(QueryResult {
                    received_length: None,
                    acknowledge: false,
                    options: options_for_plain_reply(options)?,
                    endpoint,
                    remote_session_public_keys: None,
                });
            }
            (PacketType::Read, Ok(Packet::Data(_))) => {
                // server disregards extensions
                return Ok(QueryResult {
                    received_length: Some(length),
                    acknowledge: false,
                    options: options_for_plain_reply(options)?,
                    endpoint,
                    remote_session_public_keys: None,
                });
            }
            (_, Ok(Packet::Error(p))) => {
                // retry in case server does not support extensions
                if matches!(
                    p.code,
                    ErrorCode::OptionNegotiation
                        | ErrorCode::IllegalOperation
                        | ErrorCode::Undefined
                ) && initial
                    && options.encryption_level == EncryptionLevel::None
                {
                    debug!("Received error {} retrying without extensions", p.message);
                    extensions = PacketExtensions::new();
                    used_extensions = Default::default();
                    initial = false;
                    continue;
                }
                return Err(PacketError::RemoteError(p.message).into());
            }
            _ => {
                debug!("Incorrect packet received {:x?}", data);
                return Err(PacketError::Invalid.into());
            }
        }
    }
}

/// Options for a server that answered without acknowledging any extension,
/// which also means it did not agree to encrypt anything.
fn options_for_plain_reply(
    options: ConnectionOptions,
) -> Result<ConnectionOptions, ExtensionError> {
    if matches!(
        options.encryption_level,
        EncryptionLevel::Data | EncryptionLevel::Protocol | EncryptionLevel::Full
    ) {
        return Err(ExtensionError::ClientRequiredEncryption(
            options.encryption_level,
        ));
    }
    ensure_block_size_fits(DEFAULT_DATA_BLOCK_SIZE)?;
    Ok(ConnectionOptions {
        window_size: EXTENSION_WINDOW_SIZE_MIN,
        ..options.with_block_size(DEFAULT_DATA_BLOCK_SIZE)
    })
}

/// Sends an error to the server. Every error of the client goes through here,
/// so that its message fits what the server can receive.
pub fn reply_with_error(
    socket: &impl Socket,
    endpoint: SocketAddr,
    options: &ConnectionOptions,
    mut packet: ErrorPacket,
) -> DefaultBoxedResult {
    error!("{}", packet.message);
    packet.limit_message(options.max_error_message_size(options.encrypts_protocol_packets()));
    socket.send_to(&mut Packet::Error(packet).to_bytes(), endpoint)?;
    Ok(())
}

fn wait_for_initial_packet(
    socket: &mut impl Socket,
    endpoint: SocketAddr,
    packet: Packet,
    buffer: &mut DataBuffer,
    request_timeout: Duration,
    instant: InstantCallback,
    mut retry_timeout: Duration,
) -> BoxedResult<(usize, SocketAddr)> {
    let timeout = instant();
    let buffer_size = buffer.len();
    let mut last_sent = instant();
    let mut send_request = true;
    loop {
        // a socket can leave the buffer at the size of the last datagram
        resize_buffer(buffer, buffer_size);
        if send_request {
            socket.send_to(&mut packet.clone().to_bytes(), endpoint)?;
            last_sent = instant();
        }
        debug!(
            "Initial packet elapsed {} wait {}",
            timeout.elapsed().as_secs_f32(),
            retry_timeout.as_secs_f32()
        );

        match socket.recv_from(buffer, retry_timeout.into()) {
            Ok((n, s)) => {
                if s.ip() == endpoint.ip() {
                    return Ok((n, s));
                }
                let elapsed = timeout.elapsed();
                if elapsed > request_timeout {
                    return Err(PacketError::Timeout(elapsed).into());
                }
                send_request = last_sent.elapsed() >= retry_timeout;
                continue;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                let elapsed = timeout.elapsed();
                if elapsed > request_timeout {
                    return Err(PacketError::Timeout(elapsed).into());
                }
                retry_timeout = min(
                    request_timeout.saturating_sub(elapsed),
                    retry_timeout.saturating_mul(2),
                );
                send_request = true;
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_support::*;

    fn reply(options: ConnectionOptions, message_size: usize) -> std::vec::Vec<u8> {
        let socket = ScriptedSocket::from_server([]);
        let sent = socket.sent.clone();
        let long = "x".repeat(message_size);
        let packet = ErrorPacket::new(ErrorCode::Undefined, format_str!(DefaultString, "{long}"));

        reply_with_error(&socket, server_address(), &options, packet).unwrap();

        let sent = sent.borrow();
        assert_eq!(sent.len(), 1);
        sent[0].clone()
    }

    #[test]
    fn test_plain_error_message_is_cut_to_the_block_size() {
        let sent = reply(ConnectionOptions::default().with_block_size(16), 40);

        assert_eq!(&sent[4..sent.len() - 1], "x".repeat(15).as_bytes());
        assert_eq!(sent[sent.len() - 1], 0);
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_encrypted_error_message_leaves_room_for_encryption() {
        let options = ConnectionOptions {
            encryption_level: EncryptionLevel::Full,
            ..ConnectionOptions::default().with_block_size(64)
        };

        let sent = reply(options, 40);

        assert_eq!(&sent[4..sent.len() - 1], "x".repeat(22).as_bytes());
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_error_message_is_not_shortened_for_encryption_it_does_not_get() {
        let options = ConnectionOptions {
            encryption_level: EncryptionLevel::Data,
            ..ConnectionOptions::default().with_block_size(64)
        };

        let sent = reply(options, 40);

        assert_eq!(&sent[4..sent.len() - 1], "x".repeat(40).as_bytes());
    }
}
