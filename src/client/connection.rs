use core::cmp::min;
use core::time::Duration;

use log::debug;
use log::error;

use super::extensions::create_extensions;
use super::extensions::parse_extensions;
use super::extensions::validate_extensions;
use super::ClientConfig;
use crate::config::ConnectionOptions;
use crate::config::DEFAULT_DATA_BLOCK_SIZE;
use crate::encryption::EncryptionLevel;
use crate::error::BoxedResult;
use crate::error::DefaultBoxedResult;
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
use crate::std_compat::net::SocketAddr;
use crate::time::InstantCallback;
use crate::types::DataBuffer;
use crate::types::DefaultString;
use crate::types::FilePath;

pub fn query_server<'a>(
    socket: &mut impl Socket,
    buffer: &mut DataBuffer,
    create_packet: impl Fn(RequestPacket) -> Packet<'a>,
    file_path: FilePath,
    options: ConnectionOptions,
    instant: InstantCallback,
    config: &ClientConfig,
) -> BoxedResult<(Option<usize>, bool, ConnectionOptions, SocketAddr)> {
    let mut extensions = create_extensions(&options);
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

        #[cfg(feature = "alloc")]
        buffer.resize(buffer_size, 0);
        // TODO heapless vector resizing is super slow
        #[cfg(not(feature = "alloc"))]
        unsafe {
            buffer.set_len(buffer_size)
        };

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
                error!("Server is using a new port, however configuration does not allow it");
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
                    socket.send_to(&mut e.to_bytes(), endpoint)?;
                    return Err(PacketError::RemoteError(message).into());
                }
                return Ok((
                    None,
                    true,
                    parse_extensions(p.extensions, options)?,
                    endpoint,
                ));
            }
            (PacketType::Write, Ok(Packet::Ack(_))) => {
                // server disregards extensions
                return Ok((
                    None,
                    false,
                    options.with_block_size(DEFAULT_DATA_BLOCK_SIZE),
                    endpoint,
                ));
            }
            (PacketType::Read, Ok(Packet::Data(_))) => {
                // server disregards extensions
                return Ok((
                    Some(length),
                    false,
                    options.with_block_size(DEFAULT_DATA_BLOCK_SIZE),
                    endpoint,
                ));
            }
            (_, Ok(Packet::Error(p))) => {
                // retry in case server does not support extensions
                if matches!(p.code, ErrorCode::IllegalOperation | ErrorCode::Undefined)
                    && initial
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

pub fn send_error(
    socket: &impl Socket,
    endpoint: SocketAddr,
    code: ErrorCode,
    message: DefaultString,
) -> DefaultBoxedResult {
    error!("{}", message);
    let packet = Packet::Error(ErrorPacket { code, message });
    socket.send_to(&mut packet.to_bytes(), endpoint)?;
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
    loop {
        socket.send_to(&mut packet.clone().to_bytes(), endpoint)?;
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
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}
