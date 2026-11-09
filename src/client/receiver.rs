use core::cmp::max;
use core::net::SocketAddr;
use core::time::Duration;

use log::debug;
use log::info;
use log::trace;
use rand::CryptoRng;
use rand::RngCore;

use super::ClientConfig;
use crate::buffer::create_max_buffer;
use crate::buffer::create_receive_buffer;
use crate::buffer::resize_buffer;
use crate::client::connection::query_server;
use crate::client::connection::reply_with_error;
use crate::client::connection::QueryOptions;
use crate::client::connection::QueryResult;
use crate::client::encryption_socket_builder::configure_socket;
use crate::client::encryption_socket_builder::create_initial_socket;
use crate::client::extensions::create_extensions;
use crate::client::extensions::ensure_block_size_fits;
use crate::config::print_options;
use crate::config::ConnectionOptions;
use crate::config::PREFERRED_DATA_BLOCK_SIZE;
use crate::encryption::VerifyingKey;
use crate::error::BoxedResult;
use crate::error::DefaultBoxedResult;
use crate::error::PacketError;
use crate::error::StorageError;
use crate::metrics::counter;
use crate::metrics::histogram;
use crate::packet::AckPacket;
use crate::packet::ByteConverter;
use crate::packet::ErrorCode;
use crate::packet::ErrorPacket;
use crate::packet::Packet;
use crate::packet::PacketType;
use crate::packet::SignedRequest;
use crate::socket::Socket;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::io::Write;
use crate::string::format_str;
use crate::time::InstantCallback;
use crate::types::FilePath;
use crate::writers::block_writer::BlockWriter;
use crate::writers::single_block_writer::SingleBlockWriter;

#[allow(clippy::too_many_arguments)]
pub fn receive_file<CreateWriter, Sock, W, Rng>(
    config: ClientConfig,
    local_file_path: FilePath,
    remote_file_path: FilePath,
    mut options: ConnectionOptions,
    create_writer: CreateWriter,
    socket: Sock,
    instant: InstantCallback,
    _rng: Rng,
) -> BoxedResult<(usize, Option<VerifyingKey>)>
where
    W: Write,
    Rng: CryptoRng + RngCore + Copy,
    Sock: Socket,
    CreateWriter: FnOnce(&FilePath) -> BoxedResult<W>,
{
    ensure_block_size_fits(options.block_size)?;

    if let Ok(s) = socket.local_addr() {
        info!("Listening on {} connecting to {}", s, config.endpoint);
    }

    let mut receive_buffer = create_max_buffer(max(PREFERRED_DATA_BLOCK_SIZE, options.block_size));
    let receive_max_buffer_size = receive_buffer.len();

    debug!(
        "Preparing to receive {} as {} max buffer {}",
        remote_file_path, local_file_path, receive_max_buffer_size
    );

    let (mut socket, initial_keys) = create_initial_socket(socket, &config, &mut options, _rng)?;

    let initial_rtt = instant();
    let request = SignedRequest {
        packet_type: PacketType::Read,
        file_name: remote_file_path.as_str(),
    };
    let extensions = create_extensions(&options, initial_keys.as_ref(), request);
    let QueryResult {
        mut received_length,
        acknowledge,
        options,
        endpoint,
        remote_session_public_keys,
    } = query_server(
        &mut socket,
        &mut receive_buffer,
        Packet::Read,
        instant,
        QueryOptions {
            file_path: &remote_file_path,
            options,
            config: &config,
            extensions,
        },
    )?;

    debug!(
        "Initial exchange took {}",
        initial_rtt.elapsed().as_secs_f32()
    );

    histogram!("tftp.client.handshake.duration", "connection_type" => "read")
        .record(initial_rtt.elapsed());

    let (mut socket, options) = configure_socket(
        socket,
        initial_keys,
        options,
        _rng,
        remote_session_public_keys.as_ref(),
        request,
    )?;

    if let Some(file_size) = options.file_size {
        handle_file_size(&socket, endpoint, &options, file_size, config.max_file_size)?;
    }

    let writer = create_writer(&local_file_path)?;
    let mut block_writer = SingleBlockWriter::new(writer);

    let mut last_block_ack = 0;
    let mut total = 0;
    let started = instant();

    // server sent data packet so no encryption
    if let Some(packet_length) = received_length.take() {
        if let Ok(Packet::Data(p)) = Packet::from_bytes(&receive_buffer[..packet_length]) {
            if p.data.len() > options.block_size_with_encryption() as usize {
                return Err(PacketError::Invalid.into());
            }
            handle_file_size(
                &socket,
                endpoint,
                &options,
                p.data.len() as u64,
                config.max_file_size,
            )?;
            match write_block(&mut block_writer, p.block, p.data) {
                Ok((written, index, block)) => {
                    if let Some(w) = written {
                        total += w;
                    }

                    if options.window_size <= 1
                        || last_block_ack + options.window_size as u64 == index
                        || written.unwrap_or(0) < options.block_size_with_encryption() as usize
                    {
                        trace!("Ack send {}", block);
                        let packet = Packet::Ack(AckPacket { block });
                        socket.send_to(&mut packet.to_bytes(), endpoint)?;
                        last_block_ack = index;
                    }
                }
                Err(e) => return Err(e),
            };

            if p.data.len() < options.block_size_with_encryption() as usize {
                info!("Client finished receiving {local_file_path} {total} bytes");
                histogram!("tftp.client.connection.duration", "connection_type" => "read")
                    .record(started.elapsed());
                counter!("tftp.client.connection.transfer.size", "connection_type" => "read")
                    .increment(total as u64);
                return Ok((total, None));
            }
        }
    }

    print_options("Client using", &options);

    if acknowledge {
        let packet = Packet::Ack(AckPacket { block: 0 });
        socket.send_to(&mut packet.to_bytes(), endpoint)?;
    }

    let mut timeout = instant();
    // buffer will change based on options.block_size
    let mut receive_buffer = create_receive_buffer(options.block_size);
    let max_receive_buffer_size = receive_buffer.len();

    let mut send_buffer = create_max_buffer(options.block_size);

    loop {
        let elapsed = timeout.elapsed();
        if elapsed > config.request_timeout {
            if let Ok(s) = socket.local_addr() {
                debug!("Received timeout for {}", s);
            }
            return Err(PacketError::Timeout(elapsed).into());
        }

        resize_buffer(&mut receive_buffer, max_receive_buffer_size);

        let received = match socket.recv_from(&mut receive_buffer, Duration::from_secs(1).into()) {
            Ok((n, s)) => {
                if s != endpoint {
                    continue;
                }
                n
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => {
                return Err(e.into());
            }
        };
        receive_buffer.truncate(received);

        if !matches!(
            PacketType::from_bytes(&receive_buffer),
            Ok(PacketType::Data | PacketType::Error)
        ) {
            debug!("Incorrect packet received {:x?}", receive_buffer);
            continue;
        }

        let result = match Packet::from_bytes(&receive_buffer) {
            Ok(Packet::Data(p)) => {
                debug!("Received block {} data size {}", p.block, p.data.len());
                if p.data.len() > options.block_size_with_encryption() as usize {
                    debug!("Ignoring data larger than the block size");
                    continue;
                }
                if block_writer.is_next_block(p.block) {
                    let new_size = (total + p.data.len()) as u64;
                    handle_file_size(&socket, endpoint, &options, new_size, config.max_file_size)?;
                }
                write_block(&mut block_writer, p.block, p.data)
            }
            Ok(Packet::Error(p)) => {
                return Err(PacketError::RemoteError(p.message).into());
            }
            _ => {
                debug!("Incorrect packet received {:x?}", receive_buffer);
                continue;
            }
        };

        match result {
            Ok((written, index, block)) => {
                if options.window_size <= 1
                    || last_block_ack + options.window_size as u64 == index
                    || written.unwrap_or(0) < options.block_size_with_encryption() as usize
                {
                    debug!("Ack send {}", block);
                    let packet = Packet::Ack(AckPacket { block });
                    let size = packet.to_buffer(&mut send_buffer).expect("valid buffer");
                    send_buffer.truncate(size);
                    socket.send_to(&mut send_buffer, endpoint)?;
                    last_block_ack = index;
                }
                if let Some(w) = written {
                    timeout = instant();
                    total += w;

                    if w < options.block_size_with_encryption() as usize {
                        info!("Client finished receiving {local_file_path} {total} bytes");
                        histogram!("tftp.client.connection.duration", "connection_type" => "read")
                            .record(started.elapsed());
                        counter!("tftp.client.connection.transfer.size", "connection_type" => "read")
                            .increment(total as u64);
                        return Ok((total, remote_session_public_keys.and_then(|p| p.auth)));
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
}

fn write_block(
    block_writer: &mut impl BlockWriter,
    block: u16,
    data: &[u8],
) -> BoxedResult<(Option<usize>, u64, u16)> {
    match block_writer.write_block(block, data) {
        Ok((written, index)) => Ok((Some(written), index, block)),
        Err(StorageError::ExpectedBlock(e)) => {
            debug!(
                "Received unexpected block {} expecting block after {}",
                block, e.current
            );
            Ok((None, e.current_index, e.current))
        }
        Err(StorageError::AlreadyWritten(e)) => {
            debug!(
                "Received block that was written before. Ignoring block {}",
                block
            );
            Ok((None, e.current_index, e.current))
        }
        Err(e) => Err(e.into()),
    }
}

fn handle_file_size(
    socket: &impl Socket,
    endpoint: SocketAddr,
    options: &ConnectionOptions,
    data_length: u64,
    max_file_size: u64,
) -> DefaultBoxedResult {
    if data_length > max_file_size {
        let message = format_str!(
            DefaultString,
            "Invalid file size received {} expected {}",
            data_length,
            max_file_size
        );
        let packet = ErrorPacket::new(ErrorCode::DiskFull, message);
        reply_with_error(socket, endpoint, options, packet)?;
        return Err(PacketError::Invalid.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    use crate::client::test_support::*;
    use crate::config::DEFAULT_DATA_BLOCK_SIZE;
    use crate::config::MAX_DATA_BLOCK_SIZE;
    use crate::string::format_str;
    use crate::time::test_now as instant;

    fn receive(
        socket: ScriptedSocket,
        options: ConnectionOptions,
    ) -> (BoxedResult<usize>, MemoryFile) {
        receive_with(client_config(), socket, options)
    }

    fn receive_with(
        config: ClientConfig,
        socket: ScriptedSocket,
        options: ConnectionOptions,
    ) -> (BoxedResult<usize>, MemoryFile) {
        let file = MemoryFile::default();
        let writer = file.clone();
        let result = receive_file(
            config,
            format_str!(FilePath, "local"),
            format_str!(FilePath, "remote"),
            options,
            move |_: &FilePath| Ok(writer),
            socket,
            instant,
            OsRng,
        );
        (result.map(|(total, _)| total), file)
    }

    /// Meaningful with `TFTP_MAX_BLOCK_SIZE` below 512, see `./test test_lib`.
    #[test]
    fn test_low_block_limit_default_block_size_is_an_error() {
        if DEFAULT_DATA_BLOCK_SIZE <= MAX_DATA_BLOCK_SIZE {
            return;
        }
        let (result, _) = receive(ScriptedSocket::from_server([]), Default::default());
        assert!(result.is_err());
    }

    /// Meaningful with `TFTP_MAX_BLOCK_SIZE` below 512, see `./test test_lib`.
    #[test]
    fn test_low_block_limit_server_ignoring_blksize_is_an_error() {
        if DEFAULT_DATA_BLOCK_SIZE <= MAX_DATA_BLOCK_SIZE {
            return;
        }
        let options = ConnectionOptions::default().with_block_size(MAX_DATA_BLOCK_SIZE);
        let socket = ScriptedSocket::from_server([data_packet(1, &[7; 10])]);

        let (result, file) = receive(socket, options);

        assert!(result.is_err());
        assert!(file.0.borrow().is_empty());
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_required_encryption_refuses_plain_data() {
        use crate::encryption::EncryptionLevel;

        for encryption_level in [EncryptionLevel::Data, EncryptionLevel::Protocol] {
            let options = ConnectionOptions {
                encryption_level,
                ..Default::default()
            };
            let socket = ScriptedSocket::from_server([data_packet(1, &[7; 10])]);

            let (result, file) = receive(socket, options);

            assert!(result.is_err(), "{encryption_level}");
            assert!(file.0.borrow().is_empty(), "{encryption_level}");
        }
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_low_order_key_from_server_ends_the_transfer() {
        use crate::encryption::EncryptionLevel;

        let mut oack = vec![0, 6];
        oack.extend_from_slice(b"enclevel\0data\0spubk\0");
        oack.extend_from_slice(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\0");
        let options = ConnectionOptions {
            encryption_level: EncryptionLevel::Data,
            ..Default::default()
        };
        let socket = ScriptedSocket::from_server([oack]);
        let sent = socket.sent.clone();

        let (result, _) = receive(socket, options);

        assert!(result.is_err());
        assert!(!sent.borrow().iter().any(|p| p.as_slice() == ack_packet(0)));
    }

    /// Returns whether the first request left in plaintext, for a data level
    /// client pinned to a server key.
    #[cfg(feature = "encryption")]
    fn pinned_data_request_is_plain(private_key: Option<[u8; 32]>) -> bool {
        use crate::encryption::EncryptionLevel;
        use crate::encryption::SigningKey;
        use crate::encryption::VerifyingKey;

        let server_key = SigningKey::from([3; 32]);
        let config = ClientConfig {
            private_key: private_key.map(SigningKey::from),
            remote_public_key: Some(VerifyingKey::from(&server_key)),
            ..client_config()
        };
        let options = ConnectionOptions {
            encryption_level: EncryptionLevel::Data,
            ..Default::default()
        };
        let socket = ScriptedSocket::from_server([]);
        let sent = socket.sent.clone();

        let _ = receive_with(config, socket, options);

        let is_plain = sent.borrow()[0].starts_with(&[0, 1]);
        is_plain
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_pinned_key_without_private_key_encrypts_request() {
        assert!(!pinned_data_request_is_plain(None));
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_pinned_key_with_private_key_keeps_data_level() {
        assert!(pinned_data_request_is_plain(Some([4; 32])));
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_optional_encryption_accepts_plain_data() {
        use crate::encryption::EncryptionLevel;

        let options = ConnectionOptions {
            encryption_level: EncryptionLevel::OptionalData,
            ..Default::default()
        };
        let socket = ScriptedSocket::from_server([data_packet(1, &[7; 10])]);

        let (result, file) = receive(socket, options);

        assert_eq!(result.unwrap(), 10);
        assert_eq!(file.0.borrow().len(), 10);
    }

    #[test]
    fn test_datagram_from_another_host_does_not_shrink_handshake_buffer() {
        let socket = ScriptedSocket::new([
            Incoming::Datagram(vec![1], other_address()),
            Incoming::Datagram(data_packet(1, &[7; 10]), server_address()),
        ]);

        let (result, file) = receive(socket, ConnectionOptions::default());

        assert_eq!(result.unwrap(), 10);
        assert_eq!(file.0.borrow().len(), 10);
    }

    #[test]
    fn test_server_without_options_is_acknowledged_every_block() {
        let options = ConnectionOptions {
            window_size: 8,
            ..Default::default()
        };
        let socket =
            ScriptedSocket::from_server([data_packet(1, &[7; 512]), data_packet(2, &[8; 10])]);
        let sent = socket.sent.clone();

        let (result, _) = receive(socket, options);

        assert_eq!(result.unwrap(), 522);
        assert!(sent.borrow().iter().any(|p| p.as_slice() == ack_packet(1)));
    }

    #[test]
    fn test_oversized_transfer_leaves_local_file_untouched() {
        let mut oack = vec![0, 6];
        oack.extend_from_slice(b"tsize\x002097152\0");
        let options = ConnectionOptions {
            file_size: Some(0),
            ..Default::default()
        };
        let created = core::cell::Cell::new(false);

        let result = receive_file(
            client_config(),
            format_str!(FilePath, "local"),
            format_str!(FilePath, "remote"),
            options,
            |_: &FilePath| {
                created.set(true);
                Ok(MemoryFile::default())
            },
            ScriptedSocket::from_server([oack]),
            instant,
            OsRng,
        );

        assert!(result.is_err());
        assert!(!created.get());
    }

    #[test]
    fn test_error_message_for_a_file_too_large_fits_the_block_size() {
        let socket = ScriptedSocket::from_server([]);
        let sent = socket.sent.clone();
        let options = ConnectionOptions::default().with_block_size(16);

        let result = handle_file_size(&socket, server_address(), &options, 10, 1);

        assert!(result.is_err());
        let sent = sent.borrow();
        assert_eq!(&sent[0][4..sent[0].len() - 1], b"Invalid file si");
    }

    #[test]
    fn test_block_past_max_file_size_is_not_written() {
        let config = ClientConfig {
            max_file_size: 600,
            ..client_config()
        };
        let socket =
            ScriptedSocket::from_server([data_packet(1, &[7; 512]), data_packet(2, &[8; 512])]);

        let (result, file) = receive_with(config, socket, Default::default());

        assert!(result.is_err());
        assert_eq!(file.0.borrow().len(), 512);
    }

    fn short_timeout_config() -> ClientConfig {
        ClientConfig {
            request_timeout: Duration::from_millis(30),
            ..client_config()
        }
    }

    #[test]
    fn test_stray_datagrams_do_not_hold_off_the_handshake_timeout() {
        let mut socket =
            ScriptedSocket::new((0..20).map(|_| Incoming::Datagram(vec![1], other_address())));
        socket.delay = Duration::from_millis(10);
        let sent = socket.sent.clone();

        let (result, _) = receive_with(short_timeout_config(), socket, Default::default());

        assert!(timed_out(&result));
        assert_eq!(sent.borrow().len(), 1, "stray datagrams must not resend");
    }

    #[test]
    fn test_stray_datagrams_do_not_hold_off_the_receive_timeout() {
        let mut incoming = vec![Incoming::Datagram(
            data_packet(1, &[7; 512]),
            server_address(),
        )];
        incoming.extend((0..20).map(|_| Incoming::Datagram(vec![1], other_address())));
        let mut socket = ScriptedSocket::new(incoming);
        socket.delay = Duration::from_millis(10);

        let (result, _) = receive_with(short_timeout_config(), socket, Default::default());

        assert!(timed_out(&result));
    }

    #[test]
    fn test_full_first_block_from_server_without_options_continues() {
        let socket =
            ScriptedSocket::from_server([data_packet(1, &[7; 512]), data_packet(2, &[8; 10])]);

        let (result, file) = receive(socket, ConnectionOptions::default());

        assert_eq!(result.unwrap(), 522);
        assert_eq!(file.0.borrow().len(), 522);
    }

    #[test]
    fn test_first_block_larger_than_a_block_is_refused() {
        let socket = ScriptedSocket::from_server([data_packet(1, &[7; 600])]);

        let (result, file) = receive(socket, ConnectionOptions::default());

        assert!(result.is_err());
        assert!(file.0.borrow().is_empty());
    }

    #[test]
    fn test_short_first_block_from_server_without_options_finishes() {
        let socket = ScriptedSocket::from_server([data_packet(1, &[7; 508])]);

        let (result, file) = receive(socket, ConnectionOptions::default());

        assert_eq!(result.unwrap(), 508);
        assert_eq!(file.0.borrow().len(), 508);
    }
}
