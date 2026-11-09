use core::cmp::max;
use core::mem;
use core::num::Wrapping;
use core::time::Duration;

use log::debug;
use log::info;
use log::trace;
use rand::CryptoRng;
use rand::RngCore;

use super::ClientConfig;
use crate::block_mapper::block_index;
use crate::buffer::create_max_buffer;
use crate::buffer::resize_buffer;
use crate::client::connection::query_server;
use crate::client::connection::QueryOptions;
use crate::client::connection::QueryResult;
use crate::client::encryption_socket_builder::configure_socket;
use crate::client::encryption_socket_builder::create_initial_socket;
use crate::client::extensions::create_extensions;
use crate::client::extensions::ensure_block_size_fits;
use crate::config::print_options;
use crate::config::ConnectionOptions;
use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::config::PREFERRED_DATA_BLOCK_SIZE;
use crate::encryption::VerifyingKey;
use crate::error::BoxedResult;
use crate::error::PacketError;
use crate::error::StorageError;
use crate::features::FileReader;
use crate::features::SEEK_ENABLED;
use crate::flow_control::RateControl;
use crate::flow_control::FLOW_CONTROL_PERIOD;
use crate::metrics::counter;
use crate::metrics::histogram;
use crate::packet::prepend_data_header;
use crate::packet::ByteConverter;
use crate::packet::Packet;
use crate::packet::PacketType;
use crate::packet::SignedRequest;
use crate::readers::block_reader::BlockReader;
use crate::readers::multiple_block_reader::MultipleBlockReader;
use crate::readers::single_block_reader::SingleBlockReader;
use crate::readers::Readers;
use crate::socket::Socket;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::time::Instant;
use crate::time::InstantCallback;
use crate::types::FilePath;

#[allow(clippy::too_many_arguments)]
pub fn send_file<CreateReader, R: FileReader, Sock, Rng>(
    config: ClientConfig,
    local_file_path: FilePath,
    remote_file_path: FilePath,
    mut options: ConnectionOptions,
    create_reader: CreateReader,
    socket: Sock,
    instant: InstantCallback,
    _rng: Rng,
) -> BoxedResult<(usize, Option<VerifyingKey>)>
where
    Sock: Socket,
    Rng: CryptoRng + RngCore + Copy,
    CreateReader: FnOnce(&FilePath) -> BoxedResult<(Option<u64>, R)>,
{
    ensure_block_size_fits(options.block_size)?;

    if let Ok(s) = socket.local_addr() {
        info!("Listening on {} connecting to {}", s, config.endpoint);
    }
    debug!(
        "Preparing to send {} as {}",
        local_file_path, remote_file_path
    );

    let (mut socket, initial_keys) = create_initial_socket(socket, &config, &mut options, _rng)?;

    let (file_size, reader) = create_reader(&local_file_path)?;
    if file_size > Some(0) {
        options.file_size = file_size;
    }

    let mut receive_buffer = create_max_buffer(max(PREFERRED_DATA_BLOCK_SIZE, options.block_size));

    let mut rate_control = RateControl::new(instant);

    rate_control.start_rtt(1);

    let request = SignedRequest {
        packet_type: PacketType::Write,
        file_name: remote_file_path.as_str(),
    };
    let extensions = create_extensions(&options, initial_keys.as_ref(), request);

    let QueryResult {
        received_length: _,
        acknowledge: _,
        options,
        endpoint,
        remote_session_public_keys,
    } = query_server(
        &mut socket,
        &mut receive_buffer,
        Packet::Write,
        instant,
        QueryOptions {
            file_path: &remote_file_path,
            options,
            config: &config,
            extensions,
        },
    )?;

    let initial_rtt = rate_control
        .end_rtt(1)
        .unwrap_or_else(|| Duration::from_millis(1));

    debug!("Initial exchange took {}", initial_rtt.as_secs_f32());
    histogram!("tftp.client.handshake.duration", "connection_type" => "write").record(initial_rtt);

    let (mut socket, options) = configure_socket(
        socket,
        initial_keys,
        options,
        _rng,
        remote_session_public_keys.as_ref(),
        request,
    )?;

    print_options("Client using", &options);
    rate_control.configure(options.block_size, options.window_size);

    let mut readers = block_reader(reader, &options, config.prefer_seek);
    let block_reader: &mut dyn BlockReader = match &mut readers {
        Readers::Single(r) => r,
        Readers::Multiple(r) => r,
        Readers::Seek(r) => r,
    };

    let mut total_confirmed = 0;
    let mut total_unconfirmed = 0;

    let mut no_work = Wrapping(0_u8);
    let mut last_acknowledged = 0;

    let mut fast_retransmit = false;
    let mut window_sent_at: Option<Instant> = None;
    let mut stats_calculate = instant();
    let mut packets_to_send = rate_control.packets_to_send(FLOW_CONTROL_PERIOD, options.block_size);

    // buffer will change based on options.block_size
    let mut receive_buffer = create_max_buffer(options.block_size);
    let receive_max_buffer_size = receive_buffer.len();

    let mut send_buffer = create_max_buffer(options.block_size);
    let send_max_buffer_size = send_buffer.len();

    let started = instant();
    let mut timeout = instant();
    let mut last_sent = instant();
    let mut last_received = instant();

    loop {
        let elapsed = timeout.elapsed();
        if elapsed > config.request_timeout {
            if let Ok(s) = socket.local_addr() {
                debug!("Send timeout for {}", s);
            }
            return Err(PacketError::Timeout(elapsed).into());
        }

        if stats_calculate.elapsed() > FLOW_CONTROL_PERIOD {
            packets_to_send =
                rate_control.packets_to_send(stats_calculate.elapsed(), options.block_size);
            stats_calculate = instant();
        }

        resize_buffer(&mut send_buffer, send_max_buffer_size);

        if packets_to_send == 0 {
            no_work += 1;
        } else {
            let timeout_interval = rate_control
                .timeout_interval(options.retry_packet_after_timeout, options.block_size);

            let timeout_retry = window_sent_at
                .as_ref()
                .is_some_and(|t| t.elapsed() > timeout_interval);
            let is_fast_retransmit = mem::take(&mut fast_retransmit);
            let retry = timeout_retry || is_fast_retransmit;

            let next_block = match block_reader
                .next(&mut send_buffer[DATA_PACKET_HEADER_SIZE.into()..], retry)
            {
                Ok(b) => b,
                Err(StorageError::File(e)) if e.kind() == ErrorKind::WouldBlock => {
                    trace!("Reading from a file {local_file_path} would block");
                    None
                }
                Err(e) => return Err(e.into()),
            };
            if let Some(data_block) = next_block {
                let last_read_length = data_block.size;

                debug!(
                    "Send data block {} data size {last_read_length} retry {} remaining packets {packets_to_send} timeout {}",
                    data_block.block, data_block.retry, timeout_interval.as_secs_f32()
                );

                let block_index_sent = data_block.index;
                let at_window_boundary =
                    last_acknowledged + options.window_size as u64 == block_index_sent;

                prepend_data_header(data_block.block, &mut send_buffer);
                send_buffer.truncate(DATA_PACKET_HEADER_SIZE as usize + data_block.size);

                match socket.send_to(&mut send_buffer, endpoint) {
                    Ok(_) => {
                        last_sent = instant();
                        no_work = Wrapping(1);
                        total_unconfirmed += last_read_length;
                        packets_to_send = packets_to_send.saturating_sub(1);
                        window_sent_at = None;
                        if timeout_retry {
                            rate_control.on_loss(
                                options.block_size,
                                data_block.block,
                                options.window_size,
                            );
                        }
                        if at_window_boundary {
                            rate_control.start_rtt(data_block.block);
                        }
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        no_work += 1;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                };
            } else {
                if window_sent_at.is_none() {
                    window_sent_at = Some(instant());
                }
                no_work += 1;
            }
        }

        resize_buffer(&mut receive_buffer, receive_max_buffer_size);

        let wait_for = if no_work.0 > 2 {
            Duration::from_millis(no_work.0 as u64).into()
        } else {
            None
        };

        trace!(
            "Last sent {}us Last received {}us waiting {}ms Unconfirmed {total_unconfirmed}",
            last_sent.elapsed().as_micros(),
            last_received.elapsed().as_micros(),
            wait_for.unwrap_or(Duration::ZERO).as_millis()
        );

        let length = match socket.recv_from(&mut receive_buffer, wait_for) {
            Ok((n, s)) => {
                if s != endpoint {
                    continue;
                }
                no_work = Wrapping(1);
                last_received = instant();
                n
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                no_work += 1;

                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        };
        receive_buffer.truncate(length);
        let data = &receive_buffer[..length];

        if !matches!(
            PacketType::from_bytes(data),
            Ok(PacketType::Ack | PacketType::Error)
        ) {
            debug!("Incorrect packet type received {:x?}", data);
            continue;
        }
        match Packet::from_bytes(data) {
            Ok(Packet::Ack(p)) => {
                window_sent_at = None;
                let data_length = block_reader.free_block(p.block);

                if data_length > 0 {
                    last_acknowledged = block_index(p.block, last_acknowledged);
                    timeout = instant();
                    if let Some(rtt) = rate_control.end_rtt(p.block) {
                        trace!("Rtt for block {} elapsed {}us", p.block, rtt.as_micros());
                        rate_control.on_rtt_complete(options.block_size, p.block);
                    }
                } else if rate_control.on_dup_ack(p.block, options.block_size, options.window_size)
                {
                    debug!(
                        "Fast retransmit triggered by 3 duplicate ACKs for block {}",
                        p.block
                    );
                    fast_retransmit = true;
                }

                total_confirmed += data_length;

                debug!("Acknowledge received {} total {}", p.block, total_confirmed);

                if block_reader.is_finished() {
                    info!(
                        "Client finished sending {local_file_path} {} bytes",
                        total_confirmed
                    );
                    histogram!("tftp.client.connection.duration", "connection_type" => "write")
                        .record(started.elapsed());
                    counter!("tftp.client.connection.transfer.size", "connection_type" => "write")
                        .increment(total_confirmed as u64);
                    return Ok((
                        total_confirmed,
                        remote_session_public_keys.and_then(|p| p.auth),
                    ));
                }
            }
            Ok(Packet::Error(p)) => {
                return Err(PacketError::RemoteError(p.message).into());
            }
            _ => {
                debug!("Incorrect packet received {:x?}", data);
                continue;
            }
        };
    }
}

fn block_reader<R: FileReader>(
    reader: R,
    options: &ConnectionOptions,
    prefer_seek: bool,
) -> Readers<R> {
    match (options.window_size, prefer_seek) {
        (1, false) => Readers::Single(SingleBlockReader::new(
            reader,
            options.block_size_with_encryption(),
        )),
        (_, true) if SEEK_ENABLED => Readers::Seek(
            crate::readers::multiple_block_seek_reader::MultipleBlockSeekReader::new(
                reader,
                options.block_size_with_encryption(),
                options.window_size,
            ),
        ),
        _ => Readers::Multiple(MultipleBlockReader::new(
            reader,
            options.block_size_with_encryption(),
            options.window_size,
        )),
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    use crate::client::test_support::*;
    use crate::string::format_str;
    use crate::time::test_now as instant;

    #[cfg(feature = "encryption")]
    fn send(socket: ScriptedSocket, options: ConnectionOptions, data: &[u8]) -> BoxedResult<usize> {
        send_with(client_config(), socket, options, data)
    }

    fn send_with(
        config: ClientConfig,
        socket: ScriptedSocket,
        options: ConnectionOptions,
        data: &[u8],
    ) -> BoxedResult<usize> {
        let reader = MemoryReader::new(data);
        let size = data.len() as u64;
        send_file(
            config,
            format_str!(FilePath, "local"),
            format_str!(FilePath, "remote"),
            options,
            move |_: &FilePath| Ok((Some(size), reader)),
            socket,
            instant,
            OsRng,
        )
        .map(|(total, _)| total)
    }

    #[test]
    fn test_duplicate_acks_do_not_hold_off_the_timeout() {
        let mut socket = ScriptedSocket::from_server((0..20).map(|_| ack_packet(0)));
        socket.delay = Duration::from_millis(10);
        let config = ClientConfig {
            request_timeout: Duration::from_millis(30),
            ..client_config()
        };

        let result = send_with(config, socket, ConnectionOptions::default(), &[7; 600]);

        assert!(timed_out(&result));
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_required_encryption_refuses_plain_ack() {
        use crate::encryption::EncryptionLevel;

        for encryption_level in [EncryptionLevel::Data, EncryptionLevel::Protocol] {
            let options = ConnectionOptions {
                encryption_level,
                ..Default::default()
            };
            let socket = ScriptedSocket::from_server([ack_packet(0), ack_packet(1)]);
            let sent = socket.sent.clone();

            let result = send(socket, options, &[7; 10]);

            assert!(result.is_err(), "{encryption_level}");
            assert!(!sent_data(&sent), "{encryption_level}");
        }
    }
}
