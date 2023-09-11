use core::cmp::max;
use core::time::Duration;

use log::debug;
use log::info;
use log::trace;
use rand::CryptoRng;
use rand::RngCore;

use super::ClientConfig;
use crate::block_mapper::BlockMapper;
use crate::client::connection::query_server;
use crate::config::print_options;
use crate::config::ConnectionOptions;
use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::config::MIN_BUFFER_SIZE;
use crate::encryption::PublicKey;
use crate::error::BoxedResult;
use crate::error::PacketError;
use crate::flow_control::RateControl;
use crate::macros::cfg_encryption;
use crate::macros::cfg_seek;
use crate::packet::AckPacket;
use crate::packet::ByteConverter;
use crate::packet::DataPacket;
use crate::packet::Packet;
use crate::packet::PacketType;
use crate::readers::block_reader::BlockReader;
use crate::readers::multiple_block_reader::MultipleBlockReader;
use crate::readers::single_block_reader::SingleBlockReader;
use crate::readers::Readers;
use crate::socket::Socket;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::io::Read;
use crate::time::InstantCallback;
use crate::types::DataBuffer;
use crate::types::FilePath;

cfg_encryption! {
    use crate::client::encryption_socket_builder::create_initial_socket;
    use crate::client::encryption_socket_builder::configure_socket;
}

cfg_seek! {
    use crate::std_compat::io::Seek;
}

#[allow(clippy::too_many_arguments)]
pub fn send_file<
    CreateReader,
    #[cfg(not(feature = "seek"))] R: Read,
    #[cfg(feature = "seek")] R: Read + Seek,
    Sock,
    Rng,
>(
    config: ClientConfig,
    local_file_path: FilePath,
    remote_file_path: FilePath,
    #[allow(unused_mut)] mut options: ConnectionOptions,
    create_reader: CreateReader,
    #[allow(unused_mut)] mut socket: Sock,
    instant: InstantCallback,
    _rng: Rng,
) -> BoxedResult<(usize, Option<PublicKey>)>
where
    Sock: Socket,
    Rng: CryptoRng + RngCore + Copy,
    CreateReader: Fn(&FilePath) -> BoxedResult<(Option<u64>, R)>,
{
    if let Ok(s) = socket.local_addr() {
        info!("Listening on {} connecting to {}", s, config.endpoint);
    }
    debug!(
        "Preparing to send {} as {}",
        local_file_path, remote_file_path
    );

    #[cfg(feature = "encryption")]
    let (mut socket, initial_keys) = create_initial_socket(socket, &config, &mut options, _rng)?;

    let max_buffer_size = max(
        options.block_size + DATA_PACKET_HEADER_SIZE as u16,
        MIN_BUFFER_SIZE,
    );

    let (file_size, reader) = create_reader(&local_file_path)?;
    if file_size > Some(0) {
        options.file_size = file_size;
    }

    #[allow(unused_must_use)]
    let mut buffer = {
        let mut d = DataBuffer::new();
        d.resize(max_buffer_size as usize, 0);
        d
    };

    let mut rate_control = RateControl::new(instant);

    rate_control.start_rtt(1);

    #[allow(unused_mut)]
    let (_, acknowledge, mut options, endpoint) = query_server(
        &mut socket,
        &mut buffer,
        Packet::Write,
        remote_file_path,
        options,
        instant,
        &config,
    )?;

    let initial_rtt = rate_control
        .end_rtt(1)
        .unwrap_or_else(|| Duration::from_millis(1));

    debug!("Initial exchange took {}", initial_rtt.as_secs_f32());

    #[cfg(feature = "encryption")]
    let (mut socket, options) = configure_socket(socket, initial_keys, options);

    print_options("Client using", &options);

    if acknowledge {
        let packet = Packet::Ack(AckPacket { block: 0 });
        socket.send_to(&mut packet.to_bytes(), endpoint)?;
    }

    let mut readers = block_reader(reader, &options, config.prefer_seek);
    let block_reader: &mut dyn BlockReader = match &mut readers {
        Readers::Single(r) => r,
        Readers::Multiple(r) => r,
        #[cfg(feature = "seek")]
        Readers::Seek(r) => r,
    };

    let mut timeout = instant();
    let mut last_sent = instant();
    let mut last_received = instant();

    let mut total_confirmed = 0;
    // total_unconfirmed exist, but rust reports never used
    #[allow(unused_variables)]
    let mut total_unconfirmed = 0;

    let mut stats_calculate = instant();

    let mut no_work: u8 = 0;
    let mut packets_to_send = u32::MAX;
    let flow_control_period = Duration::from_millis(200);
    let mut last_acknowledged = 0;

    rate_control.acknoledged_data(options.block_size as usize, 1);
    rate_control.calculate_transmit_rate(
        options.block_size,
        options.window_size,
        options.retry_packet_after_timeout,
        initial_rtt,
    );
    let mut block_mapper = BlockMapper::new();

    loop {
        if stats_calculate.elapsed() > flow_control_period {
            rate_control.calculate_transmit_rate(
                options.block_size,
                options.window_size,
                options.retry_packet_after_timeout,
                stats_calculate.elapsed(),
            );
            stats_calculate = instant();

            // packets_to_send = u32::MAX;
            packets_to_send = if config.ignore_rate_control {
                u32::MAX
            } else {
                rate_control.packets_to_send(flow_control_period, options.block_size)
            };
        }

        if packets_to_send > 0 {
            let timeout_interval = rate_control
                .timeout_interval(options.retry_packet_after_timeout, options.block_size);
            let retry = last_sent.elapsed() > timeout_interval;
            if let Some(data_block) = block_reader.next(retry)? {
                let last_read_length = data_block.data.len();

                debug!(
                    "Send data block {} data size {last_read_length} retry {} remaining packets {packets_to_send}",
                    data_block.block, data_block.retry
                );

                let block_index = block_mapper.index(data_block.block);
                if last_acknowledged + options.window_size as u64 == block_index {
                    if data_block.retry {
                        rate_control.increment_errors();
                    }
                    rate_control.start_rtt(data_block.block);
                }

                let data_packet = Packet::Data(DataPacket {
                    block: data_block.block,
                    data: &data_block.data,
                });
                match socket.send_to(&mut data_packet.to_bytes(), endpoint) {
                    Ok(_) => {
                        last_sent = instant();
                        no_work = 1;
                        rate_control.data_sent(last_read_length);
                        total_unconfirmed += last_read_length;
                        packets_to_send -= 1;
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        no_work = no_work.wrapping_add(1);
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                };
            } else {
                no_work = no_work.wrapping_add(1);
            }
        } else {
            no_work = no_work.wrapping_add(1);
            rate_control.mark_as_data_limited();
        }

        #[cfg(feature = "alloc")]
        buffer.resize(max_buffer_size as usize, 0);
        // TODO heapless vector resizing is super slow
        #[cfg(not(feature = "alloc"))]
        unsafe {
            buffer.set_len(max_buffer_size as usize)
        };

        let wait_for = if no_work > 2 {
            Duration::from_millis(no_work as u64).into()
        } else {
            None
        };

        trace!(
            "Last sent {}us Last received {}us waiting {}ms",
            last_sent.elapsed().as_micros(),
            last_received.elapsed().as_micros(),
            wait_for.unwrap_or(Duration::ZERO).as_millis()
        );

        let length = match socket.recv_from(&mut buffer, wait_for) {
            Ok((n, s)) => {
                if s != endpoint {
                    continue;
                }
                no_work = 1;
                last_received = instant();
                n
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                let elapsed = timeout.elapsed();
                if elapsed > config.request_timeout {
                    if let Ok(s) = socket.local_addr() {
                        debug!("Send timeout for {}", s);
                    }
                    return Err(PacketError::Timeout(elapsed).into());
                }
                no_work = no_work.wrapping_add(1);

                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        };
        buffer.truncate(length);
        let data = &buffer[..length];

        if !matches!(
            PacketType::from_bytes(data),
            Ok(PacketType::Ack | PacketType::Error)
        ) {
            debug!("Incorrect packet type received {:x?}", data);
            continue;
        }
        match Packet::from_bytes(data) {
            Ok(Packet::Ack(p)) => {
                timeout = instant();
                let data_length = block_reader.free_block(p.block);
                last_acknowledged = block_mapper.index(p.block);

                rate_control.acknoledged_data(
                    data_length,
                    (data_length / options.block_size as usize) as u32,
                );
                if let Some(rtt) = rate_control.end_rtt(p.block) {
                    trace!("Rtt for block {} elapsed {}us", p.block, rtt.as_micros());
                }

                total_confirmed += data_length;

                debug!("Acknowledge received {} total {}", p.block, total_confirmed);

                if block_reader.is_finished() {
                    info!("Client finished sending with bytes {}", total_confirmed);
                    return Ok((total_confirmed, options.remote_public_key()));
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

fn block_reader<#[cfg(not(feature = "seek"))] R: Read, #[cfg(feature = "seek")] R: Read + Seek>(
    reader: R,
    options: &ConnectionOptions,
    prefer_seek: bool,
) -> Readers<R> {
    match (options.window_size, prefer_seek) {
        (1, false) => Readers::Single(SingleBlockReader::new(reader, options.block_size)),
        #[cfg(feature = "seek")]
        (_, true) => Readers::Seek(
            crate::readers::multiple_block_seek_reader::MultipleBlockSeekReader::new(
                reader,
                options.block_size,
                options.window_size,
            ),
        ),
        _ => Readers::Multiple(MultipleBlockReader::new(
            reader,
            options.block_size,
            options.window_size,
        )),
    }
}
