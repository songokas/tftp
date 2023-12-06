use core::cmp::max;
use core::time::Duration;

use log::debug;
use log::info;
use log::trace;
use rand::CryptoRng;
use rand::RngCore;

use super::ClientConfig;
use crate::client::connection::query_server;
use crate::client::connection::send_error;
use crate::config::print_options;
use crate::config::ConnectionOptions;
use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::config::MIN_BUFFER_SIZE;
use crate::encryption::PublicKey;
use crate::error::BoxedResult;
use crate::error::DefaultBoxedResult;
use crate::error::PacketError;
use crate::error::StorageError;
use crate::macros::cfg_encryption;
use crate::packet::AckPacket;
use crate::packet::ByteConverter;
use crate::packet::ErrorCode;
use crate::packet::Packet;
use crate::packet::PacketType;
use crate::socket::Socket;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::io::Write;
use crate::std_compat::net::SocketAddr;
use crate::string::format_str;
use crate::time::InstantCallback;
use crate::types::DataBuffer;
use crate::types::FilePath;
use crate::writers::block_writer::BlockWriter;
use crate::writers::single_block_writer::SingleBlockWriter;

cfg_encryption! {
    use crate::client::encryption_socket_builder::create_initial_socket;
    use crate::client::encryption_socket_builder::configure_socket;
}

#[allow(clippy::too_many_arguments)]
pub fn receive_file<CreateWriter, Sock, W, Rng>(
    config: ClientConfig,
    local_file_path: FilePath,
    remote_file_path: FilePath,
    #[allow(unused_mut)] mut options: ConnectionOptions,
    create_writer: CreateWriter,
    #[allow(unused_mut)] mut socket: Sock,
    instant: InstantCallback,
    _rng: Rng,
) -> BoxedResult<(usize, Option<PublicKey>)>
where
    W: Write,
    Rng: CryptoRng + RngCore + Copy,
    Sock: Socket,
    CreateWriter: Fn(&FilePath) -> BoxedResult<W>,
{
    let max_buffer_size = max(
        options.block_size + DATA_PACKET_HEADER_SIZE as u16,
        MIN_BUFFER_SIZE,
    );
    if let Ok(s) = socket.local_addr() {
        info!("Listening on {} connecting to {}", s, config.endpoint);
    }
    debug!(
        "Preparing to receive {} as {} max buffer {}",
        remote_file_path, local_file_path, max_buffer_size
    );

    #[cfg(feature = "encryption")]
    let (mut socket, initial_keys) = create_initial_socket(socket, &config, &mut options, _rng)?;

    #[allow(unused_must_use)]
    let mut buffer = {
        let mut d = DataBuffer::new();
        d.resize(max_buffer_size as usize, 0);
        d
    };

    let initial_rtt = instant();
    #[allow(unused_mut)]
    let (mut received_length, acknowledge, mut options, endpoint) = query_server(
        &mut socket,
        &mut buffer,
        Packet::Read,
        remote_file_path,
        options,
        instant,
        &config,
    )?;

    debug!(
        "Initial exchange took {}",
        initial_rtt.elapsed().as_secs_f32()
    );

    #[cfg(feature = "encryption")]
    let (mut socket, options) = configure_socket(socket, initial_keys, options);

    let writer = create_writer(&local_file_path)?;
    let mut block_writer = SingleBlockWriter::new(writer);

    let mut last_block_ack = 0;
    let mut total = 0;

    // server sent data packet so no encryption
    if let Some(packet_length) = received_length.take() {
        if let Ok(Packet::Data(p)) = Packet::from_bytes(&buffer[..packet_length]) {
            handle_file_size(&socket, endpoint, packet_length, config.max_file_size)?;
            if let Some(w) = write_block(
                &socket,
                endpoint,
                &mut block_writer,
                p.block,
                p.data,
                &options,
                &mut last_block_ack,
            )? {
                total += w;
            };

            if packet_length != options.block_size_with_encryption() as usize {
                info!("Client finished receiving {local_file_path} {total} bytes");
                return Ok((packet_length, None));
            }
        }
    }

    print_options("Client using", &options);

    if let Some(file_size) = options.file_size {
        handle_file_size(&socket, endpoint, file_size as usize, config.max_file_size)?;
    }

    if acknowledge {
        let packet = Packet::Ack(AckPacket { block: 0 });
        socket.send_to(&mut packet.to_bytes(), endpoint)?;
    }

    let mut timeout = instant();

    loop {
        #[cfg(feature = "alloc")]
        buffer.resize(max_buffer_size as usize, 0);
        // TODO heapless vector resizing is super slow
        #[cfg(not(feature = "alloc"))]
        unsafe {
            buffer.set_len(max_buffer_size as usize)
        };

        let length = match socket.recv_from(&mut buffer, Duration::from_secs(1).into()) {
            Ok((n, s)) => {
                if s != endpoint {
                    continue;
                }
                trace!("Received packet size {}", n);
                n
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                let elapsed = timeout.elapsed();
                if elapsed > config.request_timeout {
                    if let Ok(s) = socket.local_addr() {
                        debug!("Receive timeout for {}", s);
                    }
                    return Err(PacketError::Timeout(elapsed).into());
                }
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        };
        buffer.truncate(length);

        if !matches!(
            PacketType::from_bytes(&buffer),
            Ok(PacketType::Data | PacketType::Error)
        ) {
            debug!("Incorrect packet received {:x?}", &buffer);
            continue;
        }

        match Packet::from_bytes(&buffer) {
            Ok(Packet::Data(p)) => {
                match write_block(
                    &socket,
                    endpoint,
                    &mut block_writer,
                    p.block,
                    p.data,
                    &options,
                    &mut last_block_ack,
                ) {
                    Ok(Some(written)) => {
                        timeout = instant();
                        total += written;

                        if written < options.block_size_with_encryption() as usize {
                            info!("Client finished receiving {local_file_path} {total} bytes");
                            return Ok((total, options.remote_public_key()));
                        }
                    }
                    Ok(None) => continue,
                    Err(e) => return Err(e),
                };
                // this would write more than expected but only by a block size maximum
                handle_file_size(&socket, endpoint, total, config.max_file_size)?;
            }
            Ok(Packet::Error(p)) => {
                return Err(PacketError::RemoteError(p.message).into());
            }
            _ => {
                debug!("Incorrect packet received {:x?}", &buffer);
                continue;
            }
        };
    }
}

fn write_block(
    socket: &impl Socket,
    endpoint: SocketAddr,
    block_writer: &mut impl BlockWriter,
    mut block: u16,
    data: &[u8],
    options: &ConnectionOptions,
    last_ack: &mut u64,
) -> BoxedResult<Option<usize>> {
    let (written, index) = match block_writer.write_block(block, data) {
        Ok((written, index)) => (Some(written), index),
        Err(StorageError::ExpectedBlock(e)) => {
            debug!(
                "Received unexpected block {} expecting block after {}",
                block, e.current
            );
            block = e.current;
            (None, e.current_index)
        }
        Err(StorageError::AlreadyWritten(e)) => {
            debug!(
                "Received block that was written before. Ignoring block {}",
                block
            );
            block = e.current;
            (None, e.current_index)
        }
        Err(e) => return Err(e.into()),
    };

    if options.window_size <= 1
        || *last_ack + options.window_size as u64 == index
        || written.unwrap_or(0) < options.block_size_with_encryption() as usize
    {
        debug!("Ack send {}", block);
        let packet = Packet::Ack(AckPacket { block });
        socket.send_to(&mut packet.to_bytes(), endpoint)?;
        *last_ack = index;
    }
    Ok(written)
}

fn handle_file_size(
    socket: &impl Socket,
    endpoint: SocketAddr,
    data_length: usize,
    max_file_size: u64,
) -> DefaultBoxedResult {
    if data_length > max_file_size as usize {
        let message = format_str!(
            DefaultString,
            "Invalid file size received {} expected {}",
            data_length,
            max_file_size
        );
        send_error(socket, endpoint, ErrorCode::DiskFull, message)?;
        return Err(PacketError::Invalid.into());
    }
    Ok(())
}
