use core::{cmp::max, fmt::write, mem::size_of_val, time::Duration};

use log::{debug, error, info, trace, warn};
use rand::{CryptoRng, RngCore};

use crate::{
    config::{
        print_options, ConnectionOptions, DATA_PACKET_HEADER_SIZE, MAX_BLOCKS_READER,
        MAX_BLOCKS_WRITER, MAX_BUFFER_SIZE, MIN_BUFFER_SIZE,
    },
    encryption::{encode_public_key, FinalizeKeysCallback, PrivateKey, PublicKey},
    error::{BoxedResult, DefaultBoxedResult, StorageError},
    map::{Entry, Map},
    packet::{
        AckPacket, ByteConverter, DataPacket, ErrorCode, ErrorPacket, OptionalAck, Packet,
        PacketType,
    },
    server::{
        connection::{ClientType, Connection, ConnectionBuilder},
        validation::handle_file_size,
    },
    socket::Socket,
    std_compat::{
        io::{ErrorKind, Read, Seek, Write},
        net::SocketAddr,
    },
    storage::{BlockReader, BlockWriter},
    string::format_str,
    time::InstantCallback,
    types::{DataBuffer, DefaultString, FilePath},
};

#[cfg(feature = "alloc")]
type Clients<R, W, S> = Map<SocketAddr, Connection<R, W, S>>;
#[cfg(not(feature = "alloc"))]
type Clients<R, W, S> =
    Map<SocketAddr, Connection<R, W, S>, { crate::config::MAX_CLIENTS as usize }>;

#[cfg(all(feature = "alloc", feature = "encryption"))]
pub type AuthorizedKeys = alloc::vec::Vec<PublicKey>;
#[cfg(all(not(feature = "alloc"), feature = "encryption"))]
pub type AuthorizedKeys = heapless::Vec<PublicKey, { crate::config::MAX_CLIENTS as usize }>;
#[cfg(not(feature = "encryption"))]
pub type AuthorizedKeys = ();

pub struct ServerConfig {
    pub listen: SocketAddr,
    pub directory: FilePath,
    pub allow_overwrite: bool,
    pub max_queued_blocks_reader: u16,
    pub max_queued_blocks_writer: u16,
    pub max_window_size: u16,
    pub request_timeout: Duration,
    pub max_connections: u16,
    pub max_file_size: u64,
    pub max_block_size: u16,
    pub authorized_keys: Option<AuthorizedKeys>,
    pub private_key: Option<PrivateKey>,
    pub required_full_encryption: bool,
    pub require_server_port_change: bool,
}

pub fn server<CreateReader, CreateWriter, R, W, Rng, CreateSocket, S>(
    config: ServerConfig,
    create_reader: CreateReader,
    create_writer: CreateWriter,
    create_socket: CreateSocket,
    instant: InstantCallback,
    mut rng: Rng,
) -> DefaultBoxedResult
where
    S: Socket,
    Rng: CryptoRng + RngCore + Copy,
    R: Read + Seek,
    CreateSocket: Fn(&str, usize) -> BoxedResult<S>,
    CreateReader: Fn(&FilePath, &ServerConfig) -> BoxedResult<(Option<u64>, R)>,
    W: Write + Seek,
    CreateWriter: Fn(&FilePath, &ServerConfig) -> BoxedResult<W>,
{
    info!("Starting server on {}", config.listen);

    let max_buffer_size = max(
        config.max_block_size + DATA_PACKET_HEADER_SIZE as u16,
        MIN_BUFFER_SIZE,
    );
    assert!(max_buffer_size <= MAX_BUFFER_SIZE);
    #[allow(unused_must_use)]
    let mut buffer = {
        let mut d = DataBuffer::new();
        d.resize(max_buffer_size as usize, 0);
        d
    };
    let mut clients: Clients<_, _, _> = Clients::new();
    debug!(
        "Size of all clients in memory {} bytes",
        size_of_val(&clients)
    );

    #[cfg(feature = "encryption")]
    if let Some(private_key) = config.private_key.as_ref() {
        info!(
            "Server public key {}",
            encode_public_key(&PublicKey::from(private_key))?
        );
    }

    let listen = format_str!(
        DefaultString,
        "{}:{}",
        &config.listen.ip(),
        &config.listen.port()
    );
    let socket = create_socket(&listen, 1)?;
    let mut timeout_duration = instant();
    let mut last_socket_addr: Option<SocketAddr> = None;
    let mut no_work: u8 = 0;
    let mut last_received = instant();
    loop {
        let send_duration = instant();
        if timeout_duration.elapsed() > Duration::from_secs(2) {
            timeout_clients(&mut clients, config.request_timeout);
            timeout_duration = instant();
        }
        let sent = send_data_blocks(&mut clients);
        if sent > 0 {
            no_work = 1;
        } else {
            no_work = no_work.wrapping_add(1);
        }

        #[cfg(feature = "alloc")]
        buffer.resize(max_buffer_size as usize, 0);
        // TODO heapless vector resizing is super slow
        #[cfg(not(feature = "alloc"))]
        unsafe {
            buffer.set_len(max_buffer_size as usize)
        };
        let wait_for = if clients.is_empty() {
            Duration::from_millis(500).into()
        } else if no_work > 2 {
            Duration::from_millis(no_work as u64).into()
        } else {
            None
        };

        trace!(
            "Total clients {} sent {} packets in {}us waiting {}ms last received {}us",
            clients.len(),
            sent,
            send_duration.elapsed().as_micros(),
            wait_for.unwrap_or(Duration::ZERO).as_millis(),
            last_received.elapsed().as_micros(),
        );

        let (mut received_length, from_client) = match socket.recv_from(&mut buffer, wait_for) {
            Ok(n) => {
                no_work = 1;
                last_received = instant();
                n
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                if config.require_server_port_change {
                    let mut recv = None;
                    for (s, c) in clients.iter() {
                        if last_socket_addr == Some(*s) {
                            continue;
                        }
                        match c.recv_from(&mut buffer, None) {
                            Ok(n) => {
                                recv = Some(n);
                                no_work = 1;
                                last_received = instant();
                                break;
                            }
                            _ => continue,
                        }
                    }
                    if let Some(p) = recv {
                        last_socket_addr = Some(p.1);
                        p
                    } else {
                        last_socket_addr = None;
                        continue;
                    }
                } else {
                    no_work = no_work.wrapping_add(1);
                    continue;
                }
            }
            Err(e) => return Err(e.into()),
        };
        buffer.truncate(received_length);
        let client_length = clients.len();

        match clients.entry(from_client) {
            Entry::Occupied(mut entry) => {
                let mut connection = entry.get_mut();
                if !connection.receive_packet(&mut buffer) {
                    continue;
                }

                let packet_type = PacketType::from_bytes(&buffer);
                if !matches!(
                    packet_type,
                    Ok(PacketType::Data | PacketType::Ack | PacketType::Error)
                ) {
                    debug!("Incorrect packet type received {:x?}", buffer);
                    continue;
                }

                match Packet::from_bytes(&buffer) {
                    Ok(Packet::Data(p)) => {
                        let data_length = p.data.len();

                        debug!(
                            "Packet received block {} size {} total {} from {}",
                            p.block, data_length, connection.transfer, from_client
                        );

                        let mut write_elapsed = instant();
                        match write_block(&mut connection, p.block, p.data) {
                            Ok(n) if n > 0 => {
                                connection.last_updated = instant();
                                connection.transfer += n;
                                trace!(
                                    "Block {} written in {}us",
                                    p.block,
                                    write_elapsed.elapsed().as_micros()
                                );
                            }
                            Ok(_) => continue,
                            Err(e) => {
                                connection.send_packet(Packet::Error(e));
                                entry.remove();
                                continue;
                            }
                        }

                        // this would write more than expected but only by a block size maximum
                        if let Err(e) =
                            handle_file_size(connection.transfer as u64, config.max_file_size)
                        {
                            connection.send_packet(Packet::Error(e));
                            entry.remove();
                            continue;
                        }
                    }
                    Ok(Packet::Ack(p)) => {
                        let ClientType::Reader(ref mut block_reader): ClientType<R, _> = connection.client_type else {
                            continue;
                        };

                        debug!("Ack received {} {}", p.block, from_client);

                        if block_reader.free_block(p.block) > 0 {
                            connection.last_updated = instant();
                        }
                        if block_reader.is_finished() {
                            info!("Client read {} finished", from_client);
                            entry.remove();
                            continue;
                        }
                    }
                    Ok(Packet::Error(p)) => {
                        error!("Error received {:?} {}", p.code, p.message);
                        entry.remove();
                        continue;
                    }
                    _ => {
                        debug!("Incorrect packet received {:x?}", buffer);
                        continue;
                    }
                };
            }
            Entry::Vacant(entry) => {
                if client_length >= config.max_connections as usize {
                    error!(
                        "Max connections {} reached. Ignoring connection from {}",
                        config.max_connections, from_client
                    );
                    continue;
                }

                let mut builder =
                    match ConnectionBuilder::from_new_connection(&config, &mut buffer, rng) {
                        Ok(b) => b,
                        Err(e) => {
                            debug!("New connection error {}", e);
                            continue;
                        }
                    };

                if !matches!(
                    PacketType::from_bytes(&buffer),
                    Ok(PacketType::Write | PacketType::Read)
                ) {
                    debug!("Incorrect packet type received {:x?}", buffer);
                    continue;
                }

                debug!("Received from new client {}", from_client);

                match Packet::from_bytes(&buffer) {
                    Ok(Packet::Write(p)) => {
                        debug!(
                            "New client writing to file {} in directory {}",
                            p.file_name, config.directory
                        );

                        let Ok(()) = builder.with_request(p, config.max_window_size, rng) else {
                            continue;
                        };

                        let Ok((mut connection, used_extensions, encrypt_new_connection)): Result<(Connection<_, W, _>, _, _), _> =
                            builder.build_writer(&socket, from_client, &create_writer, &create_socket, instant)
                        else {
                            continue;
                        };

                        if !used_extensions.is_empty() {
                            if !connection.send_packet(Packet::OptionalAck(OptionalAck {
                                extensions: used_extensions,
                            })) {
                                continue;
                            }
                        } else if !connection.send_packet(Packet::Ack(AckPacket { block: 0 })) {
                            continue;
                        }
                        // // new encryption starts only here
                        if let Some(keys) = encrypt_new_connection {
                            connection.encryptor = keys.encryptor.into();
                        }

                        print_options("Server writing using", &connection.options);

                        entry.insert(connection);
                    }
                    Ok(Packet::Read(p)) => {
                        debug!(
                            "New client reading file {} in directory {}",
                            p.file_name, config.directory
                        );

                        let Ok(()) = builder.with_request(p, config.max_window_size, rng) else {
                            continue;
                        };

                        let Ok((mut connection, used_extensions, encrypt_new_connection)): Result<(Connection<R, _, _>, _, _), _> =
                            builder.build_reader(&socket, from_client, &create_reader, &create_socket, instant) else {
                            continue;
                        };

                        if !used_extensions.is_empty() {
                            if !connection.send_packet(Packet::OptionalAck(OptionalAck {
                                extensions: used_extensions,
                            })) {
                                continue;
                            }
                        }

                        // new encryption starts only here
                        if let Some(keys) = encrypt_new_connection {
                            connection.encryptor = keys.encryptor.into();
                        }

                        print_options("Server reading using", &connection.options);

                        entry.insert(connection);
                    }
                    _ => {
                        debug!("Incorrect packet received {:x?}", buffer);
                        continue;
                    }
                };
            }
        }
    }
}

fn write_block<R, W: Write + Seek, S>(
    connection: &mut Connection<R, W, S>,
    mut block: u16,
    data: &[u8],
) -> Result<usize, ErrorPacket>
where
    S: Socket,
{
    let ClientType::Writer(ref mut block_writer): ClientType<_, W> = connection.client_type else {
        return Ok(0);
    };
    let (length, last_in_window) = match block_writer.write_block(block, data) {
        Ok((n, l)) => {
            debug!("Write block {} written size {}", block, n);
            (n, l)
        }
        Err(StorageError::ExpectedBlock((expected, current))) => {
            debug!("Received unexpected block {} expecting {}", block, expected);
            block = current;
            (0, true)
        }
        Err(StorageError::AlreadyWriten) => {
            debug!(
                "Received block that was written before. Ignoring block {}",
                block
            );
            (0, true)
        }
        Err(StorageError::CapacityReached) => {
            debug!(
                "Capacity reached waiting for previous blocks. Ignoring block {}",
                block
            );
            return Ok(0);
        }
        Err(e) => {
            error!("Failed to write block {} {}", block, e);
            return Err(ErrorPacket::new(
                ErrorCode::AccessVioliation,
                format_str!(DefaultString, "{}", e),
            ));
        }
    };

    if connection.options.window_size <= 1
        || last_in_window
        || block_writer.is_finished_below(connection.options.block_size)
    {
        if !connection.send_packet(Packet::Ack(AckPacket { block })) {
            error!("Unable to ack block {}", block);
        }
    }
    Ok(length)
}

fn timeout_clients<R, W: Write + Seek, S: Socket>(
    clients: &mut Clients<R, W, S>,
    request_timeout: Duration,
) {
    clients.retain(|client, connection| {
        let client_type = match connection.client_type {
            ClientType::Writer(ref w) => {
                if w.is_finished_below(connection.options.block_size) {
                    info!("Client write finished {}", client);
                    return false;
                }
                "write"
            }
            ClientType::Reader(_) => "read",
        };
        if connection.last_updated.elapsed() <= request_timeout {
            return true;
        }

        warn!(
            "Client {} timeout {} {}",
            client_type,
            client,
            connection.last_updated.elapsed().as_secs_f32()
        );

        let message = format_str!(
            DefaultString,
            "Client timeout {}",
            connection.last_updated.elapsed().as_secs_f32()
        );
        connection.send_packet(Packet::Error(ErrorPacket::new(
            ErrorCode::AccessVioliation,
            message,
        )));
        false
    });
}

fn send_data_blocks<R: Read + Seek, W, S: Socket>(clients: &mut Clients<R, W, S>) -> usize {
    let mut sent = 0;
    clients.retain(|_, connection| {
        for _ in 0..1 {
            let block_reader = match &mut connection.client_type {
                ClientType::Reader(r) => r,
                ClientType::Writer(_) => return true,
            };

            let packet_block = match block_reader.next() {
                Ok(Some(b)) => b,
                Ok(None) => return true,
                Err(e) => {
                    error!("Failed to read {}", e);
                    connection.send_packet(Packet::Error(ErrorPacket::new(
                        ErrorCode::AccessVioliation,
                        format_str!(DefaultString, "{}", e),
                    )));
                    return false;
                }
            };
            let packet_sent = connection.send_packet(Packet::Data(DataPacket {
                block: packet_block.block,
                data: &packet_block.data,
            }));
            if packet_sent {
                sent += 1;
            }
        }
        true
    });
    sent
}
