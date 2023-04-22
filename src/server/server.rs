use core::{cmp::max, fmt::write, mem::size_of_val, num::NonZeroU32, time::Duration};

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
    socket::{BoundSocket, Socket, ToSocketId},
    std_compat::{
        io::{ErrorKind, Read, Seek, Write},
        net::SocketAddr,
        time::Instant,
    },
    storage::{BlockReader, BlockWriter},
    string::format_str,
    time::InstantCallback,
    types::{DataBuffer, DefaultString, FilePath},
};

#[cfg(all(feature = "alloc", not(feature = "multi_thread")))]
type Clients<R, W, B> = Map<SocketAddr, Connection<R, W, B>>;
#[cfg(all(not(feature = "alloc"), not(feature = "multi_thread")))]
type Clients<R, W, B> =
    Map<SocketAddr, Connection<R, W, B>, { crate::config::MAX_CLIENTS as usize }>;

#[cfg(all(feature = "std", feature = "alloc", feature = "multi_thread"))]
type Handles = Map<SocketAddr, std::thread::JoinHandle<()>>;
#[cfg(all(feature = "std", not(feature = "alloc"), feature = "multi_thread"))]
type Handles =
    Map<SocketAddr, std::thread::JoinHandle<()>, { crate::config::MAX_CLIENTS as usize }>;

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

#[allow(clippy::too_many_arguments)]
pub fn server<CreateReader, CreateWriter, R, W, Rng, CreateSocket, CreateBoundSocket, S, B>(
    config: ServerConfig,
    create_reader: CreateReader,
    create_writer: CreateWriter,
    create_socket: CreateSocket,
    create_bound_socket: CreateBoundSocket,
    instant: InstantCallback,
    mut rng: Rng,
) -> DefaultBoxedResult
where
    S: Socket + ToSocketId,
    B: BoundSocket + ToSocketId + Send + 'static,
    Rng: CryptoRng + RngCore + Copy,
    R: Read + Seek + Send + 'static,
    CreateSocket: Fn(&str, usize, bool) -> BoxedResult<S>,
    CreateBoundSocket: Fn(&str, usize, SocketAddr) -> BoxedResult<B>,
    CreateReader: Fn(&FilePath, &ServerConfig) -> BoxedResult<(Option<u64>, R)>,
    W: Write + Seek + Send + 'static,
    CreateWriter: Fn(&FilePath, &ServerConfig) -> BoxedResult<W>,
{
    info!("Starting server on {}", config.listen);

    let mut buffer = create_max_buffer(config.max_block_size);
    let max_buffer_size = buffer.len();

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
    let mut socket_id = NonZeroU32::new(1).expect("Socket id must be more than zero");
    let mut socket = create_socket(&listen, 0, true)?;

    #[cfg(not(feature = "multi_thread"))]
    {
        let mut timeout_duration = instant();
        let mut next_client_to_send = 0;
        let mut next_client_to_receive = 0;
        let mut wait_control = WaitControl::new();
        let execute_timeout_client = Duration::from_secs(2);
        let mut clients: Clients<_, _, _> = Clients::new();
        debug!(
            "Size of all clients in memory {} bytes",
            size_of_val(&clients)
        );

        loop {
            let send_duration = instant();
            if timeout_duration.elapsed() > execute_timeout_client {
                clients.retain(|client, connection: &mut Connection<_, _, B>| {
                    !timeout_client(connection, config.request_timeout)
                });
                timeout_duration = instant();
            }

            let sent_in = instant();

            let (sent, recv_next_client_to_send) =
                send_data_blocks(&mut clients, next_client_to_send);
            next_client_to_send = recv_next_client_to_send;
            wait_control.sending(sent);

            debug!(
                "Sent {sent} next {recv_next_client_to_send} in {}",
                sent_in.elapsed().as_secs_f32()
            );

            #[cfg(feature = "alloc")]
            buffer.resize(max_buffer_size as usize, 0);
            // TODO heapless vector resizing is super slow
            #[cfg(not(feature = "alloc"))]
            unsafe {
                buffer.set_len(max_buffer_size as usize)
            };

            let client_received_in = instant();

            let client_received = clients.iter().skip(next_client_to_receive).find_map(
                |(client_socket_addr, connection)| {
                    next_client_to_receive += 1;
                    if socket.notified(&connection.socket) {
                        match connection.recv(&mut buffer, None) {
                            Ok(b) => {
                                if let Err(_) = socket.modify_interest(
                                    connection.socket.socket_id(),
                                    connection.socket.as_raw_fd(),
                                ) {
                                    warn!("Unable to modify epoll");
                                }
                                Some((b, *client_socket_addr))
                            }
                            _ => None,
                        }
                    } else {
                        None
                    }
                },
            );

            debug!(
                "Received from client {:?} next {next_client_to_receive} in {}",
                client_received,
                client_received_in.elapsed().as_secs_f32()
            );

            let received_in = instant();

            let (received_length, from_client) = match client_received {
                Some(r) => r,
                None => match socket.recv_from(&mut buffer, wait_control.wait_for(clients.len())) {
                    Ok((received, from_client)) => {
                        // ignore existing connection attemps on the main socket
                        if clients.contains_key(&from_client) {
                            next_client_to_receive = 0;
                            continue;
                        }
                        trace!("New connection from {from_client} next {next_client_to_receive}");
                        next_client_to_receive = 0;
                        (received, from_client)
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        next_client_to_receive = 0;
                        wait_control.receiver_idle();
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                },
            };

            debug!(
                "Received connection from {from_client} in {}",
                received_in.elapsed().as_secs_f32(),
            );

            wait_control.receiving();
            buffer.truncate(received_length);

            let clients_len = clients.len();
            let processed_in = instant();

            match clients.entry(from_client) {
                Entry::Occupied(mut entry) => {
                    let mut connection = entry.get_mut();
                    match &connection.client_type {
                        ClientType::Reader(r) => handle_read(&mut connection, &mut buffer, instant),
                        ClientType::Writer(r) => handle_write(
                            &mut connection,
                            &mut buffer,
                            instant,
                            config.max_file_size,
                        ),
                    };
                }
                Entry::Vacant(entry) => {
                    if clients_len >= config.max_connections as usize {
                        info!(
                            "Max connections {} reached. Ignoring connection from {}",
                            config.max_connections, from_client
                        );
                        continue;
                    }
                    let Some(connection) = create_new_connection(&config, &mut socket_id, &mut buffer, &socket, from_client, &create_reader, &create_writer, &create_bound_socket, instant, rng) else {
                    continue;
                };
                    entry.insert(connection);
                }
            }

            debug!(
                "Processed connection from {from_client} in {}",
                processed_in.elapsed().as_secs_f32(),
            );
        }
    }

    #[cfg(all(feature = "std", feature = "multi_thread"))]
    {
        let mut handles = Handles::new();

        loop {
            #[cfg(feature = "alloc")]
            buffer.resize(max_buffer_size, 0);
            // TODO heapless vector resizing is super slow
            #[cfg(not(feature = "alloc"))]
            unsafe {
                buffer.set_len(max_buffer_size)
            };

            let received_in = instant();
            let (received_length, from_client) =
                match socket.recv_from(&mut buffer, Duration::from_secs(1).into()) {
                    Ok(connection_received) => connection_received,
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };

            debug!(
                "Received connection from {from_client} in {} exists {}",
                received_in.elapsed().as_secs_f32(),
                handles.contains_key(&from_client),
            );

            if handles.contains_key(&from_client) {
                continue;
            }

            buffer.truncate(received_length);

            if handles.len() >= config.max_connections as usize {
                info!(
                    "Max connections {} reached. Ignoring connection from {}",
                    config.max_connections, from_client
                );
                continue;
            }

            let Some(connection) = create_new_connection(&config, &mut socket_id, &mut buffer, &socket, from_client, &create_reader, &create_writer, &create_bound_socket, instant, rng) else {
            continue;
        };
            let handle = match &connection.client_type {
                ClientType::Reader(r) => spawn_reader(connection, instant, config.request_timeout),
                ClientType::Writer(r) => spawn_writer(
                    connection,
                    instant,
                    config.request_timeout,
                    config.max_file_size,
                ),
            };
            handles.insert(from_client, handle);
            handles.retain(|_, t| !t.is_finished());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn create_new_connection<R, W, B, S, CreateReader, CreateWriter, CreateBoundSocket, Rng>(
    config: &ServerConfig,
    socket_id: &mut NonZeroU32,
    buffer: &mut DataBuffer,
    socket: &S,
    from_client: SocketAddr,
    create_reader: &CreateReader,
    create_writer: &CreateWriter,
    create_bound_socket: &CreateBoundSocket,
    instant: InstantCallback,
    mut rng: Rng,
) -> Option<Connection<R, W, B>>
where
    S: Socket,
    B: BoundSocket + ToSocketId,
    Rng: CryptoRng + RngCore + Copy,
    R: Read + Seek,
    CreateBoundSocket: Fn(&str, usize, SocketAddr) -> BoxedResult<B>,
    CreateReader: Fn(&FilePath, &ServerConfig) -> BoxedResult<(Option<u64>, R)>,
    W: Write + Seek,
    CreateWriter: Fn(&FilePath, &ServerConfig) -> BoxedResult<W>,
{
    let mut builder = match ConnectionBuilder::from_new_connection(config, buffer, rng) {
        Ok(b) => b,
        Err(e) => {
            debug!("New connection error {}", e);
            return None;
        }
    };

    match Packet::from_bytes(&buffer) {
        Ok(Packet::Write(p)) => {
            debug!(
                "New client {from_client} writing to file {} in directory {}",
                p.file_name, config.directory
            );

            let Ok(()) = builder.with_request(p, config.max_window_size, rng) else {
            return None;
        };

            *socket_id = socket_id
                .checked_add(1)
                .or_else(|| NonZeroU32::new(1))
                .expect("Socket id expected");

            let Ok((mut connection, used_extensions, encrypt_new_connection)): Result<(Connection<_, W, _>, _, _), _> =
            builder.build_writer(socket, from_client, &create_writer, &create_bound_socket, instant, socket_id.get() as usize)
        else {
            return None;
        };

            if !used_extensions.is_empty() {
                if !connection.send_packet(Packet::OptionalAck(OptionalAck {
                    extensions: used_extensions,
                })) {
                    return None;
                }
            } else if !connection.send_packet(Packet::Ack(AckPacket { block: 0 })) {
                return None;
            }
            // new encryption starts only here
            if let Some(keys) = encrypt_new_connection {
                connection.encryptor = keys.encryptor.into();
            }

            print_options("Server writing using", &connection.options);

            connection.into()
        }
        Ok(Packet::Read(p)) => {
            debug!(
                "New client {from_client} reading file {} in directory {}",
                p.file_name, config.directory
            );

            let Ok(()) = builder.with_request(p, config.max_window_size, rng) else {
            return None;
        };
            *socket_id = socket_id
                .checked_add(1)
                .or_else(|| NonZeroU32::new(1))
                .expect("Socket id expected");

            let Ok((mut connection, used_extensions, encrypt_new_connection)): Result<(Connection<R, _, _>, _, _), _> =
            builder.build_reader(socket, from_client, &create_reader, &create_bound_socket, instant, socket_id.get() as usize) else {
                return None;
        };

            if !used_extensions.is_empty() {
                if !connection.send_packet(Packet::OptionalAck(OptionalAck {
                    extensions: used_extensions,
                })) {
                    return None;
                }
            }

            // new encryption starts only here
            if let Some(keys) = encrypt_new_connection {
                connection.encryptor = keys.encryptor.into();
            }

            print_options("Server reading using", &connection.options);

            connection.into()
        }
        _ => {
            debug!("Incorrect packet received {:x?}", buffer);
            None
        }
    }
}

#[cfg(all(feature = "std", feature = "multi_thread"))]
fn spawn_reader<
    R: Read + Seek + Send + 'static,
    W: Write + Seek + Send + 'static,
    B: BoundSocket + Send + 'static,
>(
    mut connection: Connection<R, W, B>,
    instant: InstantCallback,
    request_timeout: Duration,
) -> std::thread::JoinHandle<()> {
    use crate::config::ENCRYPTION_TAG_SIZE;

    std::thread::spawn(move || {
        let mut buffer = create_max_buffer(
            connection.options.block_size
                + if connection.options.is_encrypting() {
                    ENCRYPTION_TAG_SIZE as u16
                } else {
                    0
                },
        );
        let mut wait_control = WaitControl::new();
        let max_buffer_size = buffer.len();
        loop {
            if timeout_client(&mut connection, request_timeout) {
                return;
            }
            let sent = send_data_block(&mut connection);
            wait_control.sending(sent);

            #[cfg(feature = "alloc")]
            buffer.resize(max_buffer_size, 0);
            // TODO heapless vector resizing is super slow
            #[cfg(not(feature = "alloc"))]
            unsafe {
                buffer.set_len(max_buffer_size)
            };

            let received_length = match connection.recv(&mut buffer, wait_control.wait_for(1)) {
                Ok(connection_received) => connection_received,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    wait_control.receiver_idle();
                    continue;
                }
                Err(e) => return,
            };
            wait_control.receiving();
            buffer.truncate(received_length);
            handle_read(&mut connection, &mut buffer, instant);
        }
    })
}

#[cfg(all(feature = "std", feature = "multi_thread"))]
fn spawn_writer<
    R: Send + 'static,
    W: Write + Seek + Send + 'static,
    B: BoundSocket + Send + 'static,
>(
    mut connection: Connection<R, W, B>,
    instant: InstantCallback,
    request_timeout: Duration,
    max_file_size: u64,
) -> std::thread::JoinHandle<()> {
    use crate::config::ENCRYPTION_TAG_SIZE;

    std::thread::spawn(move || {
        let mut buffer = create_max_buffer(
            connection.options.block_size
                + if connection.options.is_encrypting() {
                    ENCRYPTION_TAG_SIZE as u16
                } else {
                    0
                },
        );
        let max_buffer_size = buffer.len();
        loop {
            if timeout_client(&mut connection, request_timeout) {
                return;
            }
            #[cfg(feature = "alloc")]
            buffer.resize(max_buffer_size, 0);
            // TODO heapless vector resizing is super slow
            #[cfg(not(feature = "alloc"))]
            unsafe {
                buffer.set_len(max_buffer_size)
            };

            let received_length = match connection.recv(&mut buffer, Duration::from_secs(1).into())
            {
                Ok(connection_received) => connection_received,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return,
            };
            buffer.truncate(received_length);
            handle_write(&mut connection, &mut buffer, instant, max_file_size);
        }
    })
}

fn create_max_buffer(max_block_size: u16) -> DataBuffer {
    let max_buffer_size = max(
        max_block_size + DATA_PACKET_HEADER_SIZE as u16,
        MIN_BUFFER_SIZE,
    );
    assert!(max_buffer_size <= MAX_BUFFER_SIZE);
    #[allow(unused_must_use)]
    let mut buffer = {
        let mut d = DataBuffer::new();
        d.resize(max_buffer_size as usize, 0);
        d
    };
    buffer
}

fn handle_write<R, W: Write + Seek, B: BoundSocket>(
    connection: &mut Connection<R, W, B>,
    mut buffer: &mut DataBuffer,
    instant: InstantCallback,
    max_file_size: u64,
) -> Option<()> {
    if !connection.decrypt_packet(buffer) {
        return None;
    }

    let packet_type = PacketType::from_bytes(buffer);
    if !matches!(
        packet_type,
        Ok(PacketType::Data | PacketType::Ack | PacketType::Error)
    ) {
        debug!(
            "Incorrect packet type received from {} {} {:x?}",
            connection.endpoint,
            buffer.len(),
            buffer,
        );
        return None;
    }

    match Packet::from_bytes(buffer) {
        Ok(Packet::Data(p)) => {
            let data_length = p.data.len();

            debug!(
                "Packet received block {} size {} total {} from {}",
                p.block, data_length, connection.transfer, connection.endpoint
            );

            let mut write_elapsed = instant();
            match write_block(connection, p.block, p.data) {
                Ok(n) if n > 0 => {
                    connection.last_updated = instant();
                    connection.transfer += n;
                    trace!(
                        "Block {} written in {}us",
                        p.block,
                        write_elapsed.elapsed().as_micros()
                    );
                }
                Ok(_) => return None,
                Err(e) => {
                    connection.send_packet(Packet::Error(e));
                    connection.invalid = true;
                    return None;
                }
            }

            // this would write more than expected but only by a block size maximum
            if let Err(e) = handle_file_size(connection.transfer as u64, max_file_size) {
                connection.send_packet(Packet::Error(e));
                connection.invalid = true;
                return None;
            }
        }
        Ok(Packet::Ack(_)) => {
            return None;
        }
        Ok(Packet::Error(p)) => {
            error!("Error received {:?} {}", p.code, p.message);
            connection.invalid = true;
            return None;
        }
        _ => {
            debug!(
                "Incorrect packet received from {} {:x?}",
                connection.endpoint, buffer
            );
            return None;
        }
    };
    Some(())
}

fn handle_read<R: Read + Seek, W, B: BoundSocket>(
    connection: &mut Connection<R, W, B>,
    mut buffer: &mut DataBuffer,
    instant: InstantCallback,
) -> Option<()> {
    if !connection.decrypt_packet(buffer) {
        return None;
    }

    let packet_type = PacketType::from_bytes(buffer);
    if !matches!(packet_type, Ok(PacketType::Ack | PacketType::Error)) {
        debug!(
            "Incorrect packet type received from {} {:x?}",
            connection.endpoint, buffer,
        );
        return None;
    }

    match Packet::from_bytes(buffer) {
        Ok(Packet::Ack(p)) => {
            let ClientType::Reader(ref mut block_reader): ClientType<R, _> = connection.client_type else {
                return None;
            };

            debug!("Ack received {} {}", p.block, connection.endpoint);

            if block_reader.free_block(p.block) > 0 {
                connection.last_updated = instant();
            }
            if block_reader.is_finished() {
                info!("Client read {} finished", connection.endpoint);
                connection.invalid = true;
                return None;
            }
        }
        Ok(Packet::Error(p)) => {
            error!("Error received {:?} {}", p.code, p.message);
            connection.invalid = true;
            return None;
        }
        _ => {
            debug!(
                "Incorrect packet received from {} {:x?}",
                connection.endpoint, buffer
            );
            return None;
        }
    };
    Some(())
}

fn write_block<R, W: Write + Seek, B>(
    connection: &mut Connection<R, W, B>,
    mut block: u16,
    data: &[u8],
) -> Result<usize, ErrorPacket>
where
    B: BoundSocket,
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

fn timeout_client<R, W: Write + Seek, B: BoundSocket>(
    connection: &mut Connection<R, W, B>,
    request_timeout: Duration,
) -> bool {
    let client_type = match connection.client_type {
        ClientType::Writer(ref w) => {
            if w.is_finished_below(connection.options.block_size) {
                info!("Client write finished {}", connection.endpoint);
                return true;
            }
            "write"
        }
        ClientType::Reader(_) => "read",
    };
    if connection.invalid {
        return true;
    }
    if connection.last_updated.elapsed() <= request_timeout {
        return false;
    }

    warn!(
        "Client {} timeout {} {}",
        client_type,
        connection.endpoint,
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
    true
}

fn send_data_block<R: Read + Seek, W, B: BoundSocket>(
    connection: &mut Connection<R, W, B>,
) -> bool {
    let block_reader = match &mut connection.client_type {
        ClientType::Reader(r) => r,
        ClientType::Writer(_) => return false,
    };

    let packet_block = match block_reader.next(connection.options.retry_packet_after_timeout) {
        Ok(Some(b)) => b,
        Ok(None) => return false,
        Err(e) => {
            error!("Failed to read {}", e);
            connection.send_packet(Packet::Error(ErrorPacket::new(
                ErrorCode::AccessVioliation,
                format_str!(DefaultString, "{}", e),
            )));
            connection.invalid = true;
            return false;
        }
    };
    connection.send_packet(Packet::Data(DataPacket {
        block: packet_block.block,
        data: &packet_block.data,
    }))
}

#[cfg(not(feature = "multi_thread"))]
fn send_data_blocks<R: Read + Seek, W, B: BoundSocket>(
    clients: &mut Clients<R, W, B>,
    next_client: usize,
) -> (bool, usize) {
    let mut current_client: Option<usize> = clients
        .iter_mut()
        .filter(|(_, connection)| {
            matches!(connection.client_type, ClientType::Reader(_)) && !connection.invalid
        })
        .enumerate()
        .skip(next_client)
        .find_map(|(index, (s, c))| send_data_block(c).then(|| index + 1));
    if current_client.is_none() {
        current_client = clients
            .iter_mut()
            .filter(|(_, connection)| {
                matches!(connection.client_type, ClientType::Reader(_)) && !connection.invalid
            })
            .take(next_client)
            .enumerate()
            .find_map(|(index, (s, c))| send_data_block(c).then(|| index + 1));
    }

    (
        current_client.is_some(),
        current_client.unwrap_or(next_client),
    )
}

struct WaitControl {
    idle: u8,
    sending: bool,
    receiving: bool,
}

impl WaitControl {
    fn new() -> Self {
        Self {
            idle: 0,
            sending: false,
            receiving: false,
        }
    }

    fn sending(&mut self, sent: bool) {
        if sent {
            self.idle = 0;
            self.sending = true;
        } else {
            self.idle = self.idle.wrapping_add(1);
            self.sending = false;
        }
    }

    fn receiver_idle(&mut self) {
        self.idle = self.idle.wrapping_add(1);
        self.receiving = false;
    }

    fn receiving(&mut self) {
        self.idle = 0;
        self.receiving = true;
    }

    fn wait_for(&self, client_size: usize) -> Option<Duration> {
        if client_size == 0 {
            Duration::from_millis(500).into()
        } else if !self.sending && !self.receiving {
            Duration::from_millis(self.idle as u64).into()
        } else {
            None
        }
    }
}
