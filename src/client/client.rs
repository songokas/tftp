use core::{
    cmp::{max, min},
    time::Duration,
};

use log::{debug, error, info, trace, warn};
use rand::{CryptoRng, RngCore};

use super::extensions::{create_extensions, parse_extensions, validate_extensions};
use crate::{
    config::{
        print_options, ConnectionOptions, DATA_PACKET_HEADER_SIZE, DEFAULT_DATA_BLOCK_SIZE,
        ENCRYPTION_TAG_SIZE, MIN_BUFFER_SIZE,
    },
    encryption::{
        encode_public_key, EncryptionKeys, EncryptionLevel, InitialKeys, PrivateKey, PublicKey,
    },
    error::{BoxedResult, DefaultBoxedResult, EncryptionError, PacketError, StorageError},
    flow_control::RateControl,
    key_management::{create_finalized_keys, create_initial_keys},
    packet::{
        AckPacket, ByteConverter, DataPacket, ErrorCode, ErrorPacket, Mode, Packet,
        PacketExtensions, PacketType, RequestPacket,
    },
    socket::Socket,
    std_compat::{
        io::{ErrorKind, Read, Seek, Write},
        net::SocketAddr,
        time::Instant,
    },
    storage::{BlockReader, BlockWriter, FileReader, FileWriter},
    string::format_str,
    time::InstantCallback,
    types::{DataBuffer, DefaultString, FilePath},
};

#[derive(Clone)]
pub struct ClientConfig {
    pub listen: DefaultString,
    pub endpoint: SocketAddr,
    pub max_blocks_in_memory: u16,
    pub request_timeout: Duration,
    pub max_file_size: u64,
    pub private_key: Option<PrivateKey>,
    pub remote_public_key: Option<PublicKey>,
    pub allow_server_port_change: bool,
}

pub fn send_file<CreateReader, R, Sock, Rng>(
    config: ClientConfig,
    local_file_path: FilePath,
    remote_file_path: FilePath,
    mut options: ConnectionOptions,
    create_reader: CreateReader,
    socket: Sock,
    instant: InstantCallback,
    rng: Rng,
) -> BoxedResult<(usize, Option<PublicKey>)>
where
    R: Read + Seek,
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
    let (socket, initial_keys) = create_initial_socket(socket, &config, &mut options, rng)?;

    let mut max_buffer_size = max(
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

    print_options("Client initial", &options);

    let (_, acknowledge, mut options, endpoint) = query_server(
        &socket,
        &mut buffer,
        PacketType::Write,
        remote_file_path,
        options,
        instant,
        &config,
    )?;

    #[cfg(feature = "encryption")]
    let (socket, options) = configure_socket(socket, initial_keys, options);

    print_options("Client using", &options);

    if acknowledge {
        let packet = Packet::Ack(AckPacket { block: 0 });
        socket.send_to(&mut packet.to_bytes(), endpoint)?;
    }

    let mut block_reader = FileReader::from_reader(
        reader,
        config.max_blocks_in_memory,
        options.block_size,
        options.retry_packet_after_timeout,
        instant,
        options.window_size,
    );

    let mut timeout = instant();
    let mut last_sent = instant();
    let mut last_received = instant();

    let mut total_unconfirmed = 0;
    let mut total_confirmed = 0;

    let mut rate_control = RateControl::new(instant);
    let mut stats_print = instant();
    let mut stats_calculate = instant();
    
    let mut no_work: u8 = 0;
    let mut packets_to_send = u32::MAX;
    let packet_send_window: u32 = 200;


    loop {
        if stats_calculate.elapsed().as_millis() > packet_send_window as u128 {
            rate_control.calculate_transmit_rate(
                options.block_size,
                options.window_size,
                options.retry_packet_after_timeout.as_secs_f64(),
            );
            stats_calculate = instant();
            packets_to_send = u32::MAX;
            // rate_control.packets_to_send(packet_send_window, options.block_size as u32);
        }
        if stats_print.elapsed().as_secs() > 2 {
            rate_control.print_info();
            stats_print = instant();
        }

        if packets_to_send > 0 {
            if let Some(data_block) = block_reader.next()? {
                let data_length = data_block.data.len();

                debug!(
                    "Send data block {} data size {} ack {}",
                    data_block.block, data_length, data_block.expect_ack
                );
                if data_block.expect_ack {
                    rate_control.start_rtt(data_block.block);
                }
                if data_block.retry > 0 {
                    rate_control.increment_errors();
                }

                let data_packet = Packet::Data(DataPacket {
                    block: data_block.block,
                    data: &data_block.data,
                });
                match socket.send_to(&mut data_packet.to_bytes(), endpoint) {
                    Ok(n) => {
                        last_sent = instant();
                        no_work = 1;
                        rate_control.data_sent(data_length);
                        total_unconfirmed += data_length;
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

        debug!(
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
                debug!("Acknowledge received {}", p.block);
                timeout = instant();
                let data_length = block_reader.free_block(p.block);

                rate_control.data_received(data_length);
                if let Some(rtt) = rate_control.end_rtt(p.block) {
                    debug!("Rtt for block {} elapsed {}us", p.block, rtt.as_micros());
                }

                total_confirmed += data_length;

                if block_reader.is_finished() {
                    info!("Client finished sending");
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

pub fn receive_file<CreateWriter, Sock, W, Rng>(
    config: ClientConfig,
    local_file_path: FilePath,
    remote_file_path: FilePath,
    mut options: ConnectionOptions,
    create_writer: CreateWriter,
    mut socket: Sock,
    instant: InstantCallback,
    rng: Rng,
) -> BoxedResult<(usize, Option<PublicKey>)>
where
    W: Write + Seek,
    Rng: CryptoRng + RngCore + Copy,
    Sock: Socket,
    CreateWriter: Fn(&FilePath) -> BoxedResult<W>,
{
    let mut max_buffer_size = max(
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
    let (socket, initial_keys) = create_initial_socket(socket, &config, &mut options, rng)?;

    #[allow(unused_must_use)]
    let mut buffer = {
        let mut d = DataBuffer::new();
        d.resize(max_buffer_size as usize, 0);
        d
    };

    print_options("Client initial", &options);

    let (mut received_length, acknowledge, mut options, endpoint) = query_server(
        &socket,
        &mut buffer,
        PacketType::Read,
        remote_file_path,
        options,
        instant,
        &config,
    )?;

    #[cfg(feature = "encryption")]
    let (socket, options) = configure_socket(socket, initial_keys, options);

    let writer = create_writer(&local_file_path)?;
    let mut block_writer = FileWriter::from_writer(
        writer,
        options.block_size,
        config.max_blocks_in_memory,
        options.window_size,
    );

    // server sent data packet so no encryption
    if let Some(packet_length) = received_length.take() {
        if let Ok(Packet::Data(p)) = Packet::from_bytes(&buffer[..packet_length]) {
            handle_file_size(&socket, endpoint, packet_length, config.max_file_size)?;
            write_block(
                &socket,
                endpoint,
                &mut block_writer,
                p.block,
                p.data,
                &options,
            )?;

            if packet_length != options.block_size as usize {
                info!("Client finished receiving");
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
    let mut total = 0;
    let mut no_work: u8 = 0;

    loop {
        #[cfg(feature = "alloc")]
        buffer.resize(max_buffer_size as usize, 0);
        // TODO heapless vector resizing is super slow
        #[cfg(not(feature = "alloc"))]
        unsafe {
            buffer.set_len(max_buffer_size as usize)
        };

        let wait_for = if no_work > 1 {
            Duration::from_millis(no_work as u64).into()
        } else {
            None
        };
        let length = match socket.recv_from(&mut buffer, wait_for) {
            Ok((n, s)) => {
                if s != endpoint {
                    continue;
                }
                debug!("Received packet size {}", n);
                no_work = 1;
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
                no_work = no_work.wrapping_add(1);
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
                ) {
                    Ok(n) => {
                        if n > 0 {
                            timeout = instant();
                            no_work = 1;
                        } else {
                            no_work = no_work.wrapping_add(1);
                        }
                        total += n;
                    }
                    Err(e) => return Err(e),
                }
                // this would write more than expected but only by a block size maximum
                handle_file_size(&socket, endpoint, total, config.max_file_size)?;

                if block_writer.is_finished_below(options.block_size) {
                    info!("Client finished receiving");
                    return Ok((total, options.remote_public_key()));
                }
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

#[cfg(feature = "encryption")]
fn create_initial_socket(
    socket: impl Socket,
    config: &ClientConfig,
    mut options: &mut ConnectionOptions,
    rng: impl CryptoRng + RngCore + Copy,
) -> BoxedResult<(
    crate::socket::EncryptionBoundSocket<impl Socket>,
    Option<InitialKeys>,
)> {
    if options.encryption_level == EncryptionLevel::None {
        return Ok((crate::socket::EncryptionBoundSocket::wrap(socket), None));
    }

    if let Some(p) = config.remote_public_key {
        let keys = create_finalized_keys(&config.private_key, &p, None, rng);
        options.encryption_keys = Some(EncryptionKeys::LocalToRemote(keys.public, p));
        if options.encryption_level == EncryptionLevel::Protocol {
            options.encryption_level = EncryptionLevel::Full;
        }
        info!("Client public key {}", encode_public_key(&keys.public)?);
        let socket = crate::socket::EncryptionBoundSocket::new(
            socket,
            Some(keys.encryptor),
            keys.public,
            options.encryption_level,
        );
        return Ok((socket, None));
    }
    let initial_keys = create_initial_keys(&config.private_key, rng);
    info!(
        "Client public key {}",
        encode_public_key(&initial_keys.public)?
    );
    options.encryption_keys = Some(EncryptionKeys::ClientKey(initial_keys.public));
    Ok((
        crate::socket::EncryptionBoundSocket::wrap(socket),
        initial_keys.into(),
    ))
}

#[cfg(feature = "encryption")]
fn configure_socket(
    mut socket: crate::socket::EncryptionBoundSocket<impl Socket>,
    initial_keys: Option<InitialKeys>,
    mut options: ConnectionOptions,
) -> (impl Socket, ConnectionOptions) {
    let (socket, mut options) = match (
        options.encryption_level,
        initial_keys,
        options.encryption_keys,
    ) {
        (
            EncryptionLevel::Protocol | EncryptionLevel::Data,
            Some(keys),
            Some(EncryptionKeys::ServerKey(p, n)),
        ) => {
            let final_keys = keys.finalize(&p, n);
            options.encryption_keys = Some(EncryptionKeys::LocalToRemote(final_keys.public, p));
            socket.encryptor = Some(final_keys.encryptor);
            socket.public_key = final_keys.public.into();
            socket.encryption_level = options.encryption_level;
            (socket, options)
        }
        (
            EncryptionLevel::Protocol | EncryptionLevel::Data,
            None,
            Some(EncryptionKeys::ServerKey(p, n)),
        ) => {
            if socket.public_key.is_some() {
                options.encryption_keys =
                    Some(EncryptionKeys::LocalToRemote(socket.public_key.unwrap(), p));
            } else {
                options.encryption_keys = None;
            }
            if let Some(mut encryptor) = socket.encryptor {
                encryptor.nonce = n;
                socket.encryptor = encryptor.into();
            }
            socket.encryption_level = options.encryption_level;
            (socket, options)
        }
        (_, _, keys) => {
            options.encryption_keys = keys;
            (socket, options)
        }
    };

    if socket.encryptor.is_some()
        && matches!(
            socket.encryption_level,
            EncryptionLevel::Data | EncryptionLevel::Protocol | EncryptionLevel::Full
        )
    {
        options.block_size -= ENCRYPTION_TAG_SIZE as u16;
    }
    (socket, options)
}

fn query_server(
    socket: &impl Socket,
    buffer: &mut DataBuffer,
    packet_type: PacketType,
    file_path: FilePath,
    options: ConnectionOptions,
    instant: InstantCallback,
    config: &ClientConfig,
) -> BoxedResult<(Option<usize>, bool, ConnectionOptions, SocketAddr)> {
    let mut extensions = create_extensions(&options);
    let mut used_extensions = extensions.clone();
    let mut initial = true;

    let request_timeout = config.request_timeout;
    let endpoint = config.endpoint;

    loop {
        let request_packet = RequestPacket {
            file_name: file_path.clone(),
            mode: Mode::Octet,
            extensions,
        };
        let packet = match packet_type {
            PacketType::Read => Packet::Read(request_packet),
            PacketType::Write => Packet::Write(request_packet),
            _ => panic!("Invalid packet type provided"),
        };

        let (length, endpoint) = wait_for_initial_packet(
            socket,
            config.endpoint,
            packet,
            buffer,
            request_timeout,
            instant,
        )?;
        if config.endpoint != endpoint {
            if !config.allow_server_port_change {
                error!("Server is using new port, however configuration does not allow it");
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
                if initial && options.encryption_level == EncryptionLevel::None {
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

fn send_error(
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

fn write_block(
    socket: &impl Socket,
    endpoint: SocketAddr,
    block_writer: &mut impl BlockWriter,
    mut block: u16,
    data: &[u8],
    options: &ConnectionOptions,
) -> BoxedResult<usize> {
    let (length, last_in_window) = match block_writer.write_block(block, data) {
        Ok((n, l)) => (n, l),
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
        Err(e) => return Err(e.into()),
    };

    if options.window_size <= 1
        || last_in_window
        || block_writer.is_finished_below(options.block_size)
    {
        debug!("Ack send {}", block);
        let packet = Packet::Ack(AckPacket { block });
        socket.send_to(&mut packet.to_bytes(), endpoint)?;
    }
    Ok(length)
}

fn wait_for_initial_packet(
    socket: &impl Socket,
    endpoint: SocketAddr,
    packet: Packet,
    buffer: &mut DataBuffer,
    request_timeout: Duration,
    instant: InstantCallback,
) -> BoxedResult<(usize, SocketAddr)> {
    let timeout = instant();
    loop {
        socket.send_to(&mut packet.clone().to_bytes(), endpoint)?;
        debug!("Initial packet elapsed {}", timeout.elapsed().as_secs_f32());

        match socket.recv_from(buffer, Duration::from_millis(200).into()) {
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
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}
