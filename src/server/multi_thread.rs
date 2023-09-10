use std::thread::spawn;
use std::thread::JoinHandle;

use core::num::NonZeroU32;
use core::time::Duration;

use log::debug;
use log::info;
use rand::CryptoRng;
use rand::RngCore;

use crate::config::ENCRYPTION_TAG_SIZE;
use crate::encryption::encode_public_key;
use crate::encryption::PublicKey;
use crate::error::BoxedResult;
use crate::error::DefaultBoxedResult;
use crate::macros::cfg_seek;
use crate::macros::cfg_stack;
use crate::map::Map;
use crate::readers::block_reader::BlockReader;
use crate::readers::Readers;
use crate::server::connection::ClientType;
use crate::server::connection::Connection;
use crate::server::connection::ConnectionType;
use crate::server::helpers::connection::accept_connection;
use crate::server::helpers::connection::create_builder;
use crate::server::helpers::connection::create_max_buffer;
use crate::server::helpers::connection::timeout_client;
use crate::server::helpers::read::handle_read;
use crate::server::helpers::read::send_data_block;
use crate::server::helpers::write::handle_write;
use crate::server::readers_available::ReadersAvailable;
use crate::server::wait_control::WaitControl;
use crate::socket::BoundSocket;
use crate::socket::Socket;
use crate::socket::ToSocketId;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::io::Read;
use crate::std_compat::io::Write;
use crate::std_compat::net::SocketAddr;
use crate::string::format_str;
use crate::time::InstantCallback;
use crate::types::FilePath;
use crate::writers::block_writer::BlockWriter;
use crate::writers::Writers;

use super::config::ServerConfig;

cfg_seek! {
    use crate::std_compat::io::Seek;
}

cfg_stack! {
    use crate::config::MAX_CLIENTS;
}

#[allow(clippy::too_many_arguments)]
pub fn server<
    CreateReader,
    CreateWriter,
    #[cfg(not(feature = "seek"))] R: Read + Send + 'static,
    #[cfg(feature = "seek")] R: Read + Seek + Send + 'static,
    W,
    Rng,
    CreateSocket,
    CreateBoundSocket,
    S,
    B,
>(
    config: ServerConfig,
    create_reader: CreateReader,
    create_writer: CreateWriter,
    create_socket: CreateSocket,
    create_bound_socket: CreateBoundSocket,
    instant: InstantCallback,
    rng: Rng,
) -> DefaultBoxedResult
where
    S: Socket + ToSocketId,
    B: BoundSocket + ToSocketId + Send + 'static,
    Rng: CryptoRng + RngCore + Copy,
    CreateSocket: Fn(&str, usize, bool) -> BoxedResult<S>,
    CreateBoundSocket: Fn(&str, usize, SocketAddr) -> BoxedResult<B>,
    CreateReader: Fn(&FilePath, &ServerConfig) -> BoxedResult<(Option<u64>, R)>,
    W: Write + Send + 'static,
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
    let mut client_socket_id = NonZeroU32::new(1).expect("Socket id must be more than zero");
    let mut socket = create_socket(&listen, 0, true)?;

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

        let socket_id = client_socket_id
            .checked_add(1)
            .or_else(|| NonZeroU32::new(1))
            .expect("Socket id expected");

        let Some((builder, connection_type)) = create_builder(
            &config,
            socket_id.get() as usize,
            &mut buffer,
            from_client,
            rng,
        ) else {
            continue;
        };

        let Ok((mut connection, client_type, used_extensions, encryption_keys)) =
            (match connection_type {
                ConnectionType::Read => builder
                    .build_reader(
                        &socket,
                        from_client,
                        &create_reader,
                        &create_bound_socket,
                        instant,
                        ReadersAvailable::all(),
                    )
                    .map(|(c, r, e, k)| (c, ClientType::Reader(r), e, k)),
                ConnectionType::Write => builder
                    .build_writer(
                        &socket,
                        from_client,
                        &create_writer,
                        &create_bound_socket,
                        instant,
                    )
                    .map(|(c, w, e, k)| (c, ClientType::Writer(w), e, k)),
            })
        else {
            continue;
        };

        let Some(_) = accept_connection(
            &mut connection,
            connection_type,
            used_extensions,
            encryption_keys,
        ) else {
            continue;
        };

        client_socket_id = socket_id;

        let handle = match client_type {
            ClientType::Reader(r) => match r {
                Readers::Single(r) => spawn_reader(connection, r, instant, config.request_timeout),
                Readers::Multiple(r) => {
                    spawn_reader(connection, r, instant, config.request_timeout)
                }
                #[cfg(feature = "seek")]
                Readers::Seek(r) => spawn_reader(connection, r, instant, config.request_timeout),
            },
            ClientType::Writer(w) => match w {
                Writers::Single(w) => spawn_writer(
                    connection,
                    w,
                    instant,
                    config.request_timeout,
                    config.max_file_size,
                ),
            },
        };
        let _ = handles.insert(from_client, handle);
        handles.retain(|_, t| !t.is_finished());
    }
}

fn spawn_reader<R: BlockReader + Send + 'static, B: BoundSocket + Send + 'static>(
    mut connection: Connection<B>,
    mut reader: R,
    instant: InstantCallback,
    request_timeout: Duration,
) -> JoinHandle<()> {
    spawn(move || {
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
            let sent = send_data_block(&mut connection, &mut reader);
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
                Err(_) => return,
            };
            wait_control.receiving();
            buffer.truncate(received_length);
            handle_read(&mut connection, &mut reader, &mut buffer, instant);
        }
    })
}

fn spawn_writer<W: BlockWriter + Send + 'static, B: BoundSocket + Send + 'static>(
    mut connection: Connection<B>,
    mut block_writer: W,
    instant: InstantCallback,
    request_timeout: Duration,
    max_file_size: u64,
) -> JoinHandle<()> {
    spawn(move || {
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
                Err(_) => return,
            };
            buffer.truncate(received_length);
            handle_write(
                &mut connection,
                &mut block_writer,
                &mut buffer,
                instant,
                max_file_size,
            );
        }
    })
}

#[cfg(feature = "alloc")]
type Handles = Map<SocketAddr, JoinHandle<()>>;
#[cfg(not(feature = "alloc"))]
type Handles = Map<SocketAddr, JoinHandle<()>, { MAX_CLIENTS as usize }>;