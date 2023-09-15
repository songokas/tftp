use core::mem::size_of_val;
use core::num::NonZeroU32;
use core::time::Duration;

use log::*;
use rand::CryptoRng;
use rand::RngCore;

use super::config::ServerConfig;
use super::helpers::read::send_data_block;
use crate::error::BoxedResult;
use crate::error::DefaultBoxedResult;
use crate::macros::cfg_alloc;
use crate::macros::cfg_encryption;
use crate::macros::cfg_seek;
use crate::macros::cfg_stack;
use crate::map::Entry;
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
use crate::writers::Writers;

cfg_encryption! {
    use crate::encryption::encode_public_key;
    use crate::encryption::PublicKey;
}

cfg_stack! {
    use core::cell::RefCell;
    use crate::writers::single_block_writer::SingleBlockWriter;
    use crate::config::MAX_CLIENTS;
    use crate::readers::pool_reader::*;
}

cfg_alloc! {
    use crate::writers::block_writer::BlockWriter;
}

cfg_seek! {
    use crate::std_compat::io::Seek;
}

#[allow(clippy::too_many_arguments)]
pub fn server<
    CreateReader,
    CreateWriter,
    #[cfg(not(feature = "seek"))] R: Read,
    #[cfg(feature = "seek")] R: Read + Seek,
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
    W: Write,
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

    let mut timeout_duration = instant();
    let mut next_client_to_send = 0;
    let mut next_client_to_receive = 0;
    let mut wait_control = WaitControl::new();
    let execute_timeout_client = Duration::from_secs(2);

    #[cfg(not(feature = "alloc"))]
    let single_block_readers = RefCell::new(SingleBlockReaders::new());
    #[cfg(not(feature = "alloc"))]
    let multi_block_readers = RefCell::new(MultiBlockReaders::new());
    #[cfg(all(not(feature = "alloc"), feature = "seek"))]
    let multi_block_seek_readers = RefCell::new(MultiBlockSeekReaders::new());

    let mut clients: Clients<_, _, _> = Clients::new();

    trace!(
        "Size of all clients in memory {} bytes",
        size_of_val(&clients)
    );

    loop {
        if timeout_duration.elapsed() > execute_timeout_client {
            clients.retain(|_, (c, _)| !timeout_client::<B>(c, config.request_timeout));
            timeout_duration = instant();
        }

        #[cfg(feature = "alloc")]
        buffer.resize(max_buffer_size as usize, 0);
        // TODO heapless vector resizing is super slow
        #[cfg(not(feature = "alloc"))]
        unsafe {
            buffer.set_len(max_buffer_size as usize)
        };

        let sent_in = instant();

        let (sent, recv_next_client_to_send) = send_data_blocks(&mut clients, next_client_to_send);

        next_client_to_send = recv_next_client_to_send;
        wait_control.sending(sent);

        trace!(
            "Sent {sent} next {recv_next_client_to_send} in {}",
            sent_in.elapsed().as_secs_f32()
        );

        let client_received_in = instant();

        let client_received = clients.iter().skip(next_client_to_receive).find_map(
            |(client_socket_addr, (connection, _))| {
                next_client_to_receive += 1;
                if socket.notified(&connection.socket) {
                    match connection.recv(&mut buffer, None) {
                        Ok(b) => {
                            if socket.modify_interest(
                                connection.socket.socket_id(),
                                connection.socket.as_raw_fd(),
                            ).is_err() {
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

        trace!(
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
                    trace!("New connection from {from_client} next client index {next_client_to_receive}");
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

        trace!(
            "Received connection from {from_client} in {}",
            received_in.elapsed().as_secs_f32(),
        );

        wait_control.receiving();
        buffer.truncate(received_length);

        let clients_len = clients.len();
        let processed_in = instant();

        match clients.entry(from_client) {
            Entry::Occupied(mut entry) => {
                let (ref mut connection, ref mut client_type) = entry.get_mut();
                match client_type {
                    ClientType::Reader(r) => handle_read(connection, r, &mut buffer, instant),
                    ClientType::Writer(w) => {
                        handle_write(connection, w, &mut buffer, instant, config.max_file_size)
                    }
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
                        ConnectionType::Read => {
                            #[cfg(feature = "alloc")]
                            let readers_available = ReadersAvailable::all();
                            #[cfg(not(feature = "alloc"))]
                            let readers_available = ReadersAvailable::from_used(
                                single_block_readers.borrow().len(),
                                multi_block_readers.borrow().len(),
                                #[cfg(feature = "seek")]
                                multi_block_seek_readers.borrow().len(),
                                #[cfg(not(feature = "seek"))]
                                0,
                            );
                            builder
                                .build_reader(
                                    &socket,
                                    from_client,
                                    &create_reader,
                                    &create_bound_socket,
                                    instant,
                                    readers_available,
                                )
                                .map(|(c, r, e, k)| (c, ClientType::Reader(r), e, k))
                        }
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

                #[cfg(feature = "alloc")]
                let client_type: ClientType<
                    alloc::boxed::Box<dyn BlockReader>,
                    alloc::boxed::Box<dyn BlockWriter>,
                > = match client_type {
                    ClientType::Reader(r) => match r {
                        Readers::Single(r) => ClientType::Reader(alloc::boxed::Box::new(r)),
                        Readers::Multiple(r) => ClientType::Reader(alloc::boxed::Box::new(r)),
                        #[cfg(feature = "seek")]
                        Readers::Seek(r) => ClientType::Reader(alloc::boxed::Box::new(r)),
                    },
                    ClientType::Writer(w) => match w {
                        Writers::Single(w) => ClientType::Writer(alloc::boxed::Box::new(w)),
                    },
                };
                #[cfg(not(feature = "alloc"))]
                let client_type: ClientType<PoolReader<R>, SingleBlockWriter<W>> = match client_type
                {
                    ClientType::Reader(r) => match r {
                        Readers::Single(r) => {
                            let Some(reader) = PoolReader::from_single(r, &single_block_readers)
                            else {
                                error!("Exausted single pool readers");
                                continue;
                            };
                            ClientType::Reader(reader)
                        }
                        Readers::Multiple(r) => {
                            let Some(reader) = PoolReader::from_multi(r, &multi_block_readers)
                            else {
                                error!("Exausted multi pool readers");
                                continue;
                            };
                            ClientType::Reader(reader)
                        }
                        #[cfg(feature = "seek")]
                        Readers::Seek(r) => {
                            let Some(reader) = PoolReader::from_seek(r, &multi_block_seek_readers)
                            else {
                                error!("Exausted multi pool seek readers");
                                continue;
                            };
                            ClientType::Reader(reader)
                        }
                    },
                    ClientType::Writer(w) => match w {
                        Writers::Single(w) => ClientType::Writer(w),
                    },
                };

                #[cfg(feature = "alloc")]
                entry.insert((connection, client_type));
                #[cfg(not(feature = "alloc"))]
                if entry.insert((connection, client_type)).is_err() {
                    error!("Exausted all connections");
                }
            }
        }

        trace!(
            "Processed connection from {from_client} in {}",
            processed_in.elapsed().as_secs_f32(),
        );
    }
}

fn send_data_blocks<R: BlockReader, W, B: BoundSocket>(
    clients: &mut Clients<R, W, B>,
    next_client: usize,
) -> (bool, usize) {
    let mut current_client: Option<usize> = clients
        .iter_mut()
        .filter(|(_, (connection, client_type))| {
            matches!(client_type, ClientType::Reader(_))
                && !(connection.invalid || connection.finished)
        })
        .enumerate()
        .skip(next_client)
        .find_map(|(index, (_, (c, ct)))| match ct {
            ClientType::Reader(r) => send_data_block(c, r).then_some(index + 1),
            _ => None,
        });
    if current_client.is_none() {
        current_client = clients
            .iter_mut()
            .filter(|(_, (connection, ct))| {
                matches!(ct, ClientType::Reader(_)) && !(connection.invalid || connection.finished)
            })
            .take(next_client)
            .enumerate()
            .find_map(|(index, (_, (c, ct)))| match ct {
                ClientType::Reader(r) => send_data_block(c, r).then_some(index + 1),
                _ => None,
            });
    }

    (
        current_client.is_some(),
        current_client.unwrap_or(next_client),
    )
}

type ClientConnection<R, W, B> = (Connection<B>, ClientType<R, W>);

#[cfg(feature = "alloc")]
type Clients<R, W, B> = Map<SocketAddr, ClientConnection<R, W, B>>;
#[cfg(not(feature = "alloc"))]
type Clients<R, W, B> = Map<SocketAddr, ClientConnection<R, W, B>, { MAX_CLIENTS as usize }>;
