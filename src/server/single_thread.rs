use core::net::SocketAddr;
use core::num::NonZeroU32;
use core::time::Duration;

use log::*;
use rand::CryptoRng;
use rand::RngCore;

use super::client_store::ClientStore;
use super::config::ServerConfig;
use super::helpers::read::send_data_block;
use crate::buffer::create_max_buffer;
use crate::buffer::create_receive_buffer;
use crate::buffer::resize_buffer;
use crate::config::MAX_CLIENTS;
use crate::error::BoxedResult;
use crate::error::DefaultBoxedResult;
use crate::features::FileReader;
use crate::map::insert_vacant;
use crate::map::Entry;
use crate::map::Map;
use crate::metrics::gauge;
use crate::packet::ByteConverter;
use crate::packet::Packet;
use crate::readers::block_reader::BlockReader;
use crate::server::connection::ClientType;
use crate::server::connection::Connection;
use crate::server::connection::ConnectionType;
use crate::server::connection_builder::ConnectionBuilder;
use crate::server::helpers::connection::accept_connection;
use crate::server::helpers::connection::handle_packet;
use crate::server::helpers::connection::timeout_client;
use crate::server::helpers::read::handle_read;
use crate::server::helpers::write::handle_write;
use crate::server::session_encryption;
use crate::server::wait_control::WaitControl;
use crate::socket::BoundSocket;
use crate::socket::Socket;
use crate::socket::ToSocketId;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::io::Write;
use crate::time::InstantCallback;
use crate::types::DataBuffer;
use crate::types::FilePath;

#[allow(clippy::too_many_arguments)]
pub fn server<
    CreateReader,
    CreateWriter,
    R: FileReader,
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
    CreateSocket: Fn(SocketAddr, usize, bool, usize) -> BoxedResult<S>,
    CreateBoundSocket: Fn(SocketAddr, usize, SocketAddr) -> BoxedResult<B>,
    CreateReader: Fn(&FilePath, &ServerConfig) -> BoxedResult<(Option<u64>, R)>,
    W: Write,
    CreateWriter: Fn(&FilePath, &ServerConfig) -> BoxedResult<W>,
{
    info!("Starting server on a {}", config.listen);

    let mut receive_buffer = create_receive_buffer(config.max_block_size);
    let receive_max_buffer_size = receive_buffer.len();

    session_encryption::log_server_public_key(&config)?;

    let mut client_socket_id = NonZeroU32::new(1).expect("Socket id must be more than zero");
    let mut socket = create_socket(config.listen, 0, true, config.max_connections as usize)?;

    let mut timeout_duration = instant();
    let mut next_client_to_send = 0;
    let mut next_client_to_receive = 0;
    let mut wait_control = WaitControl::new();
    let execute_timeout_client = Duration::from_secs(2);

    let client_store = ClientStore::new();

    let mut clients: Clients<_, _, _, _> = Clients::new();

    client_store.trace_sizes(core::mem::size_of_val(&clients));

    let mut send_buffer = create_max_buffer(config.max_block_size);

    loop {
        resize_buffer(&mut receive_buffer, receive_max_buffer_size);

        if timeout_duration.elapsed() > execute_timeout_client {
            clients.retain(|_, (c, _)| {
                !timeout_client::<B, Rng>(c, config.request_timeout, &mut send_buffer)
            });
            timeout_duration = instant();
        }

        let sent_in = instant();

        let (sent, recv_next_client_to_send) =
            send_data_blocks(&mut clients, next_client_to_send, &mut send_buffer, instant);

        next_client_to_send = recv_next_client_to_send;
        wait_control.sending(sent);

        trace!(
            "Sent {sent} next {recv_next_client_to_send} in {}",
            sent_in.elapsed().as_secs_f32()
        );

        let client_received_in = instant();

        let client_received = clients.iter_mut().skip(next_client_to_receive).find_map(
            |(client_socket_addr, (connection, _))| {
                next_client_to_receive += 1;
                if socket.notified(&connection.socket) {
                    match connection.recv(&mut receive_buffer, None) {
                        Ok(b) => {
                            if socket
                                .modify_interest(
                                    connection.socket.socket_id(),
                                    connection.socket.as_raw_fd(),
                                )
                                .is_err()
                            {
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
            None => {
                match socket.recv_from(&mut receive_buffer, wait_control.wait_for(clients.len())) {
                    Ok((received, from_client)) => {
                        // ignore existing connection attempts on the main socket
                        if clients
                            .get(&from_client)
                            .is_some_and(|(c, _)| !c.can_be_replaced())
                        {
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
                }
            }
        };

        trace!(
            "Received connection from {from_client} in {}",
            received_in.elapsed().as_secs_f32(),
        );

        wait_control.receiving();
        receive_buffer.truncate(received_length);

        // a client can reuse its port while its finished connection is still kept
        if clients
            .get(&from_client)
            .is_some_and(|(c, _)| c.can_be_replaced())
            && is_new_request(&config, &receive_buffer, rng)
        {
            clients.remove(&from_client);
        }

        let clients_len = clients.len();
        let processed_in = instant();

        match clients.entry(from_client) {
            Entry::Occupied(mut entry) => {
                let (ref mut connection, ref mut client_type) = entry.get_mut();
                if connection.invalid.is_some() {
                    continue;
                }
                match client_type {
                    ClientType::Reader(r) => {
                        handle_read(connection, r, &mut receive_buffer, instant)
                    }
                    ClientType::Writer(w) => handle_write(
                        connection,
                        w,
                        &mut receive_buffer,
                        &mut send_buffer,
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

                let socket_id = client_socket_id
                    .checked_add(1)
                    .or_else(|| NonZeroU32::new(1))
                    .expect("Socket id expected");

                let mut builder = ConnectionBuilder::from_new_connection(
                    &config,
                    &mut receive_buffer,
                    rng,
                    socket_id.get() as usize,
                );
                let connection_type = match handle_packet(
                    &mut builder,
                    &config,
                    &mut receive_buffer,
                    from_client,
                    rng,
                ) {
                    Ok(Some(c)) => c,
                    Ok(None) => continue,
                    Err(e) => {
                        debug!("Failed to handle packet {e}");
                        builder.reject_options(&socket, from_client, &e);
                        continue;
                    }
                };

                let Ok((mut connection, client_type, used_extensions, connection_keys)) =
                    (match connection_type {
                        ConnectionType::Read => {
                            let readers_available = client_store.available();
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
                    &mut receive_buffer,
                    connection_keys,
                ) else {
                    continue;
                };

                client_socket_id = socket_id;

                let Some(client_type) = client_store.keep(client_type) else {
                    continue;
                };

                if !insert_vacant(entry, (connection, client_type)) {
                    error!("Exhausted all connections");
                }
            }
        }

        gauge!("tftp.server.open_connections").set(clients.len() as f64);

        trace!(
            "Processed connection from {from_client} in {}",
            processed_in.elapsed().as_secs_f32(),
        );
    }
}

fn is_new_request<Rng: CryptoRng + RngCore + Copy>(
    config: &ServerConfig,
    buffer: &DataBuffer,
    rng: Rng,
) -> bool {
    matches!(
        Packet::from_bytes(buffer),
        Ok(Packet::Read(_) | Packet::Write(_))
    ) || session_encryption::open_initial_packet(config, &mut buffer.clone(), rng).is_some()
}

fn send_data_blocks<R: BlockReader, W, B: BoundSocket, Rng: CryptoRng + RngCore + Copy>(
    clients: &mut Clients<R, W, B, Rng>,
    next_client: usize,
    buffer: &mut DataBuffer,
    instant: InstantCallback,
) -> (bool, usize) {
    let mut current_client: Option<usize> = clients
        .iter_mut()
        .filter(|(_, (connection, client_type))| {
            matches!(client_type, ClientType::Reader(_))
                && !(connection.invalid.is_some() || connection.finished)
        })
        .enumerate()
        .skip(next_client)
        .find_map(|(index, (_, (c, ct)))| match ct {
            ClientType::Reader(r) => send_data_block(c, r, buffer, instant).then_some(index + 1),
            _ => None,
        });
    if current_client.is_none() {
        current_client = clients
            .iter_mut()
            .filter(|(_, (connection, ct))| {
                matches!(ct, ClientType::Reader(_))
                    && !(connection.invalid.is_some() || connection.finished)
            })
            .take(next_client)
            .enumerate()
            .find_map(|(index, (_, (c, ct)))| match ct {
                ClientType::Reader(r) => {
                    send_data_block(c, r, buffer, instant).then_some(index + 1)
                }
                _ => None,
            });
    }

    (
        current_client.is_some(),
        current_client.unwrap_or(next_client),
    )
}

type ClientConnection<R, W, B, Rng> = (Connection<B, Rng>, ClientType<R, W>);

type Clients<R, W, B, Rng> =
    Map<SocketAddr, ClientConnection<R, W, B, Rng>, { MAX_CLIENTS as usize }>;

#[cfg(test)]
mod tests {
    use core::cell::RefCell;
    use core::time::Duration;
    use std::collections::VecDeque;
    use std::vec::Vec;

    use rand::rngs::OsRng;

    use super::*;
    use crate::client::test_support::*;
    use crate::string::format_str;
    use crate::time::test_now as instant;
    use crate::types::FilePath;

    const WRITE_REQUEST: &[u8] = b"\0\x02file\0octet\0";
    const LAST_BLOCK: &[u8] = b"\0\x03\0\x01data";
    const LAST_ACK: &[u8] = b"\0\x04\0\x01";
    /// Longer than the retry interval a finished connection is kept for.
    const PAST_GRACE: Duration = Duration::from_millis(120);

    fn test_config() -> ServerConfig {
        ServerConfig {
            listen: server_address(),
            directory: format_str!(FilePath, "/tmp"),
            allow_overwrite: true,
            max_window_size: 1,
            request_timeout: Duration::from_secs(60),
            max_connections: 4,
            max_file_size: 1024,
            max_block_size: 512,
            authorized_keys: None,
            private_key: None,
            require_full_encryption: false,
            require_server_port_change: false,
            prefer_seek: false,
            directory_list: None,
            max_directory_depth: 4,
            error_to_authorized_only: false,
        }
    }

    fn socket(datagrams: &[&[u8]], delay: Duration) -> ScriptedSocket {
        let mut socket = ScriptedSocket::from_server(datagrams.iter().map(|d| d.to_vec()));
        socket.delay = delay;
        socket
    }

    /// The server goes back to its connections only after the main socket idles.
    fn main_socket(datagrams: usize, delay: Duration) -> ScriptedSocket {
        let mut incoming = Vec::new();
        for _ in 0..datagrams {
            incoming.push(Incoming::Datagram(WRITE_REQUEST.to_vec(), server_address()));
            incoming.extend([Incoming::Idle, Incoming::Idle, Incoming::Idle]);
        }
        let mut socket = ScriptedSocket::new(incoming);
        socket.delay = delay;
        socket
    }

    /// Runs the server until `main` is out of datagrams. Returns how many times
    /// a file was opened for writing.
    fn serve(main: ScriptedSocket, connection: ScriptedSocket) -> usize {
        let opened = RefCell::new(0);
        let main = RefCell::new(Some(main));
        let connections = RefCell::new(VecDeque::from([connection]));

        let result = server(
            test_config(),
            |_: &FilePath, _: &ServerConfig| Ok((None, MemoryReader::new(&[]))),
            |_: &FilePath, _: &ServerConfig| {
                *opened.borrow_mut() += 1;
                Ok(MemoryFile::default())
            },
            |_, _, _, _| Ok(main.borrow_mut().take().unwrap()),
            |_, _, _| {
                let next = connections.borrow_mut().pop_front();
                Ok(next.unwrap_or_else(|| ScriptedSocket::from_server([])))
            },
            instant,
            OsRng,
        );

        assert!(result.is_err(), "server only stops when the socket fails");
        opened.into_inner()
    }

    fn acks(sent: &Shared<Vec<Vec<u8>>>) -> usize {
        sent.borrow()
            .iter()
            .filter(|p| p.as_slice() == LAST_ACK)
            .count()
    }

    #[test]
    fn test_new_request_replaces_a_finished_connection() {
        let main = main_socket(1, Duration::ZERO);
        let connection = socket(&[LAST_BLOCK, WRITE_REQUEST], PAST_GRACE);

        assert_eq!(serve(main, connection), 2);
    }

    #[test]
    fn test_new_request_on_the_main_socket_replaces_a_finished_connection() {
        let main = main_socket(2, PAST_GRACE);
        let connection = socket(&[LAST_BLOCK], Duration::ZERO);

        assert_eq!(serve(main, connection), 2);
    }

    #[test]
    fn test_request_right_after_finishing_is_treated_as_a_duplicate() {
        let main = main_socket(1, Duration::ZERO);
        let connection = socket(&[LAST_BLOCK, WRITE_REQUEST], Duration::ZERO);

        assert_eq!(serve(main, connection), 1);
    }

    #[test]
    fn test_retransmitted_last_block_keeps_the_finished_connection() {
        let main = main_socket(1, Duration::ZERO);
        let connection = socket(&[LAST_BLOCK, LAST_BLOCK], PAST_GRACE);
        let sent = connection.sent.clone();

        assert_eq!(serve(main, connection), 1);
        assert_eq!(acks(&sent), 2);
    }
}
