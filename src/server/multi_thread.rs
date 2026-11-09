use core::cmp::min;
use core::net::SocketAddr;
use core::num::NonZeroU32;
use core::time::Duration;

use log::debug;
use log::info;
use log::trace;
use rand::CryptoRng;
use rand::RngCore;

use super::config::ServerConfig;
use crate::buffer::create_max_buffer;
use crate::buffer::create_receive_buffer;
use crate::buffer::resize_buffer;
use crate::config::MAX_CLIENTS;
use crate::error::BoxedResult;
use crate::error::DefaultBoxedResult;
use crate::features::FileReader;
use crate::map::Map;
use crate::metrics::counter;
use crate::metrics::gauge;
use crate::packet::ErrorCode;
use crate::packet::ErrorPacket;
use crate::readers::block_reader::BlockReader;
use crate::readers::Readers;
use crate::server::connection::ClientType;
use crate::server::connection::Connection;
use crate::server::connection::ConnectionType;
use crate::server::connection_builder::ConnectionBuilder;
use crate::server::helpers::connection::accept_connection;
use crate::server::helpers::connection::handle_packet;
use crate::server::helpers::connection::timeout_client;
use crate::server::helpers::read::handle_read;
use crate::server::helpers::read::send_data_block;
use crate::server::helpers::write::handle_write;
use crate::server::readers_available::ReadersAvailable;
use crate::server::session_encryption;
use crate::server::spawner::Spawner;
use crate::server::spawner::TaskHandle;
use crate::server::wait_control::WaitControl;
use crate::socket::BoundSocket;
use crate::socket::Socket;
use crate::socket::ToSocketId;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::io::Write;
use crate::string::format_str;
use crate::time::InstantCallback;
use crate::types::FilePath;
use crate::writers::block_writer::BlockWriter;
use crate::writers::Writers;

/// One accepted connection, ready to be passed to a [`Spawner`].
pub struct Job<B, Rng, R, W> {
    connection: Connection<B, Rng>,
    client: ClientType<Readers<R>, Writers<W>>,
    instant: InstantCallback,
    request_timeout: Duration,
    max_file_size: u64,
}

/// Runs every connection through `spawner`, which must be able to run
/// `config.max_connections` jobs at the same time. With `std`, `ThreadSpawner`
/// runs each one on a new thread.
#[allow(clippy::too_many_arguments)]
pub fn server<
    CreateReader,
    CreateWriter,
    R: FileReader + Send + 'static,
    W,
    Rng,
    CreateSocket,
    CreateBoundSocket,
    S,
    B,
    Sp,
>(
    config: ServerConfig,
    create_reader: CreateReader,
    create_writer: CreateWriter,
    create_socket: CreateSocket,
    create_bound_socket: CreateBoundSocket,
    instant: InstantCallback,
    rng: Rng,
    mut spawner: Sp,
) -> DefaultBoxedResult
where
    S: Socket + ToSocketId,
    B: BoundSocket + ToSocketId + Send + 'static,
    Rng: CryptoRng + RngCore + Copy + Send + 'static,
    CreateSocket: Fn(SocketAddr, usize, bool, usize) -> BoxedResult<S>,
    CreateBoundSocket: Fn(SocketAddr, usize, SocketAddr) -> BoxedResult<B>,
    CreateReader: Fn(&FilePath, &ServerConfig) -> BoxedResult<(Option<u64>, R)>,
    W: Write + Send + 'static,
    CreateWriter: Fn(&FilePath, &ServerConfig) -> BoxedResult<W>,
    Sp: Spawner<Job<B, Rng, R, W>>,
{
    info!("Starting server on {}", config.listen);

    let mut receive_buffer = create_max_buffer(config.max_block_size);
    let receive_max_buffer_size = receive_buffer.len();

    session_encryption::log_server_public_key(&config)?;

    let mut client_socket_id = NonZeroU32::new(1).expect("Socket id must be more than zero");
    let mut socket = create_socket(config.listen, 0, true, config.max_connections as usize)?;

    let mut handles: Handles<Sp::Handle> = Handles::new();

    loop {
        resize_buffer(&mut receive_buffer, receive_max_buffer_size);

        let received_in = instant();
        let (received_length, from_client) =
            match socket.recv_from(&mut receive_buffer, Duration::from_secs(1).into()) {
                Ok(connection_received) => connection_received,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    handles.retain(|_, t| !t.is_finished());
                    gauge!("tftp.server.open_connections").set(handles.len() as f64);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

        handles.retain(|_, t| !t.is_finished());
        gauge!("tftp.server.open_connections").set(handles.len() as f64);

        trace!(
            "Received connection in {}s from_client={from_client} connection exists={}",
            received_in.elapsed().as_secs_f32(),
            handles.contains_key(&from_client),
        );

        if handles.contains_key(&from_client) {
            continue;
        }

        counter!("tftp.server.incoming_connections").increment(1);

        receive_buffer.truncate(received_length);

        // a build without alloc has room for MAX_CLIENTS handles only
        if handles.len() >= min(config.max_connections, MAX_CLIENTS) as usize {
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
        let connection_type =
            match handle_packet(&mut builder, &config, &mut receive_buffer, from_client, rng) {
                Ok(Some(c)) => c,
                Ok(None) => continue,
                Err(e) => {
                    debug!("Failed to handle packet {e}");
                    builder.reject_options(&socket, from_client, &e);
                    continue;
                }
            };

        let Ok((mut connection, client_type, used_extensions, session_keys)) =
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
            &mut receive_buffer,
            session_keys,
        ) else {
            continue;
        };

        client_socket_id = socket_id;

        let job = Job {
            connection,
            client: client_type,
            instant,
            request_timeout: config.request_timeout,
            max_file_size: config.max_file_size,
        };
        let handle = match spawner.spawn(job, run_job::<B, Rng, R, W>) {
            Ok(handle) => handle,
            Err(job) => {
                info!("Unable to start a task for connection from {from_client}");
                resize_buffer(&mut receive_buffer, receive_max_buffer_size);
                job.connection.reply_with_error(
                    ErrorPacket::new(
                        ErrorCode::Undefined,
                        format_str!(DefaultString, "Server resources busy"),
                    ),
                    &mut receive_buffer,
                );
                continue;
            }
        };
        let _ = handles.insert(from_client, handle);
        gauge!("tftp.server.open_connections").set(handles.len() as f64);
    }
}

fn run_job<B: BoundSocket, Rng: CryptoRng + RngCore + Copy, R: FileReader, W: Write>(
    job: Job<B, Rng, R, W>,
) {
    let Job {
        connection,
        client,
        instant,
        request_timeout,
        max_file_size,
    } = job;
    match client {
        ClientType::Reader(Readers::Single(r)) => {
            run_reader(connection, r, instant, request_timeout)
        }
        ClientType::Reader(Readers::Multiple(r)) => {
            run_reader(connection, r, instant, request_timeout)
        }
        ClientType::Reader(Readers::Seek(r)) => run_reader(connection, r, instant, request_timeout),
        ClientType::Writer(Writers::Single(w)) => {
            run_writer(connection, w, instant, request_timeout, max_file_size)
        }
    }
}

fn run_reader<R: BlockReader, B: BoundSocket, Rng: CryptoRng + RngCore + Copy>(
    mut connection: Connection<B, Rng>,
    mut reader: R,
    instant: InstantCallback,
    request_timeout: Duration,
) {
    let mut receive_buffer = create_max_buffer(connection.options.block_size);
    let mut send_buffer = create_max_buffer(connection.options.block_size);
    let mut wait_control = WaitControl::new();
    let max_buffer_size = receive_buffer.len();

    loop {
        if timeout_client(&mut connection, request_timeout, &mut send_buffer) {
            return;
        }
        let sent = send_data_block(&mut connection, &mut reader, &mut send_buffer, instant);
        wait_control.sending(sent);

        resize_buffer(&mut receive_buffer, max_buffer_size);

        let received_length = match connection.recv(&mut receive_buffer, wait_control.wait_for(1)) {
            Ok(connection_received) => connection_received,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                wait_control.receiver_idle();
                continue;
            }
            Err(_) => {
                return;
            }
        };
        wait_control.receiving();
        receive_buffer.truncate(received_length);
        handle_read(&mut connection, &mut reader, &mut receive_buffer, instant);
    }
}

fn run_writer<W: BlockWriter, B: BoundSocket, Rng: CryptoRng + RngCore + Copy>(
    mut connection: Connection<B, Rng>,
    mut block_writer: W,
    instant: InstantCallback,
    request_timeout: Duration,
    max_file_size: u64,
) {
    let mut receive_buffer = create_receive_buffer(connection.options.block_size);
    let mut send_buffer = create_max_buffer(connection.options.block_size);
    let receive_max_buffer_size = receive_buffer.len();

    while !connection.finished {
        if timeout_client(&mut connection, request_timeout, &mut send_buffer) {
            return;
        }

        resize_buffer(&mut receive_buffer, receive_max_buffer_size);

        let received_length =
            match connection.recv(&mut receive_buffer, Duration::from_secs(1).into()) {
                Ok(connection_received) => connection_received,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    continue;
                }
                Err(_) => {
                    return;
                }
            };
        receive_buffer.truncate(received_length);
        handle_write(
            &mut connection,
            &mut block_writer,
            &mut receive_buffer,
            &mut send_buffer,
            instant,
            max_file_size,
        );
    }

    // the final ACK can be lost, and the client then retransmits its last block
    let linger = connection
        .options
        .retry_packet_after_timeout
        .saturating_mul(FINAL_ACK_RETRIES)
        .min(request_timeout);
    let finished_at = instant();
    while finished_at.elapsed() < linger && connection.invalid.is_none() {
        resize_buffer(&mut receive_buffer, receive_max_buffer_size);

        let wait_for = linger.saturating_sub(finished_at.elapsed());
        let received_length = match connection.recv(&mut receive_buffer, wait_for.into()) {
            Ok(connection_received) => connection_received,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(_) => return,
        };
        receive_buffer.truncate(received_length);
        handle_write(
            &mut connection,
            &mut block_writer,
            &mut receive_buffer,
            &mut send_buffer,
            instant,
            max_file_size,
        );
    }
}

/// How many client retransmissions a finished writer stays to answer.
const FINAL_ACK_RETRIES: u32 = 3;

type Handles<H> = Map<SocketAddr, H, { MAX_CLIENTS as usize }>;

#[cfg(test)]
mod tests {
    use core::net::IpAddr;
    use core::net::Ipv4Addr;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::vec::Vec;

    use rand::rngs::OsRng;

    use super::*;
    use crate::server::spawner::Spawner;
    use crate::server::spawner::TaskHandle;
    use crate::socket::SocketRawFd;
    use crate::std_compat::io;
    use crate::std_compat::io::Read;
    use crate::std_compat::io::Seek;
    use crate::std_compat::io::SeekFrom;
    use crate::string::format_str;
    use crate::time::test_now as instant;
    use crate::types::DataBuffer;

    const WRITE_REQUEST: &[u8] = b"\0\x02file\0octet\0";

    fn address() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6969)
    }

    /// Delivers the same write request a fixed number of times, then fails,
    /// which is the only way to make the server return.
    struct ScriptedSocket {
        requests: usize,
        distinct_clients: bool,
    }

    impl ToSocketId for ScriptedSocket {
        fn as_raw_fd(&self) -> SocketRawFd {
            0
        }

        fn socket_id(&self) -> usize {
            0
        }
    }

    impl Socket for ScriptedSocket {
        fn recv_from(
            &mut self,
            buffer: &mut DataBuffer,
            _wait_for: Option<Duration>,
        ) -> io::Result<(usize, SocketAddr)> {
            if self.requests == 0 {
                return Err(ErrorKind::Other.into());
            }
            self.requests -= 1;
            buffer[..WRITE_REQUEST.len()].copy_from_slice(WRITE_REQUEST);
            let mut from = address();
            if self.distinct_clients {
                from.set_port(self.requests as u16 + 1);
            }
            Ok((WRITE_REQUEST.len(), from))
        }

        fn send_to(&self, buffer: &mut DataBuffer, _addr: SocketAddr) -> io::Result<usize> {
            Ok(buffer.len())
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(address())
        }

        fn modify_interest(&mut self, _socket_id: usize, _raw_fd: SocketRawFd) -> io::Result<()> {
            Ok(())
        }
    }

    struct ClosedBoundSocket {
        receives: Arc<AtomicUsize>,
    }

    impl ToSocketId for ClosedBoundSocket {
        fn as_raw_fd(&self) -> SocketRawFd {
            0
        }

        fn socket_id(&self) -> usize {
            0
        }
    }

    impl BoundSocket for ClosedBoundSocket {
        fn recv(
            &mut self,
            _buffer: &mut DataBuffer,
            _wait_for: Option<Duration>,
        ) -> io::Result<usize> {
            self.receives.fetch_add(1, Ordering::SeqCst);
            Err(ErrorKind::Other.into())
        }

        fn send(&self, buffer: &mut DataBuffer) -> io::Result<usize> {
            Ok(buffer.len())
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(address())
        }
    }

    struct Sink;

    impl Read for Sink {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Sink {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            Ok(buffer.len())
        }

        fn write_fmt(&mut self, _fmt: core::fmt::Arguments<'_>) -> io::Result<()> {
            Ok(())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Seek for Sink {
        fn seek(&mut self, _position: SeekFrom) -> io::Result<u64> {
            Ok(0)
        }
    }

    struct FixedHandle {
        finished: bool,
    }

    impl TaskHandle for FixedHandle {
        fn is_finished(&self) -> bool {
            self.finished
        }
    }

    /// Runs accepted jobs on the calling thread.
    struct InlineSpawner {
        attempts: Arc<AtomicUsize>,
        accept: bool,
        finished: bool,
    }

    impl<J: Send + 'static> Spawner<J> for InlineSpawner {
        type Handle = FixedHandle;

        fn spawn(&mut self, job: J, run: fn(J)) -> Result<Self::Handle, J> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if !self.accept {
                return Err(job);
            }
            run(job);
            Ok(FixedHandle {
                finished: self.finished,
            })
        }
    }

    /// Returns how many spawns were attempted and how often a job read its socket.
    fn serve(requests: usize, accept: bool, finished: bool) -> (usize, usize) {
        let attempts = Arc::new(AtomicUsize::new(0));
        let receives = Arc::new(AtomicUsize::new(0));
        let job_receives = receives.clone();
        let config = ServerConfig {
            listen: address(),
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
        };

        let result = server(
            config,
            |_: &FilePath, _: &ServerConfig| Ok((None, Sink)),
            |_: &FilePath, _: &ServerConfig| Ok(Sink),
            |_, _, _, _| {
                Ok(ScriptedSocket {
                    requests,
                    distinct_clients: false,
                })
            },
            |_, _, _| {
                Ok(ClosedBoundSocket {
                    receives: job_receives.clone(),
                })
            },
            instant,
            OsRng,
            InlineSpawner {
                attempts: attempts.clone(),
                accept,
                finished,
            },
        );

        assert!(result.is_err(), "server only stops when the socket fails");
        (
            attempts.load(Ordering::SeqCst),
            receives.load(Ordering::SeqCst),
        )
    }

    /// Delivers `incoming` to a connection, then fails.
    struct ScriptedBoundSocket {
        incoming: VecDeque<Vec<u8>>,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl ToSocketId for ScriptedBoundSocket {
        fn as_raw_fd(&self) -> SocketRawFd {
            0
        }

        fn socket_id(&self) -> usize {
            0
        }
    }

    impl BoundSocket for ScriptedBoundSocket {
        fn recv(
            &mut self,
            buffer: &mut DataBuffer,
            _wait_for: Option<Duration>,
        ) -> io::Result<usize> {
            let Some(datagram) = self.incoming.pop_front() else {
                return Err(ErrorKind::Other.into());
            };
            buffer[..datagram.len()].copy_from_slice(&datagram);
            Ok(datagram.len())
        }

        fn send(&self, buffer: &mut DataBuffer) -> io::Result<usize> {
            self.sent.lock().unwrap().push(buffer.to_vec());
            Ok(buffer.len())
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(address())
        }
    }

    fn test_config() -> ServerConfig {
        ServerConfig {
            listen: address(),
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

    /// Runs one write request against a connection receiving `incoming` and
    /// returns what the connection sent.
    fn serve_upload(incoming: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let sent: Arc<Mutex<Vec<Vec<u8>>>> = Default::default();
        let connection_sent = sent.clone();
        let incoming = Mutex::new(Some(incoming));
        let result = server(
            test_config(),
            |_: &FilePath, _: &ServerConfig| Ok((None, Sink)),
            |_: &FilePath, _: &ServerConfig| Ok(Sink),
            |_, _, _, _| {
                Ok(ScriptedSocket {
                    requests: 1,
                    distinct_clients: false,
                })
            },
            |_, _, _| {
                Ok(ScriptedBoundSocket {
                    incoming: incoming.lock().unwrap().take().unwrap().into(),
                    sent: connection_sent.clone(),
                })
            },
            instant,
            OsRng,
            InlineSpawner {
                attempts: Default::default(),
                accept: true,
                finished: false,
            },
        );
        assert!(result.is_err(), "server only stops when the socket fails");
        let sent = sent.lock().unwrap().clone();
        sent
    }

    #[test]
    fn test_connections_stop_at_the_capacity_of_the_build() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let requests = MAX_CLIENTS as usize + 1;
        let config = ServerConfig {
            max_connections: MAX_CLIENTS + 1,
            ..test_config()
        };

        let result = server(
            config,
            |_: &FilePath, _: &ServerConfig| Ok((None, Sink)),
            |_: &FilePath, _: &ServerConfig| Ok(Sink),
            |_, _, _, _| {
                Ok(ScriptedSocket {
                    requests,
                    distinct_clients: true,
                })
            },
            |_, _, _| {
                Ok(ClosedBoundSocket {
                    receives: Default::default(),
                })
            },
            instant,
            OsRng,
            InlineSpawner {
                attempts: attempts.clone(),
                accept: true,
                finished: false,
            },
        );

        assert!(result.is_err(), "server only stops when the socket fails");
        assert_eq!(attempts.load(Ordering::SeqCst), MAX_CLIENTS as usize);
    }

    #[test]
    fn test_rejected_connection_is_told_so() {
        let sent: Arc<Mutex<Vec<Vec<u8>>>> = Default::default();
        let connection_sent = sent.clone();

        let result = server(
            test_config(),
            |_: &FilePath, _: &ServerConfig| Ok((None, Sink)),
            |_: &FilePath, _: &ServerConfig| Ok(Sink),
            |_, _, _, _| {
                Ok(ScriptedSocket {
                    requests: 1,
                    distinct_clients: false,
                })
            },
            |_, _, _| {
                Ok(ScriptedBoundSocket {
                    incoming: VecDeque::new(),
                    sent: connection_sent.clone(),
                })
            },
            instant,
            OsRng,
            InlineSpawner {
                attempts: Default::default(),
                accept: false,
                finished: false,
            },
        );

        assert!(result.is_err(), "server only stops when the socket fails");
        let sent = sent.lock().unwrap();
        assert!(sent.iter().any(|p| p.starts_with(&[0, 5])), "{sent:?}");
    }

    /// Counts the bytes that reach the file.
    #[derive(Clone)]
    struct CountingFile(Arc<AtomicUsize>);

    impl Write for CountingFile {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.fetch_add(buffer.len(), Ordering::SeqCst);
            Ok(buffer.len())
        }

        fn write_fmt(&mut self, _fmt: core::fmt::Arguments<'_>) -> io::Result<()> {
            Ok(())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_block_past_max_file_size_is_not_written() {
        let written = Arc::new(AtomicUsize::new(0));
        let file = CountingFile(written.clone());
        let mut first = b"\0\x03\0\x01".to_vec();
        first.extend_from_slice(&[7; 512]);
        let mut second = b"\0\x03\0\x02".to_vec();
        second.extend_from_slice(&[8; 512]);
        let incoming = Mutex::new(Some(vec![first, second]));
        let config = ServerConfig {
            max_file_size: 600,
            ..test_config()
        };

        let result = server(
            config,
            |_: &FilePath, _: &ServerConfig| Ok((None, Sink)),
            move |_: &FilePath, _: &ServerConfig| Ok(file.clone()),
            |_, _, _, _| {
                Ok(ScriptedSocket {
                    requests: 1,
                    distinct_clients: false,
                })
            },
            |_, _, _| {
                Ok(ScriptedBoundSocket {
                    incoming: incoming.lock().unwrap().take().unwrap().into(),
                    sent: Default::default(),
                })
            },
            instant,
            OsRng,
            InlineSpawner {
                attempts: Default::default(),
                accept: true,
                finished: false,
            },
        );

        assert!(result.is_err(), "server only stops when the socket fails");
        assert_eq!(written.load(Ordering::SeqCst), 512);
    }

    #[test]
    fn test_failed_socket_leaves_target_file_untouched() {
        let opened = Arc::new(AtomicUsize::new(0));
        let writer_opened = opened.clone();

        let result = server(
            test_config(),
            |_: &FilePath, _: &ServerConfig| Ok((None, Sink)),
            move |_: &FilePath, _: &ServerConfig| {
                writer_opened.fetch_add(1, Ordering::SeqCst);
                Ok(Sink)
            },
            |_, _, _, _| {
                Ok(ScriptedSocket {
                    requests: 1,
                    distinct_clients: false,
                })
            },
            |_, _, _| -> BoxedResult<ClosedBoundSocket> {
                Err(crate::error::PacketError::Invalid.into())
            },
            instant,
            OsRng,
            InlineSpawner {
                attempts: Default::default(),
                accept: true,
                finished: false,
            },
        );

        assert!(result.is_err(), "server only stops when the socket fails");
        assert_eq!(opened.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_retransmitted_final_block_is_acknowledged_again() {
        let last_block = b"\0\x03\0\x01data".to_vec();

        let sent = serve_upload(vec![last_block.clone(), last_block]);

        let final_acks = sent
            .iter()
            .filter(|p| p.as_slice() == b"\0\x04\0\x01")
            .count();
        assert_eq!(final_acks, 2, "{sent:?}");
    }

    #[test]
    fn test_accepted_connection_runs_on_injected_spawner() {
        let (attempts, receives) = serve(1, true, false);
        assert_eq!(attempts, 1);
        assert_eq!(receives, 1);
    }

    #[test]
    fn test_running_connection_is_not_spawned_twice() {
        let (attempts, _) = serve(2, true, false);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn test_finished_connection_can_be_spawned_again() {
        let (attempts, _) = serve(2, true, true);
        assert_eq!(attempts, 2);
    }

    #[test]
    fn test_rejected_connection_is_not_tracked() {
        let (attempts, receives) = serve(2, false, false);
        assert_eq!(attempts, 2);
        assert_eq!(receives, 0);
    }
}
