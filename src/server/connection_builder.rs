use core::net::SocketAddr;
use core::num::NonZeroU8;

use log::*;
use rand::CryptoRng;
use rand::RngCore;

use super::config::ServerConfig;
use super::connection::Connection;
use super::extensions::parse_extensions;
use super::readers_available::ReadersAvailable;
use super::validation::validate_request_options;
use crate::config::ConnectionOptions;
use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::encryption::*;
use crate::error::open_error_code;
use crate::error::AvailabilityError;
use crate::error::BoxedResult;
use crate::error::ExtensionError;
use crate::error::FileError;
use crate::features::FileReader;
use crate::flow_control::RateControl;
use crate::flow_control::FLOW_CONTROL_PERIOD;
use crate::map::Entry;
use crate::packet::ErrorCode;
use crate::packet::ErrorPacket;
use crate::packet::Extension;
use crate::packet::Packet;
use crate::packet::PacketExtensions;
use crate::packet::PacketType;
use crate::packet::RequestPacket;
use crate::packet::SignedRequest;
use crate::readers::multiple_block_reader::MultipleBlockReader;
use crate::readers::multiple_block_seek_reader::MultipleBlockSeekReader;
use crate::readers::single_block_reader::SingleBlockReader;
use crate::readers::Readers;
use crate::server::helpers::connection::SessionKeys;
use crate::server::session_encryption;
use crate::socket::BoundSocket;
use crate::socket::Socket;
use crate::socket::ToSocketId;
use crate::std_compat::io::Write;
use crate::std_compat::time::Instant;
use crate::string::format_str;
use crate::types::DataBuffer;
use crate::types::FilePath;
use crate::writers::single_block_writer::SingleBlockWriter;
use crate::writers::Writers;

pub struct ConnectionBuilder<'a, Rng> {
    config: &'a ServerConfig,
    options: ConnectionOptions,
    used_extensions: PacketExtensions,
    file_name: Option<FilePath>,
    session_keys: Option<SessionKeys<Rng>>,
    handshake_encryption: Option<Encryptor<Rng>>,
    socket_id: usize,
}

impl<'a, Rng> ConnectionBuilder<'a, Rng>
where
    Rng: CryptoRng + RngCore + Copy,
{
    pub fn from_new_connection(
        config: &'a ServerConfig,
        buffer: &mut DataBuffer,
        rng: Rng,
        socket_id: usize,
    ) -> Self {
        let create_default_builder = || Self {
            config,
            options: Default::default(),
            session_keys: None,
            handshake_encryption: None,
            used_extensions: PacketExtensions::new(),
            file_name: None,
            socket_id,
        };
        let mut builder = create_default_builder();
        if let Some(encryptor) = session_encryption::open_initial_packet(config, buffer, rng) {
            builder.handshake_encryption = encryptor.into();
            builder.options.encryption_level = EncryptionLevel::Full;
            debug!("Initial packet encrypted");
        }
        builder
    }

    pub fn with_request(
        &mut self,
        packet_type: PacketType,
        request: RequestPacket,
        max_window_size: u16,
        rng: Rng,
    ) -> Result<(), ExtensionError> {
        let signed_request = SignedRequest {
            packet_type,
            file_name: request.file_name.as_str(),
        };
        let (used_extensions, options, session_keys) = parse_extensions(
            request.extensions,
            signed_request,
            self.options.clone(),
            self.config,
            max_window_size,
            rng,
        )?;
        self.file_name = Some(request.file_name);
        self.used_extensions = used_extensions;
        self.options = options;
        self.session_keys = session_keys;
        Ok(())
    }

    pub fn build_writer<W, CreateWriter, CreateBoundSocket, S, B>(
        self,
        socket: &S,
        client: SocketAddr,
        create_writer: &CreateWriter,
        create_bound_socket: &CreateBoundSocket,
        instant: fn() -> Instant,
    ) -> WritersResult<B, W, Rng>
    where
        S: Socket,
        B: BoundSocket + ToSocketId,
        W: Write,
        CreateBoundSocket: Fn(SocketAddr, usize, SocketAddr) -> BoxedResult<B>,
        CreateWriter: Fn(&FilePath, &ServerConfig) -> BoxedResult<W>,
    {
        let file_name = self.file_name.clone().ok_or(FileError::InvalidFileName)?;
        let file_path = self.validated_file_path(socket, client, &file_name)?;

        // opening the file can truncate it, so only do that once nothing else can fail
        let mut listen = self.config.listen;
        if self.config.require_server_port_change {
            listen.set_port(0);
        }

        let new_socket = match create_bound_socket(listen, self.socket_id, client) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to create socket {}", e);
                return Err(e);
            }
        };

        let writer = match create_writer(&file_path, self.config) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to open file {} {}", file_path, e);

                let error_packet = ErrorPacket::new(
                    open_error_code(&e, ErrorCode::DiskFull),
                    format_str!(DefaultString, "Unable to write file {}", file_name),
                );
                self.reply_with_error(socket, client, error_packet);
                return Err(e);
            }
        };

        #[cfg(not(feature = "multi_thread"))]
        if socket.add_interest(&new_socket).is_err() {
            warn!("Unable to add socket {} to epoll", new_socket.socket_id());
        }

        let mut rate_control = RateControl::new(instant);
        rate_control.configure(self.options.block_size, self.options.window_size);
        Ok((
            Connection {
                socket: new_socket,
                last_updated: instant(),
                started: instant(),
                transfer: 0,
                options: self.options,
                endpoint: client,
                encryptor: self.handshake_encryption,
                finished: false,
                invalid: None,
                last_acknowledged: 0,
                retry_packet_multiplier: NonZeroU8::new(1).expect("Non zero multiplier"),
                writer: true,
                rate_control,
                packets_to_send: u32::MAX,
                rate_period: instant(),
                window_sent_at: None,
                fast_retransmit: false,
            },
            block_writer(writer),
            self.used_extensions,
            self.session_keys,
        ))
    }

    pub fn build_reader<R: FileReader, CreateReader, CreateBoundSocket, S, B>(
        mut self,
        socket: &S,
        client: SocketAddr,
        create_reader: &CreateReader,
        create_bound_socket: &CreateBoundSocket,
        instant: fn() -> Instant,
        readers_available: ReadersAvailable,
    ) -> ReadersResult<B, R, Rng>
    where
        S: Socket,
        B: BoundSocket + ToSocketId,
        CreateBoundSocket: Fn(SocketAddr, usize, SocketAddr) -> BoxedResult<B>,
        CreateReader: Fn(&FilePath, &ServerConfig) -> BoxedResult<(Option<u64>, R)>,
    {
        let file_name = self.file_name.clone().ok_or(FileError::InvalidFileName)?;
        let file_path = self.validated_file_path(socket, client, &file_name)?;
        let (transfer_size, reader) = match create_reader(&file_path, self.config) {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open file {} {}", file_path, e);
                let error_packet = ErrorPacket::new(
                    open_error_code(&e, ErrorCode::Undefined),
                    format_str!(DefaultString, "Unable to read file {}", file_name),
                );
                self.reply_with_error(socket, client, error_packet);
                return Err(e);
            }
        };

        self.options.file_size = transfer_size;
        // we know about the filesize once reader is created
        match (
            self.options.file_size,
            self.used_extensions.entry(Extension::TransferSize),
        ) {
            (Some(s), Entry::Occupied(mut entry)) if s > 0 => {
                *entry.get_mut() = format_str!(ExtensionValue, "{}", s);
            }
            #[allow(unused_mut)]
            (None, Entry::Occupied(mut entry)) => {
                entry.remove();
            }
            _ => (),
        };
        let mut listen = self.config.listen;
        if self.config.require_server_port_change {
            listen.set_port(0);
        }
        let new_socket = match create_bound_socket(listen, self.socket_id, client) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to create socket {}", e);
                return Err(e);
            }
        };
        #[cfg(not(feature = "multi_thread"))]
        if socket.add_interest(&new_socket).is_err() {
            warn!("Unable to add socket {} to epoll", new_socket.socket_id());
        }
        let Some(r) = block_reader(
            reader,
            &self.options,
            &readers_available,
            self.config.prefer_seek,
        ) else {
            error!(
                "No readers available for window_size {} {readers_available:?}",
                self.options.window_size
            );
            let error_packet = ErrorPacket::new(
                ErrorCode::DiskFull,
                format_str!(DefaultString, "Server resources busy"),
            );
            self.reply_with_error(socket, client, error_packet);
            return Err(AvailabilityError::NoReaderAvailable.into());
        };

        let mut rate_control = RateControl::new(instant);
        rate_control.configure(self.options.block_size, self.options.window_size);
        let initial_packets =
            rate_control.packets_to_send(FLOW_CONTROL_PERIOD, self.options.block_size);
        Ok((
            Connection {
                socket: new_socket,
                transfer: 0,
                options: self.options,
                endpoint: client,
                encryptor: self.handshake_encryption,
                last_updated: instant(),
                started: instant(),
                finished: false,
                invalid: None,
                last_acknowledged: 0,
                retry_packet_multiplier: NonZeroU8::new(1).expect("Non zero multiplier"),
                writer: false,
                rate_control,
                packets_to_send: initial_packets,
                rate_period: instant(),
                window_sent_at: None,
                fast_retransmit: false,
            },
            r,
            self.used_extensions,
            self.session_keys,
        ))
    }

    fn validated_file_path(
        &self,
        socket: &impl Socket,
        client: SocketAddr,
        file_name: &FilePath,
    ) -> BoxedResult<FilePath> {
        validate_request_options(file_name, &self.options, self.config).map_err(
            |(error_packet, error)| {
                self.reply_with_error(socket, client, error_packet);
                error
            },
        )
    }

    /// Answers a request whose options could not be accepted.
    pub fn reject_options(&self, socket: &impl Socket, client: SocketAddr, error: &ExtensionError) {
        self.reply_with_error(
            socket,
            client,
            ErrorPacket::new(
                ErrorCode::OptionNegotiation,
                format_str!(DefaultString, "{error}"),
            ),
        );
    }

    /// True once negotiation has accepted the client's key from `authorized_keys`.
    fn client_is_authorized(&self) -> bool {
        self.config.authorized_keys.is_some() && self.session_keys.is_some()
    }

    pub fn reply_with_error(
        &self,
        socket: &impl Socket,
        client: SocketAddr,
        mut error_packet: ErrorPacket,
    ) {
        if self.config.error_to_authorized_only && !self.client_is_authorized() {
            return;
        }
        let encrypted = self.handshake_encryption.is_some();
        error_packet.limit_message(self.options.max_error_message_size(encrypted));
        reply_with_error(
            socket,
            client,
            error_packet,
            self.handshake_encryption.as_ref(),
            self.options.block_size_with_encryption() + DATA_PACKET_HEADER_SIZE as u16,
        );
    }
}

fn reply_with_error<Rng: CryptoRng + RngCore + Clone>(
    socket: &impl Socket,
    client: SocketAddr,
    error_packet: ErrorPacket,
    encryptor: Option<&Encryptor<Rng>>,
    expected_block_size: u16,
) {
    let packet = Packet::Error(error_packet);
    let Some(mut bytes) =
        session_encryption::encrypted_error_bytes(packet, encryptor, expected_block_size)
    else {
        return;
    };
    if let Err(e) = socket.send_to(&mut bytes, client) {
        warn!("Failed to reply to {client} {e}");
    }
}

fn block_reader<R: FileReader>(
    reader: R,
    options: &ConnectionOptions,
    readers_available: &ReadersAvailable,
    prefer_seek: bool,
) -> Option<Readers<R>> {
    if prefer_seek && readers_available.seek() {
        return Readers::Seek(MultipleBlockSeekReader::new(
            reader,
            options.block_size_with_encryption(),
            options.window_size,
        ))
        .into();
    }
    if options.window_size == 1 && readers_available.single_block() {
        return Readers::Single(SingleBlockReader::new(
            reader,
            options.block_size_with_encryption(),
        ))
        .into();
    }

    if readers_available.multi_block() {
        return Readers::Multiple(MultipleBlockReader::new(
            reader,
            options.block_size_with_encryption(),
            options.window_size,
        ))
        .into();
    }

    if readers_available.seek() {
        return Readers::Seek(MultipleBlockSeekReader::new(
            reader,
            options.block_size_with_encryption(),
            options.window_size,
        ))
        .into();
    }
    None
}

fn block_writer<W: Write>(writer: W) -> Writers<W> {
    Writers::Single(SingleBlockWriter::new(writer))
}

type ReadersResult<B, R, Rng> = BoxedResult<(
    Connection<B, Rng>,
    Readers<R>,
    PacketExtensions,
    Option<SessionKeys<Rng>>,
)>;

type WritersResult<B, W, Rng> = BoxedResult<(
    Connection<B, Rng>,
    Writers<W>,
    PacketExtensions,
    Option<SessionKeys<Rng>>,
)>;

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    #[allow(unused_imports)]
    use std::vec::Vec;

    use super::*;
    #[allow(unused_imports)]
    use crate::std_compat::io::Read;
    #[allow(unused_imports)]
    use crate::std_compat::io::Seek;
    #[allow(unused_imports)]
    use crate::std_compat::io::SeekFrom;

    mod replies {
        use core::time::Duration;

        use rand::rngs::OsRng;

        use super::*;
        use crate::client::test_support::*;
        #[allow(unused_imports)]
        use crate::encryption::*;
        use crate::error::BoxedResult;
        use crate::string::format_str;
        use crate::time::test_now as instant;

        fn config(error_to_authorized_only: bool) -> ServerConfig {
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
                error_to_authorized_only,
            }
        }

        fn builder(config: &ServerConfig) -> ConnectionBuilder<'_, OsRng> {
            ConnectionBuilder {
                config,
                options: Default::default(),
                session_keys: None,
                handshake_encryption: None,
                used_extensions: PacketExtensions::new(),
                file_name: Some(format_str!(FilePath, "/../")),
                socket_id: 1,
            }
        }

        #[cfg(feature = "encryption")]
        fn error_packet(message: &str) -> ErrorPacket {
            ErrorPacket::new(
                ErrorCode::Undefined,
                format_str!(DefaultString, "{message}"),
            )
        }

        /// Asks the builder to open an invalid file name, and returns what
        /// the client was sent.
        fn reject_file_name(
            builder: ConnectionBuilder<'_, OsRng>,
        ) -> std::vec::Vec<std::vec::Vec<u8>> {
            let socket = ScriptedSocket::from_server([]);
            let sent = socket.sent.clone();
            let create_writer = |_: &FilePath, _: &ServerConfig| -> BoxedResult<MemoryFile> {
                Ok(MemoryFile::default())
            };
            let create_bound_socket =
                |_: SocketAddr, _: usize, _: SocketAddr| -> BoxedResult<ScriptedSocket> {
                    Ok(ScriptedSocket::from_server([]))
                };

            let result = builder.build_writer(
                &socket,
                server_address(),
                &create_writer,
                &create_bound_socket,
                instant,
            );

            assert!(result.is_err());
            let sent = sent.borrow().clone();
            sent
        }

        fn io_error(kind: crate::std_compat::io::ErrorKind) -> crate::error::BoxedError {
            crate::std_compat::io::Error::from(kind).into()
        }

        fn named_builder<'a>(
            config: &'a ServerConfig,
            file_name: &str,
        ) -> ConnectionBuilder<'a, OsRng> {
            let mut builder = builder(config);
            builder.file_name = Some(format_str!(FilePath, "{file_name}"));
            builder
        }

        /// The error code a client gets when the file cannot be opened for reading.
        fn read_error_code(error: crate::error::BoxedError) -> Vec<u8> {
            read_error_reply("file", error)[..4].to_vec()
        }

        /// The error code a client gets when the file cannot be opened for writing.
        fn write_error_code(error: crate::error::BoxedError) -> Vec<u8> {
            write_error_reply("file", error)[..4].to_vec()
        }

        /// The packet a client gets when the file cannot be opened for reading.
        fn read_error_reply(file_name: &str, error: crate::error::BoxedError) -> Vec<u8> {
            let config = config(false);
            let socket = ScriptedSocket::from_server([]);
            let sent = socket.sent.clone();
            let error = core::cell::RefCell::new(Some(error));
            let create_reader =
                |_: &FilePath, _: &ServerConfig| -> BoxedResult<(Option<u64>, MemoryReader)> {
                    Err(error.borrow_mut().take().unwrap())
                };
            let create_bound_socket =
                |_: SocketAddr, _: usize, _: SocketAddr| -> BoxedResult<ScriptedSocket> {
                    Ok(ScriptedSocket::from_server([]))
                };

            let result = named_builder(&config, file_name).build_reader(
                &socket,
                server_address(),
                &create_reader,
                &create_bound_socket,
                instant,
                ReadersAvailable::new(1, 1, 1),
            );

            assert!(result.is_err());
            let reply = sent.borrow()[0].to_vec();
            reply
        }

        /// The packet a client gets when the file cannot be opened for writing.
        fn write_error_reply(file_name: &str, error: crate::error::BoxedError) -> Vec<u8> {
            let config = config(false);
            let socket = ScriptedSocket::from_server([]);
            let sent = socket.sent.clone();
            let error = core::cell::RefCell::new(Some(error));
            let create_writer = |_: &FilePath, _: &ServerConfig| -> BoxedResult<MemoryFile> {
                Err(error.borrow_mut().take().unwrap())
            };
            let create_bound_socket =
                |_: SocketAddr, _: usize, _: SocketAddr| -> BoxedResult<ScriptedSocket> {
                    Ok(ScriptedSocket::from_server([]))
                };

            let result = named_builder(&config, file_name).build_writer(
                &socket,
                server_address(),
                &create_writer,
                &create_bound_socket,
                instant,
            );

            assert!(result.is_err());
            let reply = sent.borrow()[0].to_vec();
            reply
        }

        #[test]
        fn test_open_failure_fits_a_file_name_of_the_longest_size() {
            use crate::config::MAX_FILE_PATH_SIZE;
            use crate::std_compat::io::ErrorKind;
            use crate::string::expected_message;

            let name = "x".repeat(MAX_FILE_PATH_SIZE as usize);

            let reply = read_error_reply(&name, io_error(ErrorKind::NotFound));
            let full = format!("Unable to read file {name}");
            assert_eq!(
                &reply[4..reply.len() - 1],
                expected_message(&full).as_bytes()
            );

            let reply = write_error_reply(&name, io_error(ErrorKind::Other));
            let full = format!("Unable to write file {name}");
            assert_eq!(
                &reply[4..reply.len() - 1],
                expected_message(&full).as_bytes()
            );
        }

        #[test]
        fn test_rejected_options_use_the_option_negotiation_code() {
            let config = config(false);
            let socket = ScriptedSocket::from_server([]);
            let sent = socket.sent.clone();

            builder(&config).reject_options(
                &socket,
                server_address(),
                &ExtensionError::NotAuthorized,
            );

            assert_eq!(sent.borrow()[0][..4], [0, 5, 0, 8]);
        }

        #[test]
        fn test_open_failures_report_their_tftp_error_code() {
            use crate::error::FileError;
            use crate::std_compat::io::ErrorKind;

            assert_eq!(read_error_code(io_error(ErrorKind::NotFound)), [0, 5, 0, 1]);
            assert_eq!(
                read_error_code(io_error(ErrorKind::PermissionDenied)),
                [0, 5, 0, 2]
            );
            assert_eq!(
                read_error_code(FileError::InvalidFileName.into()),
                [0, 5, 0, 2]
            );
            assert_eq!(read_error_code(io_error(ErrorKind::Other)), [0, 5, 0, 0]);
            assert_eq!(
                write_error_code(io_error(ErrorKind::AlreadyExists)),
                [0, 5, 0, 6]
            );
            assert_eq!(
                write_error_code(io_error(ErrorKind::PermissionDenied)),
                [0, 5, 0, 2]
            );
            assert_eq!(write_error_code(io_error(ErrorKind::Other)), [0, 5, 0, 3]);
        }

        #[test]
        fn test_validation_error_honors_authorized_only() {
            let config = config(true);
            assert!(reject_file_name(builder(&config)).is_empty());
        }

        #[cfg(feature = "encryption")]
        fn full_encryption_builder(
            config: &ServerConfig,
            block_size: u16,
        ) -> ConnectionBuilder<'_, OsRng> {
            let server_key = VerifyingKey::from(&SigningKey::from([3; 32]));
            let (encryptor, _) = create_encryptor_with_auth_keys(OsRng, &server_key).unwrap();
            let mut builder = builder(config);
            builder.handshake_encryption = encryptor.into();
            builder.options.encryption_level = EncryptionLevel::Full;
            builder.options.block_size = block_size;
            builder
        }

        #[cfg(feature = "encryption")]
        #[test]
        fn test_errors_reach_only_listed_clients_when_restricted() {
            let cases = [
                (true, true, true, 1),
                (true, true, false, 0),
                (true, false, true, 0),
                (false, false, false, 1),
            ];
            for (restricted, has_list, authenticated, expected) in cases {
                let mut config = config(restricted);
                if has_list {
                    config.authorized_keys = Some(Default::default());
                }
                let mut builder = builder(&config);
                if authenticated {
                    let server_key = VerifyingKey::from(&SigningKey::from([3; 32]));
                    let (encryptor, _) =
                        create_encryptor_with_auth_keys(OsRng, &server_key).unwrap();
                    builder.session_keys = Some(SessionKeys { encryptor });
                }
                let socket = ScriptedSocket::from_server([]);
                let sent = socket.sent.clone();

                builder.reply_with_error(&socket, server_address(), error_packet("failed"));

                assert_eq!(
                    sent.borrow().len(),
                    expected,
                    "restricted={restricted} list={has_list} authenticated={authenticated}"
                );
            }
        }

        #[cfg(feature = "encryption")]
        #[test]
        fn test_error_fits_the_header_of_a_small_encrypted_block() {
            let config = config(false);
            let builder = full_encryption_builder(&config, 64);
            let socket = ScriptedSocket::from_server([]);
            let sent = socket.sent.clone();

            // 25 bytes as a packet: more than the 23 of payload, within the 27
            // an encrypted data block can hold
            builder.reply_with_error(
                &socket,
                server_address(),
                error_packet("twenty-characters-ab"),
            );

            assert_eq!(sent.borrow().len(), 1);
        }

        #[cfg(feature = "encryption")]
        #[test]
        fn test_encrypted_error_message_is_cut_to_a_small_block() {
            let config = config(false);
            let builder = full_encryption_builder(&config, 64);
            let socket = ScriptedSocket::from_server([]);
            let sent = socket.sent.clone();

            builder.reply_with_error(&socket, server_address(), error_packet(&"x".repeat(40)));

            assert_eq!(sent.borrow().len(), 1);
            assert_eq!(sent.borrow()[0].len(), 68);
        }

        #[test]
        fn test_plain_error_message_is_cut_to_a_small_block() {
            let config = config(false);
            let mut builder = builder(&config);
            builder.options.block_size = 16;
            let socket = ScriptedSocket::from_server([]);
            let sent = socket.sent.clone();
            let long = "x".repeat(40);
            let packet =
                ErrorPacket::new(ErrorCode::Undefined, format_str!(DefaultString, "{long}"));

            builder.reply_with_error(&socket, server_address(), packet);

            let sent = sent.borrow();
            assert_eq!(&sent[0][4..sent[0].len() - 1], "x".repeat(15).as_bytes());
        }

        #[cfg(feature = "encryption")]
        #[test]
        fn test_validation_error_is_encrypted_in_an_encrypted_handshake() {
            let config = config(false);

            let sent = reject_file_name(full_encryption_builder(&config, 512));

            assert_eq!(sent.len(), 1);
            assert!(!sent[0].starts_with(&[0, 5]), "{:?}", sent[0]);
        }
    }

    #[test]
    fn test_block_reader_window_size_1() {
        let options = ConnectionOptions::default();
        let cursor = Cursor::new(vec![1, 2, 3, 4]);

        let readers_available = ReadersAvailable::new(1, 1, 1);
        let result = block_reader(cursor.clone(), &options, &readers_available, true);
        #[cfg(feature = "seek")]
        assert!(matches!(result.unwrap(), Readers::Seek(_)));
        #[cfg(not(feature = "seek"))]
        assert!(matches!(result.unwrap(), Readers::Single(_)));

        let readers_available = ReadersAvailable::new(1, 1, 1);
        let result = block_reader(cursor.clone(), &options, &readers_available, false);
        assert!(matches!(result.unwrap(), Readers::Single(_)));

        let readers_available = ReadersAvailable::new(0, 1, 1);
        let result = block_reader(cursor.clone(), &options, &readers_available, false).unwrap();
        assert!(matches!(result, Readers::Multiple(_)), "{result:?}");

        let readers_available = ReadersAvailable::new(0, 0, 1);
        let result = block_reader(cursor.clone(), &options, &readers_available, true);
        #[cfg(feature = "seek")]
        assert!(matches!(result.unwrap(), Readers::Seek(_)));
        #[cfg(not(feature = "seek"))]
        assert!(result.is_none());
    }

    #[test]
    fn test_block_reader_window_size_4() {
        let options = ConnectionOptions {
            window_size: 4,
            ..ConnectionOptions::default()
        };
        let cursor = Cursor::new(vec![1, 2, 3, 4]);

        let readers_available = ReadersAvailable::new(1, 1, 1);
        let result = block_reader(cursor.clone(), &options, &readers_available, true);
        #[cfg(feature = "seek")]
        assert!(matches!(result.unwrap(), Readers::Seek(_)));
        #[cfg(not(feature = "seek"))]
        assert!(matches!(result.unwrap(), Readers::Multiple(_)));

        let readers_available = ReadersAvailable::new(1, 1, 1);
        let result = block_reader(cursor.clone(), &options, &readers_available, false);
        assert!(matches!(result.unwrap(), Readers::Multiple(_)));

        let readers_available = ReadersAvailable::new(0, 0, 1);
        let result = block_reader(cursor.clone(), &options, &readers_available, false);
        #[cfg(feature = "seek")]
        assert!(matches!(result.unwrap(), Readers::Seek(_)));
        #[cfg(not(feature = "seek"))]
        assert!(result.is_none());
    }

    #[cfg(not(feature = "std"))]
    impl Seek for Cursor<Vec<u8>> {
        fn seek(&mut self, pos: SeekFrom) -> crate::std_compat::io::Result<u64> {
            let pos = match pos {
                SeekFrom::Start(p) => std::io::SeekFrom::Start(p),
                SeekFrom::Current(p) => std::io::SeekFrom::Current(p),
                SeekFrom::End(p) => std::io::SeekFrom::End(p),
            };
            std::io::Seek::seek(self, pos).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::Other)
            })
        }
    }
}
