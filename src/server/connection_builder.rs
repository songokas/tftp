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
use crate::encryption::*;
use crate::error::AvailabilityError;
use crate::error::BoxedResult;
use crate::error::ExtensionError;
use crate::error::FileError;
use crate::macros::cfg_encryption;
use crate::macros::cfg_seek;
use crate::map::Entry;
use crate::packet::ByteConverter;
use crate::packet::ErrorCode;
use crate::packet::ErrorPacket;
use crate::packet::Extension;
use crate::packet::Packet;
use crate::packet::PacketExtensions;
use crate::packet::RequestPacket;
use crate::readers::multiple_block_reader::MultipleBlockReader;
use crate::readers::single_block_reader::SingleBlockReader;
use crate::readers::Readers;
use crate::server::helpers::connection::SessionKeys;
use crate::socket::BoundSocket;
use crate::socket::Socket;
use crate::socket::ToSocketId;
use crate::std_compat::io::Read;
use crate::std_compat::io::Write;
use core::net::SocketAddr;
use crate::std_compat::time::Instant;
use crate::string::ensure_size;
use crate::string::format_str;
use crate::types::DataBuffer;
use crate::types::FilePath;
use crate::writers::single_block_writer::SingleBlockWriter;
use crate::writers::Writers;

cfg_encryption! {
    use crate::encrypted_packet::InitialPacket;
    use crate::encrypted_packet::EncryptedPacket;
}

cfg_seek! {
    use crate::std_compat::io::Seek;
    use crate::readers::multiple_block_seek_reader::MultipleBlockSeekReader;
}

pub struct ConnectionBuilder<'a, Rng> {
    config: &'a ServerConfig,
    options: ConnectionOptions,
    used_extensions: PacketExtensions,
    file_name: Option<FilePath>,
    session_keys: Option<SessionKeys>,
    handshake_encryption: Option<Encryptor<Rng>>,
    socket_id: usize,
}

impl<'a, Rng> ConnectionBuilder<'a, Rng>
where
    Rng: CryptoRng + RngCore + Copy,
{
    #[allow(unused_variables)]
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
        #[cfg(feature = "encryption")]
        {
            let Some(private_key) = config.private_key.clone() else {
                trace!("Ignoring encryption for initial packet: no private key set");
                return create_default_builder();
            };
            let Ok(packet) = InitialPacket::from_bytes(buffer) else {
                trace!("Ignoring encryption for initial packet: invalid format");
                return create_default_builder();
            };

            let remote_handshake_public_key = packet.session_public_key;

            let auth_keys = create_auth_keys(private_key);
            let (encryptor, public_key) = auth_keys.finalize(&remote_handshake_public_key, rng);
            let Ok(data) = packet.decrypt(&encryptor) else {
                trace!("Ignoring encryption for initial packet: failed to decrypt");
                return create_default_builder();
            };
            *buffer = data;
            let mut builder = create_default_builder();
            builder.handshake_encryption = encryptor.into();
            builder.options.encryption_level = EncryptionLevel::Full;
            debug!("Initial packet encrypted");
            builder
        }
        #[cfg(not(feature = "encryption"))]
        create_default_builder()
    }

    pub fn with_request(
        &mut self,
        request: RequestPacket,
        max_window_size: u16,
        rng: Rng,
    ) -> Result<(), ExtensionError> {
        let (used_extensions, options, session_keys) = parse_extensions(
            request.extensions,
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
        let file_path = validate_request_options(
            socket,
            client,
            &file_name,
            &self.options,
            &self.used_extensions,
            self.config,
        )?;

        let writer = match create_writer(&file_path, self.config) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to open file {} {}", file_path, e);

                let error_packet = ErrorPacket::new(
                    ErrorCode::DiskFull,
                    format_str!(
                        DefaultString,
                        "Unable to write file {}",
                        ensure_size(&file_name, 100)
                    ),
                );
                self.reply_with_error(socket, client, error_packet);
                return Err(e);
            }
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

        Ok((
            Connection {
                socket: new_socket,
                last_updated: instant(),
                last_sent: instant(),
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
            },
            block_writer(writer),
            self.used_extensions,
            self.session_keys,
        ))
    }

    pub fn build_reader<
        #[cfg(not(feature = "seek"))] R: Read,
        #[cfg(feature = "seek")] R: Read + Seek,
        CreateReader,
        CreateBoundSocket,
        S,
        B,
    >(
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
        let file_path = validate_request_options(
            socket,
            client,
            &file_name,
            &self.options,
            &self.used_extensions,
            self.config,
        )?;
        let (transfer_size, reader) = match create_reader(&file_path, self.config) {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open file {} {}", file_path, e);
                let error_packet = ErrorPacket::new(
                    ErrorCode::DiskFull,
                    format_str!(
                        DefaultString,
                        "Unable to read file {}",
                        ensure_size(&file_name, 100)
                    ),
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

        Ok((
            Connection {
                socket: new_socket,
                transfer: 0,
                options: self.options,
                endpoint: client,
                encryptor: self.handshake_encryption,
                last_updated: instant(),
                last_sent: instant(),
                started: instant(),
                finished: false,
                invalid: None,
                last_acknowledged: 0,
                retry_packet_multiplier: NonZeroU8::new(1).expect("Non zero multiplier"),
                writer: false,
            },
            r,
            self.used_extensions,
            self.session_keys,
        ))
    }

    pub fn reply_with_error(
        &self,
        socket: &impl Socket,
        client: SocketAddr,
        error_packet: ErrorPacket,
    ) {
        if self.config.error_to_authorized_only {
            return;
        }
        reply_with_error(
            socket,
            client,
            error_packet,
            self.handshake_encryption.as_ref(),
            self.options.block_size_with_encryption(),
        );
    }
}

fn reply_with_error<Rng: CryptoRng + RngCore + Clone>(
    socket: &impl Socket,
    client: SocketAddr,
    error_packet: ErrorPacket,
    _encryptor: Option<&Encryptor<Rng>>,
    _expected_block_size: u16,
) {
    let packet = Packet::Error(error_packet);
    #[cfg(feature = "encryption")]
    let mut bytes = if let Some(encryptor) = _encryptor {
        let mut buffer = packet.to_bytes();
        if let Err(e) = EncryptedPacket::encrypt(encryptor, &mut buffer, _expected_block_size) {
            warn!("Failed to encrypt error packet {e}");
            return;
        }
        buffer
    } else {
        packet.to_bytes()
    };
    #[cfg(not(feature = "encryption"))]
    let mut bytes = packet.to_bytes();
    if let Err(e) = socket.send_to(&mut bytes, client) {
        warn!("Failed to reply to {client} {e}");
    }
}

fn block_reader<#[cfg(not(feature = "seek"))] R: Read, #[cfg(feature = "seek")] R: Read + Seek>(
    reader: R,
    options: &ConnectionOptions,
    readers_available: &ReadersAvailable,
    _prefer_seek: bool,
) -> Option<Readers<R>> {
    #[cfg(feature = "seek")]
    if _prefer_seek && readers_available.seek() {
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

    #[cfg(feature = "seek")]
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
    Option<SessionKeys>,
)>;

type WritersResult<B, W, Rng> = BoxedResult<(
    Connection<B, Rng>,
    Writers<W>,
    PacketExtensions,
    Option<SessionKeys>,
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
