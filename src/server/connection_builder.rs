use core::num::NonZeroU16;

use log::*;
use rand::CryptoRng;
use rand::RngCore;

use super::config::ServerConfig;
use super::connection::Connection;
use super::extensions::create_options;
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
use crate::socket::BoundSocket;
use crate::socket::Socket;
use crate::socket::ToSocketId;
use crate::std_compat::io::Read;
use crate::std_compat::io::Write;
use crate::std_compat::net::SocketAddr;
use crate::std_compat::time::Instant;
use crate::string::format_str;
use crate::types::DataBuffer;
use crate::types::FilePath;
use crate::writers::single_block_writer::SingleBlockWriter;
use crate::writers::Writers;

cfg_encryption! {
    use core::mem::size_of;
    use crate::error::EncryptionError;
    use crate::key_management::create_finalized_keys;
    use crate::packet::PacketType;
}

cfg_seek! {
    use crate::std_compat::io::Seek;
    use crate::readers::multiple_block_seek_reader::MultipleBlockSeekReader;
}

pub struct ConnectionBuilder<'a> {
    config: &'a ServerConfig,
    options: ConnectionOptions,
    used_extensions: PacketExtensions,
    file_name: Option<FilePath>,
    finalized_keys: Option<FinalizedKeys>,
    socket_id: usize,
}

impl<'a> ConnectionBuilder<'a> {
    #[allow(unused_variables)]
    pub fn from_new_connection(
        config: &'a ServerConfig,
        buffer: &mut DataBuffer,
        rng: impl CryptoRng + RngCore + Copy,
        socket_id: usize,
    ) -> Result<Self, ExtensionError> {
        #[allow(unused_mut)]
        let mut options = ConnectionOptions::default();
        #[cfg(feature = "encryption")]
        let finalized_keys = if let Ok(Some((ignore, finalized_keys, remote_public_key))) =
            handle_encrypted(&config.private_key, buffer, rng)
        {
            let can_access = if let Some(keys) = &config.authorized_keys {
                let result = keys.contains(&remote_public_key);
                if !result {
                    debug!(
                        "Received new connection however public key was not authorized {:x?}",
                        remote_public_key
                    );
                }
                result
            } else {
                true
            };
            if can_access {
                #[allow(clippy::iter_cloned_collect)]
                let mut data: DataBuffer = buffer[ignore..].iter().copied().collect();
                if finalized_keys.encryptor.decrypt(&mut data).is_err() {
                    error!("Failed to decrypt initial connection");
                    None
                } else {
                    *buffer = data;
                    options.encryption_keys = Some(EncryptionKeys::LocalToRemote(
                        finalized_keys.public,
                        remote_public_key,
                    ));
                    options.encryption_level = EncryptionLevel::Full;
                    Some(finalized_keys)
                }
            } else {
                None
            }
        } else {
            None
        };

        #[cfg(feature = "encryption")]
        if finalized_keys.is_none() && config.required_full_encryption {
            return Err(ExtensionError::ServerRequiredEncryption(
                EncryptionLevel::Full,
            ));
        }

        #[cfg(not(feature = "encryption"))]
        let finalized_keys = None;
        Ok(Self {
            config,
            options,
            finalized_keys,
            used_extensions: PacketExtensions::new(),
            file_name: None,
            socket_id,
        })
    }

    pub fn with_request(
        &mut self,
        request: RequestPacket,
        max_window_size: u16,
        rng: impl CryptoRng + RngCore + Copy,
    ) -> BoxedResult<()> {
        let (used_extensions, options, finalized_keys) = create_options(
            request.extensions,
            self.options.clone(),
            self.config,
            self.finalized_keys.take(),
            max_window_size,
            rng,
        )?;
        self.file_name = Some(request.file_name);
        self.used_extensions = used_extensions;
        self.options = options;
        self.finalized_keys = finalized_keys;
        Ok(())
    }

    pub fn build_writer<W, CreateWriter, CreateBoundSocket, S, B>(
        mut self,
        socket: &S,
        client: SocketAddr,
        create_writer: &CreateWriter,
        create_bound_socket: &CreateBoundSocket,
        instant: fn() -> Instant,
    ) -> WritersResult<B, W>
    where
        S: Socket,
        B: BoundSocket + ToSocketId,
        W: Write,
        CreateBoundSocket: Fn(&str, usize, SocketAddr) -> BoxedResult<B>,
        CreateWriter: Fn(&FilePath, &ServerConfig) -> BoxedResult<W>,
    {
        let file_name = self.file_name.ok_or(FileError::InvalidFileName)?;
        let (encryptor, finalized_keys) = if self.options.encryption_level != EncryptionLevel::Full
        {
            (None, self.finalized_keys.take())
        } else {
            (self.finalized_keys.map(|f| f.encryptor), None)
        };
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

                let packet = Packet::Error(ErrorPacket::new(
                    ErrorCode::DiskFull,
                    format_str!(DefaultString, "Unable to write file {}", file_name),
                ));
                socket.send_to(&mut packet.to_bytes(), client)?;
                return Err(e);
            }
        };
        let listen = if self.config.require_server_port_change {
            format_str!(DefaultString, "{}:{}", self.config.listen.ip(), 0)
        } else {
            format_str!(
                DefaultString,
                "{}:{}",
                self.config.listen.ip(),
                self.config.listen.port()
            )
        };

        let new_socket = match create_bound_socket(&listen, self.socket_id, client) {
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
                transfer: 0,
                options: self.options,
                endpoint: client,
                encryptor,
                finished: false,
                invalid: false,
                last_acknoledged: 0,
                retry_packet_multiplier: NonZeroU16::new(1).expect("Non zero multiplier"),
            },
            block_writer(writer),
            self.used_extensions,
            finalized_keys,
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
    ) -> ReadersResult<B, R>
    where
        S: Socket,
        B: BoundSocket + ToSocketId,
        CreateBoundSocket: Fn(&str, usize, SocketAddr) -> BoxedResult<B>,
        CreateReader: Fn(&FilePath, &ServerConfig) -> BoxedResult<(Option<u64>, R)>,
    {
        let file_name = self.file_name.ok_or(FileError::InvalidFileName)?;
        let (encryptor, finalized_keys) = if self.options.encryption_level != EncryptionLevel::Full
        {
            (None, self.finalized_keys.take())
        } else {
            (self.finalized_keys.map(|f| f.encryptor), None)
        };
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
                let packet = Packet::Error(ErrorPacket::new(
                    ErrorCode::DiskFull,
                    format_str!(DefaultString, "Unable to read file {}", file_name),
                ));
                socket.send_to(&mut packet.to_bytes(), client)?;
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

        let listen = if self.config.require_server_port_change {
            format_str!(DefaultString, "{}:{}", self.config.listen.ip(), 0)
        } else {
            format_str!(
                DefaultString,
                "{}:{}",
                self.config.listen.ip(),
                self.config.listen.port()
            )
        };
        let new_socket = match create_bound_socket(&listen, self.socket_id, client) {
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
            let packet = Packet::Error(ErrorPacket::new(
                ErrorCode::DiskFull,
                format_str!(DefaultString, "Server resources busy"),
            ));
            socket.send_to(&mut packet.to_bytes(), client)?;
            return Err(AvailabilityError::NoReaderAvailable.into());
        };

        Ok((
            Connection {
                socket: new_socket,
                transfer: 0,
                options: self.options,
                endpoint: client,
                encryptor,
                last_updated: instant(),
                finished: false,
                invalid: false,
                last_acknoledged: 0,
                retry_packet_multiplier: NonZeroU16::new(1).expect("Non zero multiplier"),
            },
            r,
            self.used_extensions,
            finalized_keys,
        ))
    }
}

#[cfg(feature = "encryption")]
fn handle_encrypted(
    private_key: &Option<PrivateKey>,
    data: &mut DataBuffer,
    rng: impl CryptoRng + RngCore + Copy,
) -> Result<Option<(usize, FinalizedKeys, PublicKey)>, EncryptionError> {
    // as long as we dont use standard packet type this should be good. randomize ?
    match PacketType::from_bytes(data) {
        Ok(PacketType::InitialEncryption) => (),
        _ => return Ok(None),
    };
    let remote_public_key: [u8; size_of::<PublicKey>()] = data
        .get(size_of::<PacketType>()..size_of::<PacketType>() + size_of::<PublicKey>())
        .map(|n| n.try_into())
        .transpose()
        .map_err(|_| EncryptionError::Decrypt)?
        .ok_or(EncryptionError::Decrypt)?;

    let remote_nonce: [u8; size_of::<Nonce>()] = data
        .get(
            size_of::<PacketType>() + size_of::<PublicKey>()
                ..size_of::<PacketType>() + size_of::<PublicKey>() + size_of::<Nonce>(),
        )
        .map(|n| n.try_into())
        .transpose()
        .map_err(|_| EncryptionError::Decrypt)?
        .ok_or(EncryptionError::Decrypt)?;

    let remote_key = remote_public_key.into();
    let finalized_keys =
        create_finalized_keys(private_key, &remote_key, Some(remote_nonce.into()), rng);
    Ok(Some((
        size_of::<PacketType>() + size_of::<PublicKey>() + size_of::<Nonce>(),
        finalized_keys,
        remote_key,
    )))
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
            options.block_size,
            options.window_size,
        ))
        .into();
    }
    if options.window_size == 1 && readers_available.single_block() {
        return Readers::Single(SingleBlockReader::new(reader, options.block_size)).into();
    }

    if readers_available.multi_block() {
        return Readers::Multiple(MultipleBlockReader::new(
            reader,
            options.block_size,
            options.window_size,
        ))
        .into();
    }

    #[cfg(feature = "seek")]
    if readers_available.seek() {
        return Readers::Seek(MultipleBlockSeekReader::new(
            reader,
            options.block_size,
            options.window_size,
        ))
        .into();
    }
    None
}

fn block_writer<W: Write>(writer: W) -> Writers<W> {
    Writers::Single(SingleBlockWriter::new(writer))
}

type ReadersResult<B, R> = BoxedResult<(
    Connection<B>,
    Readers<R>,
    PacketExtensions,
    Option<FinalizedKeys>,
)>;

type WritersResult<B, W> = BoxedResult<(
    Connection<B>,
    Writers<W>,
    PacketExtensions,
    Option<FinalizedKeys>,
)>;

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use crate::std_compat::io::Read;
    #[allow(unused_imports)]
    use crate::std_compat::io::Seek;
    #[allow(unused_imports)]
    use crate::std_compat::io::SeekFrom;

    use std::io::Cursor;
    #[allow(unused_imports)]
    use std::vec::Vec;

    use super::*;

    #[test]
    fn test_block_reader_window_size_1() {
        let options = ConnectionOptions::default();
        let cursor = Cursor::new(vec![1, 2, 3, 4]);
        #[cfg(not(feature = "std"))]
        let cursor = CursorReader { cursor };

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
        let mut options = ConnectionOptions::default();
        options.window_size = 4;
        let cursor = Cursor::new(vec![1, 2, 3, 4]);
        #[cfg(not(feature = "std"))]
        let cursor = CursorReader { cursor };

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
    #[derive(Debug, Clone)]
    struct CursorReader {
        cursor: Cursor<Vec<u8>>,
    }
    #[cfg(not(feature = "std"))]
    impl Read for CursorReader {
        fn read(&mut self, buf: &mut [u8]) -> crate::std_compat::io::Result<usize> {
            use std::io::Read;
            self.cursor.read(buf).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::Other)
            })
        }
    }

    #[cfg(not(feature = "std"))]
    impl Seek for CursorReader {
        fn seek(&mut self, pos: SeekFrom) -> crate::std_compat::io::Result<u64> {
            use std::io::Seek;
            let pos = match pos {
                SeekFrom::Start(p) => std::io::SeekFrom::Start(p),
                SeekFrom::Current(p) => std::io::SeekFrom::Current(p),
                SeekFrom::End(p) => std::io::SeekFrom::End(p),
            };
            self.cursor.seek(pos).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::Other)
            })
        }
    }
}
