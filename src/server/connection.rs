use core::{cmp::min, time::Duration};

use log::{debug, error};
use rand::{CryptoRng, RngCore};

use super::{extensions::create_options, validation::validate_request_options};
use crate::{
    config::{ConnectionOptions, ENCRYPTION_TAG_SIZE},
    encryption::{
        overwrite_data_packet, EncryptionKeys, EncryptionLevel, Encryptor, FinalizeKeysCallback,
        FinalizedKeys, Nonce, PrivateKey, PublicKey,
    },
    error::{BoxedResult, EncryptionError, ExtensionError, FileError},
    map::Entry,
    packet::{
        ByteConverter, ErrorCode, ErrorPacket, Extension, Packet, PacketExtensions, PacketType,
        RequestPacket,
    },
    server::ServerConfig,
    socket::Socket,
    std_compat::{
        io::{self, Read, Seek, Write},
        net::SocketAddr,
        time::Instant,
    },
    storage::{FileReader, FileWriter},
    string::format_str,
    types::{DataBuffer, FilePath},
};

pub enum ClientType<R, W> {
    Reader(FileReader<R>),
    Writer(FileWriter<W>),
}

pub struct Connection<R, W, S> {
    pub socket: S,
    pub options: ConnectionOptions,
    pub encryptor: Option<Encryptor>,
    pub last_updated: Instant,
    pub transfer: usize,
    pub client_type: ClientType<R, W>,
    pub endpoint: SocketAddr,
}

impl<R, W, S: Socket> Connection<R, W, S> {
    pub fn recv_from(
        &self,
        buffer: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buffer, wait_for)
    }

    pub fn receive_packet(&self, _buffer: &mut DataBuffer) -> bool {
        #[cfg(feature = "encryption")]
        if let (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) =
            (self.options.encryption_level, &self.encryptor)
        {
            if encryptor.decrypt(_buffer).is_err() {
                error!("Failed to decrypt packet {:x?}", &_buffer);
                return false;
            }
        }

        #[cfg(feature = "encryption")]
        if let (Ok(PacketType::Data), EncryptionLevel::Data, Some(encryptor)) = (
            PacketType::from_bytes(&_buffer),
            self.options.encryption_level,
            &self.encryptor,
        ) {
            if let Err(_) = overwrite_data_packet(_buffer, |buf| encryptor.decrypt(buf)) {
                error!("Failed to decrypt data {:x?}", &_buffer);
                return false;
            }
        }

        return true;
    }

    pub fn send_packet(&self, packet: Packet) -> bool {
        let packet_name = packet.packet_type();
        match &packet {
            Packet::Data(d) => debug!("Send {} {} {}", packet_name, d.block, self.endpoint),
            Packet::Ack(d) => debug!("Send {} {} {}", packet_name, d.block, self.endpoint),
            _ => debug!("Send {} {}", packet_name, self.endpoint),
        };

        let mut data = packet.to_bytes();

        #[cfg(feature = "encryption")]
        if let (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) =
            (self.options.encryption_level, &self.encryptor)
        {
            if encryptor.encrypt(&mut data).is_err() {
                error!("Failed to encrypt data {:x?}", &data);
                return false;
            }
        }
        #[cfg(feature = "encryption")]
        if let (EncryptionLevel::Data, Some(encryptor)) =
            (self.options.encryption_level, &self.encryptor)
        {
            if overwrite_data_packet(&mut data, |buf| encryptor.encrypt(buf)).is_err() {
                error!("Failed to encrypt data {:x?}", &data);
                return false;
            }
        }
        if let Err(e) = self.socket.send_to(&mut data, self.endpoint) {
            error!("Failed to send {} for {} {}", packet_name, self.endpoint, e);
            return false;
        }
        true
    }
}

pub struct ConnectionBuilder<'a> {
    config: &'a ServerConfig,
    options: ConnectionOptions,
    used_extensions: PacketExtensions,
    file_name: Option<FilePath>,
    finalized_keys: Option<FinalizedKeys>,
}

impl<'a> ConnectionBuilder<'a> {
    #[allow(unused_variables)]
    pub fn from_new_connection(
        config: &'a ServerConfig,
        buffer: &mut DataBuffer,
        rng: impl CryptoRng + RngCore + Copy,
    ) -> Result<Self, ExtensionError> {
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

    pub(crate) fn build_writer<W, CreateWriter, R, CreateSocket, S>(
        mut self,
        socket: &S,
        client: SocketAddr,
        create_writer: &CreateWriter,
        create_socket: &CreateSocket,
        instant: fn() -> Instant,
    ) -> BoxedResult<(Connection<R, W, S>, PacketExtensions, Option<FinalizedKeys>)>
    where
        S: Socket,
        W: Write + Seek,
        CreateSocket: Fn(&str, usize) -> BoxedResult<S>,
        CreateWriter: Fn(&FilePath, &ServerConfig) -> BoxedResult<W>,
    {
        let file_name = self.file_name.ok_or_else(|| FileError::InvalidFileName)?;
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

        let writer = match create_writer(&file_path, &self.config) {
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
        let new_socket = if self.config.require_server_port_change {
            let listen = format_str!(DefaultString, "{}:{}", self.config.listen.ip(), 0);
            create_socket(&listen, 0)?
        } else {
            socket.try_clone()?
        };
        Ok((
            Connection {
                socket: new_socket,
                last_updated: instant(),
                transfer: 0,
                client_type: ClientType::Writer(FileWriter::from_writer(
                    writer,
                    self.options.block_size,
                    self.config.max_queued_blocks_writer,
                    self.options.window_size,
                )),
                options: self.options,
                endpoint: client,
                encryptor,
            },
            self.used_extensions,
            finalized_keys,
        ))
    }

    pub fn build_reader<R, CreateReader, W, CreateSocket, S>(
        mut self,
        socket: &S,
        client: SocketAddr,
        create_reader: &CreateReader,
        create_socket: &CreateSocket,
        instant: fn() -> Instant,
    ) -> BoxedResult<(Connection<R, W, S>, PacketExtensions, Option<FinalizedKeys>)>
    where
        S: Socket,
        CreateSocket: Fn(&str, usize) -> BoxedResult<S>,
        R: Read + Seek,
        CreateReader: Fn(&FilePath, &ServerConfig) -> BoxedResult<(Option<u64>, R)>,
    {
        let file_name = self.file_name.ok_or_else(|| FileError::InvalidFileName)?;
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
        let (transfer_size, reader) = match create_reader(&file_path, &self.config) {
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
            (None, Entry::Occupied(mut entry)) => {
                entry.remove();
            }
            _ => (),
        };

        let block_reader = FileReader::from_reader(
            reader,
            self.config.max_queued_blocks_reader,
            self.options.block_size,
            self.options.retry_packet_after_timeout,
            instant,
            self.options.window_size,
        );
        let new_socket = if self.config.require_server_port_change {
            let listen = format_str!(DefaultString, "{}:{}", self.config.listen.ip(), 0);
            create_socket(&listen, 0)?
        } else {
            socket.try_clone()?
        };
        Ok((
            Connection {
                socket: new_socket,
                transfer: 0,
                client_type: ClientType::Reader(block_reader),
                options: self.options,
                endpoint: client,
                encryptor,
                last_updated: instant(),
            },
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
    use core::mem::size_of;

    use crate::{
        encryption::{FinalizedKeys, Nonce, PrivateKey, PublicKey},
        key_management::create_finalized_keys,
    };
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
    let mut finalized_keys =
        create_finalized_keys(private_key, &remote_key, Some(remote_nonce.into()), rng);
    // finalized_keys.encryptor.nonce = remote_nonce.into();
    Ok(Some((
        size_of::<PacketType>() + size_of::<PublicKey>() + size_of::<Nonce>(),
        finalized_keys,
        remote_key,
    )))
}
