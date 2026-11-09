//! Everything that differs between feature sets is defined here, with the same
//! names in every build, so the rest of the library needs no `cfg`.

use crate::std_compat::io::Read;

pub const SEEK_ENABLED: bool = cfg!(feature = "seek");
pub const ENCRYPTION_ENABLED: bool = cfg!(feature = "encryption");

/// What the library requires from a file it reads: `Seek` as well as `Read`
/// when built with the `seek` feature.
#[cfg(feature = "seek")]
pub trait FileReader: Read + crate::std_compat::io::Seek {}
#[cfg(feature = "seek")]
impl<T: Read + crate::std_compat::io::Seek> FileReader for T {}

#[cfg(not(feature = "seek"))]
pub trait FileReader: Read {}
#[cfg(not(feature = "seek"))]
impl<T: Read> FileReader for T {}

#[cfg(not(feature = "seek"))]
pub use seek_disabled::MultipleBlockSeekReader;

#[cfg(not(feature = "seek"))]
mod seek_disabled {
    use core::convert::Infallible;
    use core::marker::PhantomData;

    use crate::error::StorageError;
    use crate::readers::block_reader::Block;
    use crate::readers::block_reader::BlockReader;

    /// Can not exist, so `Readers::Seek` arms compile to nothing.
    #[derive(Debug)]
    pub struct MultipleBlockSeekReader<R>(Infallible, PhantomData<R>);

    impl<R> MultipleBlockSeekReader<R> {
        /// Callers check [`super::SEEK_ENABLED`] first.
        pub fn new(_reader: R, _block_size: u16, _max_blocks_to_read: u16) -> Self {
            unreachable!("seek readers require the seek feature")
        }
    }

    impl<R> BlockReader for MultipleBlockSeekReader<R> {
        fn next(
            &mut self,
            _buffer: &mut [u8],
            _retry: bool,
        ) -> Result<Option<Block>, StorageError> {
            match self.0 {}
        }

        fn free_block(&mut self, _block: u16) -> usize {
            match self.0 {}
        }

        fn is_finished(&self) -> bool {
            match self.0 {}
        }
    }
}

#[cfg(not(feature = "encryption"))]
pub mod no_encryption {
    use core::marker::PhantomData;

    pub type PublicKey = ();
    pub type Nonce = ();
    pub type PrivateKey = ();
    pub type VerifyingKey = ();
    pub type SigningKey = ();
    pub type EncryptionKey = ();
    pub type InitialKeys = ();
    pub struct PublicKeyPair {
        pub auth: Option<()>,
        pub session: (),
    }

    pub type Encryptor<Rng> = PhantomData<Rng>;
    pub type SessionContext = ();

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EncryptionLevel {
        Data,
        Protocol,
        Full,
        OptionalData,
        OptionalProtocol,
        None,
    }
    impl core::fmt::Display for EncryptionLevel {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "none")
        }
    }
}

#[cfg(not(feature = "encryption"))]
pub mod no_key_management {
    pub fn append_to_known_hosts() {}
    pub fn get_from_known_hosts() {}
    pub fn read_authorized_keys() {}
    pub fn create_finalized_keys() {}
    pub fn create_initial_keys() {}
    pub type AuthorizedKeys = ();
}

/// Same functions as `client/encryption_socket_builder.rs`, leaving the socket as is.
#[cfg(not(feature = "encryption"))]
pub(crate) mod no_encryption_socket_builder {
    use crate::client::ClientConfig;
    use crate::config::ConnectionOptions;
    use crate::encryption::InitialKeys;
    use crate::encryption::PublicKeyPair;
    use crate::error::BoxedResult;
    use crate::packet::SignedRequest;

    pub fn create_initial_socket<S, Rng>(
        socket: S,
        _config: &ClientConfig,
        _options: &mut ConnectionOptions,
        _rng: Rng,
    ) -> BoxedResult<(S, Option<InitialKeys>)> {
        Ok((socket, None))
    }

    pub fn configure_socket<S, Rng>(
        socket: S,
        _initial_keys: Option<InitialKeys>,
        options: ConnectionOptions,
        _rng: Rng,
        _remote_public_key_pair: Option<&PublicKeyPair>,
        _request: SignedRequest,
    ) -> BoxedResult<(S, ConnectionOptions)> {
        Ok((socket, options))
    }
}

/// Same functions as `server/session_encryption.rs`, for a session that is never encrypted.
#[cfg(not(feature = "encryption"))]
pub(crate) mod no_server_session_encryption {
    use core::net::SocketAddr;

    use crate::config::ConnectionOptions;
    use crate::config::EXTENSION_BLOCK_SIZE_MIN;
    use crate::encryption::Encryptor;
    use crate::error::DefaultBoxedResult;
    use crate::error::ExtensionError;
    use crate::packet::ByteConverter;
    use crate::packet::Packet;
    use crate::packet::PacketExtensions;
    use crate::packet::PacketType;
    use crate::server::connection::Connection;
    use crate::server::helpers::connection::SessionKeys;
    use crate::server::ServerConfig;
    use crate::types::DataBuffer;

    pub fn decrypt_packet<Rng>(
        _options: &ConnectionOptions,
        _encryptor: &Option<Encryptor<Rng>>,
        _endpoint: SocketAddr,
        _buffer: &mut DataBuffer,
    ) -> bool {
        true
    }

    pub fn encrypt_packet<Rng>(
        _options: &ConnectionOptions,
        _encryptor: &Option<Encryptor<Rng>>,
        _packet_name: PacketType,
        _data: &mut DataBuffer,
    ) -> bool {
        true
    }

    pub fn open_initial_packet<Rng>(
        _config: &ServerConfig,
        _buffer: &mut DataBuffer,
        _rng: Rng,
    ) -> Option<Encryptor<Rng>> {
        None
    }

    pub fn encrypted_error_bytes<Rng>(
        packet: Packet,
        _encryptor: Option<&Encryptor<Rng>>,
        _expected_block_size: u16,
    ) -> Option<DataBuffer> {
        Some(packet.to_bytes())
    }

    pub fn min_block_size(_client_extensions: &PacketExtensions) -> u16 {
        EXTENSION_BLOCK_SIZE_MIN
    }

    pub fn negotiate<R>(
        _client_extensions: &PacketExtensions,
        _request: crate::packet::SignedRequest,
        options: ConnectionOptions,
        _config: &ServerConfig,
        used_extensions: PacketExtensions,
        _rng: R,
    ) -> Result<(PacketExtensions, ConnectionOptions, Option<SessionKeys<R>>), ExtensionError> {
        Ok((used_extensions, options, None))
    }

    pub fn start_session<B, Rng>(
        _connection: &mut Connection<B, Rng>,
        _session_keys: Option<SessionKeys<Rng>>,
    ) {
    }

    pub fn log_server_public_key(_config: &ServerConfig) -> DefaultBoxedResult {
        Ok(())
    }
}

/// Same functions as `client/session_encryption.rs`, for a session that is never encrypted.
#[cfg(not(feature = "encryption"))]
pub(crate) mod no_client_session_encryption {
    use crate::config::ConnectionOptions;
    use crate::encryption::InitialKeys;
    use crate::encryption::PublicKeyPair;
    use crate::error::ExtensionError;
    use crate::packet::PacketExtensions;
    use crate::packet::SignedRequest;

    pub fn add_extensions(
        _options: &ConnectionOptions,
        _initial_keys: Option<&InitialKeys>,
        _request: SignedRequest,
        _used_extensions: &mut PacketExtensions,
    ) {
    }

    pub fn parse_reply(
        _server_extensions: &PacketExtensions,
        options: ConnectionOptions,
    ) -> Result<(ConnectionOptions, Option<PublicKeyPair>), ExtensionError> {
        Ok((options, None))
    }
}
