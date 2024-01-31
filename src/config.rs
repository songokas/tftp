use core::time::Duration;

use log::debug;

use crate::encryption::EncryptionKeys;
use crate::encryption::EncryptionLevel;
use crate::encryption::PublicKey;
use crate::macros::cfg_alloc;
use crate::macros::cfg_stack;

pub const DEFAULT_DATA_BLOCK_SIZE: u16 = 512;
// PacketType + block(u16)
pub const DATA_PACKET_HEADER_SIZE: u8 = 4;

pub const MAX_DATA_BLOCK_SIZE: u16 = 1425;

/// maximum size of the packet buffer
pub const MAX_BUFFER_SIZE: u16 = MAX_DATA_BLOCK_SIZE + DATA_PACKET_HEADER_SIZE as u16;
pub const MIN_BUFFER_SIZE: u16 = DEFAULT_DATA_BLOCK_SIZE + DATA_PACKET_HEADER_SIZE as u16;

#[cfg(feature = "encryption")]
pub const ENCRYPTION_TAG_SIZE: u8 = 16;
#[cfg(not(feature = "encryption"))]
pub const ENCRYPTION_TAG_SIZE: u8 = 0;

#[cfg(feature = "encryption")]
pub const ENCRYPTION_PADDING_SIZE: u8 = 1;
#[cfg(not(feature = "encryption"))]
pub const ENCRYPTION_PADDING_SIZE: u8 = 0;

#[cfg(feature = "encryption")]
pub const ENCRYPTION_NONCE_SIZE: u8 = 24;
#[cfg(not(feature = "encryption"))]
pub const ENCRYPTION_NONCE_SIZE: u8 = 0;

cfg_alloc!(
    /// how many clients server can manage at once
    pub const MAX_CLIENTS: u16 = 5000;
    /// max window size
    pub const MAX_BLOCKS_FOR_MULTI_READER: u16 = 1000;
    pub const DEFAULT_WINDOW_SIZE: u8 = 8;
);

cfg_stack!(
    // heapless FvIndexMap requires map size to be power of 2
    pub const MAX_CLIENTS: u16 = 128;
    pub const MAX_BLOCKS_FOR_MULTI_READER: u16 = 16;
    /// how many single readers available window size = 1
    pub const MAX_SINGLE_READERS: u16 = 64;
    /// how many multi readers available window size > 1
    pub const MAX_MULTI_READERS: u16 = 16;
    /// how many seek readers available window size > 1
    pub const MAX_MULTI_SEEK_READERS: u16 = 64;
    pub const DEFAULT_WINDOW_SIZE: u8 = 4;
);

pub const MAX_EXTENSION_VALUE_SIZE: u8 = 45;
pub const MAX_DEFAULT_STRING_SIZE: u8 = 140;
pub const MAX_FILE_PATH_SIZE: u8 = 150;

pub const DEFAULT_RETRY_PACKET_TIMEOUT: Duration = Duration::from_millis(80);
pub const EXTENSION_WINDOW_SIZE_MIN: u16 = 1;
// pub const EXTENSION_WINDOW_SIZE_MAX: u16 = 65535;
pub const EXTENSION_BLOCK_SIZE_MIN: u16 = DEFAULT_DATA_BLOCK_SIZE;
// pub const EXTENSION_BULK_SIZE_MAX: u16 = 65464;
pub const EXTENSION_TIMEOUT_SIZE_MIN: u8 = 1;
pub const EXTENSION_TIMEOUT_SIZE_MAX: u8 = 255;

#[derive(Clone, Debug)]
pub struct ConnectionOptions {
    pub block_size: u16,
    pub retry_packet_after_timeout: Duration,
    pub file_size: Option<u64>,
    pub encryption_keys: Option<EncryptionKeys>,
    pub encryption_level: EncryptionLevel,
    pub window_size: u16,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_DATA_BLOCK_SIZE,
            retry_packet_after_timeout: DEFAULT_RETRY_PACKET_TIMEOUT,
            file_size: None,
            encryption_keys: None,
            encryption_level: EncryptionLevel::None,
            window_size: EXTENSION_WINDOW_SIZE_MIN,
        }
    }
}

impl ConnectionOptions {
    pub fn with_block_size(mut self, block_size: u16) -> Self {
        self.block_size = block_size;
        self
    }

    pub fn with_file_size(mut self, file_size: u64) -> Self {
        self.file_size = Some(file_size);
        self
    }

    pub fn remote_public_key(&self) -> Option<PublicKey> {
        match self.encryption_keys {
            Some(EncryptionKeys::LocalToRemote(_, p)) => p.into(),
            _ => None,
        }
    }

    pub fn block_size_with_encryption(&self) -> u16 {
        if !self.is_encrypting() {
            return self.block_size;
        }

        match self.encryption_level {
            EncryptionLevel::Data => {
                self.block_size - ENCRYPTION_TAG_SIZE as u16 - ENCRYPTION_NONCE_SIZE as u16
            }
            EncryptionLevel::Full | EncryptionLevel::Protocol => {
                self.block_size
                    - ENCRYPTION_TAG_SIZE as u16
                    - ENCRYPTION_PADDING_SIZE as u16
                    - ENCRYPTION_NONCE_SIZE as u16
            }
            EncryptionLevel::OptionalData
            | EncryptionLevel::OptionalProtocol
            | EncryptionLevel::None => self.block_size,
        }
    }

    pub fn is_encrypting(&self) -> bool {
        matches!(
            self.encryption_keys,
            Some(crate::encryption::EncryptionKeys::LocalToRemote(..))
        )
    }
}

pub fn print_options(context: &str, options: &ConnectionOptions) {
    debug!(
        "{} options - block_size: {}, window size: {}, file_size: {} bytes, retry packet: {}ms, encryption level: {}, encrypting: {}",
        context,
        options.block_size_with_encryption(),
        options.window_size,
        options.file_size.unwrap_or(0),
        options.retry_packet_after_timeout.as_millis(),
        options.encryption_level,
        options.is_encrypting(),

    );
}
