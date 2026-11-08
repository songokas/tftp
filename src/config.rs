use core::time::Duration;

use log::debug;

use crate::encryption::EncryptionLevel;
use crate::macros::cfg_alloc;
use crate::macros::cfg_stack;

pub const DEFAULT_DATA_BLOCK_SIZE: u16 = 512;
// PacketType + block(u16)
pub const DATA_PACKET_HEADER_SIZE: u8 = 4;

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

pub const MIN_ENCRYPTION_SIZE: u8 =
    ENCRYPTION_TAG_SIZE + ENCRYPTION_NONCE_SIZE + ENCRYPTION_PADDING_SIZE;

pub const MIN_DATA_BLOCK_SIZE: u16 = 8;
pub const PREFERRED_DATA_BLOCK_SIZE: u16 = if MAX_DATA_BLOCK_SIZE < 1425 {
    MAX_DATA_BLOCK_SIZE
} else {
    1425
};

cfg_alloc!(
    /// how many clients server can manage at once
    pub const MAX_CLIENTS: u16 = 5000;
    /// max window size
    pub const MAX_BLOCKS_FOR_MULTI_READER: u16 = 1000;
    pub const DEFAULT_WINDOW_SIZE: u8 = 8;
    pub const MAX_DATA_BLOCK_SIZE: u16 = 65464;
);

cfg_stack!(
    /// Parses a limit given through a `TFTP_*` environment variable at build time.
    const fn build_limit(value: Option<&str>, default: u16) -> u16 {
        let Some(value) = value else {
            return default;
        };
        let digits = value.as_bytes();
        assert!(!digits.is_empty(), "TFTP_* build limits must be numbers");
        let mut limit: u32 = 0;
        let mut index = 0;
        while index < digits.len() {
            assert!(
                digits[index].is_ascii_digit(),
                "TFTP_* build limits must be numbers"
            );
            limit = limit * 10 + (digits[index] - b'0') as u32;
            assert!(
                limit <= u16::MAX as u32,
                "TFTP_* build limits must fit in 16 bits"
            );
            index += 1;
        }
        limit as u16
    }

    const fn default_pool_size(size: u16) -> u16 {
        if size < 2 {
            2
        } else {
            size
        }
    }

    // heapless FvIndexMap requires map size to be power of 2
    pub const MAX_CLIENTS: u16 = build_limit(option_env!("TFTP_MAX_CLIENTS"), 128);
    const _: () = assert!(
        MAX_CLIENTS > 1 && MAX_CLIENTS.is_power_of_two(),
        "TFTP_MAX_CLIENTS must be a power of two greater than 1"
    );

    pub const MAX_BLOCKS_FOR_MULTI_READER: u16 =
        build_limit(option_env!("TFTP_MAX_WINDOW_SIZE"), 16);
    const _: () = assert!(
        MAX_BLOCKS_FOR_MULTI_READER >= 1,
        "TFTP_MAX_WINDOW_SIZE must be at least 1"
    );

    /// how many single readers available window size = 1
    pub const MAX_SINGLE_READERS: u16 = build_limit(
        option_env!("TFTP_MAX_SINGLE_READERS"),
        default_pool_size(MAX_CLIENTS / 2),
    );
    const _: () = assert!(
        MAX_SINGLE_READERS > 1 && MAX_SINGLE_READERS.is_power_of_two(),
        "TFTP_MAX_SINGLE_READERS must be a power of two greater than 1"
    );

    /// how many multi readers available window size > 1
    pub const MAX_MULTI_READERS: u16 = build_limit(
        option_env!("TFTP_MAX_MULTI_READERS"),
        default_pool_size(MAX_CLIENTS / 16),
    );
    const _: () = assert!(
        MAX_MULTI_READERS > 1 && MAX_MULTI_READERS.is_power_of_two(),
        "TFTP_MAX_MULTI_READERS must be a power of two greater than 1"
    );

    /// how many seek readers available window size > 1
    pub const MAX_MULTI_SEEK_READERS: u16 = build_limit(
        option_env!("TFTP_MAX_SEEK_READERS"),
        default_pool_size(MAX_CLIENTS / 2),
    );
    const _: () = assert!(
        MAX_MULTI_SEEK_READERS > 1 && MAX_MULTI_SEEK_READERS.is_power_of_two(),
        "TFTP_MAX_SEEK_READERS must be a power of two greater than 1"
    );

    const DEFAULT_WINDOW_SIZE_LIMIT: u16 = build_limit(
        option_env!("TFTP_DEFAULT_WINDOW_SIZE"),
        if MAX_BLOCKS_FOR_MULTI_READER < 4 {
            MAX_BLOCKS_FOR_MULTI_READER
        } else {
            4
        },
    );
    const _: () = assert!(
        DEFAULT_WINDOW_SIZE_LIMIT >= 1
            && DEFAULT_WINDOW_SIZE_LIMIT <= MAX_BLOCKS_FOR_MULTI_READER
            && DEFAULT_WINDOW_SIZE_LIMIT <= u8::MAX as u16,
        "TFTP_DEFAULT_WINDOW_SIZE must be between 1 and min(TFTP_MAX_WINDOW_SIZE, 255)"
    );
    pub const DEFAULT_WINDOW_SIZE: u8 = DEFAULT_WINDOW_SIZE_LIMIT as u8;

    pub const MAX_DATA_BLOCK_SIZE: u16 = build_limit(option_env!("TFTP_MAX_BLOCK_SIZE"), 1425);
    const _: () = assert!(
        MAX_DATA_BLOCK_SIZE >= MIN_DATA_BLOCK_SIZE && MAX_DATA_BLOCK_SIZE <= 65464,
        "TFTP_MAX_BLOCK_SIZE must be between 8 and 65464"
    );
);

/// maximum size of the packet buffer
pub const MAX_BUFFER_SIZE: u16 = MAX_DATA_BLOCK_SIZE + DATA_PACKET_HEADER_SIZE as u16;
pub const MIN_BUFFER_SIZE: u16 = MIN_DATA_BLOCK_SIZE + DATA_PACKET_HEADER_SIZE as u16;

pub const MAX_EXTENSION_VALUE_SIZE: u8 = 88; // current max ENCODED_SIGNATURE_LENGTH;
pub const MAX_DEFAULT_STRING_SIZE: u8 = 140;
pub const MAX_FILE_PATH_SIZE: u8 = 150;

pub const DEFAULT_RETRY_PACKET_TIMEOUT: Duration = Duration::from_millis(80);
pub const EXTENSION_WINDOW_SIZE_MIN: u16 = 1;
// pub const EXTENSION_WINDOW_SIZE_MAX: u16 = 65535;
pub const EXTENSION_BLOCK_SIZE_MIN: u16 = MIN_DATA_BLOCK_SIZE;
pub const EXTENSION_BLOCK_SIZE_MAX: u16 = MAX_DATA_BLOCK_SIZE;
pub const EXTENSION_TIMEOUT_SIZE_MIN: u8 = 1;
pub const EXTENSION_TIMEOUT_SIZE_MAX: u8 = 255;

#[derive(Clone, Debug)]
pub struct ConnectionOptions {
    pub block_size: u16,
    pub retry_packet_after_timeout: Duration,
    pub file_size: Option<u64>,
    pub encryption_level: EncryptionLevel,
    pub window_size: u16,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_DATA_BLOCK_SIZE,
            retry_packet_after_timeout: DEFAULT_RETRY_PACKET_TIMEOUT,
            file_size: None,
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

    pub fn block_size_with_encryption(&self) -> u16 {
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
        self.encryption_level != EncryptionLevel::None
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
