use core::{cmp::min, time::Duration};

use log::debug;

use crate::{
    encryption::{EncryptionKeys, EncryptionLevel, PublicKey},
    macros::{cfg_alloc, cfg_stack_large_window, cfg_stack_many_clients},
};

pub const DEFAULT_DATA_BLOCK_SIZE: u16 = 512;
pub const DATA_PACKET_HEADER_SIZE: u8 = 4;

pub const MAX_DATA_BLOCK_SIZE: u16 = 1416;

/// maximum size of the packet buffer
pub const MAX_BUFFER_SIZE: u16 = MAX_DATA_BLOCK_SIZE + DATA_PACKET_HEADER_SIZE as u16;
pub const MIN_BUFFER_SIZE: u16 = DEFAULT_DATA_BLOCK_SIZE + DATA_PACKET_HEADER_SIZE as u16;

#[cfg(feature = "encryption")]
pub const ENCRYPTION_TAG_SIZE: u8 = 16;
#[cfg(not(feature = "encryption"))]
pub const ENCRYPTION_TAG_SIZE: u8 = 0;

cfg_alloc!(
    /// how many clients server can manage at once
    pub const MAX_CLIENTS: u16 = 5000;
    pub const MAX_BLOCKS_WRITER: u16 = 2000;
    pub const MAX_BLOCKS_READER: u16 = 1000;
    pub const DEFAULT_WINDOW_SIZE: u8 = 8;
);

cfg_stack_many_clients!(
    pub const MAX_CLIENTS: u16 = 100;
    pub const MAX_BLOCKS_WRITER: u16 = 4;
    pub const MAX_BLOCKS_READER: u16 = 4;
    pub const DEFAULT_WINDOW_SIZE: u8 = 4;
);

cfg_stack_large_window!(
    pub const MAX_CLIENTS: u16 = 3;
    pub const MAX_BLOCKS_WRITER: u16 = 64;
    pub const MAX_BLOCKS_READER: u16 = 64;
    pub const DEFAULT_WINDOW_SIZE: u8 = 8;
);

pub const MAX_EXTENSION_VALUE_SIZE: u8 = 45;
pub const MAX_DEFAULT_STRING_SIZE: u8 = 140;
pub const MAX_FILE_PATH_SIZE: u8 = 150;

pub const DEFAULT_RETRY_PACKET_TIMEOUT: Duration = Duration::from_millis(80);
pub const EXTENSION_WINDOW_SIZE_MIN: u16 = 1;
// pub const EXTENSION_WINDOW_SIZE_MAX: u16 = 65535;
pub const EXTENSION_BLOCK_SIZE_MIN: u16 = 8 + ENCRYPTION_TAG_SIZE as u16;
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
            Some(EncryptionKeys::LocalToRemote(_, p)) => p.clone().into(),
            _ => None,
        }
    }
}

pub fn print_options(context: &str, options: &ConnectionOptions) {
    debug!(
        "{} options - block_size: {}, window size: {}, file_size: {} bytes, retry packet: {}ms, encryption level: {}, encrypting: {}",
        context,
        options.block_size,
        options.window_size,
        options.file_size.unwrap_or(0),
        options.retry_packet_after_timeout.as_millis(),
        options.encryption_level,
        matches!(
            options.encryption_keys,
            Some(crate::encryption::EncryptionKeys::LocalToRemote(..))
        ),
    );
}
