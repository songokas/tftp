use core::fmt::Display;
use core::fmt::Formatter;
use core::time::Duration;

use tftp_dus::config::ConnectionOptions;
use tftp_dus::config::MIN_DATA_BLOCK_SIZE;
use tftp_dus::config::MIN_ENCRYPTION_SIZE;
use tftp_dus::encryption::EncryptionLevel;

#[derive(Debug, PartialEq, Eq)]
pub enum OptionsError {
    InvalidEncryptionLevel,
    BlockSizeTooSmall { minimum: u16 },
}

impl Display for OptionsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            OptionsError::InvalidEncryptionLevel => {
                write!(f, "Invalid encryption level specified")
            }
            OptionsError::BlockSizeTooSmall { minimum } => {
                write!(f, "Block size with encryption must be at least {minimum}")
            }
        }
    }
}

impl std::error::Error for OptionsError {}

#[cfg(feature = "encryption")]
fn parse_encryption_level(level: &str) -> Result<EncryptionLevel, OptionsError> {
    level
        .parse()
        .map_err(|_| OptionsError::InvalidEncryptionLevel)
}

#[cfg(not(feature = "encryption"))]
fn parse_encryption_level(_level: &str) -> Result<EncryptionLevel, OptionsError> {
    Ok(EncryptionLevel::None)
}

/// `encryption_level` is ignored when built without the `encryption` feature.
pub fn connection_options(
    encryption_level: &str,
    block_size: u64,
    window_size: u64,
    retry_timeout_ms: u64,
    file_size: Option<u64>,
) -> Result<ConnectionOptions, OptionsError> {
    let encryption_level = parse_encryption_level(encryption_level)?;
    let minimum = MIN_DATA_BLOCK_SIZE + MIN_ENCRYPTION_SIZE as u16;
    if encryption_level != EncryptionLevel::None && block_size < minimum as u64 {
        return Err(OptionsError::BlockSizeTooSmall { minimum });
    }
    Ok(ConnectionOptions {
        block_size: block_size as u16,
        retry_packet_after_timeout: Duration::from_millis(retry_timeout_ms),
        file_size,
        encryption_level,
        window_size: window_size as u16,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_options() {
        let options = connection_options("none", 512, 4, 80, Some(7)).unwrap();
        assert_eq!(options.block_size, 512);
        assert_eq!(options.window_size, 4);
        assert_eq!(options.retry_packet_after_timeout.as_millis(), 80);
        assert_eq!(options.file_size, Some(7));
        assert_eq!(options.encryption_level, EncryptionLevel::None);
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_connection_options_validates_encryption() {
        let minimum = MIN_DATA_BLOCK_SIZE + MIN_ENCRYPTION_SIZE as u16;
        assert_eq!(
            connection_options("protocol", minimum as u64 - 1, 4, 80, None).unwrap_err(),
            OptionsError::BlockSizeTooSmall { minimum }
        );
        assert!(connection_options("protocol", minimum as u64, 4, 80, None).is_ok());
        assert_eq!(
            connection_options("unknown", 512, 4, 80, None).unwrap_err(),
            OptionsError::InvalidEncryptionLevel
        );
        assert!(connection_options("none", minimum as u64 - 1, 4, 80, None).is_ok());
    }
}
