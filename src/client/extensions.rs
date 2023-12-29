use core::time::Duration;

use log::debug;

use crate::config::ConnectionOptions;
use crate::config::DEFAULT_DATA_BLOCK_SIZE;
use crate::config::DEFAULT_RETRY_PACKET_TIMEOUT;
use crate::config::EXTENSION_BLOCK_SIZE_MIN;
use crate::config::EXTENSION_TIMEOUT_SIZE_MAX;
use crate::config::EXTENSION_TIMEOUT_SIZE_MIN;
use crate::config::EXTENSION_WINDOW_SIZE_MIN;
#[cfg(feature = "encryption")]
use crate::encryption::*;
use crate::error::ExtensionError;
use crate::packet::ErrorCode;
use crate::packet::ErrorPacket;
use crate::packet::Extension;
use crate::packet::PacketExtensions;
use crate::string::format_str;
use crate::types::DefaultString;

pub fn validate_extensions(
    new_extensions: &PacketExtensions,
    used_extensions: &PacketExtensions,
) -> Result<(), ErrorPacket> {
    #[allow(unused_must_use)]
    let remaining = new_extensions
        .iter()
        .filter(|(e, _)| !used_extensions.contains_key(e))
        .fold(DefaultString::new(), |mut s, (k, _)| {
            s.push_str(k.as_str());
            s.push(',');
            s
        });
    let names = remaining.as_str().trim_end_matches(',');
    if !names.is_empty() {
        let message = format_str!(
            DefaultString,
            "Server sent options {} not initialized by client",
            names
        );
        return Err(ErrorPacket::new(ErrorCode::IllegalOperation, message));
    }
    Ok(())
}

pub fn create_extensions(options: &ConnectionOptions) -> PacketExtensions {
    let mut extensions = PacketExtensions::new();
    if options.block_size != DEFAULT_DATA_BLOCK_SIZE {
        let _ = extensions.insert(
            Extension::BlockSize,
            format_str!(ExtensionValue, "{}", options.block_size as u64),
        );
    }

    if options.retry_packet_after_timeout != DEFAULT_RETRY_PACKET_TIMEOUT
        && options.retry_packet_after_timeout.as_secs() >= EXTENSION_TIMEOUT_SIZE_MIN as u64
    {
        let _ = extensions.insert(
            Extension::Timeout,
            format_str!(
                ExtensionValue,
                "{}",
                options.retry_packet_after_timeout.as_secs()
            ),
        );
    }

    if let Some(file_size) = options.file_size {
        let _ = extensions.insert(
            Extension::TransferSize,
            format_str!(ExtensionValue, "{}", file_size),
        );
    }

    if options.window_size != EXTENSION_WINDOW_SIZE_MIN {
        let _ = extensions.insert(
            Extension::WindowSize,
            format_str!(ExtensionValue, "{}", options.window_size),
        );
    }

    #[cfg(feature = "encryption")]
    if options.encryption_level != EncryptionLevel::None {
        match (&options.encryption_keys, options.encryption_level) {
            (Some(EncryptionKeys::ClientKey(s)), l) => {
                let value = encode_public_key(s).expect("invalid key");
                let _ = extensions.insert(Extension::PublicKey, value);
                let _ = extensions.insert(
                    Extension::EncryptionLevel,
                    format_str!(ExtensionValue, "{}", l),
                );
            }
            // protocol contains encrypted data already
            (Some(EncryptionKeys::LocalToRemote(local, _)), l)
                if matches!(
                    l,
                    EncryptionLevel::Data
                        | EncryptionLevel::OptionalData
                        | EncryptionLevel::OptionalProtocol
                ) =>
            {
                let value = encode_public_key(local).expect("invalid key");
                let _ = extensions.insert(Extension::PublicKey, value);
                let _ = extensions.insert(
                    Extension::EncryptionLevel,
                    format_str!(ExtensionValue, "{}", l),
                );
            }
            _ => (),
        }
    }

    debug!("Client extensions {:?}", extensions);
    extensions
}

pub fn parse_extensions(
    extensions: PacketExtensions,
    mut options: ConnectionOptions,
) -> Result<ConnectionOptions, ExtensionError> {
    if let Some(block_size) = extensions.get(&Extension::BlockSize) {
        let server_block_size: u16 = block_size.parse().unwrap_or(0);
        if (EXTENSION_BLOCK_SIZE_MIN..=options.block_size).contains(&server_block_size) {
            options.block_size = server_block_size;
        } else {
            return Err(ExtensionError::InvalidExtension(Extension::BlockSize));
        }
    } else {
        options.block_size = DEFAULT_DATA_BLOCK_SIZE;
    }

    if let Some(window_size) = extensions.get(&Extension::WindowSize) {
        let server_window_size: u16 = window_size.parse().unwrap_or(0);
        if (EXTENSION_WINDOW_SIZE_MIN..=options.window_size).contains(&server_window_size) {
            options.window_size = server_window_size;
        } else {
            return Err(ExtensionError::InvalidExtension(Extension::WindowSize));
        }
    } else {
        options.window_size = EXTENSION_WINDOW_SIZE_MIN;
    }

    if let Some(timeout) = extensions.get(&Extension::Timeout) {
        let server_retry_seconds: u8 = timeout.parse().unwrap_or(0);
        if (EXTENSION_TIMEOUT_SIZE_MIN..=EXTENSION_TIMEOUT_SIZE_MAX).contains(&server_retry_seconds)
        {
            options.retry_packet_after_timeout = Duration::from_secs(server_retry_seconds as u64);
        } else {
            return Err(ExtensionError::InvalidExtension(Extension::Timeout));
        }
    } else {
        options.retry_packet_after_timeout = DEFAULT_RETRY_PACKET_TIMEOUT;
    }

    if let Some(tsize) = extensions.get(&Extension::TransferSize) {
        let server_file_size: u64 = tsize.parse().unwrap_or(0);
        if options.file_size.is_none() || Some(0) == options.file_size {
            options.file_size = Some(server_file_size);
        } else if options.file_size > Some(0) && options.file_size != Some(server_file_size) {
            return Err(ExtensionError::InvalidExtension(Extension::TransferSize));
        }
    }

    #[cfg(feature = "encryption")]
    if options.encryption_level != EncryptionLevel::Full {
        let _expected_encryption_level = options.encryption_level;
        if let (Some(pkey), Some(Ok(level))) = (
            extensions.get(&Extension::PublicKey),
            extensions
                .get(&Extension::EncryptionLevel)
                .map(|s| s.parse()),
        ) {
            match &options.encryption_keys {
                Some(EncryptionKeys::ClientKey(_)) => {
                    let remote_public_key = decode_public_key(pkey.as_bytes())?;
                    options.encryption_keys = Some(EncryptionKeys::ServerKey(remote_public_key));
                    options.encryption_level = level;
                }
                Some(EncryptionKeys::LocalToRemote(_, r)) => {
                    let remote_public_key = decode_public_key(pkey.as_bytes())?;
                    if r.as_bytes() != remote_public_key.as_bytes() {
                        return Err(ExtensionError::InvalidExtension(Extension::PublicKey));
                    }
                    options.encryption_keys = Some(EncryptionKeys::ServerKey(remote_public_key));
                    options.encryption_level = level;
                }
                _ => return Err(ExtensionError::InvalidExtension(Extension::PublicKey)),
            }
        }

        if matches!(
            _expected_encryption_level,
            EncryptionLevel::Data | EncryptionLevel::Protocol
        ) && !matches!(
            options.encryption_level,
            EncryptionLevel::Data | EncryptionLevel::Protocol
        ) {
            return Err(ExtensionError::ClientRequiredEncryption(
                options.encryption_level,
            ));
        }
    }
    Ok(options)
}

#[cfg(test)]
mod tests {

    use super::*;
    #[allow(unused_imports)]
    use crate::encryption::*;

    #[test]
    fn test_validate_extensions() {
        let options = ConnectionOptions {
            block_size: 500,
            retry_packet_after_timeout: Duration::from_secs(7),
            file_size: 0.into(),
            encryption_keys: None,
            encryption_level: EncryptionLevel::None,
            window_size: 8,
        };
        let client_extensions = create_extensions(&options);
        assert_eq!(client_extensions.len(), 4);

        let mut server_extensions = PacketExtensions::new();
        let _ = server_extensions.insert(Extension::BlockSize, "101".parse().unwrap());
        let _ = server_extensions.insert(Extension::TransferSize, "6".parse().unwrap());
        let _ = server_extensions.insert(Extension::Timeout, "6".parse().unwrap());
        let _ = server_extensions.insert(Extension::WindowSize, "2".parse().unwrap());

        validate_extensions(&server_extensions, &client_extensions).unwrap();
    }

    #[test]
    fn test_validate_extensions_unknown_server_extensions() {
        let mut client_extensions = PacketExtensions::new();
        let _ = client_extensions.insert(Extension::BlockSize, "101".parse().unwrap());

        let mut server_extensions = PacketExtensions::new();
        let _ = server_extensions.insert(Extension::BlockSize, "101".parse().unwrap());
        let _ = server_extensions.insert(Extension::TransferSize, "6".parse().unwrap());
        let _ = server_extensions.insert(Extension::Timeout, "6".parse().unwrap());
        let _ = server_extensions.insert(Extension::WindowSize, "2".parse().unwrap());

        let result = validate_extensions(&server_extensions, &client_extensions);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_options() {
        let options = ConnectionOptions {
            block_size: 500,
            retry_packet_after_timeout: Duration::from_secs(7),
            file_size: 0.into(),
            encryption_keys: None,
            encryption_level: EncryptionLevel::None,
            window_size: 8,
        };
        let extensions = create_extensions(&options);
        assert_eq!(extensions.len(), 4);

        assert_eq!(
            extensions.get(&Extension::BlockSize),
            Some(&"500".parse().unwrap())
        );
        assert_eq!(
            extensions.get(&Extension::Timeout),
            Some(&"7".parse().unwrap())
        );
        assert_eq!(
            extensions.get(&Extension::TransferSize),
            Some(&"0".parse().unwrap())
        );
        assert_eq!(
            extensions.get(&Extension::WindowSize),
            Some(&"8".parse().unwrap())
        );
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_create_options_no_encryption_key() {
        let options = ConnectionOptions {
            block_size: 500,
            retry_packet_after_timeout: Duration::from_secs(7),
            file_size: 0.into(),
            encryption_keys: None,
            encryption_level: EncryptionLevel::OptionalProtocol,
            window_size: 8,
        };
        let extensions = create_extensions(&options);
        assert_eq!(extensions.len(), 4);
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_create_options_encryption() {
        use std::vec::Vec;

        let bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let key: [u8; 32] = bytes.try_into().unwrap();
        let options = ConnectionOptions {
            block_size: 500,
            retry_packet_after_timeout: Duration::from_secs(7),
            file_size: 0.into(),
            encryption_keys: EncryptionKeys::ClientKey(PublicKey::from(key)).into(),
            encryption_level: EncryptionLevel::OptionalProtocol,
            window_size: 8,
        };
        let extensions = create_extensions(&options);
        assert_eq!(extensions.len(), 6);

        assert_eq!(
            extensions.get(&Extension::EncryptionLevel),
            Some(&"optional-protocol".parse().unwrap())
        );
        assert!(extensions.get(&Extension::PublicKey).is_some(),);
    }

    #[test]
    fn test_parse_extensions() {
        let options = ConnectionOptions {
            block_size: 512,
            retry_packet_after_timeout: Duration::from_secs(7),
            file_size: 0.into(),
            encryption_keys: None,
            encryption_level: EncryptionLevel::None,
            window_size: 8,
        };
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(Extension::BlockSize, "512".parse().unwrap());
        let _ = extensions.insert(Extension::TransferSize, "6".parse().unwrap());
        let _ = extensions.insert(Extension::Timeout, "6".parse().unwrap());
        let _ = extensions.insert(Extension::WindowSize, "2".parse().unwrap());

        assert_eq!(extensions.len(), 4, "{extensions:?}");

        let result = parse_extensions(extensions, options.clone()).unwrap();

        assert_eq!(result.window_size, 2);
        assert_eq!(result.block_size, 512);
        assert_eq!(result.file_size, Some(6));
        assert_eq!(result.retry_packet_after_timeout, Duration::from_secs(6));
    }

    #[test]
    fn test_parse_extensions_disallowed_block_size() {
        let options = ConnectionOptions::default();
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(Extension::BlockSize, "0".parse().unwrap());

        let result = parse_extensions(extensions, options.clone());

        assert!(matches!(
            result,
            Err(ExtensionError::InvalidExtension(Extension::BlockSize))
        ));
    }

    #[test]
    fn test_parse_extensions_disallowed_window_size() {
        let options = ConnectionOptions::default();
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(Extension::WindowSize, "2".parse().unwrap());

        let result = parse_extensions(extensions, options.clone());

        assert!(matches!(
            result,
            Err(ExtensionError::InvalidExtension(Extension::WindowSize))
        ));
    }

    #[test]
    fn test_parse_extensions_disallowed_transfer_size() {
        let mut options = ConnectionOptions::default();
        options.file_size = 6.into();
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(Extension::TransferSize, "2".parse().unwrap());

        let result = parse_extensions(extensions, options.clone());

        assert!(matches!(
            result,
            Err(ExtensionError::InvalidExtension(Extension::TransferSize))
        ));
    }

    #[test]
    fn test_parse_extensions_disallowed_retry_timeout() {
        let mut options = ConnectionOptions::default();
        options.retry_packet_after_timeout = Duration::from_secs(1);
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(Extension::Timeout, "0".parse().unwrap());

        let result = parse_extensions(extensions, options.clone());

        assert!(matches!(
            result,
            Err(ExtensionError::InvalidExtension(Extension::Timeout))
        ));
    }

    #[test]
    fn test_parse_extensions_invalid_server_value() {
        let options = ConnectionOptions::default();
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(Extension::BlockSize, "any".parse().unwrap());

        let result = parse_extensions(extensions, options.clone());

        assert!(matches!(
            result,
            Err(ExtensionError::InvalidExtension(Extension::BlockSize))
        ));
    }
}
