use core::time::Duration;

use log::debug;

use crate::client::session_encryption;
use crate::config::ConnectionOptions;
use crate::config::DEFAULT_DATA_BLOCK_SIZE;
use crate::config::DEFAULT_RETRY_PACKET_TIMEOUT;
use crate::config::EXTENSION_BLOCK_SIZE_MAX;
use crate::config::EXTENSION_BLOCK_SIZE_MIN;
use crate::config::EXTENSION_TIMEOUT_SIZE_MAX;
use crate::config::EXTENSION_TIMEOUT_SIZE_MIN;
use crate::config::EXTENSION_WINDOW_SIZE_MIN;
use crate::encryption::*;
use crate::error::ExtensionError;
use crate::packet::ErrorCode;
use crate::packet::ErrorPacket;
use crate::packet::Extension;
use crate::packet::PacketExtensions;
use crate::packet::SignedRequest;
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
        return Err(ErrorPacket::new(ErrorCode::OptionNegotiation, message));
    }
    Ok(())
}

/// Refuses a block size this build has no buffer for: without `alloc`,
/// `TFTP_MAX_BLOCK_SIZE` can be below the 512 bytes of a plain TFTP transfer.
pub fn ensure_block_size_fits(block_size: u16) -> Result<(), ExtensionError> {
    if block_size > EXTENSION_BLOCK_SIZE_MAX {
        return Err(ExtensionError::InvalidExtension(Extension::BlockSize));
    }
    Ok(())
}

pub fn create_extensions(
    options: &ConnectionOptions,
    initial_keys: Option<&InitialKeys>,
    request: SignedRequest,
) -> PacketExtensions {
    let mut used_extensions = PacketExtensions::new();
    if options.block_size != DEFAULT_DATA_BLOCK_SIZE {
        let _ = used_extensions.insert(
            Extension::BlockSize,
            format_str!(ExtensionValue, "{}", options.block_size as u64),
        );
    }

    if options.retry_packet_after_timeout != DEFAULT_RETRY_PACKET_TIMEOUT
        && options.retry_packet_after_timeout.as_secs() >= EXTENSION_TIMEOUT_SIZE_MIN as u64
    {
        let _ = used_extensions.insert(
            Extension::Timeout,
            format_str!(
                ExtensionValue,
                "{}",
                options.retry_packet_after_timeout.as_secs()
            ),
        );
    }

    if let Some(file_size) = options.file_size {
        let _ = used_extensions.insert(
            Extension::TransferSize,
            format_str!(ExtensionValue, "{}", file_size),
        );
    }

    if options.window_size != EXTENSION_WINDOW_SIZE_MIN {
        let _ = used_extensions.insert(
            Extension::WindowSize,
            format_str!(ExtensionValue, "{}", options.window_size),
        );
    }

    session_encryption::add_extensions(options, initial_keys, request, &mut used_extensions);

    debug!("Client extensions {:?}", used_extensions);
    used_extensions
}

pub fn parse_extensions(
    server_extensions: PacketExtensions,
    mut options: ConnectionOptions,
) -> Result<(ConnectionOptions, Option<PublicKeyPair>), ExtensionError> {
    if let Some(block_size) = server_extensions.get(&Extension::BlockSize) {
        let server_block_size: u16 = block_size.parse().unwrap_or(0);
        if (EXTENSION_BLOCK_SIZE_MIN..=options.block_size).contains(&server_block_size) {
            options.block_size = server_block_size;
        } else {
            return Err(ExtensionError::InvalidExtension(Extension::BlockSize));
        }
    } else {
        ensure_block_size_fits(DEFAULT_DATA_BLOCK_SIZE)?;
        options.block_size = DEFAULT_DATA_BLOCK_SIZE;
    }

    if let Some(window_size) = server_extensions.get(&Extension::WindowSize) {
        let server_window_size: u16 = window_size.parse().unwrap_or(0);
        if (EXTENSION_WINDOW_SIZE_MIN..=options.window_size).contains(&server_window_size) {
            options.window_size = server_window_size;
        } else {
            return Err(ExtensionError::InvalidExtension(Extension::WindowSize));
        }
    } else {
        options.window_size = EXTENSION_WINDOW_SIZE_MIN;
    }

    if let Some(timeout) = server_extensions.get(&Extension::Timeout) {
        let server_retry_seconds: u8 = timeout.parse().unwrap_or(0);
        if (EXTENSION_TIMEOUT_SIZE_MIN..=EXTENSION_TIMEOUT_SIZE_MAX).contains(&server_retry_seconds)
        {
            options.retry_packet_after_timeout = Duration::from_secs(server_retry_seconds as u64);
        } else {
            return Err(ExtensionError::InvalidExtension(Extension::Timeout));
        }
    } else if options.retry_packet_after_timeout.as_secs() >= EXTENSION_TIMEOUT_SIZE_MIN as u64 {
        // the server refused the requested timeout; one below a second was never
        // sent, so it still applies
        options.retry_packet_after_timeout = DEFAULT_RETRY_PACKET_TIMEOUT;
    }

    if let Some(tsize) = server_extensions.get(&Extension::TransferSize) {
        let server_file_size: u64 = tsize.parse().unwrap_or(0);
        if options.file_size.is_none() || Some(0) == options.file_size {
            options.file_size = Some(server_file_size);
        } else if options.file_size > Some(0) && options.file_size != Some(server_file_size) {
            return Err(ExtensionError::InvalidExtension(Extension::TransferSize));
        }
    }

    session_encryption::parse_reply(&server_extensions, options)
}

#[cfg(test)]
mod tests {

    use super::*;
    #[allow(unused_imports)]
    use crate::encryption::*;
    use crate::packet::PacketType;

    fn test_request() -> SignedRequest<'static> {
        SignedRequest {
            packet_type: PacketType::Read,
            file_name: "file",
        }
    }

    #[test]
    fn test_validate_extensions() {
        let options = ConnectionOptions {
            block_size: 500,
            retry_packet_after_timeout: Duration::from_secs(7),
            file_size: 0.into(),
            encryption_level: EncryptionLevel::None,
            window_size: 8,
        };
        let client_extensions = create_extensions(&options, None, test_request());
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
            encryption_level: EncryptionLevel::None,
            window_size: 8,
        };
        let extensions = create_extensions(&options, None, test_request());
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

    // #[cfg(feature = "encryption")]
    // #[test]
    // fn test_create_options_no_encryption_key() {
    //     let options = ConnectionOptions {
    //         block_size: 500,
    //         retry_packet_after_timeout: Duration::from_secs(7),
    //         file_size: 0.into(),
    //         encryption_level: EncryptionLevel::OptionalProtocol,
    //         window_size: 8,
    //     };
    //     let extensions = create_extensions(&options, None, test_request());
    //     assert_eq!(extensions.len(), 4);
    // }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_create_options_encryption() {
        use std::vec::Vec;

        use rand::rngs::OsRng;

        let options = ConnectionOptions {
            block_size: 500,
            retry_packet_after_timeout: Duration::from_secs(7),
            file_size: 0.into(),
            encryption_level: EncryptionLevel::OptionalProtocol,
            window_size: 8,
        };

        let bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let private_key: [u8; 32] = bytes.try_into().unwrap();
        let initial_keys = create_initial_keys(Some(&SigningKey::from(private_key)), OsRng);
        let extensions = create_extensions(&options, Some(&initial_keys), test_request());
        assert_eq!(extensions.len(), 8);

        assert_eq!(
            extensions.get(&Extension::EncryptionLevel),
            Some(&"optional-protocol".parse().unwrap())
        );
        assert!(extensions.contains_key(&Extension::SessionPublicKey));
        assert!(extensions.contains_key(&Extension::AuthPublicKey));
        assert!(extensions.contains_key(&Extension::Signature));
    }

    #[test]
    fn test_reply_without_timeout_keeps_a_retry_that_was_never_requested() {
        let options = ConnectionOptions {
            retry_packet_after_timeout: Duration::from_millis(200),
            ..Default::default()
        };

        let (result, _) = parse_extensions(PacketExtensions::new(), options).unwrap();

        assert_eq!(
            result.retry_packet_after_timeout,
            Duration::from_millis(200)
        );
    }

    #[test]
    fn test_reply_without_timeout_drops_a_refused_retry() {
        let options = ConnectionOptions {
            retry_packet_after_timeout: Duration::from_secs(7),
            ..Default::default()
        };

        let (result, _) = parse_extensions(PacketExtensions::new(), options).unwrap();

        assert_eq!(
            result.retry_packet_after_timeout,
            DEFAULT_RETRY_PACKET_TIMEOUT
        );
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_block_size_without_room_for_encryption_is_refused() {
        // data level adds 40 bytes, protocol level 41, and at least one byte of
        // payload must remain
        for (level, reply, block_size) in [
            (EncryptionLevel::Data, "data", "40"),
            (EncryptionLevel::Protocol, "protocol", "8"),
            (EncryptionLevel::Protocol, "protocol", "41"),
        ] {
            let options = ConnectionOptions {
                encryption_level: level,
                block_size: 512,
                ..Default::default()
            };
            let mut extensions = PacketExtensions::new();
            let _ = extensions.insert(Extension::BlockSize, block_size.parse().unwrap());
            let _ = extensions.insert(Extension::EncryptionLevel, reply.parse().unwrap());
            let _ = extensions.insert(
                Extension::SessionPublicKey,
                "Yhk58FaJO5dnct6VgrfRXtjqd9m3h2JHrD/Jecov2wY="
                    .parse()
                    .unwrap(),
            );

            let result = parse_extensions(extensions, options);

            assert!(
                matches!(
                    result,
                    Err(ExtensionError::InvalidExtension(Extension::BlockSize))
                ),
                "{level} {block_size}"
            );
        }
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_reply_with_another_required_level_is_refused() {
        for (requested, reply) in [
            (EncryptionLevel::Protocol, "data"),
            (EncryptionLevel::Data, "protocol"),
        ] {
            let options = ConnectionOptions {
                encryption_level: requested,
                ..Default::default()
            };
            let mut extensions = PacketExtensions::new();
            let _ = extensions.insert(Extension::EncryptionLevel, reply.parse().unwrap());
            let _ = extensions.insert(
                Extension::SessionPublicKey,
                "Yhk58FaJO5dnct6VgrfRXtjqd9m3h2JHrD/Jecov2wY="
                    .parse()
                    .unwrap(),
            );

            let result = parse_extensions(extensions, options);

            assert!(
                matches!(result, Err(ExtensionError::ClientRequiredEncryption(_))),
                "{requested}"
            );
        }
    }

    #[test]
    fn test_parse_extensions() {
        let options = ConnectionOptions {
            block_size: 512,
            retry_packet_after_timeout: Duration::from_secs(7),
            file_size: 0.into(),
            encryption_level: EncryptionLevel::None,
            window_size: 8,
        };
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(Extension::BlockSize, "512".parse().unwrap());
        let _ = extensions.insert(Extension::TransferSize, "6".parse().unwrap());
        let _ = extensions.insert(Extension::Timeout, "6".parse().unwrap());
        let _ = extensions.insert(Extension::WindowSize, "2".parse().unwrap());

        assert_eq!(extensions.len(), 4, "{extensions:?}");

        let (result, _) = parse_extensions(extensions, options.clone()).unwrap();

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
        let options = ConnectionOptions {
            file_size: 6.into(),
            ..Default::default()
        };
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
        let options = ConnectionOptions {
            retry_packet_after_timeout: Duration::from_secs(1),
            ..Default::default()
        };
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
