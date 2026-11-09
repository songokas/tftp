use core::cmp::max;
use core::time::Duration;

use log::*;
use rand::CryptoRng;
use rand::RngCore;

use super::config::ServerConfig;
use crate::config::ConnectionOptions;
use crate::config::EXTENSION_BLOCK_SIZE_MAX;
use crate::config::EXTENSION_BLOCK_SIZE_MIN;
use crate::config::EXTENSION_TIMEOUT_SIZE_MIN;
use crate::config::EXTENSION_WINDOW_SIZE_MIN;
use crate::error::ExtensionError;
use crate::packet::Extension;
use crate::packet::PacketExtensions;
use crate::packet::SignedRequest;
use crate::server::helpers::connection::SessionKeys;
use crate::server::session_encryption;
use crate::string::format_str;

pub fn parse_extensions<R: CryptoRng + RngCore + Copy>(
    client_extensions: PacketExtensions,
    request: SignedRequest,
    mut options: ConnectionOptions,
    config: &ServerConfig,
    max_window_size: u16,
    rng: R,
) -> Result<(PacketExtensions, ConnectionOptions, Option<SessionKeys<R>>), ExtensionError> {
    let mut used_extensions = PacketExtensions::new();
    if let Some(size) = client_extensions.get(&Extension::BlockSize) {
        let client_block_size: u16 = size.parse().unwrap_or(0);
        let min_block_size = session_encryption::min_block_size(&client_extensions);
        if min_block_size > config.max_block_size {
            return Err(ExtensionError::InvalidExtension(Extension::BlockSize));
        }
        if (EXTENSION_BLOCK_SIZE_MIN..=config.max_block_size).contains(&client_block_size) {
            options.block_size = max(client_block_size, min_block_size);
            let _ = used_extensions.insert(
                Extension::BlockSize,
                format_str!(ExtensionValue, "{}", options.block_size),
            );
        } else if client_block_size > config.max_block_size {
            options.block_size = config.max_block_size;
            let _ = used_extensions.insert(
                Extension::BlockSize,
                format_str!(ExtensionValue, "{}", options.block_size),
            );
        } else {
            warn!("Invalid block size received {} skipping", size);
        }
    }

    // a request without blksize needs 512 byte blocks, which a build with a
    // lower TFTP_MAX_BLOCK_SIZE has no room for
    if options.block_size > EXTENSION_BLOCK_SIZE_MAX {
        return Err(ExtensionError::InvalidExtension(Extension::BlockSize));
    }

    if let Some(window_size) = client_extensions.get(&Extension::WindowSize) {
        let client_window_size: u16 = window_size.parse().unwrap_or(0);
        if (EXTENSION_WINDOW_SIZE_MIN..=max_window_size).contains(&client_window_size) {
            options.window_size = client_window_size;
            let _ = used_extensions.insert(
                Extension::WindowSize,
                format_str!(ExtensionValue, "{}", options.window_size),
            );
        } else if client_window_size > max_window_size {
            options.window_size = max_window_size;
            let _ = used_extensions.insert(
                Extension::WindowSize,
                format_str!(ExtensionValue, "{}", options.window_size),
            );
        } else {
            warn!(
                "Invalid window size received {} skipping",
                client_window_size
            );
        }
    }

    if let Some(timeout) = client_extensions.get(&Extension::Timeout) {
        let client_retry_seconds: u8 = timeout.parse().unwrap_or(0);
        if (EXTENSION_TIMEOUT_SIZE_MIN as u64..=config.request_timeout.as_secs())
            .contains(&(client_retry_seconds as u64))
        {
            options.retry_packet_after_timeout = Duration::from_secs(client_retry_seconds as u64);
            let _ = used_extensions.insert(
                Extension::Timeout,
                format_str!(ExtensionValue, "{}", client_retry_seconds),
            );
        } else {
            warn!("Invalid retry timeout received {} skipping", timeout);
        }
    }

    if let Some(size) = client_extensions.get(&Extension::TransferSize) {
        match size.parse() {
            Ok(c) => {
                options.file_size = Some(c);
                let _ = used_extensions.insert(
                    Extension::TransferSize,
                    format_str!(ExtensionValue, "{}", c),
                );
            }
            Err(_) => {
                warn!("Invalid transfer size received {} skipping", size);
            }
        }
    }
    session_encryption::negotiate(
        &client_extensions,
        request,
        options,
        config,
        used_extensions,
        rng,
    )
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    use crate::config::DEFAULT_DATA_BLOCK_SIZE;
    use crate::config::MAX_DATA_BLOCK_SIZE;
    #[allow(unused_imports)]
    use crate::encryption::*;
    use crate::packet::PacketType;
    use crate::types::FilePath;

    #[test]
    fn test_parse_extensions() {
        let extensions = PacketExtensions::new();
        let options = ConnectionOptions::default();
        let (extensions, ..) = parse_extensions(
            extensions,
            test_request(),
            options,
            &create_config(),
            8,
            OsRng,
        )
        .unwrap();
        assert_eq!(extensions.len(), 0);

        let options = ConnectionOptions::default();
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(Extension::BlockSize, "512".parse().unwrap());
        let _ = extensions.insert(Extension::TransferSize, "6".parse().unwrap());
        let _ = extensions.insert(Extension::Timeout, "7".parse().unwrap());
        let _ = extensions.insert(Extension::WindowSize, "8".parse().unwrap());
        let (extensions, options, ..) = parse_extensions(
            extensions,
            test_request(),
            options,
            &create_config(),
            8,
            OsRng,
        )
        .unwrap();
        assert_eq!(extensions.len(), 4, "{extensions:?}");
        assert_eq!(options.window_size, 8);
        assert_eq!(options.block_size, 101);
        assert_eq!(options.file_size, Some(6));
        assert_eq!(options.retry_packet_after_timeout, Duration::from_secs(7));
    }

    #[test]
    fn test_parse_invalid_extensions() {
        let options = ConnectionOptions::default();
        let extensions = PacketExtensions::new();
        let (extensions, ..) = parse_extensions(
            extensions,
            test_request(),
            options,
            &create_config(),
            8,
            OsRng,
        )
        .unwrap();
        assert_eq!(extensions.len(), 0);

        let options = ConnectionOptions::default();
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(Extension::BlockSize, "1".parse().unwrap());
        let _ = extensions.insert(Extension::TransferSize, "a".parse().unwrap());
        let _ = extensions.insert(Extension::Timeout, "0".parse().unwrap());
        let _ = extensions.insert(Extension::WindowSize, "0".parse().unwrap());
        let (extensions, options, ..) = parse_extensions(
            extensions,
            test_request(),
            options,
            &create_config(),
            8,
            OsRng,
        )
        .unwrap();
        assert_eq!(extensions.len(), 0);
        assert_ne!(options.block_size, 1);
        assert_ne!(options.file_size, Some(0));
        assert_ne!(options.retry_packet_after_timeout, Duration::from_secs(0));
    }

    /// Meaningful with `TFTP_MAX_BLOCK_SIZE` below 512, see `./test test_lib`.
    #[test]
    fn test_low_block_limit_request_without_blksize_is_refused() {
        if DEFAULT_DATA_BLOCK_SIZE <= MAX_DATA_BLOCK_SIZE {
            return;
        }
        let result = parse_extensions(
            PacketExtensions::new(),
            test_request(),
            ConnectionOptions::default(),
            &create_config(),
            8,
            OsRng,
        );
        assert!(matches!(
            result,
            Err(ExtensionError::InvalidExtension(Extension::BlockSize))
        ));
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_parse_extensions_encryption() {
        use chacha20poly1305::aead::OsRng;

        use crate::encryption::EncryptionLevel;

        let options = ConnectionOptions::default();
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(
            Extension::SessionPublicKey,
            "Yhk58FaJO5dnct6VgrfRXtjqd9m3h2JHrD/Jecov2wY="
                .parse()
                .unwrap(),
        );

        let _ = extensions.insert(Extension::EncryptionLevel, "none".parse().unwrap());
        let (extensions, options, ..) = parse_extensions(
            extensions,
            test_request(),
            options,
            &create_config(),
            8,
            OsRng,
        )
        .unwrap();
        assert_eq!(extensions.len(), 0, "{extensions:?}");
        assert_eq!(options.encryption_level, EncryptionLevel::None);
    }

    fn test_request() -> SignedRequest<'static> {
        SignedRequest {
            packet_type: PacketType::Write,
            file_name: "file",
        }
    }

    /// Extensions from a client holding a signing key, for the given request.
    #[cfg(feature = "encryption")]
    fn signed_extensions(request: SignedRequest) -> PacketExtensions {
        let initial_keys = create_initial_keys(Some(&SigningKey::from([9; 32])), OsRng);
        let options = ConnectionOptions {
            encryption_level: EncryptionLevel::Data,
            ..Default::default()
        };
        crate::client::extensions::create_extensions(&options, Some(&initial_keys), request)
    }

    #[cfg(feature = "encryption")]
    fn negotiate_signed(
        extensions: PacketExtensions,
        request: SignedRequest,
    ) -> Option<ExtensionError> {
        parse_extensions(
            extensions,
            request,
            ConnectionOptions::default(),
            &create_config(),
            8,
            OsRng,
        )
        .err()
    }

    #[cfg(feature = "encryption")]
    fn protocol_level_extensions(block_size: &str) -> PacketExtensions {
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(Extension::BlockSize, block_size.parse().unwrap());
        let _ = extensions.insert(Extension::EncryptionLevel, "protocol".parse().unwrap());
        let _ = extensions.insert(
            Extension::SessionPublicKey,
            "Yhk58FaJO5dnct6VgrfRXtjqd9m3h2JHrD/Jecov2wY="
                .parse()
                .unwrap(),
        );
        extensions
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_low_order_session_key_is_refused_before_the_request_is_accepted() {
        let mut extensions = protocol_level_extensions("512");
        let _ = extensions.insert(
            Extension::SessionPublicKey,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                .parse()
                .unwrap(),
        );

        let result = parse_extensions(
            extensions,
            test_request(),
            ConnectionOptions::default(),
            &create_config(),
            8,
            OsRng,
        );

        assert!(matches!(result, Err(ExtensionError::InvalidPublicKey)));
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_encrypted_block_size_keeps_room_for_payload() {
        let (_, options, _) = parse_extensions(
            protocol_level_extensions("41"),
            test_request(),
            ConnectionOptions::default(),
            &create_config(),
            8,
            OsRng,
        )
        .unwrap();

        assert_eq!(options.block_size, 42);
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_encryption_is_refused_when_max_block_size_has_no_room() {
        let config = ServerConfig {
            max_block_size: 32,
            ..create_config()
        };
        for block_size in ["16", "65535"] {
            let result = parse_extensions(
                protocol_level_extensions(block_size),
                test_request(),
                ConnectionOptions::default(),
                &config,
                8,
                OsRng,
            );

            assert!(
                matches!(
                    result,
                    Err(ExtensionError::InvalidExtension(Extension::BlockSize))
                ),
                "{block_size}"
            );
        }
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_signature_accepts_the_signed_request() {
        let extensions = signed_extensions(test_request());
        assert!(negotiate_signed(extensions, test_request()).is_none());
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_signature_refuses_another_file_name() {
        let extensions = signed_extensions(test_request());
        let replayed = SignedRequest {
            file_name: "other",
            ..test_request()
        };
        assert!(matches!(
            negotiate_signed(extensions, replayed),
            Some(ExtensionError::InvalidSignature)
        ));
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_signature_refuses_another_request_type() {
        let extensions = signed_extensions(test_request());
        let replayed = SignedRequest {
            packet_type: PacketType::Read,
            ..test_request()
        };
        assert!(matches!(
            negotiate_signed(extensions, replayed),
            Some(ExtensionError::InvalidSignature)
        ));
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_signature_refuses_another_encryption_level() {
        let mut extensions = signed_extensions(test_request());
        let _ = extensions.insert(Extension::EncryptionLevel, "protocol".parse().unwrap());
        assert!(matches!(
            negotiate_signed(extensions, test_request()),
            Some(ExtensionError::InvalidSignature)
        ));
    }

    fn create_config() -> ServerConfig {
        let listen: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        ServerConfig {
            listen,
            directory: FilePath::new(),
            allow_overwrite: false,
            request_timeout: Duration::from_secs(10),
            max_connections: 1,
            max_file_size: 1,
            max_block_size: 101,
            authorized_keys: None,
            private_key: None,
            require_full_encryption: false,
            require_server_port_change: false,
            max_window_size: 8,
            prefer_seek: false,
            directory_list: None,
            max_directory_depth: 10,
            error_to_authorized_only: false,
        }
    }
}
