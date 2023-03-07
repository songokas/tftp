use core::time::Duration;

use log::{debug, error, warn};
use rand::{CryptoRng, RngCore};

use crate::{
    config::{
        ConnectionOptions, ENCRYPTION_TAG_SIZE, EXTENSION_BLOCK_SIZE_MIN,
        EXTENSION_TIMEOUT_SIZE_MAX, EXTENSION_TIMEOUT_SIZE_MIN, EXTENSION_WINDOW_SIZE_MIN,
    },
    encryption::{
        decode_public_key, encode_nonce, encode_public_key, EncryptionKeys, EncryptionLevel,
        FinalizeKeysCallback, FinalizedKeys,
    },
    error::ExtensionError,
    key_management::create_finalized_keys,
    map::Entry,
    packet::{Extension, PacketExtensions, PacketType},
    server::ServerConfig,
    string::format_str,
};

#[allow(unused_variables)]
pub fn create_options(
    extensions: PacketExtensions,
    mut options: ConnectionOptions,
    config: &ServerConfig,
    finalized_keys: Option<FinalizedKeys>,
    max_window_size: u16,
    rng: impl CryptoRng + RngCore + Copy,
) -> Result<(PacketExtensions, ConnectionOptions, Option<FinalizedKeys>), ExtensionError> {
    let mut used_extensions = PacketExtensions::new();
    if let Some(size) = extensions.get(&Extension::BlockSize) {
        let client_block_size: u16 = size.parse().unwrap_or(0);
        if (EXTENSION_BLOCK_SIZE_MIN..=config.max_block_size).contains(&client_block_size) {
            options.block_size = client_block_size;
            used_extensions.insert(
                Extension::BlockSize,
                format_str!(ExtensionValue, "{}", options.block_size),
            );
        } else if client_block_size > config.max_block_size {
            options.block_size = config.max_block_size;
            used_extensions.insert(
                Extension::BlockSize,
                format_str!(ExtensionValue, "{}", options.block_size),
            );
        } else {
            warn!("Invalid block size received {} skipping", size);
        }
    }

    if let Some(window_size) = extensions.get(&Extension::WindowSize) {
        let client_window_size: u16 = window_size.parse().unwrap_or(0);
        if (EXTENSION_WINDOW_SIZE_MIN..=max_window_size).contains(&client_window_size) {
            options.window_size = client_window_size;
            used_extensions.insert(
                Extension::WindowSize,
                format_str!(ExtensionValue, "{}", options.window_size),
            );
        } else if client_window_size > max_window_size {
            options.window_size = max_window_size;
            used_extensions.insert(
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

    if let Some(timeout) = extensions.get(&Extension::Timeout) {
        let client_retry_seconds: u8 = timeout.parse().unwrap_or(0);
        if (EXTENSION_TIMEOUT_SIZE_MIN as u64..=config.request_timeout.as_secs())
            .contains(&(client_retry_seconds as u64))
        {
            options.retry_packet_after_timeout = Duration::from_secs(client_retry_seconds as u64);
            used_extensions.insert(
                Extension::Timeout,
                format_str!(ExtensionValue, "{}", client_retry_seconds),
            );
        } else {
            warn!("Invalid retry timeout received {} skipping", timeout);
        }
    }

    if let Some(size) = extensions.get(&Extension::TransferSize) {
        match size.parse() {
            Ok(c) => {
                options.file_size = Some(c);
                used_extensions.insert(
                    Extension::TransferSize,
                    format_str!(ExtensionValue, "{}", c),
                );
            }
            Err(_) => {
                warn!("Invalid transfer size received {} skipping", size);
            }
        }
    }

    #[cfg(feature = "encryption")]
    let finalized_keys = if finalized_keys.is_none() {
        // allow only authorized keys and encryption
        if let (Some(keys), public) = (
            &config.authorized_keys,
            extensions.get(&Extension::PublicKey),
        ) {
            match public
                .map(|p| decode_public_key(p.as_bytes()))
                .transpose()?
            {
                Some(remote_public_key) if keys.contains(&remote_public_key) => (),
                _ => {
                    debug!("Received new connection options however public key was not authorized",);
                    return Err(ExtensionError::InvalidPublicKey);
                }
            }
        }

        if let (Some(public), Some(nonce), Some(Ok(level))) = (
            extensions.get(&Extension::PublicKey),
            extensions.get(&Extension::Nonce),
            extensions
                .get(&Extension::EncryptionLevel)
                .map(|s| s.parse()),
        ) {
            let remote_public_key = decode_public_key(public.as_bytes())?;
            let final_keys =
                create_finalized_keys(&config.private_key, &remote_public_key, None, rng);
            used_extensions.insert(
                Extension::PublicKey,
                encode_public_key(&final_keys.public).expect("public key encoder"),
            );
            used_extensions.insert(
                Extension::Nonce,
                encode_nonce(&final_keys.nonce()).expect("nonce encoder"),
            );
            options.encryption_keys = Some(EncryptionKeys::LocalToRemote(
                final_keys.public,
                remote_public_key,
            ));
            options.encryption_level = match level {
                EncryptionLevel::OptionalData => EncryptionLevel::Data,
                EncryptionLevel::OptionalProtocol => EncryptionLevel::Protocol,
                _ => level,
            };
            used_extensions.insert(
                Extension::EncryptionLevel,
                format_str!(ExtensionValue, "{}", options.encryption_level),
            );
            final_keys.into()
        } else {
            None
        }
    } else {
        finalized_keys
    };

    #[cfg(feature = "encryption")]
    if finalized_keys.is_some()
        && matches!(
            options.encryption_level,
            EncryptionLevel::Data | EncryptionLevel::Protocol | EncryptionLevel::Full
        )
    {
        options.block_size -= ENCRYPTION_TAG_SIZE as u16;
    }
    debug!("Server extensions {:?}", used_extensions);
    Ok((used_extensions, options, finalized_keys))
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    #[cfg(feature = "encryption")]
    use crate::encryption::{
        decode_nonce, decode_private_key, FinalizedKeys, InitialKeys, PrivateKey, PublicKey,
    };
    use crate::types::FilePath;

    #[test]
    fn test_parse_extensions() {
        let extensions = PacketExtensions::new();
        let options = ConnectionOptions::default();
        let (extensions, ..) =
            create_options(extensions, options, &create_config(), None, 8, OsRng).unwrap();
        assert_eq!(extensions.len(), 0);

        let options = ConnectionOptions::default();
        let mut extensions = PacketExtensions::new();
        extensions.insert(Extension::BlockSize, "500".parse().unwrap());
        extensions.insert(Extension::TransferSize, "6".parse().unwrap());
        extensions.insert(Extension::Timeout, "7".parse().unwrap());
        extensions.insert(Extension::WindowSize, "8".parse().unwrap());
        let (extensions, options, _) =
            create_options(extensions, options, &create_config(), None, 8, OsRng).unwrap();
        assert_eq!(extensions.len(), 4, "{:?}", extensions);
        assert_eq!(options.window_size, 8);
        assert_eq!(options.block_size, 101);
        assert_eq!(options.file_size, Some(6));
        assert_eq!(options.retry_packet_after_timeout, Duration::from_secs(7));
    }

    #[test]
    fn test_parse_invalid_extensions() {
        let options = ConnectionOptions::default();
        let extensions = PacketExtensions::new();
        let (extensions, ..) =
            create_options(extensions, options, &create_config(), None, 8, OsRng).unwrap();
        assert_eq!(extensions.len(), 0);

        let options = ConnectionOptions::default();
        let mut extensions = PacketExtensions::new();
        extensions.insert(Extension::BlockSize, "1".parse().unwrap());
        extensions.insert(Extension::TransferSize, "a".parse().unwrap());
        extensions.insert(Extension::Timeout, "0".parse().unwrap());
        extensions.insert(Extension::WindowSize, "0".parse().unwrap());
        let (extensions, options, _) =
            create_options(extensions, options, &create_config(), None, 8, OsRng).unwrap();
        assert_eq!(extensions.len(), 0);
        assert_ne!(options.block_size, 1);
        assert_ne!(options.file_size, Some(0));
        assert_ne!(options.retry_packet_after_timeout, Duration::from_secs(0));
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_parse_extensions_encryption() {
        use chacha20poly1305::aead::OsRng;

        use crate::encryption::{
            decode_nonce, decode_private_key, EncryptionLevel, Encryptor, FinalizedKeys,
            InitialKeys,
        };

        let options = ConnectionOptions::default();
        let mut extensions = PacketExtensions::new();
        extensions.insert(
            Extension::PublicKey,
            "Yhk58FaJO5dnct6VgrfRXtjqd9m3h2JHrD/Jecov2wY="
                .parse()
                .unwrap(),
        );
        extensions.insert(
            Extension::Nonce,
            "Tw2EobyajLuhvFY9WNMfIFK7GGWqOCfI".parse().unwrap(),
        );

        extensions.insert(Extension::EncryptionLevel, "none".parse().unwrap());
        let (extensions, options, _) =
            create_options(extensions, options, &create_config(), None, 8, OsRng).unwrap();
        assert_eq!(extensions.len(), 3);
        assert_eq!(options.encryption_level, EncryptionLevel::None);
    }

    fn create_config() -> ServerConfig {
        let listen: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        #[cfg(not(feature = "std"))]
        let listen = std_to_socket_addr(listen);
        ServerConfig {
            listen,
            directory: FilePath::new(),
            allow_overwrite: false,
            max_queued_blocks_reader: 1,
            max_queued_blocks_writer: 1,
            request_timeout: Duration::from_secs(10),
            max_connections: 1,
            max_file_size: 1,
            max_block_size: 101,
            authorized_keys: None,
            private_key: None,
            required_full_encryption: false,
            require_server_port_change: false,
            max_window_size: 8,
        }
    }

    #[cfg(not(feature = "std"))]
    fn std_to_socket_addr(addr: std::net::SocketAddr) -> crate::std_compat::net::SocketAddr {
        match addr {
            std::net::SocketAddr::V4(a) => crate::std_compat::net::SocketAddr {
                ip: crate::std_compat::net::IpVersion::Ipv4(a.ip().octets()),
                port: a.port(),
            },
            std::net::SocketAddr::V6(a) => crate::std_compat::net::SocketAddr {
                ip: crate::std_compat::net::IpVersion::Ipv6(a.ip().octets()),
                port: a.port(),
            },
        }
    }
}
