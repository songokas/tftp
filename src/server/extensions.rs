use core::time::Duration;

use log::*;
use rand::CryptoRng;
use rand::RngCore;

use super::config::ServerConfig;
use crate::config::ConnectionOptions;
use crate::config::EXTENSION_BLOCK_SIZE_MIN;
use crate::config::EXTENSION_TIMEOUT_SIZE_MIN;
use crate::config::EXTENSION_WINDOW_SIZE_MIN;
use crate::error::ExtensionError;
use crate::macros::cfg_encryption;
use crate::packet::Extension;
use crate::packet::PacketExtensions;
use crate::server::helpers::connection::SessionKeys;
use crate::string::format_str;

cfg_encryption!(
    use ed25519_dalek::ed25519::signature::SignerMut;
    use ed25519_dalek::Signature;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::Verifier;
    use ed25519_dalek::VerifyingKey;
    use crate::encryption::*;
);

#[allow(unused_variables)]
pub fn parse_extensions<R: CryptoRng + RngCore + Copy>(
    client_extensions: PacketExtensions,
    mut options: ConnectionOptions,
    config: &ServerConfig,
    max_window_size: u16,
    rng: R,
) -> Result<(PacketExtensions, ConnectionOptions, Option<SessionKeys>), ExtensionError> {
    let mut used_extensions = PacketExtensions::new();
    if let Some(size) = client_extensions.get(&Extension::BlockSize) {
        let client_block_size: u16 = size.parse().unwrap_or(0);
        if (EXTENSION_BLOCK_SIZE_MIN..=config.max_block_size).contains(&client_block_size) {
            options.block_size = client_block_size;
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
    #[cfg(feature = "encryption")]
    {
        let client_encryption_level = client_extensions
            .get(&Extension::EncryptionLevel)
            .map(|s| s.parse())
            .transpose()?;

        let client_encryption_level_with_default =
            client_encryption_level.unwrap_or(EncryptionLevel::None);

        if config.require_full_encryption && options.encryption_level != EncryptionLevel::Full {
            debug!(
                "Server requires full encryption however client_encryption_level={}",
                client_encryption_level_with_default
            );
            return Err(ExtensionError::ServerRequiredEncryption(
                EncryptionLevel::Full,
            ));
        }

        options.encryption_level = match client_encryption_level_with_default {
            EncryptionLevel::Full => {
                // full encryption level required but not fully encrypted
                if options.encryption_level != EncryptionLevel::Full {
                    return Err(ExtensionError::InvalidExtension(Extension::EncryptionLevel));
                }
                EncryptionLevel::Full
            }
            EncryptionLevel::Data | EncryptionLevel::OptionalData => EncryptionLevel::Data,
            EncryptionLevel::Protocol | EncryptionLevel::OptionalProtocol => {
                EncryptionLevel::Protocol
            }
            EncryptionLevel::None => {
                if config.authorized_keys.is_none() {
                    return Ok((used_extensions, options, None));
                } else {
                    return Err(ExtensionError::ServerRequiredEncryption(
                        EncryptionLevel::Data,
                    ));
                }
            }
        };

        if client_encryption_level.is_some() {
            let _ = used_extensions.insert(
                Extension::EncryptionLevel,
                format_str!(ExtensionValue, "{}", options.encryption_level),
            );
        }

        let Some(remote_session_public_key) = client_extensions
            .get(&Extension::SessionPublicKey)
            .map(|p| decode_public_key(p.as_bytes()))
            .transpose()?
        else {
            debug!("Invalid session key provided",);
            return Err(ExtensionError::InvalidPublicKey);
        };

        let remote_auth_public_key = client_extensions
            .get(&Extension::AuthPublicKey)
            .map(|p| decode_verifying_key(p.as_bytes()))
            .transpose()?;

        if let Some(auth_public_key) = remote_auth_public_key {
            let Some(signature) = client_extensions
                .get(&Extension::Signature)
                .map(|p| decode_signature(p.as_bytes()))
                .transpose()?
            else {
                debug!("Invalid signature received",);
                return Err(ExtensionError::InvalidSignature);
            };
            let verifying_key = match VerifyingKey::from_bytes(auth_public_key.as_bytes()) {
                Ok(k) => k,
                Err(e) => {
                    debug!("Invalid authorization key provided");
                    return Err(ExtensionError::InvalidSignature);
                }
            };
            if let Err(e) = verifying_key.verify(remote_session_public_key.as_bytes(), &signature) {
                debug!("Unable to verify error={e}",);
                return Err(ExtensionError::InvalidSignature);
            }
        }
        if let Some(authorized_keys) = &config.authorized_keys {
            let Some(p) = remote_auth_public_key else {
                debug!("Received new connection options however public key is missing",);
                return Err(ExtensionError::InvalidPublicKey);
            };
            if !authorized_keys.contains(&p) {
                debug!("Received new connection options however public key was not authorized",);
                return Err(ExtensionError::NotAuthorized);
            }
        }

        let server_keys = create_initial_keys(config.private_key.as_ref(), rng);

        let value = encode_public_key(&server_keys.session.public_key).expect("invalid key");
        let _ = used_extensions.insert(Extension::SessionPublicKey, value);

        if let Some(auth) = &server_keys.auth {
            if remote_auth_public_key.is_some() {
                let value = encode_verifying_key(&auth.public_key).expect("invalid key");
                let _ = used_extensions.insert(Extension::AuthPublicKey, value);
                let mut signing_key = SigningKey::from_bytes(auth.private_key.as_bytes());
                let signature: Signature =
                    signing_key.sign(server_keys.session.public_key.as_bytes());
                let value = encode_signature(&signature).expect("invalid key");
                let _ = used_extensions.insert(Extension::Signature, value);
            }
        }
        Ok((
            used_extensions,
            options,
            SessionKeys {
                server_keys,
                remote_session_public_key,
            }
            .into(),
        ))
    }
    #[cfg(not(feature = "encryption"))]
    Ok((used_extensions, options, None))
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    #[allow(unused_imports)]
    use crate::encryption::*;
    use crate::types::FilePath;

    #[test]
    fn test_parse_extensions() {
        let extensions = PacketExtensions::new();
        let options = ConnectionOptions::default();
        let (extensions, ..) =
            parse_extensions(extensions, options, &create_config(), 8, OsRng).unwrap();
        assert_eq!(extensions.len(), 0);

        let options = ConnectionOptions::default();
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(Extension::BlockSize, "512".parse().unwrap());
        let _ = extensions.insert(Extension::TransferSize, "6".parse().unwrap());
        let _ = extensions.insert(Extension::Timeout, "7".parse().unwrap());
        let _ = extensions.insert(Extension::WindowSize, "8".parse().unwrap());
        let (extensions, options, ..) =
            parse_extensions(extensions, options, &create_config(), 8, OsRng).unwrap();
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
        let (extensions, ..) =
            parse_extensions(extensions, options, &create_config(), 8, OsRng).unwrap();
        assert_eq!(extensions.len(), 0);

        let options = ConnectionOptions::default();
        let mut extensions = PacketExtensions::new();
        let _ = extensions.insert(Extension::BlockSize, "1".parse().unwrap());
        let _ = extensions.insert(Extension::TransferSize, "a".parse().unwrap());
        let _ = extensions.insert(Extension::Timeout, "0".parse().unwrap());
        let _ = extensions.insert(Extension::WindowSize, "0".parse().unwrap());
        let (extensions, options, ..) =
            parse_extensions(extensions, options, &create_config(), 8, OsRng).unwrap();
        assert_eq!(extensions.len(), 0);
        assert_ne!(options.block_size, 1);
        assert_ne!(options.file_size, Some(0));
        assert_ne!(options.retry_packet_after_timeout, Duration::from_secs(0));
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
        let (extensions, options, ..) =
            parse_extensions(extensions, options, &create_config(), 8, OsRng).unwrap();
        assert_eq!(extensions.len(), 0, "{extensions:?}");
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
