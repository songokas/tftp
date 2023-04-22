use core::time::Duration;

use log::{debug, error};

use crate::{
    config::{
        ConnectionOptions, DEFAULT_DATA_BLOCK_SIZE, DEFAULT_RETRY_PACKET_TIMEOUT,
        ENCRYPTION_TAG_SIZE, EXTENSION_BLOCK_SIZE_MIN, EXTENSION_TIMEOUT_SIZE_MAX,
        EXTENSION_TIMEOUT_SIZE_MIN, EXTENSION_WINDOW_SIZE_MIN,
    },
    encryption::*,
    error::ExtensionError,
    packet::{ErrorCode, ErrorPacket, Extension, PacketExtensions},
    string::format_str,
    types::DefaultString,
};

pub fn validate_extensions(
    extensions: &PacketExtensions,
    used_extensions: &PacketExtensions,
) -> Result<(), ErrorPacket> {
    #[allow(unused_must_use)]
    let remaining = extensions
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
        extensions.insert(
            Extension::BlockSize,
            format_str!(ExtensionValue, "{}", options.block_size as u64),
        );
    }

    if options.retry_packet_after_timeout != DEFAULT_RETRY_PACKET_TIMEOUT
        && options.retry_packet_after_timeout.as_secs() >= EXTENSION_TIMEOUT_SIZE_MIN as u64
    {
        extensions.insert(
            Extension::Timeout,
            format_str!(
                ExtensionValue,
                "{}",
                options.retry_packet_after_timeout.as_secs()
            ),
        );
    }

    if let Some(file_size) = options.file_size {
        extensions.insert(
            Extension::TransferSize,
            format_str!(ExtensionValue, "{}", file_size),
        );
    }

    if options.window_size != EXTENSION_WINDOW_SIZE_MIN {
        extensions.insert(
            Extension::WindowSize,
            format_str!(ExtensionValue, "{}", options.window_size),
        );
    }

    #[cfg(feature = "encryption")]
    if options.encryption_level != EncryptionLevel::None {
        match (&options.encryption_keys, options.encryption_level) {
            (Some(EncryptionKeys::ClientKey(s)), l) => {
                let value = encode_public_key(s).expect("invalid key");
                extensions.insert(Extension::PublicKey, value);
                extensions.insert(Extension::Nonce, "0".parse().expect("convert to string"));
                extensions.insert(
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
                extensions.insert(Extension::PublicKey, value);
                extensions.insert(Extension::Nonce, "0".parse().expect("convert to string"));
                extensions.insert(
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
    mut extensions: PacketExtensions,
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
        if options.file_size.is_none() {
            options.file_size = Some(server_file_size);
        } else if options.file_size > Some(0) && options.file_size != Some(server_file_size) {
            return Err(ExtensionError::InvalidExtension(Extension::TransferSize));
        }
    }

    #[cfg(feature = "encryption")]
    if options.encryption_level != EncryptionLevel::Full {
        let _expected_encryption_level = options.encryption_level;
        if let (Some(pkey), Some(nonce), Some(Ok(level))) = (
            extensions.get(&Extension::PublicKey),
            extensions.get(&Extension::Nonce),
            extensions
                .get(&Extension::EncryptionLevel)
                .map(|s| s.parse()),
        ) {
            match &options.encryption_keys {
                Some(EncryptionKeys::ClientKey(_)) => {
                    let remote_public_key = decode_public_key(pkey.as_bytes())?;
                    let remote_nonce = decode_nonce(nonce.as_bytes())?;
                    options.encryption_keys =
                        Some(EncryptionKeys::ServerKey(remote_public_key, remote_nonce));
                    options.encryption_level = level;
                }
                Some(EncryptionKeys::LocalToRemote(l, r)) => {
                    let remote_public_key = decode_public_key(pkey.as_bytes())?;
                    if r.as_bytes() != remote_public_key.as_bytes() {
                        return Err(ExtensionError::InvalidExtension(Extension::PublicKey));
                    }
                    let remote_nonce = decode_nonce(nonce.as_bytes())?;
                    options.encryption_keys =
                        Some(EncryptionKeys::ServerKey(remote_public_key, remote_nonce));
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
