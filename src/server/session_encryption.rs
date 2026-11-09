//! The encrypted parts of a server session. Built only with the `encryption`
//! feature: `features::no_server_session_encryption` has the same functions for
//! builds without it.

use core::net::SocketAddr;

use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::Signature;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;
use log::*;
use rand::CryptoRng;
use rand::RngCore;

use crate::config::ConnectionOptions;
use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::config::EXTENSION_BLOCK_SIZE_MIN;
use crate::config::MIN_ENCRYPTION_SIZE;
use crate::encrypted_packet::EncryptedDataPacket;
use crate::encrypted_packet::EncryptedPacket;
use crate::encrypted_packet::InitialPacket;
use crate::encryption::*;
use crate::error::DefaultBoxedResult;
use crate::error::ExtensionError;
use crate::packet::ByteConverter;
use crate::packet::Extension;
use crate::packet::Packet;
use crate::packet::PacketExtensions;
use crate::packet::PacketType;
use crate::packet::SignedRequest;
use crate::server::connection::Connection;
use crate::server::helpers::connection::SessionKeys;
use crate::server::ServerConfig;
use crate::string::format_str;
use crate::types::DataBuffer;

pub fn decrypt_packet<Rng: CryptoRng + RngCore + Clone>(
    options: &ConnectionOptions,
    encryptor: &Option<Encryptor<Rng>>,
    endpoint: SocketAddr,
    buffer: &mut DataBuffer,
) -> bool {
    if let (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) =
        (options.encryption_level, encryptor)
    {
        if EncryptedPacket::decrypt(encryptor, buffer).is_err() {
            debug!(
                "Failed to decrypt packet from {} {} {:?}",
                endpoint,
                buffer.len(),
                buffer
            );
            return false;
        }
    }

    if let (Ok(PacketType::Data), EncryptionLevel::Data, Some(encryptor)) = (
        PacketType::from_bytes(buffer),
        options.encryption_level,
        encryptor,
    ) {
        if EncryptedDataPacket::decrypt(encryptor, buffer).is_err() {
            debug!(
                "Failed to decrypt data from {} {} {:x?}",
                endpoint,
                buffer.len(),
                buffer
            );
            return false;
        }
    }

    true
}

pub fn encrypt_packet<Rng: CryptoRng + RngCore + Clone>(
    options: &ConnectionOptions,
    encryptor: &Option<Encryptor<Rng>>,
    packet_name: PacketType,
    data: &mut DataBuffer,
) -> bool {
    if let (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) =
        (options.encryption_level, encryptor)
    {
        if EncryptedPacket::encrypt(
            encryptor,
            data,
            options.block_size_with_encryption() + DATA_PACKET_HEADER_SIZE as u16,
        )
        .is_err()
        {
            error!("Failed to encrypt data {:x?}", data);
            return false;
        }
    }
    if let (EncryptionLevel::Data, Some(encryptor), PacketType::Data) =
        (options.encryption_level, encryptor, packet_name)
    {
        if EncryptedDataPacket::encrypt(encryptor, data).is_err() {
            error!("Failed to encrypt data {:x?}", data);
            return false;
        }
    }
    true
}

/// An ordinary request needs no key exchange to find out it is not encrypted.
fn is_plain_request(buffer: &DataBuffer) -> bool {
    matches!(
        Packet::from_bytes(buffer),
        Ok(Packet::Read(_) | Packet::Write(_))
    )
}

/// Decrypts a handshake addressed to the server's key in place. Returns its
/// encryptor, or `None` if the packet is not encrypted for this server.
pub fn open_initial_packet<Rng: CryptoRng + RngCore + Copy>(
    config: &ServerConfig,
    buffer: &mut DataBuffer,
    rng: Rng,
) -> Option<Encryptor<Rng>> {
    if is_plain_request(buffer) {
        return None;
    }
    let Some(private_key) = config.private_key.clone() else {
        trace!("Ignoring encryption for initial packet: no private key set");
        return None;
    };
    let Ok(packet) = InitialPacket::from_bytes(buffer) else {
        trace!("Ignoring encryption for initial packet: invalid format");
        return None;
    };

    let remote_handshake_public_key = packet.session_public_key;

    let auth_keys = create_auth_keys(private_key);
    let server_key = PublicKey::from(auth_keys.public_key.to_montgomery().to_bytes());
    let context = handshake_context(&remote_handshake_public_key, &server_key);
    let Ok((encryptor, _public_key)) =
        auth_keys.finalize(&remote_handshake_public_key, rng, Role::Server, context)
    else {
        trace!("Ignoring encryption for initial packet: low order key");
        return None;
    };
    let Ok(data) = packet.decrypt(&encryptor) else {
        trace!("Ignoring encryption for initial packet: failed to decrypt");
        return None;
    };
    *buffer = data;
    Some(encryptor)
}

pub fn encrypted_error_bytes<Rng: CryptoRng + RngCore + Clone>(
    packet: Packet,
    encryptor: Option<&Encryptor<Rng>>,
    expected_block_size: u16,
) -> Option<DataBuffer> {
    if let Some(encryptor) = encryptor {
        let mut buffer = packet.to_bytes();
        if let Err(e) = EncryptedPacket::encrypt(encryptor, &mut buffer, expected_block_size) {
            warn!("Failed to encrypt error packet {e}");
            return None;
        }
        Some(buffer)
    } else {
        Some(packet.to_bytes())
    }
}

pub fn min_block_size(client_extensions: &PacketExtensions) -> u16 {
    if client_extensions
        .get(&Extension::EncryptionLevel)
        .and_then(|s| s.parse().ok())
        .map(|e: EncryptionLevel| e != EncryptionLevel::None)
        == Some(true)
    {
        // leaves room for at least one byte of payload
        MIN_ENCRYPTION_SIZE as u16 + 1
    } else {
        EXTENSION_BLOCK_SIZE_MIN
    }
}

/// Agrees on the encryption level with the client and authorizes it.
pub fn negotiate<R: CryptoRng + RngCore + Copy>(
    client_extensions: &PacketExtensions,
    request: SignedRequest,
    mut options: ConnectionOptions,
    config: &ServerConfig,
    mut used_extensions: PacketExtensions,
    rng: R,
) -> Result<(PacketExtensions, ConnectionOptions, Option<SessionKeys<R>>), ExtensionError> {
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
        EncryptionLevel::Protocol | EncryptionLevel::OptionalProtocol => EncryptionLevel::Protocol,
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
            Err(_) => {
                debug!("Invalid authorization key provided");
                return Err(ExtensionError::InvalidSignature);
            }
        };
        let signed_level = client_extensions
            .get(&Extension::EncryptionLevel)
            .map_or("", |level| level.as_str());
        let message = signed_request_message(&remote_session_public_key, signed_level, request);
        if let Err(e) = verifying_key.verify(&message, &signature) {
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

    let InitialKeys {
        session: server_session,
        auth: server_auth,
    } = create_initial_keys(config.private_key.as_ref(), rng);
    let server_session_public_key = server_session.public_key;

    let context = SessionParameters {
        request,
        encryption_level: options.encryption_level,
        block_size: options.block_size,
        window_size: options.window_size,
        client_session_key: &remote_session_public_key,
        server_session_key: &server_session_public_key,
    }
    .context();
    // done here so that a bad key is refused before the request opens any file
    let (encryptor, _) = server_session
        .finalize(&remote_session_public_key, rng, Role::Server, context)
        .map_err(|e| {
            debug!("Invalid session key provided {e}");
            ExtensionError::InvalidPublicKey
        })?;

    let value = encode_public_key(&server_session_public_key).expect("invalid key");
    let _ = used_extensions.insert(Extension::SessionPublicKey, value);

    if let Some(auth) = &server_auth {
        if remote_auth_public_key.is_some() {
            let value = encode_verifying_key(&auth.public_key).expect("invalid key");
            let _ = used_extensions.insert(Extension::AuthPublicKey, value);
            let mut signing_key = SigningKey::from_bytes(auth.private_key.as_bytes());
            let signature: Signature = signing_key.sign(server_session_public_key.as_bytes());
            let value = encode_signature(&signature).expect("invalid key");
            let _ = used_extensions.insert(Extension::Signature, value);
        }
    }
    Ok((used_extensions, options, SessionKeys { encryptor }.into()))
}

pub fn start_session<B, Rng>(
    connection: &mut Connection<B, Rng>,
    session_keys: Option<SessionKeys<Rng>>,
) {
    if let Some(keys) = session_keys {
        connection.encryptor = keys.encryptor.into();
    }
}

pub fn log_server_public_key(config: &ServerConfig) -> DefaultBoxedResult {
    if let Some(private_key) = config.private_key.as_ref() {
        info!(
            "Server public key {}",
            encode_verifying_key(&VerifyingKey::from(private_key))?
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer(bytes: &[u8]) -> DataBuffer {
        let mut buffer = DataBuffer::new();
        let _ = crate::buffer::extend_from_slice(&mut buffer, bytes, ());
        buffer
    }

    #[test]
    fn test_plain_requests_skip_the_key_exchange() {
        assert!(is_plain_request(&buffer(b"\0\x01file\0octet\0")));
        assert!(is_plain_request(&buffer(b"\0\x02file\0octet\0")));
    }

    #[test]
    fn test_other_datagrams_may_be_encrypted_requests() {
        assert!(!is_plain_request(&buffer(&[0x7f; 120])));
        assert!(!is_plain_request(&buffer(b"\0\x04\0\x01")));
    }
}
