//! The encrypted parts of a client session. Built only with the `encryption`
//! feature: `features::no_client_session_encryption` has the same functions for
//! builds without it.

use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::Signature;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use log::*;

use crate::config::ConnectionOptions;
use crate::encryption::*;
use crate::error::ExtensionError;
use crate::packet::Extension;
use crate::packet::PacketExtensions;
use crate::packet::SignedRequest;
use crate::string::format_str;

pub fn add_extensions(
    options: &ConnectionOptions,
    initial_keys: Option<&InitialKeys>,
    request: SignedRequest,
    used_extensions: &mut PacketExtensions,
) {
    if options.encryption_level != EncryptionLevel::None {
        let keys = initial_keys.expect("initial keys must be provided");
        let value = encode_public_key(&keys.session.public_key).expect("invalid key");
        let _ = used_extensions.insert(Extension::SessionPublicKey, value);
        let level = format_str!(ExtensionValue, "{}", options.encryption_level);
        let message = signed_request_message(&keys.session.public_key, level.as_str(), request);
        let _ = used_extensions.insert(Extension::EncryptionLevel, level);
        if let Some(auth) = &keys.auth {
            let value = encode_verifying_key(&auth.public_key).expect("invalid key");
            let _ = used_extensions.insert(Extension::AuthPublicKey, value);
            let mut signing_key = SigningKey::from_bytes(auth.private_key.as_bytes());
            let signature: Signature = signing_key.sign(&message);

            let value = encode_signature(&signature).expect("invalid signature");
            let _ = used_extensions.insert(Extension::Signature, value);
        }
    }
}

/// Checks the server's reply against the requested encryption level.
pub fn parse_reply(
    server_extensions: &PacketExtensions,
    mut options: ConnectionOptions,
) -> Result<(ConnectionOptions, Option<PublicKeyPair>), ExtensionError> {
    if options.encryption_level != EncryptionLevel::None {
        let expected_encryption_level = options.encryption_level;

        let encryption_level = server_extensions
            .get(&Extension::EncryptionLevel)
            .map(|s| s.parse())
            .transpose()?;
        let server_encryption_level = encryption_level.unwrap_or(EncryptionLevel::None);

        if server_encryption_level == EncryptionLevel::None
            && matches!(
                expected_encryption_level,
                EncryptionLevel::OptionalData | EncryptionLevel::OptionalProtocol
            )
        {
            options.encryption_level = EncryptionLevel::None;
            return Ok((options, None));
        }

        // the level is not signed, so a reply must not be able to lower it
        if matches!(
            expected_encryption_level,
            EncryptionLevel::Data | EncryptionLevel::Protocol | EncryptionLevel::Full
        ) && encryption_level != Some(expected_encryption_level)
        {
            return Err(ExtensionError::ClientRequiredEncryption(
                options.encryption_level,
            ));
        }

        options.encryption_level =
            encryption_level.ok_or(ExtensionError::InvalidExtension(Extension::EncryptionLevel))?;

        if options.block_size <= options.encryption_overhead() {
            return Err(ExtensionError::InvalidExtension(Extension::BlockSize));
        }

        let remote_session_public_key = server_extensions
            .get(&Extension::SessionPublicKey)
            .map(|s| decode_public_key(s.as_bytes()))
            .transpose()?
            .ok_or(ExtensionError::InvalidExtension(
                Extension::SessionPublicKey,
            ))?;

        let remote_auth_public_key = server_extensions
            .get(&Extension::AuthPublicKey)
            .map(|s| decode_verifying_key(s.as_bytes()))
            .transpose()?;

        if let Some(auth_public_key) = remote_auth_public_key {
            let Some(signature) = server_extensions
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
                    debug!("Invalid authorization key provided {e}");
                    return Err(ExtensionError::InvalidSignature);
                }
            };
            if let Err(e) = verifying_key.verify(remote_session_public_key.as_bytes(), &signature) {
                debug!("Unable to verify error={e}",);
                return Err(ExtensionError::InvalidSignature);
            }
        }

        return Ok((
            options,
            PublicKeyPair {
                auth: remote_auth_public_key,
                session: remote_session_public_key,
            }
            .into(),
        ));
    }
    Ok((options, None))
}
