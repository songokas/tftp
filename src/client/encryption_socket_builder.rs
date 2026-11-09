use log::info;
use rand::CryptoRng;
use rand::RngCore;

use super::encryption_socket::EncryptionBoundSocket;
use super::ClientConfig;
use crate::config::ConnectionOptions;
use crate::encryption::create_encryptor_with_auth_keys;
use crate::encryption::create_initial_keys;
use crate::encryption::encode_verifying_key;
use crate::encryption::EncryptionLevel;
use crate::encryption::InitialKeys;
use crate::encryption::PublicKeyPair;
use crate::encryption::Role;
use crate::encryption::SessionParameters;
use crate::error::BoxedResult;
use crate::packet::SignedRequest;
use crate::socket::Socket;

pub fn create_initial_socket<Rng: CryptoRng + RngCore + Copy>(
    socket: impl Socket,
    config: &ClientConfig,
    options: &mut ConnectionOptions,
    rng: Rng,
) -> BoxedResult<(EncryptionBoundSocket<impl Socket, Rng>, Option<InitialKeys>)> {
    if options.encryption_level == EncryptionLevel::None {
        return Ok((
            EncryptionBoundSocket::wrap(socket, options.block_size),
            None,
        ));
    }

    let initial_keys = create_initial_keys(config.private_key.as_ref(), rng);

    let socket = if let Some(remote) = config.remote_public_key {
        // data level leaves the reply in plaintext, and without a private key
        // the server does not sign it, so the pinned key could not be checked
        if options.encryption_level == EncryptionLevel::Protocol
            || (options.encryption_level == EncryptionLevel::Data && config.private_key.is_none())
        {
            options.encryption_level = EncryptionLevel::Full;
        }
        // encryptor with server auth public key
        let (encryptor, public_key) = create_encryptor_with_auth_keys(rng, &remote)?;
        EncryptionBoundSocket::new(
            socket,
            Some(encryptor),
            public_key,
            options.encryption_level,
            options.block_size,
        )
    } else {
        EncryptionBoundSocket::wrap(socket, options.block_size)
    };
    if let Some(auth_key) = &initial_keys.auth {
        info!(
            "Client public key {}",
            encode_verifying_key(&auth_key.public_key)?
        );
    }
    Ok((socket, initial_keys.into()))
}

pub fn configure_socket<Rng: CryptoRng + RngCore + Copy>(
    mut socket: EncryptionBoundSocket<impl Socket, Rng>,
    initial_keys: Option<InitialKeys>,
    options: ConnectionOptions,
    rng: Rng,
    remote_public_key_pair: Option<&PublicKeyPair>,
    request: SignedRequest,
) -> BoxedResult<(impl Socket, ConnectionOptions)> {
    let (mut socket, options) = match (
        options.encryption_level,
        initial_keys,
        remote_public_key_pair,
    ) {
        (
            EncryptionLevel::Protocol | EncryptionLevel::Data | EncryptionLevel::Full,
            Some(keys),
            Some(remote_public_key_pair),
        ) => {
            let context = SessionParameters {
                request,
                encryption_level: options.encryption_level,
                block_size: options.block_size,
                window_size: options.window_size,
                client_session_key: &keys.session.public_key,
                server_session_key: &remote_public_key_pair.session,
            }
            .context();
            let (encryptor, public_key) = keys.session.finalize(
                &remote_public_key_pair.session,
                rng,
                Role::Client,
                context,
            )?;
            socket.connection_encryptor = encryptor.into();
            socket.public_key = public_key.into();
            socket.encryption_level = options.encryption_level;
            (socket, options)
        }
        _ => (socket, options),
    };

    socket.block_size = options.block_size_with_encryption();

    Ok((socket, options))
}
