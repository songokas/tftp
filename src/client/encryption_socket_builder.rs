use log::info;
use rand::CryptoRng;
use rand::RngCore;

use super::encryption_socket::EncryptionBoundSocket;
use super::ClientConfig;
use crate::config::ConnectionOptions;
use crate::encryption::encode_public_key;
use crate::encryption::EncryptionKeys;
use crate::encryption::EncryptionLevel;
use crate::encryption::InitialKeyPair;
use crate::error::BoxedResult;
use crate::key_management::create_finalized_keys;
use crate::key_management::create_initial_keys;
use crate::socket::Socket;

pub fn create_initial_socket<Rng: CryptoRng + RngCore + Copy>(
    socket: impl Socket,
    config: &ClientConfig,
    options: &mut ConnectionOptions,
    rng: Rng,
) -> BoxedResult<(
    EncryptionBoundSocket<impl Socket, Rng>,
    Option<InitialKeyPair>,
)> {
    if options.encryption_level == EncryptionLevel::None {
        return Ok((
            EncryptionBoundSocket::wrap(socket, options.block_size),
            None,
        ));
    }

    if let Some(p) = config.remote_public_key {
        let keys = create_finalized_keys(&config.private_key, &p, rng);
        options.encryption_keys = Some(EncryptionKeys::LocalToRemote(keys.public, p));
        if options.encryption_level == EncryptionLevel::Protocol {
            options.encryption_level = EncryptionLevel::Full;
        }
        info!("Client public key {}", encode_public_key(&keys.public)?);
        let socket = EncryptionBoundSocket::new(
            socket,
            Some(keys.encryptor),
            keys.public,
            options.encryption_level,
            options.block_size,
        );
        return Ok((socket, None));
    }
    let initial_keys = create_initial_keys(&config.private_key, rng);
    info!(
        "Client public key {}",
        encode_public_key(&initial_keys.public)?
    );
    options.encryption_keys = Some(EncryptionKeys::ClientKey(initial_keys.public));
    Ok((
        EncryptionBoundSocket::wrap(socket, options.block_size),
        initial_keys.into(),
    ))
}

pub fn configure_socket<Rng: CryptoRng + RngCore + Copy>(
    mut socket: EncryptionBoundSocket<impl Socket, Rng>,
    initial_keys: Option<InitialKeyPair>,
    mut options: ConnectionOptions,
    rng: Rng,
) -> (impl Socket, ConnectionOptions) {
    let (mut socket, options) = match (
        options.encryption_level,
        initial_keys,
        options.encryption_keys,
    ) {
        (
            EncryptionLevel::Protocol | EncryptionLevel::Data,
            Some(keys),
            Some(EncryptionKeys::ServerKey(p)),
        ) => {
            let final_keys = keys.finalize(&p, rng);
            options.encryption_keys = Some(EncryptionKeys::LocalToRemote(final_keys.public, p));
            socket.connection_encryptor = Some(final_keys.encryptor);
            socket.public_key = final_keys.public.into();
            socket.encryption_level = options.encryption_level;
            (socket, options)
        }
        (
            EncryptionLevel::Protocol | EncryptionLevel::Data,
            None,
            Some(EncryptionKeys::ServerKey(p)),
        ) => {
            if let Some(public_key) = socket.public_key {
                options.encryption_keys = Some(EncryptionKeys::LocalToRemote(public_key, p));
            } else {
                options.encryption_keys = None;
            }
            socket.encryption_level = options.encryption_level;
            (socket, options)
        }
        (_, _, keys) => {
            options.encryption_keys = keys;
            (socket, options)
        }
    };
    socket.block_size = options.block_size_with_encryption();

    (socket, options)
}
