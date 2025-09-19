use core::time::Duration;

use log::debug;
use log::warn;
use rand::CryptoRng;
use rand::RngCore;

use crate::config::print_options;
use crate::encryption::*;
use crate::error::ExtensionError;
use crate::packet::AckPacket;
use crate::packet::ByteConverter;
use crate::packet::ErrorCode;
use crate::packet::ErrorPacket;
use crate::packet::OptionalAck;
use crate::packet::Packet;
use crate::packet::PacketExtensions;
use crate::server::config::ServerConfig;
use crate::server::connection::Connection;
use crate::server::connection::ConnectionType;
use crate::server::connection_builder::ConnectionBuilder;
use crate::socket::BoundSocket;
use crate::string::format_str;
use crate::types::DataBuffer;
use core::net::SocketAddr;

#[allow(dead_code)]
pub struct SessionKeys {
    pub server_keys: InitialKeys,
    pub remote_session_public_key: PublicKey,
}

pub fn handle_packet<'a, Rng>(
    builder: &mut ConnectionBuilder<'a, Rng>,
    config: &'a ServerConfig,
    buffer: &mut DataBuffer,
    from_client: SocketAddr,
    rng: Rng,
) -> Result<Option<ConnectionType>, ExtensionError>
where
    Rng: CryptoRng + RngCore + Copy,
{
    Ok(match Packet::from_bytes(buffer) {
        Ok(Packet::Write(p)) => {
            debug!(
                "New client {from_client} writing to file {} in directory {}",
                p.file_name, config.directory
            );

            builder.with_request(p, config.max_window_size, rng)?;
            Some(ConnectionType::Write)
        }
        Ok(Packet::Read(p)) => {
            debug!(
                "New client {from_client} reading file {} in directory {}",
                p.file_name, config.directory
            );
            builder.with_request(p, config.max_window_size, rng)?;
            Some(ConnectionType::Read)
        }
        _ => {
            debug!("Incorrect packet received {:x?}", buffer);
            None
        }
    })
}

pub fn accept_connection<B: BoundSocket, Rng: CryptoRng + RngCore + Copy>(
    connection: &mut Connection<B, Rng>,
    connection_type: ConnectionType,
    used_extensions: PacketExtensions,
    buffer: &mut DataBuffer,
    _session_keys: Option<SessionKeys>,
    _rng: Rng,
) -> Option<()> {
    debug!("Server extensions {:?}", used_extensions);

    match connection_type {
        ConnectionType::Write => {
            if !used_extensions.is_empty() {
                if !connection.send_packet(
                    Packet::OptionalAck(OptionalAck {
                        extensions: used_extensions,
                    }),
                    buffer,
                ) {
                    return None;
                }
            } else if !connection.send_packet(Packet::Ack(AckPacket { block: 0 }), buffer) {
                return None;
            }
            // new encryption starts only here
            #[cfg(feature = "encryption")]
            if let Some(keys) = _session_keys {
                let (encryptor, _) = keys
                    .server_keys
                    .session
                    .finalize(&keys.remote_session_public_key, _rng);
                connection.encryptor = encryptor.into();
            }

            print_options("Server writing using", &connection.options);

            Some(())
        }
        ConnectionType::Read => {
            if !used_extensions.is_empty()
                && !connection.send_packet(
                    Packet::OptionalAck(OptionalAck {
                        extensions: used_extensions,
                    }),
                    buffer,
                )
            {
                return None;
            }

            // new encryption starts only here
            #[cfg(feature = "encryption")]
            if let Some(keys) = _session_keys {
                let (encryptor, _) = keys
                    .server_keys
                    .session
                    .finalize(&keys.remote_session_public_key, _rng);
                connection.encryptor = encryptor.into();
            }

            print_options("Server reading using", &connection.options);

            Some(())
        }
    }
}

pub fn timeout_client<B: BoundSocket, Rng: CryptoRng + RngCore + Copy>(
    connection: &mut Connection<B, Rng>,
    request_timeout: Duration,
    buffer: &mut DataBuffer,
) -> bool {
    if connection.invalid.is_some() || connection.finished {
        return true;
    }
    if connection.last_updated.elapsed() <= request_timeout {
        return false;
    }

    warn!(
        "Client {} timeout {} {} bytes",
        connection.endpoint,
        connection.last_updated.elapsed().as_secs_f32(),
        connection.transfer,
    );

    let message = format_str!(
        DefaultString,
        "Client timeout {}",
        connection.last_updated.elapsed().as_secs_f32()
    );
    connection.send_packet(
        Packet::Error(ErrorPacket::new(ErrorCode::AccessViolation, message)),
        buffer,
    );
    true
}
