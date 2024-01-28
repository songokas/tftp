use core::num::NonZeroU16;

use log::debug;
use log::error;
use log::info;
use rand::CryptoRng;
use rand::RngCore;

use crate::buffer::resize_buffer;
use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::error::StorageError;
use crate::packet::prepend_data_header;
use crate::packet::ByteConverter;
use crate::packet::ErrorCode;
use crate::packet::ErrorPacket;
use crate::packet::Packet;
use crate::packet::PacketType;
use crate::readers::block_reader::BlockReader;
use crate::server::connection::Connection;
use crate::socket::BoundSocket;
use crate::string::format_str;
use crate::time::InstantCallback;
use crate::types::DataBuffer;

pub fn send_data_block<R: BlockReader, B: BoundSocket, Rng: CryptoRng + RngCore + Copy>(
    connection: &mut Connection<B, Rng>,
    block_reader: &mut R,
    buffer: &mut DataBuffer,
) -> bool {
    let retry = connection.last_updated.elapsed()
        > connection
            .options
            .retry_packet_after_timeout
            .mul_f32(connection.retry_packet_multiplier.get() as f32);
    // ensure min buffer size
    let expected_min_buffer_size =
        DATA_PACKET_HEADER_SIZE as usize + connection.options.block_size as usize;
    if buffer.len() < expected_min_buffer_size {
        resize_buffer(buffer, expected_min_buffer_size);
    }

    let packet_block = match block_reader.next(&mut buffer[DATA_PACKET_HEADER_SIZE.into()..], retry)
    {
        Ok(Some(b)) => b,
        Ok(None) => return false,
        Err(e) => {
            error!("Failed to read {} from {}", e, connection.endpoint);

            let error_packet = match e {
                StorageError::InvalidBuffer { .. } => ErrorPacket::new(
                    ErrorCode::Undefined,
                    format_str!(DefaultString, "{}", "Storage error occurred"),
                ),
                _ => ErrorPacket::new(
                    ErrorCode::AccessVioliation,
                    format_str!(DefaultString, "{}", e),
                ),
            };
            connection.send_packet(Packet::Error(error_packet), buffer);
            connection.invalid = true;
            return false;
        }
    };
    prepend_data_header(packet_block.block, buffer);
    buffer.truncate(DATA_PACKET_HEADER_SIZE as usize + packet_block.size);
    connection.send_bytes(PacketType::Data, buffer)
}

pub fn handle_read<R: BlockReader, B: BoundSocket, Rng: CryptoRng + RngCore + Copy>(
    connection: &mut Connection<B, Rng>,
    block_reader: &mut R,
    buffer: &mut DataBuffer,
    instant: InstantCallback,
) -> Option<()> {
    if !connection.decrypt_packet(buffer) {
        return None;
    }

    let packet_type = PacketType::from_bytes(buffer);
    if !matches!(packet_type, Ok(PacketType::Ack | PacketType::Error)) {
        debug!(
            "Incorrect packet type received from {} {:x?}",
            connection.endpoint, buffer,
        );
        return None;
    }

    match Packet::from_bytes(buffer) {
        Ok(Packet::Ack(p)) => {
            debug!("Ack received {} {}", p.block, connection.endpoint);

            let bytes_freed = block_reader.free_block(p.block);
            if bytes_freed > 0 {
                connection.last_updated = instant();
                connection.transfer += bytes_freed;
                connection.retry_packet_multiplier =
                    NonZeroU16::new(1).expect("Non zero multiplier");
            } else {
                connection.retry_packet_multiplier =
                    connection.retry_packet_multiplier.saturating_add(1);
            }
            if block_reader.is_finished() {
                info!(
                    "Client read {} finished with {} bytes",
                    connection.endpoint, connection.transfer
                );
                connection.finished = true;
                return None;
            }
        }
        Ok(Packet::Error(p)) => {
            error!("Error received {:?} {}", p.code, p.message);
            connection.invalid = true;
            return None;
        }
        _ => {
            debug!(
                "Incorrect packet received from {} {:x?}",
                connection.endpoint, buffer
            );
            return None;
        }
    };
    Some(())
}
