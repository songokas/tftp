use core::mem;
use core::num::NonZeroU8;

use log::debug;
use log::error;
use log::info;
use rand::CryptoRng;
use rand::RngCore;

use crate::buffer::resize_buffer;
use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::error::StorageError;
use crate::flow_control::FLOW_CONTROL_PERIOD;
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
    instant: InstantCallback,
) -> bool {
    // Replenish send budget each period
    let elapsed = connection.rate_period.elapsed();
    if elapsed >= FLOW_CONTROL_PERIOD {
        connection.packets_to_send = connection
            .rate_control
            .packets_to_send(elapsed, connection.options.block_size);
        connection.rate_period = instant();
    }

    if connection.packets_to_send == 0 {
        return false;
    }

    let timeout = connection
        .options
        .retry_packet_after_timeout
        .mul_f32(connection.retry_packet_multiplier.get() as f32);
    let timeout_retry = connection
        .window_sent_at
        .as_ref()
        .is_some_and(|t| t.elapsed() > timeout);
    let fast_retransmit = mem::take(&mut connection.fast_retransmit);
    let retry = timeout_retry || fast_retransmit;
    if retry {
        debug!(
            "Retrying data elapsed {}ms timeout {}ms fast_retransmit={fast_retransmit}",
            connection.last_updated.elapsed().as_millis(),
            timeout.as_millis()
        );
        if timeout_retry {
            connection.retry_packet_multiplier =
                connection.retry_packet_multiplier.saturating_add(2);
        }
    }

    // ensure min buffer size
    let expected_min_buffer_size =
        DATA_PACKET_HEADER_SIZE as usize + connection.options.block_size as usize;
    if buffer.len() < expected_min_buffer_size {
        resize_buffer(buffer, expected_min_buffer_size);
    }

    let packet_block = match block_reader.next(&mut buffer[DATA_PACKET_HEADER_SIZE.into()..], retry)
    {
        Ok(Some(b)) => b,
        Ok(None) => {
            if connection.window_sent_at.is_none() {
                connection.window_sent_at = Some(instant());
            }
            return false;
        }
        Err(e) => {
            error!("Failed to read {} from {}", e, connection.endpoint);

            let error_packet = match e {
                StorageError::InvalidBuffer { .. } => ErrorPacket::new(
                    ErrorCode::Undefined,
                    format_str!(DefaultString, "Storage error occurred"),
                ),
                _ => ErrorPacket::new(
                    ErrorCode::AccessViolation,
                    format_str!(DefaultString, "{}", e,),
                ),
            };
            connection.send_packet(Packet::Error(error_packet), buffer);
            connection.invalid = instant().into();
            return false;
        }
    };

    if timeout_retry {
        connection.rate_control.on_loss(
            connection.options.block_size,
            packet_block.block,
            connection.options.window_size,
        );
    }

    prepend_data_header(packet_block.block, buffer);
    debug!(
        "Send data block {} size {}",
        packet_block.block,
        buffer.len()
    );
    buffer.truncate(DATA_PACKET_HEADER_SIZE as usize + packet_block.size);
    let sent = connection.send_bytes(PacketType::Data, buffer);
    if sent {
        connection.window_sent_at = None;
        connection.packets_to_send = connection.packets_to_send.saturating_sub(1);
        connection.rate_control.start_rtt(packet_block.block);
    }
    sent
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
                connection.window_sent_at = None;
                connection.transfer += bytes_freed;
                connection.retry_packet_multiplier =
                    if connection.retry_packet_multiplier.get() - 1 > 0 {
                        NonZeroU8::new(connection.retry_packet_multiplier.get() - 1)
                            .expect("non zero value")
                    } else {
                        NonZeroU8::new(1).expect("non zero integer")
                    };
                if let Some(_rtt) = connection.rate_control.end_rtt(p.block) {
                    connection
                        .rate_control
                        .on_rtt_complete(connection.options.block_size, p.block);
                }
            } else if connection.rate_control.on_dup_ack(
                p.block,
                connection.options.block_size,
                connection.options.window_size,
            ) {
                debug!(
                    "Fast retransmit triggered by 3 duplicate ACKs for block {}",
                    p.block
                );
                connection.fast_retransmit = true;
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
            connection.invalid = instant().into();
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
