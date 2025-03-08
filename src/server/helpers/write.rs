use log::debug;
use log::error;
use log::info;
use log::trace;
use rand::CryptoRng;
use rand::RngCore;

use crate::error::StorageError;
use crate::packet::AckPacket;
use crate::packet::ByteConverter;
use crate::packet::ErrorCode;
use crate::packet::ErrorPacket;
use crate::packet::Packet;
use crate::packet::PacketType;
use crate::server::connection::Connection;
use crate::server::validation::handle_file_size;
use crate::socket::BoundSocket;
use crate::string::format_str;
use crate::time::InstantCallback;
use crate::types::DataBuffer;
use crate::writers::block_writer::BlockWriter;

pub fn handle_write<W: BlockWriter, B: BoundSocket, Rng: CryptoRng + RngCore + Copy>(
    connection: &mut Connection<B, Rng>,
    block_writer: &mut W,
    receive_buffer: &mut DataBuffer,
    send_buffer: &mut DataBuffer,
    instant: InstantCallback,
    max_file_size: u64,
) -> Option<()> {
    if !connection.decrypt_packet(receive_buffer) {
        return None;
    }

    let packet_type = PacketType::from_bytes(receive_buffer);
    if !matches!(
        packet_type,
        Ok(PacketType::Data | PacketType::Ack | PacketType::Error)
    ) {
        debug!(
            "Incorrect packet type received from {} {} {:x?}",
            connection.endpoint,
            receive_buffer.len(),
            receive_buffer,
        );
        return None;
    }

    #[allow(unused_mut)]
    let mut write_elapsed = instant();

    let result = match Packet::from_bytes(receive_buffer) {
        Ok(Packet::Data(p)) => {
            let data_length = p.data.len();

            debug!(
                "Packet received block {} size {} total {} from {}",
                p.block, data_length, connection.transfer, connection.endpoint
            );

            write_block(block_writer, p.block, p.data)
        }
        Ok(Packet::Ack(_)) => {
            return None;
        }
        Ok(Packet::Error(p)) => {
            error!("Error received {:?} {}", p.code, p.message);
            connection.invalid = instant().into();
            return None;
        }
        _ => {
            debug!(
                "Incorrect packet received from {} {:x?}",
                connection.endpoint, receive_buffer
            );
            return None;
        }
    };

    match result {
        Ok((written, index, block)) => {
            if let Some(w) = written {
                if let Err(e) = handle_file_size((connection.transfer + w) as u64, max_file_size) {
                    connection.send_packet(Packet::Error(e), send_buffer);
                    connection.invalid = instant().into();
                    return None;
                }
            }

            trace!(
                "Block {} written in {}us",
                block,
                write_elapsed.elapsed().as_micros()
            );
            if connection.options.window_size <= 1
                || connection.last_acknowledged + connection.options.window_size as u64 == index
                || written.unwrap_or(0) < connection.options.block_size_with_encryption() as usize
            {
                if !connection.send_packet(Packet::Ack(AckPacket { block }), send_buffer) {
                    error!("Unable to ack block {}", block);
                } else {
                    connection.last_acknowledged = index;
                }
            }

            if let Some(w) = written {
                connection.last_updated = instant();
                connection.transfer += w;

                if w < connection.options.block_size_with_encryption() as usize {
                    info!(
                        "Client write {} finished with {} bytes",
                        connection.endpoint, connection.transfer
                    );
                    connection.finished = true;
                }
            }
        }
        Err(e) => {
            connection.send_packet(Packet::Error(e), send_buffer);
            connection.invalid = instant().into();
            return None;
        }
    }

    Some(())
}

fn write_block<W: BlockWriter>(
    block_writer: &mut W,
    mut block: u16,
    data: &[u8],
) -> Result<(Option<usize>, u64, u16), ErrorPacket> {
    let (written, index) = match block_writer.write_block(block, data) {
        Ok((w, i)) => {
            debug!("Write block {} written size {}", block, w);
            (Some(w), i)
        }
        Err(StorageError::ExpectedBlock(e)) => {
            debug!(
                "Received unexpected block {} expecting block after {}",
                block, e.current
            );
            block = e.current;
            (None, e.current_index)
        }
        Err(StorageError::AlreadyWritten(e)) => {
            debug!("Received block that was written before {}", block);
            block = e.current;
            (None, e.current_index)
        }
        Err(e) => {
            error!("Failed to write block {} {}", block, e);
            return Err(ErrorPacket::new(
                ErrorCode::AccessViolation,
                format_str!(DefaultString, "{}", e,),
            ));
        }
    };

    Ok((written, index, block))
}
