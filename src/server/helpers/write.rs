use log::debug;
use log::error;
use log::info;
use log::trace;

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

pub fn handle_write<W: BlockWriter, B: BoundSocket>(
    connection: &mut Connection<B>,
    block_writer: &mut W,
    buffer: &mut DataBuffer,
    instant: InstantCallback,
    max_file_size: u64,
) -> Option<()> {
    if !connection.decrypt_packet(buffer) {
        return None;
    }

    let packet_type = PacketType::from_bytes(buffer);
    if !matches!(
        packet_type,
        Ok(PacketType::Data | PacketType::Ack | PacketType::Error)
    ) {
        debug!(
            "Incorrect packet type received from {} {} {:x?}",
            connection.endpoint,
            buffer.len(),
            buffer,
        );
        return None;
    }

    match Packet::from_bytes(buffer) {
        Ok(Packet::Data(p)) => {
            let data_length = p.data.len();

            debug!(
                "Packet received block {} size {} total {} from {}",
                p.block, data_length, connection.transfer, connection.endpoint
            );

            #[allow(unused_mut)]
            let mut write_elapsed = instant();
            match write_block(connection, block_writer, p.block, p.data) {
                Ok(Some(n)) => {
                    connection.last_updated = instant();
                    connection.transfer += n;
                    trace!(
                        "Block {} written in {}us",
                        p.block,
                        write_elapsed.elapsed().as_micros()
                    );
                    if n < connection.options.block_size as usize {
                        info!(
                            "Client write {} finished with {} bytes",
                            connection.endpoint, connection.transfer
                        );
                        connection.finished = true;
                    }
                }
                Ok(_) => return None,
                Err(e) => {
                    connection.send_packet(Packet::Error(e));
                    connection.invalid = true;
                    return None;
                }
            }

            // this would write more than expected but only by a block size maximum
            if let Err(e) = handle_file_size(connection.transfer as u64, max_file_size) {
                connection.send_packet(Packet::Error(e));
                connection.invalid = true;
                return None;
            }
        }
        Ok(Packet::Ack(_)) => {
            return None;
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

fn write_block<W: BlockWriter, B>(
    connection: &mut Connection<B>,
    block_writer: &mut W,
    mut block: u16,
    data: &[u8],
) -> Result<Option<usize>, ErrorPacket>
where
    B: BoundSocket,
{
    let (written, index) = match block_writer.write_block(block, data) {
        Ok((w, i)) => {
            debug!("Write block {} written size {}", block, w);
            (Some(w), i)
        }
        Err(StorageError::ExpectedBlock {
            expected,
            current,
            current_index,
        }) => {
            debug!("Received unexpected block {} expecting {}", block, expected);
            block = current;
            (None, current_index)
        }
        Err(StorageError::AlreadyWriten(current_index)) => {
            debug!("Received block that was written before {}", block);
            (None, current_index)
        }
        Err(e) => {
            error!("Failed to write block {} {}", block, e);
            return Err(ErrorPacket::new(
                ErrorCode::AccessVioliation,
                format_str!(DefaultString, "{}", e),
            ));
        }
    };

    if connection.options.window_size <= 1
        || connection.last_acknoledged + connection.options.window_size as u64 == index
        || written.unwrap_or(0) < connection.options.block_size as usize
    {
        if !connection.send_packet(Packet::Ack(AckPacket { block })) {
            error!("Unable to ack block {}", block);
        } else {
            connection.last_acknoledged = index;
        }
    }
    Ok(written)
}
