use crate::error::StorageError;

pub trait BlockWriter {
    /// False for a retransmitted or out of order block, which `write_block` skips.
    fn is_next_block(&mut self, block: u16) -> bool;
    fn write_block(&mut self, block: u16, data: &[u8]) -> Result<(usize, u64), StorageError>;
}
