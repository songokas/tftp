use crate::error::StorageError;

pub trait BlockWriter {
    fn write_block(&mut self, block: u16, data: &[u8]) -> Result<(usize, u64), StorageError>;
}
