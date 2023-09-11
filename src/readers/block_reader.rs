use crate::error::StorageError;
use crate::types::DataBlock;

pub trait BlockReader {
    /// read next block
    fn next(&mut self, retry: bool) -> Result<Option<Block>, StorageError>;

    /// release block returning data size released
    fn free_block(&mut self, block: u16) -> usize;

    fn is_finished(&self) -> bool;
}

#[derive(Debug)]
pub struct Block {
    pub block: u16,
    pub data: DataBlock,
    pub retry: bool,
}
