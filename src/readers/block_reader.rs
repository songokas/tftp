use crate::error::StorageError;

pub trait BlockReader {
    /// read next block
    fn next(&mut self, buffer: &mut [u8], retry: bool) -> Result<Option<Block>, StorageError>;

    /// release block returning data size released
    fn free_block(&mut self, block: u16) -> usize;

    fn is_finished(&self) -> bool;
}

#[derive(Debug)]
pub struct Block {
    pub block: u16,
    pub index: u64,
    pub size: usize,
    pub retry: bool,
}
