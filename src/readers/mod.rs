use self::multiple_block_reader::MultipleBlockReader;
#[cfg(feature = "seek")]
use self::multiple_block_seek_reader::MultipleBlockSeekReader;
use self::single_block_reader::SingleBlockReader;

pub mod block_reader;
#[cfg(feature = "encryption")]
pub mod encrypted_stream_reader;
pub mod multiple_block_reader;
#[cfg(feature = "seek")]
pub mod multiple_block_seek_reader;
#[cfg(not(feature = "alloc"))]
pub mod pool_reader;
pub mod single_block_reader;

// serves as wrapper to carry types
#[derive(Debug)]
pub enum Readers<R> {
    Single(SingleBlockReader<R>),
    Multiple(MultipleBlockReader<R>),
    #[cfg(feature = "seek")]
    Seek(MultipleBlockSeekReader<R>),
}

#[cfg(feature = "alloc")]
impl<T: self::block_reader::BlockReader + ?Sized> self::block_reader::BlockReader
    for alloc::boxed::Box<T>
{
    fn next(
        &mut self,
        buffer: &mut [u8],
        retry: bool,
    ) -> Result<Option<block_reader::Block>, crate::error::StorageError> {
        self.as_mut().next(buffer, retry)
    }

    fn free_block(&mut self, block: u16) -> usize {
        self.as_mut().free_block(block)
    }

    fn is_finished(&self) -> bool {
        self.as_ref().is_finished()
    }
}

#[cfg(feature = "encryption")]
pub use encrypted_stream_reader::StreamReader;
