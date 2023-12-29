use self::single_block_writer::SingleBlockWriter;

pub mod block_writer;
#[cfg(feature = "encryption")]
pub mod encrypted_stream_writer;
pub mod single_block_writer;

pub enum Writers<W> {
    Single(SingleBlockWriter<W>),
}

#[cfg(feature = "alloc")]
impl<T: self::block_writer::BlockWriter + ?Sized> self::block_writer::BlockWriter
    for alloc::boxed::Box<T>
{
    fn write_block(
        &mut self,
        block: u16,
        data: &[u8],
    ) -> Result<(usize, u64), crate::error::StorageError> {
        self.as_mut().write_block(block, data)
    }
}
