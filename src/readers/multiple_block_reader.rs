use core::cmp::max;
use core::cmp::Ordering;

use log::trace;

use super::block_reader::Block;
use super::block_reader::BlockReader;
use crate::block_mapper::BlockMapper;
use crate::buffer::new_data_block;
use crate::buffer::SliceMutExt;
use crate::error::StorageError;
use crate::std_compat::io::Read;
use crate::types::DataBlock;

#[derive(Debug)]
pub struct MultipleBlockReader<R> {
    reader: R,
    block_mapper: BlockMapper,
    block_read: u64,
    block_size: u16,
    blocks: Buffers,
    max_blocks_to_read: u16,
    finished: bool,
}

impl<R> MultipleBlockReader<R> {
    pub fn new(reader: R, block_size: u16, max_blocks_to_read: u16) -> Self {
        #[cfg(feature = "alloc")]
        let blocks = Buffers::with_capacity(max_blocks_to_read as usize);
        #[cfg(not(feature = "alloc"))]
        let blocks = Buffers::new();
        Self {
            reader,
            block_mapper: BlockMapper::new(),
            block_read: 0,
            block_size,
            blocks,
            max_blocks_to_read,
            finished: false,
        }
    }
}

impl<R> BlockReader for MultipleBlockReader<R>
where
    R: Read,
{
    fn next(&mut self, buffer: &mut [u8], retry: bool) -> Result<Option<Block>, StorageError> {
        if self.is_finished() {
            return Ok(None);
        }

        // retry from the start if there is a block to retry
        if retry {
            let first_block = self
                .blocks
                .iter()
                .filter(|b| b.index.is_some())
                .min_by(|a, b| a.index.partial_cmp(&b.index).unwrap_or(Ordering::Less));
            if let Some(block_buffer) = first_block {
                self.block_read = block_buffer.index.unwrap();
                buffer.write_bytes(&block_buffer.data, 0_usize).ok_or(
                    StorageError::InvalidBuffer {
                        actual: buffer.len(),
                        expected: block_buffer.data.len(),
                    },
                )?;

                return Ok(Block {
                    block: self.block_mapper.block(self.block_read),
                    index: self.block_read,
                    size: block_buffer.data.len(),
                    retry: true,
                }
                .into());
            }
        }

        // next block in memory
        let index = self.block_read + 1;
        if let Some(block_buffer) = self.blocks.iter().find(|b| b.index == Some(index)) {
            buffer
                .write_bytes(&block_buffer.data, 0_usize)
                .ok_or(StorageError::InvalidBuffer {
                    actual: buffer.len(),
                    expected: block_buffer.data.len(),
                })?;
            let block = Block {
                block: self.block_mapper.block(index),
                index,
                size: block_buffer.data.len(),
                retry: true,
            };
            self.block_read = index;
            return Ok(block.into());
        }

        if self.finished
            || self.blocks.iter().filter(|b| b.index.is_some()).count()
                >= self.max_blocks_to_read as usize
        {
            return Ok(None);
        }

        let block_buffer = if let Some(b) = self.blocks.iter_mut().find(|b| b.index.is_none()) {
            b
        } else {
            let data = new_data_block(self.block_size);
            let _ = self.blocks.push(Buffer { data, index: None });
            self.blocks.last_mut().expect("last block")
        };

        trace!("Reading block {index}");

        let read = self.reader.read(&mut block_buffer.data)?;
        block_buffer.data.truncate(read);

        buffer
            .write_bytes(&block_buffer.data, 0_usize)
            .ok_or(StorageError::InvalidBuffer {
                actual: buffer.len(),
                expected: block_buffer.data.len(),
            })?;

        self.block_read = index;

        block_buffer.index = self.block_read.into();
        if read < self.block_size as usize {
            self.finished = true;
        }
        Ok(Block {
            block: self.block_mapper.block(self.block_read),
            index,
            size: block_buffer.data.len(),
            retry: false,
        }
        .into())
    }

    fn free_block(&mut self, block: u16) -> usize {
        let index = self.block_mapper.index(block);
        // block order could be random
        let blocks_to_remove = self.blocks.iter_mut().filter(|b| {
            if let Some(bindex) = b.index {
                bindex <= index
            } else {
                false
            }
        });
        let mut size = 0;
        let mut last_block_removed = None;
        for block_to_remove in blocks_to_remove {
            last_block_removed = max(last_block_removed, block_to_remove.index);
            block_to_remove.index = None;
            size += block_to_remove.data.len();
        }

        if let Some(index) = last_block_removed {
            self.block_read = index;
        }
        size
    }

    fn is_finished(&self) -> bool {
        self.blocks.iter().filter(|b| b.index.is_some()).count() == 0 && self.finished
    }
}

#[cfg(feature = "alloc")]
type Buffers = alloc::vec::Vec<Buffer>;
#[cfg(not(feature = "alloc"))]
type Buffers = heapless::Vec<Buffer, { crate::config::MAX_BLOCKS_FOR_MULTI_READER as usize }>;

#[derive(Debug)]
struct Buffer {
    data: DataBlock,
    index: Option<u64>,
}

#[cfg(test)]
mod tests {
    use crate::std_compat::io::ErrorKind;
    use crate::std_compat::io::Read;
    use crate::std_compat::io::Result;
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_next_read_and_repeat() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let mut reader = MultipleBlockReader::new(cursor, 2, 2);
        let mut buffer = [0_u8; 2];
        let block = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(block.block, 1);
        assert_eq!(&buffer, &[1, 2]);
        assert!(!reader.is_finished());

        let block = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(block.block, 2);
        assert_eq!(&buffer, &[3, 4]);

        let result = reader.next(&mut buffer, false).unwrap();
        assert!(result.is_none(), "{result:?}");

        let block = reader.next(&mut buffer, true).unwrap().unwrap();
        assert_eq!(block.block, 1);
        assert_eq!(&buffer, &[1, 2]);
        assert!(!reader.is_finished());

        let block = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(block.block, 2);
        assert_eq!(&buffer, &[3, 4]);

        let result = reader.next(&mut buffer, false).unwrap();
        assert!(result.is_none(), "{result:?}");
    }

    #[test]
    fn test_read_until_finished() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut reader = MultipleBlockReader::new(cursor, 2, 2);
        let mut buffer = [0_u8; 100];
        reader.next(&mut buffer, false).unwrap().unwrap();
        assert!(!reader.is_finished());

        reader.next(&mut buffer, false).unwrap().unwrap();
        assert!(!reader.is_finished());
        reader.free_block(2);

        reader.next(&mut buffer, false).unwrap().unwrap();
        assert!(!reader.is_finished());

        reader.next(&mut buffer, false).unwrap().unwrap();
        assert!(!reader.is_finished());

        reader.free_block(4);

        reader.next(&mut buffer, false).unwrap().unwrap();
        assert!(!reader.is_finished());
        reader.free_block(5);
        assert!(reader.is_finished());
    }

    #[test]
    fn test_next_read_from_released() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7]);
        let mut reader = MultipleBlockReader::new(cursor, 2, 2);
        let mut buffer = [0_u8; 2];
        let block = reader.next(&mut buffer, false).unwrap().unwrap();
        reader.free_block(block.block);

        let block = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(block.block, 2);
        assert_eq!(&buffer, &[3, 4]);

        let block = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(block.block, 3);
        assert_eq!(&buffer, &[5, 6]);

        let result = reader.next(&mut buffer, false).unwrap();
        assert!(result.is_none(), "{result:?}");

        let block = reader.next(&mut buffer, true).unwrap().unwrap();
        assert_eq!(block.block, 2);
        assert_eq!(&buffer, &[3, 4]);
        assert!(!reader.is_finished());

        let block = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(block.block, 3);
        assert_eq!(&buffer, &[5, 6]);

        let result = reader.next(&mut buffer, false).unwrap();
        assert!(result.is_none(), "{result:?}");
    }

    #[test]
    fn test_next_nothing_to_read() {
        let cursor = Cursor::new(vec![1, 2, 3]);
        let mut reader = MultipleBlockReader::new(cursor, 2, 2);
        let mut buffer = [0_u8; 2];
        reader.next(&mut buffer, false).unwrap().unwrap();
        let block = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(block.block, 2);
        assert_eq!(&buffer[0..1], &[3]);

        let result = reader.next(&mut buffer, false).unwrap();
        assert!(result.is_none(), "{result:?}");

        reader.free_block(block.block);

        let result = reader.next(&mut buffer, false).unwrap();
        assert!(result.is_none(), "{result:?}");

        let result = reader.next(&mut buffer, true).unwrap();
        assert!(result.is_none(), "{result:?}");
    }

    #[test]
    fn test_free_block() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5]);
        let mut reader = MultipleBlockReader::new(cursor, 2, 2);
        let mut buffer = [0_u8; 100];
        reader.next(&mut buffer, false).unwrap().unwrap();
        reader.next(&mut buffer, false).unwrap().unwrap();

        assert_eq!(4, reader.free_block(2));

        reader.next(&mut buffer, false).unwrap().unwrap();

        assert_eq!(1, reader.free_block(3));
    }

    #[test]
    fn test_free_block_while_rereading() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut reader = MultipleBlockReader::new(cursor, 2, 4);
        let mut buffer = [0_u8; 100];
        reader.next(&mut buffer, false).unwrap().unwrap();
        reader.next(&mut buffer, false).unwrap().unwrap();
        reader.next(&mut buffer, false).unwrap().unwrap();
        reader.next(&mut buffer, false).unwrap().unwrap();

        reader.next(&mut buffer, true).unwrap().unwrap();

        assert_eq!(8, reader.free_block(4));

        let block = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(block.block, 5);

        assert_eq!(1, reader.free_block(5));
    }

    #[test]
    fn test_free_block_invalid() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5]);
        let mut reader = MultipleBlockReader::new(cursor, 2, 2);
        let mut buffer = [0_u8; 100];
        assert_eq!(0, reader.free_block(1));
        reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(2, reader.free_block(2));

        reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(2, reader.free_block(10));
        assert_eq!(0, reader.free_block(10));

        reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(0, reader.free_block(2));
        assert!(!reader.is_finished());

        assert_eq!(1, reader.free_block(3));
        assert!(reader.is_finished());
    }

    #[test]
    fn test_next_file_reading_finished() {
        let cursor = Cursor::new(vec![1, 2, 3]);
        let mut reader = MultipleBlockReader::new(cursor, 2, 3);
        let mut buffer = [0_u8; 100];
        reader.next(&mut buffer, false).unwrap().unwrap();
        reader.next(&mut buffer, false).unwrap().unwrap();

        let result = reader.next(&mut buffer, false).unwrap();
        assert!(result.is_none(), "{result:?}");
    }

    #[test]
    fn test_next_file_size_matches_block_size() {
        let cursor = Cursor::new(vec![1, 2, 3, 4]);
        let mut reader = MultipleBlockReader::new(cursor, 2, 3);
        let mut buffer = [0_u8; 100];
        reader.next(&mut buffer, false).unwrap().unwrap();
        reader.next(&mut buffer, false).unwrap().unwrap();
        reader.next(&mut buffer, false).unwrap().unwrap();

        let result = reader.next(&mut buffer, false).unwrap();
        assert!(result.is_none(), "{result:?}");

        assert_eq!(4, reader.free_block(3));
        assert!(reader.is_finished());
    }

    #[test]
    fn test_read_is_always_for_new_block() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut reader = MultipleBlockReader::new(cursor, 2, 4);
        let mut buffer = [0_u8; 100];
        let result = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(result.block, 1);
        let result = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(result.block, 2);

        assert_eq!(2, reader.free_block(1));

        let result = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(result.block, 2);
        let result = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(result.block, 3);

        assert_eq!(4, reader.free_block(3));

        let result = reader.next(&mut buffer, false).unwrap().unwrap();
        assert_eq!(result.block, 4);
    }

    #[test]
    fn test_read_failure() {
        let reader = AlwaysFailReader {};
        let mut reader = MultipleBlockReader::new(reader, 2, 4);
        let mut buffer = [0_u8; 100];
        let result = reader.next(&mut buffer, false);
        assert!(matches!(result.unwrap_err(), StorageError::File(_)));
        let result = reader.next(&mut buffer, true);
        assert!(matches!(result.unwrap_err(), StorageError::File(_)));
        let result = reader.next(&mut buffer, false);
        assert!(matches!(result.unwrap_err(), StorageError::File(_)));
    }

    #[ignore]
    #[test]
    fn size_of() {
        #[cfg(feature = "alloc")]
        let expected_size = 64;
        #[cfg(not(feature = "alloc"))]
        let expected_size = 22960;
        assert_eq!(
            expected_size,
            std::mem::size_of::<MultipleBlockReader<std::fs::File>>()
        );
    }

    struct AlwaysFailReader {}

    impl Read for AlwaysFailReader {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize> {
            Err(ErrorKind::Unsupported).map_err(Into::into)
        }
    }
}
