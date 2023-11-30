use super::block_reader::Block;
use super::block_reader::BlockReader;
use crate::block_mapper::BlockMapper;
use crate::error::StorageError;
use crate::map::Map;
use crate::std_compat::io::Read;
use crate::types::DataBlock;

#[derive(Debug)]
pub struct MultipleBlockReader<R> {
    reader: R,
    block_mapper: BlockMapper,
    block_read: u64,
    block_size: u16,
    blocks: Blocks,
    max_blocks_to_read: u16,
    finished: bool,
}

impl<R> MultipleBlockReader<R> {
    pub fn new(reader: R, block_size: u16, max_blocks_to_read: u16) -> Self {
        Self {
            reader,
            block_mapper: BlockMapper::new(),
            block_read: 0,
            block_size,
            blocks: Blocks::new(),
            max_blocks_to_read,
            finished: false,
        }
    }
}

impl<R> BlockReader for MultipleBlockReader<R>
where
    R: Read,
{
    fn next(&mut self, retry: bool) -> Result<Option<Block>, StorageError> {
        if self.is_finished() {
            return Ok(None);
        }

        // retry from the start if there is a block to retry
        if retry {
            let first_block = self.blocks.iter().next();
            if let Some((index, buffer)) = first_block {
                self.block_read = *index;
                return Ok(Block {
                    block: self.block_mapper.block(*index),
                    data: buffer.clone(),
                    retry: true,
                }
                .into());
            }
        }

        // next block in memory
        let index = self.block_read + 1;
        if let Some(buffer) = self.blocks.get(&index) {
            let block = Block {
                block: self.block_mapper.block(index),
                data: buffer.clone(),
                retry: true,
            };
            self.block_read = index;
            return Ok(block.into());
        }

        if self.finished || self.blocks.len() >= self.max_blocks_to_read as usize {
            return Ok(None);
        }

        let mut buffer = {
            let mut d = DataBlock::new();
            #[cfg(feature = "alloc")]
            d.resize(self.block_size as usize, 0);
            // TODO heapless vector resizing is super slow
            #[cfg(not(feature = "alloc"))]
            unsafe {
                d.set_len(self.block_size as usize)
            };
            d
        };

        let read = self.reader.read(&mut buffer)?;
        buffer.truncate(read);

        self.block_read = index;

        let _ = self.blocks.insert(self.block_read, buffer.clone());
        if read < self.block_size as usize {
            self.finished = true;
        }
        Ok(Block {
            block: self.block_mapper.block(self.block_read),
            data: buffer,
            retry: false,
        }
        .into())
    }

    fn free_block(&mut self, block: u16) -> usize {
        let index = self.block_mapper.index(block);
        let first_index = self.blocks.iter().next().map(|(b, _)| *b).unwrap_or(0);
        let mut size = 0;
        for block_index in first_index..=index {
            let result = self.blocks.remove(&block_index);
            if result.is_some() {
                self.block_read = block_index;
            }
            size += result.map(|b| b.len()).unwrap_or(0);
        }
        size
    }

    fn is_finished(&self) -> bool {
        self.blocks.is_empty() && self.finished
    }
}

#[cfg(feature = "alloc")]
type Blocks = Map<u64, DataBlock>;
#[cfg(not(feature = "alloc"))]
type Blocks = Map<u64, DataBlock, { crate::config::MAX_BLOCKS_READER as usize }>;

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    #[allow(unused_imports)]
    use std::vec::Vec;

    use super::*;

    #[test]
    fn test_next_read_and_repeat() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        #[cfg(not(feature = "std"))]
        let cursor = CursorReader { cursor };
        let mut reader = MultipleBlockReader::new(cursor, 2, 2);

        let block = reader.next(false).unwrap().unwrap();
        assert_eq!(block.block, 1);
        assert_eq!(&block.data, &[1, 2]);
        assert!(!reader.is_finished());

        let block = reader.next(false).unwrap().unwrap();
        assert_eq!(block.block, 2);
        assert_eq!(&block.data, &[3, 4]);

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");

        let block = reader.next(true).unwrap().unwrap();
        assert_eq!(block.block, 1);
        assert_eq!(&block.data, &[1, 2]);
        assert!(!reader.is_finished());

        let block = reader.next(false).unwrap().unwrap();
        assert_eq!(block.block, 2);
        assert_eq!(&block.data, &[3, 4]);

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");
    }

    #[test]
    fn test_read_until_finished() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        #[cfg(not(feature = "std"))]
        let cursor = CursorReader { cursor };
        let mut reader = MultipleBlockReader::new(cursor, 2, 2);

        reader.next(false).unwrap().unwrap();
        assert!(!reader.is_finished());

        reader.next(false).unwrap().unwrap();
        assert!(!reader.is_finished());

        reader.free_block(2);

        reader.next(false).unwrap().unwrap();
        assert!(!reader.is_finished());

        reader.next(false).unwrap().unwrap();
        assert!(!reader.is_finished());

        reader.free_block(4);

        reader.next(false).unwrap().unwrap();
        assert!(!reader.is_finished());
        reader.free_block(5);
        assert!(reader.is_finished());
    }

    #[test]
    fn test_next_read_from_released() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7]);
        #[cfg(not(feature = "std"))]
        let cursor = CursorReader { cursor };
        let mut reader = MultipleBlockReader::new(cursor, 2, 2);

        let block = reader.next(false).unwrap().unwrap();
        reader.free_block(block.block);

        let block = reader.next(false).unwrap().unwrap();
        assert_eq!(block.block, 2);
        assert_eq!(&block.data, &[3, 4]);

        let block = reader.next(false).unwrap().unwrap();
        assert_eq!(block.block, 3);
        assert_eq!(&block.data, &[5, 6]);

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");

        let block = reader.next(true).unwrap().unwrap();
        assert_eq!(block.block, 2);
        assert_eq!(&block.data, &[3, 4]);
        assert!(!reader.is_finished());

        let block = reader.next(false).unwrap().unwrap();
        assert_eq!(block.block, 3);
        assert_eq!(&block.data, &[5, 6]);

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");
    }

    #[test]
    fn test_next_nothing_to_read() {
        let cursor = Cursor::new(vec![1, 2, 3]);
        #[cfg(not(feature = "std"))]
        let cursor = CursorReader { cursor };
        let mut reader = MultipleBlockReader::new(cursor, 2, 2);

        reader.next(false).unwrap().unwrap();
        let block = reader.next(false).unwrap().unwrap();
        assert_eq!(block.block, 2);
        assert_eq!(&block.data, &[3]);

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");

        reader.free_block(block.block);

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");

        let result = reader.next(true).unwrap();
        assert!(result.is_none(), "{result:?}");
    }

    #[test]
    fn test_free_block() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5]);
        #[cfg(not(feature = "std"))]
        let cursor = CursorReader { cursor };
        let mut reader = MultipleBlockReader::new(cursor, 2, 2);

        reader.next(false).unwrap().unwrap();
        reader.next(false).unwrap().unwrap();

        assert_eq!(4, reader.free_block(2));

        reader.next(false).unwrap().unwrap();

        assert_eq!(1, reader.free_block(3));
    }

    #[test]
    fn test_free_block_while_rereading() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        #[cfg(not(feature = "std"))]
        let cursor = CursorReader { cursor };
        let mut reader = MultipleBlockReader::new(cursor, 2, 4);

        reader.next(false).unwrap().unwrap();
        reader.next(false).unwrap().unwrap();
        reader.next(false).unwrap().unwrap();
        reader.next(false).unwrap().unwrap();

        reader.next(true).unwrap().unwrap();

        assert_eq!(8, reader.free_block(4));

        let block = reader.next(false).unwrap().unwrap();
        assert_eq!(block.block, 5);

        assert_eq!(1, reader.free_block(5));
    }

    #[test]
    fn test_free_block_invalid() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5]);
        #[cfg(not(feature = "std"))]
        let cursor = CursorReader { cursor };
        let mut reader = MultipleBlockReader::new(cursor, 2, 2);

        assert_eq!(0, reader.free_block(1));
        reader.next(false).unwrap().unwrap();
        assert_eq!(2, reader.free_block(2));

        reader.next(false).unwrap().unwrap();
        assert_eq!(2, reader.free_block(10));
        assert_eq!(0, reader.free_block(10));

        reader.next(false).unwrap().unwrap();
        assert_eq!(0, reader.free_block(2));
        assert!(!reader.is_finished());

        assert_eq!(1, reader.free_block(3));
        assert!(reader.is_finished());
    }

    #[test]
    fn test_next_file_reading_finished() {
        let cursor = Cursor::new(vec![1, 2, 3]);
        #[cfg(not(feature = "std"))]
        let cursor = CursorReader { cursor };
        let mut reader = MultipleBlockReader::new(cursor, 2, 3);

        reader.next(false).unwrap().unwrap();
        reader.next(false).unwrap().unwrap();

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");
    }

    #[test]
    fn test_next_file_size_matches_block_size() {
        let cursor = Cursor::new(vec![1, 2, 3, 4]);
        #[cfg(not(feature = "std"))]
        let cursor = CursorReader { cursor };
        let mut reader = MultipleBlockReader::new(cursor, 2, 3);

        reader.next(false).unwrap().unwrap();
        reader.next(false).unwrap().unwrap();
        reader.next(false).unwrap().unwrap();

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");

        assert_eq!(4, reader.free_block(3));
        assert!(reader.is_finished());
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

    #[cfg(not(feature = "std"))]
    #[derive(Debug)]
    struct CursorReader {
        cursor: Cursor<Vec<u8>>,
    }
    #[cfg(not(feature = "std"))]
    impl Read for CursorReader {
        fn read(&mut self, buf: &mut [u8]) -> crate::std_compat::io::Result<usize> {
            use std::io::Read;
            self.cursor.read(buf).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::Other)
            })
        }
    }
}
