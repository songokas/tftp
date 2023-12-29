use super::block_reader::Block;
use super::block_reader::BlockReader;
use crate::block_mapper::BlockMapper;
use crate::error::StorageError;
use crate::std_compat::io::Read;
use crate::std_compat::io::Seek;
use crate::std_compat::io::SeekFrom;
use crate::types::DataBlock;

#[derive(Debug)]
pub struct MultipleBlockSeekReader<R> {
    reader: R,
    block_mapper: BlockMapper,
    block_read: u64,
    block_read_confirmed: u64,
    current_block: u64,
    block_size: u16,
    last_offset: u64,
    max_blocks_to_read: u16,
    finished_block_size: Option<u16>,
}

impl<R> MultipleBlockSeekReader<R> {
    pub fn new(reader: R, block_size: u16, max_blocks_to_read: u16) -> Self {
        Self {
            reader,
            block_mapper: BlockMapper::new(),
            block_read: 0,
            block_read_confirmed: 0,
            current_block: 0,
            block_size,
            last_offset: 0,
            max_blocks_to_read,
            finished_block_size: None,
        }
    }
}

impl<R> BlockReader for MultipleBlockSeekReader<R>
where
    R: Read + Seek,
{
    fn next(&mut self, retry: bool) -> Result<Option<Block>, StorageError> {
        if self.is_finished() {
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
        let block_len = self.block_read - self.block_read_confirmed;

        // retry from the start
        if retry && self.block_read > self.block_read_confirmed {
            let first_block_offset = self.block_read_confirmed * self.block_size as u64;
            self.reader.seek(SeekFrom::Start(first_block_offset))?;
            let read = self.reader.read(&mut buffer)?;
            buffer.truncate(read);

            self.current_block = if self.block_read_confirmed > 0 {
                self.block_read_confirmed + 1
            } else {
                1
            };

            return Ok(Block {
                block: self.block_mapper.block(self.current_block),
                data: buffer.clone(),
                retry: true,
            }
            .into());
        }

        // next block in memory
        let index = self.current_block + 1;
        if self.block_read >= index {
            self.reader
                .seek(SeekFrom::Start(self.current_block * self.block_size as u64))?;
            let read = self.reader.read(&mut buffer)?;
            buffer.truncate(read);

            self.current_block = index;

            return Ok(Block {
                block: self.block_mapper.block(index),
                data: buffer.clone(),
                retry: true,
            }
            .into());
        }

        if self.finished_block_size.is_some() || block_len >= self.max_blocks_to_read as u64 {
            return Ok(None);
        }

        #[allow(clippy::seek_from_current)]
        if matches!(self.reader.seek(SeekFrom::Current(0)), Ok(p) if p != self.last_offset) {
            self.reader.seek(SeekFrom::Start(self.last_offset))?;
        }
        let read = self.reader.read(&mut buffer)?;
        buffer.truncate(read);

        if read < self.block_size as usize {
            self.finished_block_size = (read as u16).into();
        }

        self.block_read = index;
        self.current_block = index;
        self.last_offset += read as u64;

        Ok(Block {
            block: self.block_mapper.block(self.block_read),
            data: buffer,
            retry: false,
        }
        .into())
    }

    fn free_block(&mut self, block: u16) -> usize {
        let mut index = self.block_mapper.index(block);
        let mut size: usize = 0;
        if index > self.block_read_confirmed {
            if index > self.block_read {
                index = self.block_read;
            }
            size = (index - self.block_read_confirmed) as usize * self.block_size as usize;
            if index == self.block_read {
                if let Some(s) = self.finished_block_size {
                    // last block size can be different
                    size = size - self.block_size as usize + s as usize;
                }
            }

            self.block_read_confirmed = index;
            self.current_block = index;
        }
        size
    }

    fn is_finished(&self) -> bool {
        self.block_read == self.block_read_confirmed && self.finished_block_size.is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_next_read_and_repeat() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let mut reader = MultipleBlockSeekReader::new(cursor, 2, 2);

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
        let mut reader = MultipleBlockSeekReader::new(cursor, 2, 2);

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
        let mut reader = MultipleBlockSeekReader::new(cursor, 2, 2);

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
        let mut reader = MultipleBlockSeekReader::new(cursor, 2, 2);

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
        let mut reader = MultipleBlockSeekReader::new(cursor, 2, 2);

        reader.next(false).unwrap().unwrap();
        reader.next(false).unwrap().unwrap();

        assert_eq!(4, reader.free_block(2));

        reader.next(false).unwrap().unwrap();

        assert_eq!(1, reader.free_block(3));
    }

    #[test]
    fn test_free_block_invalid() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5]);
        let mut reader = MultipleBlockSeekReader::new(cursor, 2, 2);

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
    fn test_free_block_while_rereading() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut reader = MultipleBlockSeekReader::new(cursor, 2, 4);

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
    fn test_next_file_reading_finished() {
        let cursor = Cursor::new(vec![1, 2, 3]);
        let mut reader = MultipleBlockSeekReader::new(cursor, 2, 3);

        reader.next(false).unwrap().unwrap();
        reader.next(false).unwrap().unwrap();

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");
    }

    #[test]
    fn test_next_file_size_matches_block_size() {
        let cursor = Cursor::new(vec![1, 2, 3, 4]);
        let mut reader = MultipleBlockSeekReader::new(cursor, 2, 3);

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
        let expected_size = 64;
        assert_eq!(
            expected_size,
            std::mem::size_of::<MultipleBlockSeekReader<std::fs::File>>()
        );
    }
}
