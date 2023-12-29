use super::block_reader::Block;
use super::block_reader::BlockReader;
use crate::block_mapper::BlockMapper;
use crate::error::StorageError;
use crate::std_compat::io::Read;
use crate::types::DataBlock;

#[derive(Debug)]
pub struct SingleBlockReader<R> {
    reader: R,
    block_mapper: BlockMapper,
    block_read: u64,
    block_size: u16,
    block: Option<DataBlock>,
    finished: bool,
}

impl<R> SingleBlockReader<R> {
    pub fn new(reader: R, block_size: u16) -> Self {
        Self {
            reader,
            block_mapper: BlockMapper::new(),
            block_read: 0,
            block_size,
            block: None,
            finished: false,
        }
    }
}

impl<R> BlockReader for SingleBlockReader<R>
where
    R: Read,
{
    fn next(&mut self, retry: bool) -> Result<Option<Block>, StorageError> {
        if self.is_finished() {
            return Ok(None);
        }
        if let Some(buffer) = &self.block {
            return Ok(if retry {
                Block {
                    block: self.block_mapper.block(self.block_read),
                    data: buffer.clone(),
                    retry: true,
                }
                .into()
            } else {
                None
            });
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

        self.block_read += 1;

        self.block = buffer.clone().into();
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
        if self.block_read != self.block_mapper.index(block) {
            return 0;
        }
        self.block.take().map(|b| b.len()).unwrap_or(0)
    }

    fn is_finished(&self) -> bool {
        self.block.is_none() && self.finished
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    #[allow(unused_imports)]
    use std::vec::Vec;

    use super::*;

    #[test]
    fn test_next_read_and_repeat() {
        let cursor = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let mut reader = SingleBlockReader::new(cursor, 2);

        let block = reader.next(false).unwrap().unwrap();
        assert_eq!(block.block, 1);
        assert_eq!(&block.data, &[1, 2]);
        assert!(!reader.is_finished());

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");

        let block = reader.next(true).unwrap().unwrap();
        assert_eq!(block.block, 1);
        assert_eq!(&block.data, &[1, 2]);
        assert!(!reader.is_finished());

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");
    }

    #[test]
    fn test_read_until_finished() {
        let cursor = Cursor::new(vec![1, 2, 3]);
        let mut reader = SingleBlockReader::new(cursor, 2);

        reader.next(false).unwrap().unwrap();
        assert!(!reader.is_finished());

        assert_eq!(2, reader.free_block(1));

        reader.next(false).unwrap().unwrap();
        assert!(!reader.is_finished());

        reader.free_block(2);

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");

        let result = reader.next(true).unwrap();
        assert!(result.is_none(), "{result:?}");

        assert!(reader.is_finished());
    }

    #[test]
    fn test_free_block_invalid() {
        let cursor = Cursor::new(vec![1, 2, 3]);
        let mut reader = SingleBlockReader::new(cursor, 2);

        assert_eq!(0, reader.free_block(1));
        reader.next(false).unwrap().unwrap();
        assert_eq!(0, reader.free_block(2));
        assert_eq!(2, reader.free_block(1));

        reader.next(false).unwrap().unwrap();
        assert_eq!(0, reader.free_block(10));
        assert_eq!(0, reader.free_block(0));

        assert!(!reader.is_finished());
        assert_eq!(1, reader.free_block(2));
        assert!(reader.is_finished());
    }

    #[test]
    fn test_next_file_size_matches_block_size() {
        let cursor = Cursor::new(vec![1, 2, 3, 4]);
        let mut reader = SingleBlockReader::new(cursor, 2);

        reader.next(false).unwrap().unwrap();
        assert_eq!(2, reader.free_block(1));
        reader.next(false).unwrap().unwrap();
        assert_eq!(2, reader.free_block(2));
        reader.next(false).unwrap().unwrap();

        let result = reader.next(false).unwrap();
        assert!(result.is_none(), "{result:?}");

        assert_eq!(0, reader.free_block(3));
        assert!(reader.is_finished(), "{reader:?}");
    }

    #[ignore]
    #[test]
    fn size_of() {
        #[cfg(feature = "alloc")]
        let expected_size = 56;
        #[cfg(not(feature = "alloc"))]
        let expected_size = crate::config::MAX_DATA_BLOCK_SIZE as usize + 48;
        assert_eq!(
            expected_size,
            std::mem::size_of::<SingleBlockReader<std::fs::File>>()
        );
    }

    #[cfg(not(feature = "std"))]
    impl Read for Cursor<Vec<u8>> {
        fn read(&mut self, buf: &mut [u8]) -> crate::std_compat::io::Result<usize> {
            std::io::Read::read(self, buf).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::Other)
            })
        }
    }
}
