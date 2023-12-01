use core::cell::RefCell;

use crate::map::Map;
use crate::readers::block_reader::BlockReader;
use crate::readers::multiple_block_reader::MultipleBlockReader;
use crate::readers::single_block_reader::SingleBlockReader;
use crate::std_compat::io::Read;
#[cfg(feature = "seek")]
use crate::std_compat::io::Seek;

pub type SingleBlockReaders<R> = Map<
    u16,
    crate::readers::single_block_reader::SingleBlockReader<R>,
    { crate::config::MAX_SINGLE_READERS as usize },
>;
pub type MultiBlockReaders<R> = Map<
    u16,
    crate::readers::multiple_block_reader::MultipleBlockReader<R>,
    { crate::config::MAX_MULTI_READERS as usize },
>;

#[cfg(feature = "seek")]
pub type MultiBlockSeekReaders<R> = Map<
    u16,
    crate::readers::multiple_block_seek_reader::MultipleBlockSeekReader<R>,
    { crate::config::MAX_MULTI_SEEK_READERS as usize },
>;

pub enum PoolReader<'a, R> {
    Single(u16, &'a RefCell<SingleBlockReaders<R>>),
    Multi(u16, &'a RefCell<MultiBlockReaders<R>>),
    #[cfg(feature = "seek")]
    Seek(u16, &'a RefCell<MultiBlockSeekReaders<R>>),
}

impl<'a, R> PoolReader<'a, R> {
    pub fn from_single(
        reader: SingleBlockReader<R>,
        pool: &'a RefCell<SingleBlockReaders<R>>,
    ) -> Option<Self> {
        let index = {
            let p = pool.borrow();
            (0..u16::MAX).find(|k| !p.contains_key(k))?
        };
        if pool.borrow_mut().insert(index, reader).is_err() {
            return None;
        }
        Self::Single(index, pool).into()
    }

    pub fn from_multi(
        reader: MultipleBlockReader<R>,
        pool: &'a RefCell<MultiBlockReaders<R>>,
    ) -> Option<Self> {
        let index = {
            let p = pool.borrow();
            (0..u16::MAX).find(|k| !p.contains_key(k))?
        };
        if pool.borrow_mut().insert(index, reader).is_err() {
            return None;
        }
        Self::Multi(index, pool).into()
    }

    #[cfg(feature = "seek")]
    pub fn from_seek(
        reader: crate::readers::multiple_block_seek_reader::MultipleBlockSeekReader<R>,
        pool: &'a RefCell<MultiBlockSeekReaders<R>>,
    ) -> Option<Self> {
        let index = {
            let p = pool.borrow();
            (0..u16::MAX).find(|k| !p.contains_key(k))?
        };
        if pool.borrow_mut().insert(index, reader).is_err() {
            return None;
        }
        Self::Seek(index, pool).into()
    }
}

impl<'a, #[cfg(feature = "seek")] R: Read + Seek, #[cfg(not(feature = "seek"))] R: Read> BlockReader
    for PoolReader<'a, R>
{
    fn next(
        &mut self,
        retry: bool,
    ) -> Result<Option<crate::readers::block_reader::Block>, crate::error::StorageError> {
        match self {
            Self::Single(i, s) => s
                .borrow_mut()
                .get_mut(i)
                .expect("reader does not exist")
                .next(retry),
            Self::Multi(i, s) => s
                .borrow_mut()
                .get_mut(i)
                .expect("reader does not exist")
                .next(retry),
            #[cfg(feature = "seek")]
            Self::Seek(i, s) => s
                .borrow_mut()
                .get_mut(i)
                .expect("reader does not exist")
                .next(retry),
        }
    }

    fn free_block(&mut self, block: u16) -> usize {
        match self {
            Self::Single(i, s) => s
                .borrow_mut()
                .get_mut(i)
                .expect("reader does not exist")
                .free_block(block),
            Self::Multi(i, s) => s
                .borrow_mut()
                .get_mut(i)
                .expect("reader does not exist")
                .free_block(block),
            #[cfg(feature = "seek")]
            Self::Seek(i, s) => s
                .borrow_mut()
                .get_mut(i)
                .expect("reader does not exist")
                .free_block(block),
        }
    }

    fn is_finished(&self) -> bool {
        match self {
            Self::Single(i, s) => s
                .borrow()
                .get(i)
                .expect("reader does not exist")
                .is_finished(),
            Self::Multi(i, s) => s
                .borrow()
                .get(i)
                .expect("reader does not exist")
                .is_finished(),
            #[cfg(feature = "seek")]
            Self::Seek(i, s) => s
                .borrow()
                .get(i)
                .expect("reader does not exist")
                .is_finished(),
        }
    }
}

impl<'a, R> Drop for PoolReader<'a, R> {
    fn drop(&mut self) {
        match self {
            Self::Single(i, s) => {
                s.borrow_mut().remove(i);
            }
            Self::Multi(i, s) => {
                s.borrow_mut().remove(i);
            }
            #[cfg(feature = "seek")]
            Self::Seek(i, s) => {
                s.borrow_mut().remove(i);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::vec::Vec;

    use super::*;
    use crate::readers::block_reader::BlockReader;
    use crate::std_compat::io::Read;
    use crate::std_compat::io::Seek;
    use crate::std_compat::io::SeekFrom;

    #[test]
    fn test_pool_reader_single() {
        let cursor = Cursor::new(vec![1]);
        let cursor = CursorReader { cursor };
        let pool = RefCell::new(SingleBlockReaders::new());
        {
            let mut reader =
                PoolReader::from_single(SingleBlockReader::new(cursor, 2), &pool).unwrap();
            let block = reader.next(false).unwrap().unwrap();
            assert_eq!(block.block, 1);
            assert_eq!(1, reader.free_block(1));
            assert!(reader.is_finished());
            assert_eq!(pool.borrow().len(), 1);
        }
        assert_eq!(pool.borrow().len(), 0);
    }

    #[test]
    fn test_pool_reader_multi() {
        let cursor = Cursor::new(vec![1]);
        let cursor = CursorReader { cursor };
        let pool = RefCell::new(MultiBlockReaders::new());
        {
            let mut reader =
                PoolReader::from_multi(MultipleBlockReader::new(cursor, 2, 2), &pool).unwrap();
            let block = reader.next(false).unwrap().unwrap();
            assert_eq!(block.block, 1);
            assert_eq!(1, reader.free_block(1));
            assert!(reader.is_finished());
            assert_eq!(pool.borrow().len(), 1);
        }
        assert_eq!(pool.borrow().len(), 0);
    }

    #[cfg(feature = "seek")]
    #[test]
    fn test_pool_reader_seek() {
        let cursor = Cursor::new(vec![1]);
        let cursor = CursorReader { cursor };
        let pool = RefCell::new(MultiBlockSeekReaders::new());
        {
            let mut reader = PoolReader::from_seek(
                crate::readers::multiple_block_seek_reader::MultipleBlockSeekReader::new(
                    cursor, 2, 2,
                ),
                &pool,
            )
            .unwrap();
            let block = reader.next(false).unwrap().unwrap();
            assert_eq!(block.block, 1);
            assert_eq!(1, reader.free_block(1));
            assert!(reader.is_finished());
            assert_eq!(pool.borrow().len(), 1);
        }
        assert_eq!(pool.borrow().len(), 0);
    }

    #[ignore]
    #[test]
    fn size_of() {
        #[cfg(feature = "alloc")]
        let expected_size = 72;
        #[cfg(not(feature = "alloc"))]
        let expected_size = 16;
        assert_eq!(
            expected_size,
            std::mem::size_of::<PoolReader<std::fs::File>>()
        );
    }

    #[derive(Debug)]
    struct CursorReader {
        cursor: Cursor<Vec<u8>>,
    }
    impl Read for CursorReader {
        fn read(&mut self, buf: &mut [u8]) -> crate::std_compat::io::Result<usize> {
            #[allow(unused_imports)]
            use std::io::Read;
            self.cursor.read(buf).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::Other)
            })
        }
    }

    impl Seek for CursorReader {
        fn seek(&mut self, pos: SeekFrom) -> crate::std_compat::io::Result<u64> {
            #[allow(unused_imports)]
            use std::io::Seek;
            let pos = match pos {
                SeekFrom::Start(p) => std::io::SeekFrom::Start(p),
                SeekFrom::Current(p) => std::io::SeekFrom::Current(p),
                SeekFrom::End(p) => std::io::SeekFrom::End(p),
            };
            self.cursor.seek(pos).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::Other)
            })
        }
    }
}
