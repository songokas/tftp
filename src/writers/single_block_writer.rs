use log::trace;

use super::block_writer::BlockWriter;
use crate::block_mapper::BlockMapper;
use crate::error::ExistingBlock;
use crate::error::StorageError;
use crate::std_compat::io::Write;

#[derive(Debug)]
pub struct SingleBlockWriter<W> {
    writer: W,
    block_mapper: BlockMapper,
    block_written: u64,
}

impl<W> SingleBlockWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            block_mapper: BlockMapper::new(),
            block_written: 0,
        }
    }
}

impl<W> BlockWriter for SingleBlockWriter<W>
where
    W: Write,
{
    fn write_block(&mut self, block: u16, data: &[u8]) -> Result<(usize, u64), StorageError> {
        let provided_index = self.block_mapper.index(block);
        // writing blocks start at position 1
        let expected_index = self.block_written + 1;

        if provided_index < expected_index {
            return Err(StorageError::AlreadyWritten(ExistingBlock {
                current: self.block_mapper.block(self.block_written),
                current_index: self.block_written,
            }));
        }
        if provided_index > expected_index {
            return Err(StorageError::ExpectedBlock(ExistingBlock {
                current: self.block_mapper.block(self.block_written),
                current_index: self.block_written,
            }));
        }

        trace!("Writing block {expected_index}");

        let written = self.writer.write(data)?;
        self.block_written = expected_index;
        Ok((written, self.block_written))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::vec::Vec;

    use super::*;

    #[test]
    fn test_write_block() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let cursor = Arc::new(Mutex::new(Cursor::new(vec![])));
        let r = CursorWriter {
            cursor: cursor.clone(),
        };
        let mut writer = SingleBlockWriter::new(r);

        let result = writer.write_block(0, &data[0..5]);
        assert!(matches!(
            result,
            Err(StorageError::AlreadyWritten(ExistingBlock {
                current: 0,
                current_index: 0
            }))
        ),);

        let written = writer.write_block(1, &data[0..5]).unwrap();
        assert_eq!(written, (5, 1));

        let result = writer.write_block(1, &data[0..5]);
        assert!(
            matches!(
                result,
                Err(StorageError::AlreadyWritten(ExistingBlock {
                    current: 1,
                    current_index: 1
                }))
            ),
            "{writer:?}"
        );

        let result = writer.write_block(3, &data[0..5]);
        assert!(
            matches!(
                result,
                Err(StorageError::ExpectedBlock(ExistingBlock {
                    current: 1,
                    current_index: 1
                }))
            ),
            "{result:?}"
        );

        let written = writer.write_block(2, &data[5..]).unwrap();
        assert_eq!(written, (5, 2));
        assert_eq!(&data, cursor.lock().unwrap().get_ref());
    }

    #[derive(Debug)]
    struct CursorWriter {
        cursor: Arc<Mutex<Cursor<Vec<u8>>>>,
    }

    impl Write for CursorWriter {
        fn write(&mut self, buf: &[u8]) -> crate::std_compat::io::Result<usize> {
            std::io::Write::write(&mut *self.cursor.lock().unwrap(), buf).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::Other)
            })
        }
        fn write_fmt(&mut self, _: core::fmt::Arguments<'_>) -> crate::std_compat::io::Result<()> {
            todo!()
        }

        fn flush(&mut self) -> crate::std_compat::io::Result<()> {
            Ok(())
        }
    }
}
