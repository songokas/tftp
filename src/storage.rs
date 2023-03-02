use core::{
    cmp::{max, min},
    time::Duration,
};

use log::debug;

use crate::{
    config::MAX_DATA_BLOCK_SIZE,
    error::StorageError,
    map::{Entry, Map},
    std_compat::{
        io::{Read, Seek, SeekFrom, Write},
        time::Instant,
    },
    time::InstantCallback,
    types::DataBlock,
};

#[cfg(feature = "alloc")]
type BlockMapWriter<T> = Map<u64, T>;
#[cfg(not(feature = "alloc"))]
type BlockMapWriter<T> = Map<u64, T, { crate::config::MAX_BLOCKS_WRITER as usize }>;
#[cfg(feature = "alloc")]
type BlockMapReader<T> = Map<u64, T>;
#[cfg(not(feature = "alloc"))]
type BlockMapReader<T> = Map<u64, T, { crate::config::MAX_BLOCKS_READER as usize }>;

pub trait BlockWriter {
    fn write_block(&mut self, block: u16, data: &[u8]) -> Result<(usize, bool), StorageError>;
    fn is_finished_below(&self, block_size: u16) -> bool;
}

pub struct FileWriter<T> {
    writer: T,
    current_block_written: u64,
    #[cfg(feature = "seek")]
    allocated_blocks: BlockMapWriter<bool>,
    #[cfg(not(feature = "seek"))]
    allocated_blocks: BlockMapWriter<DataBlock>,
    last_block_size: Option<u16>,
    block_size: u16,
    max_blocks_to_allocate: u16,
    #[cfg(feature = "seek")]
    last_block_allocated: u64,
    block_mapper: BlockMapper,
    window_size: u16,
}

impl<T> FileWriter<T>
where
    T: Write + Seek,
{
    pub fn from_writer(
        writer: T,
        block_size: u16,
        max_blocks_to_allocate: u16,
        window_size: u16,
    ) -> Self {
        let max_blocks_to_allocate = if window_size > 1 {
            window_size
        } else {
            max_blocks_to_allocate
        };
        #[cfg(not(feature = "alloc"))]
        assert!(
            max_blocks_to_allocate <= crate::config::MAX_BLOCKS_WRITER,
            "Writer blocks {} must be <= {}",
            max_blocks_to_allocate,
            crate::config::MAX_BLOCKS_READER
        );
        Self {
            writer,
            current_block_written: 0,
            allocated_blocks: BlockMapWriter::new(),
            last_block_size: None,
            block_size,
            max_blocks_to_allocate,
            #[cfg(feature = "seek")]
            last_block_allocated: 0,
            block_mapper: BlockMapper::new(),
            window_size,
        }
    }
}

impl<T> BlockWriter for FileWriter<T>
where
    T: Write + Seek,
{
    fn write_block(&mut self, block: u16, data: &[u8]) -> Result<(usize, bool), StorageError> {
        let expected_index = self.block_mapper.clone().index(block);
        if expected_index > self.current_block_written + 1
            && expected_index - self.current_block_written > self.max_blocks_to_allocate as u64
        {
            return Err(StorageError::CapacityReached);
        }
        let index = self.block_mapper.index(block);
        if index <= self.current_block_written {
            return Err(StorageError::AlreadyWriten);
        }

        if self.window_size > 1 && index > self.current_block_written + 1 {
            return Err(StorageError::ExpectedBlock((
                self.block_mapper.block(self.current_block_written + 1),
                self.block_mapper.block(self.current_block_written),
            )));
        } else {
            #[cfg(feature = "seek")]
            // allow to allocate what is within allowed range
            if index > self.current_block_written + 1 && !self.allocated_blocks.contains_key(&index)
            {
                if self.current_block_written > self.last_block_allocated {
                    self.last_block_allocated = self.current_block_written;
                }

                if index <= self.last_block_allocated {
                    return Err(StorageError::AlreadyWriten);
                }

                // remaining block will be allocated with seek
                let blocks_to_allocate = index - self.last_block_allocated - 1;
                if blocks_to_allocate > 0 {
                    #[allow(unused_must_use)]
                    let mut buffer = {
                        let mut d = DataBlock::new();
                        d.resize(self.block_size as usize, 0);
                        d
                    };

                    for _ in 0..blocks_to_allocate {
                        let position =
                            (self.last_block_allocated as usize) * self.block_size as usize;
                        self.writer.seek(SeekFrom::Start(position as u64))?;
                        self.last_block_allocated += 1;
                        self.allocated_blocks
                            .insert(self.last_block_allocated, true);
                        self.writer.write(&buffer)?;
                    }
                }
                self.last_block_allocated += 1;
            }
            #[cfg(not(feature = "seek"))]
            if index > self.current_block_written + 1 {
                if self.allocated_blocks.contains_key(&index) {
                    return Err(StorageError::AlreadyWriten);
                }
                if data.len() < self.block_size as usize {
                    self.last_block_size = Some(data.len() as u16);
                }
                self.allocated_blocks
                    .insert(index, data.iter().copied().collect());
                return Ok((0, false));
            }
        }

        #[cfg(feature = "seek")]
        let position = (index - 1) * self.block_size as u64;
        #[cfg(feature = "seek")]
        if matches!(self.writer.seek(SeekFrom::Current(0)), Ok(p) if p != position) {
            self.writer.seek(SeekFrom::Start(position))?;
        }
        let mut written = self.writer.write(data)?;
        let remaining_blocks = self.allocated_blocks.len();
        self.allocated_blocks.remove(&index);
        // last packet received
        if data.len() < self.block_size as usize {
            self.last_block_size = Some(data.len() as u16);
        }
        #[cfg(feature = "seek")]
        if remaining_blocks > 0 && self.allocated_blocks.is_empty() {
            self.current_block_written = self.last_block_allocated;
        } else if index == self.current_block_written + 1 {
            self.current_block_written += 1;
        }
        #[cfg(not(feature = "seek"))]
        {
            self.current_block_written += 1;
        }
        #[cfg(not(feature = "seek"))]
        while let Some(b) = self.allocated_blocks.get(&(self.current_block_written + 1)) {
            self.current_block_written += 1;
            written += self.writer.write(b)?;
            self.allocated_blocks.remove(&self.current_block_written);
        }
        let last_in_window = self.current_block_written % self.window_size as u64 == 0;
        Ok((written, last_in_window))
    }

    fn is_finished_below(&self, block_size: u16) -> bool {
        self.current_block_written > 0
            && self.allocated_blocks.is_empty()
            && self.last_block_size.is_some()
            && self.last_block_size < Some(block_size)
    }
}

/// Since not all packet are received/acknowledged this serves as a repeater
pub trait BlockReader {
    fn next(&mut self) -> Result<Option<Block>, StorageError>;
    /// release block returning data size released
    fn free_block(&mut self, block: u16) -> usize;
    fn is_finished(&self) -> bool;
}

#[derive(Debug)]
pub struct FileReader<T> {
    reader: T,
    blocks: BlockMapReader<TimedBlock>,
    max_blocks_in_memory: u16,
    file_reading_finished: bool,
    current_block_read: u64,
    block_size: u16,
    retry_timeout: Duration,
    instant: InstantCallback,
    block_mapper: BlockMapper,
    start_window: u64,
    end_window: u64,
    window_size: u16,
    window_last_read: Instant,
}

impl<T> FileReader<T>
where
    T: Read + Seek,
{
    pub fn from_reader(
        reader: T,
        max_blocks_in_memory: u16,
        block_size: u16,
        retry_timeout: Duration,
        instant: InstantCallback,
        window_size: u16,
    ) -> Self {
        let max_blocks_in_memory = if window_size > 1 {
            window_size
        } else {
            max_blocks_in_memory
        };
        #[cfg(not(feature = "alloc"))]
        assert!(
            max_blocks_in_memory <= crate::config::MAX_BLOCKS_READER,
            "Reader blocks {} must be <= {}",
            max_blocks_in_memory,
            crate::config::MAX_BLOCKS_READER
        );
        Self {
            reader,
            blocks: BlockMapReader::<TimedBlock>::new(),
            max_blocks_in_memory,
            file_reading_finished: false,
            current_block_read: 0,
            block_size,
            retry_timeout,
            instant,
            block_mapper: BlockMapper::new(),
            start_window: 1,
            end_window: window_size as u64,
            window_size,
            window_last_read: instant(),
        }
    }

    fn read_block(&mut self, block: u64) -> Result<Option<DataBlock>, StorageError> {
        let position = (block as u64 - 1) * self.block_size as u64;
        #[cfg(feature = "seek")]
        if matches!(self.reader.seek(SeekFrom::Current(0)), Ok(p) if p != position) {
            self.reader.seek(SeekFrom::Start(position))?;
        }
        #[allow(unused_must_use)]
        let mut buffer = {
            let mut d = DataBlock::new();
            d.resize(self.block_size as usize, 0);
            d
        };
        let read = self.reader.read(&mut buffer)?;
        buffer.truncate(read);
        Ok(Some(buffer))
    }
}

impl<T> BlockReader for FileReader<T>
where
    T: Read + Seek,
{
    fn next(&mut self) -> Result<Option<Block>, StorageError> {
        if self.is_finished() {
            return Ok(None);
        }

        if self.window_size > 1 {
            if self.window_last_read.elapsed() > self.retry_timeout {
                self.window_last_read = (self.instant)();
                self.current_block_read = self.start_window - 1;
            }
            if self.current_block_read == self.end_window {
                return Ok(None);
            }
        } else {
            let block_size = self.blocks.len() as u16;
            let next = self
                .blocks
                .iter_mut()
                .find(|(_, t)| t.last_read.elapsed() >= self.retry_timeout)
                .map(|(b, t)| (b, t));

            if next.is_some()
                || block_size >= self.max_blocks_in_memory
                || self.file_reading_finished
            {
                if let Some((index, t)) = next {
                    t.retry += 1;
                    t.last_read = (self.instant)();
                    let index = *index;
                    let block = self.block_mapper.block(index);
                    debug!(
                        "Retried block {} index {} retries {}",
                        block, index, t.retry
                    );
                    let retry = t.retry;
                    #[cfg(feature = "seek")]
                    return self.read_block(index).map(|o| {
                        o.map(|d| Block {
                            block,
                            data: d,
                            retry,
                            expect_ack: true,
                        })
                    });
                    #[cfg(not(feature = "seek"))]
                    return Ok(Some(Block {
                        block,
                        data: t.data.clone(),
                        retry,
                        expect_ack: true,
                    }));
                } else {
                    return Ok(None);
                };
            }

            let earliest = self
                .blocks
                .iter()
                .min_by(|a, b| a.0.cmp(&b.0))
                .map(|(b, _)| *b);

            if let Some(b) = earliest {
                if self.current_block_read - b >= self.max_blocks_in_memory as u64 {
                    return Ok(None);
                }
            }
        }

        let index = self.current_block_read + 1;
        #[cfg(not(feature = "seek"))]
        if let Some(td) = self.blocks.get_mut(&index) {
            self.window_last_read = (self.instant)();
            td.retry += 1;
            td.last_read = (self.instant)();
            self.current_block_read = index;
            debug!("Retried block {} {}", index, td.retry);
            let block = self.block_mapper.block(index);
            return Ok(Some(Block {
                block,
                data: td.data.clone(),
                retry: td.retry,
                expect_ack: if self.window_size > 1 {
                    self.current_block_read == self.end_window
                } else {
                    true
                },
            }));
        }
        let result = self.read_block(index);
        if matches!(&result, Ok(Some(d)) if d.len() < self.block_size as usize) {
            self.file_reading_finished = true;
            self.end_window = index;
        }
        if let Ok(Some(d)) = &result {
            self.window_last_read = (self.instant)();
            self.current_block_read = index;
            self.blocks.insert(
                index,
                TimedBlock {
                    last_read: (self.instant)(),
                    #[cfg(not(feature = "seek"))]
                    data: d.clone(),
                    retry: 0,
                    size: d.len(),
                },
            );
        }
        let block = self.block_mapper.block(index);
        result.map(|o| {
            o.map(|data| Block {
                block,
                data,
                retry: 0,
                expect_ack: if self.window_size > 1 {
                    self.current_block_read == self.end_window
                } else {
                    true
                },
            })
        })
    }

    fn free_block(&mut self, block: u16) -> usize {
        let index = self.block_mapper.index(block);

        if index > self.current_block_read {
            return 0;
        }
        let mut size = 0;

        if self.window_size <= 1 {
            size += self.blocks.remove(&index).map(|t| t.size).unwrap_or(0);
        } else {
            if index <= self.end_window && index >= self.start_window {
                for b in self.start_window..=index {
                    size += self.blocks.remove(&b).map(|t| t.size).unwrap_or(0);
                }
                self.start_window = index + 1;
                if !self.file_reading_finished {
                    self.end_window = self.start_window + self.window_size as u64 - 1;
                }
            };
        }
        size
    }

    fn is_finished(&self) -> bool {
        self.blocks.is_empty() && self.file_reading_finished
    }
}

#[derive(Debug, Clone, Copy)]
struct BlockMapper {
    current_block_set: u64,
    next_block_set: u64,
}

impl BlockMapper {
    fn new() -> Self {
        Self {
            current_block_set: 1,
            next_block_set: 1,
        }
    }

    fn index(&mut self, block: u16) -> u64 {
        if self.current_block_set == self.next_block_set && block > u16::MAX - 10000 {
            self.next_block_set += 1;
        }
        if self.current_block_set != self.next_block_set {
            if block < 10000 {
                let next_block = self.next_block_set - 1;
                return (next_block * u16::MAX as u64) + block as u64 + next_block;
            } else if block >= 10000 && block < 20000 {
                self.current_block_set += 1;
            }
        }
        let current_block = self.current_block_set - 1;
        let mut index = (current_block * u16::MAX as u64) + block as u64;
        if current_block > 0 {
            index += current_block;
        }
        index
    }

    // block index
    // 0 0
    // 1 1
    // 2 2
    // 3 3
    // 4 4
    // 5 5
    // 0 6
    // 1 7
    // 2 8
    // 3 9
    // 4 10
    // 5 11
    // 0 12
    // 1 13
    // 2 14
    // 3 15
    // 4 16
    // 5 17
    // 0 18
    // 1 19
    // 2 20
    // 3 21
    fn block(&self, index: u64) -> u16 {
        if index > u16::MAX as u64 {
            let part = index / (u16::MAX as u64 + 1);
            return (index - (part * (u16::MAX as u64 + 1))) as u16;
        }
        index as u16
    }
}

#[derive(Debug)]
pub struct Block {
    pub block: u16,
    pub data: DataBlock,
    pub retry: u16,
    pub expect_ack: bool,
}

#[derive(Debug)]
pub struct TimedBlock {
    last_read: Instant,
    #[cfg(not(feature = "seek"))]
    data: DataBlock,
    retry: u16,
    size: usize,
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        sync::{Arc, Mutex},
        thread::sleep,
        vec::Vec,
    };

    use super::*;

    #[test]
    fn test_block_write() {
        let random_bytes: Vec<u8> = (0..102).map(|_| rand::random::<u8>()).collect();
        let cursor = Arc::new(Mutex::new(Cursor::new(vec![])));
        let writer = CursorWriter {
            cursor: cursor.clone(),
        };
        let mut block_writer = FileWriter::from_writer(writer, 20, 4, 1);
        block_writer.write_block(1, &random_bytes[..20]).unwrap();
        let result = block_writer.write_block(1, &random_bytes[..20]);
        assert!(
            matches!(result, Err(StorageError::AlreadyWriten)),
            "{:?}",
            result
        );
        assert!(!block_writer.is_finished_below(20));
        block_writer.write_block(3, &random_bytes[40..60]).unwrap();
        block_writer.write_block(4, &random_bytes[60..80]).unwrap();
        block_writer.write_block(5, &random_bytes[80..100]).unwrap();
        let result = block_writer.write_block(6, &random_bytes[100..102]);
        assert!(
            matches!(result, Err(StorageError::CapacityReached)),
            "{:?}",
            result
        );
        assert!(!block_writer.is_finished_below(20));
        block_writer.write_block(2, &random_bytes[20..40]).unwrap();
        let (result, last_in_window) = block_writer
            .write_block(6, &random_bytes[100..102])
            .unwrap();
        assert_eq!(result, 2);
        assert!(last_in_window);
        assert!(block_writer.is_finished_below(20));
        assert_eq!(&random_bytes, cursor.lock().unwrap().get_ref());
    }

    #[test]
    fn test_block_write_random_order() {
        let random_bytes: Vec<u8> = (0..100).map(|_| rand::random::<u8>()).collect();
        let writer = Cursor::new(vec![]);
        #[cfg(not(feature = "std"))]
        let writer = CursorWriter {
            cursor: Arc::new(Mutex::new(writer)),
        };
        let mut block_writer = FileWriter::from_writer(writer, 20, 4, 1);

        let result = block_writer.write_block(5, &random_bytes[..20]);
        assert!(
            matches!(result, Err(StorageError::CapacityReached)),
            "{:?}",
            result
        );
        block_writer.write_block(1, &random_bytes[..20]).unwrap();
        block_writer.write_block(4, &random_bytes[..20]).unwrap();
        block_writer.write_block(5, &random_bytes[..20]).unwrap();
        let result = block_writer.write_block(5, &random_bytes[..20]);
        assert!(
            matches!(result, Err(StorageError::AlreadyWriten)),
            "{:?}",
            result
        );
        let result = block_writer.write_block(6, &random_bytes[..20]);
        assert!(
            matches!(result, Err(StorageError::CapacityReached)),
            "{:?}",
            result
        );
        let result = block_writer.write_block(9, &random_bytes[..20]);
        assert!(
            matches!(result, Err(StorageError::CapacityReached)),
            "{:?}",
            result
        );
        block_writer.write_block(2, &random_bytes[..20]).unwrap();
        block_writer.write_block(6, &random_bytes[..2]).unwrap();
        assert!(!block_writer.is_finished_below(20));
        let result = block_writer.write_block(2, &random_bytes[..20]);
        assert!(
            matches!(result, Err(StorageError::AlreadyWriten)),
            "{:?}",
            result
        );
        block_writer.write_block(3, &random_bytes[..20]).unwrap();
        assert!(block_writer.is_finished_below(20));
    }

    #[test]
    fn test_block_write_window_size() {
        let random_bytes: Vec<u8> = (0..102).map(|_| rand::random::<u8>()).collect();
        let cursor = Arc::new(Mutex::new(Cursor::new(vec![])));
        let writer = CursorWriter {
            cursor: cursor.clone(),
        };
        let mut block_writer = FileWriter::from_writer(writer, 20, 0, 3);
        let (s, last_in_windown) = block_writer.write_block(1, &random_bytes[..20]).unwrap();
        assert_eq!(s, 20);
        assert!(!last_in_windown);
        let result = block_writer.write_block(1, &random_bytes[..20]);
        assert!(
            matches!(result, Err(StorageError::AlreadyWriten)),
            "{:?}",
            result
        );
        assert!(!block_writer.is_finished_below(20));
        let result = block_writer.write_block(3, &random_bytes[40..60]);
        assert!(
            matches!(result, Err(StorageError::ExpectedBlock(_))),
            "{:?}",
            result
        );
        let result = block_writer.write_block(6, &random_bytes[100..102]);
        assert!(
            matches!(result, Err(StorageError::CapacityReached)),
            "{:?}",
            result
        );
        assert!(!block_writer.is_finished_below(20));

        for i in 2..6_usize {
            let (l, last_in_window) = block_writer
                .write_block(i as u16, &random_bytes[i * 10..2 * i * 10])
                .unwrap();
            assert_eq!(s, 20);
            if i % 3 == 0 {
                assert!(last_in_window);
            } else {
                assert!(!last_in_window);
            }
            assert!(!block_writer.is_finished_below(20));
        }

        let (s, last_in_windown) = block_writer
            .write_block(6, &random_bytes[100..102])
            .unwrap();
        assert_eq!(s, 2);
        assert!(last_in_windown);
        assert!(block_writer.is_finished_below(20));
    }

    #[test]
    fn test_block_write_window_size_1_packet() {
        let random_bytes: Vec<u8> = (0..102).map(|_| rand::random::<u8>()).collect();
        let cursor = Arc::new(Mutex::new(Cursor::new(vec![])));
        let writer = CursorWriter {
            cursor: cursor.clone(),
        };
        let mut block_writer = FileWriter::from_writer(writer, 20, 0, 3);
        let (s, last_in_windown) = block_writer.write_block(1, &random_bytes[..16]).unwrap();
        assert_eq!(s, 16);
        assert!(!last_in_windown);
        assert!(block_writer.is_finished_below(20));
    }

    #[test]
    fn test_block_read() {
        let random_bytes: Vec<u8> = (0..100).map(|_| rand::random::<u8>()).collect();
        let inner_reader = Cursor::new(random_bytes.clone());
        #[cfg(not(feature = "std"))]
        let inner_reader = CursorReader {
            cursor: inner_reader,
        };
        let mut block_reader = FileReader::from_reader(
            inner_reader,
            2,
            20,
            Duration::from_millis(100),
            instant_callback,
            1,
        );

        //can read upto maximum blocks
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 1);
        assert_eq!(&block.data, &random_bytes[0..20]);
        sleep(Duration::from_millis(20));
        let result = block_reader.next().unwrap();
        assert_eq!(result.unwrap().block, 2);
        let result = block_reader.next().unwrap();
        assert!(result.is_none());

        // retry reading last blocks
        sleep(Duration::from_millis(101));
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 1);
        assert_eq!(&block.data, &random_bytes[0..20]);
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 2);
        assert_eq!(&block.data, &random_bytes[20..40]);
        let result = block_reader.next().unwrap();
        assert!(result.is_none());

        // can read more blocks after free
        let size = block_reader.free_block(1);
        assert_eq!(size, 20);
        let result = block_reader.next().unwrap();
        assert_eq!(result.unwrap().block, 3);
        let result = block_reader.next().unwrap();
        assert!(result.is_none());

        let size = block_reader.free_block(2);
        assert_eq!(size, 20);
        let size = block_reader.free_block(3);
        assert_eq!(size, 20);
        let size = block_reader.free_block(4);
        assert_eq!(size, 0);
        let result = block_reader.next().unwrap();
        assert_eq!(result.unwrap().block, 4);
        let result = block_reader.next().unwrap();
        assert_eq!(result.unwrap().block, 5);
        let size = block_reader.free_block(5);
        assert_eq!(size, 20);

        // last block is empty
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 6);
        assert_eq!(block.data, []);
        let block = block_reader.next().unwrap();
        assert!(block.is_none());
        let size = block_reader.free_block(6);
        assert_eq!(size, 0);

        // its not finished until all blocks are freed
        assert!(!block_reader.is_finished(), "{:?}", block_reader);
        let result = block_reader.next().unwrap();
        assert!(result.is_none());

        let size = block_reader.free_block(4);
        assert_eq!(size, 20);
        assert!(block_reader.is_finished(), "{:?}", block_reader);
        let result = block_reader.next().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_block_read_window_size() {
        let random_bytes: Vec<u8> = (0..100).map(|_| rand::random::<u8>()).collect();
        let inner_reader = Cursor::new(random_bytes.clone());
        #[cfg(not(feature = "std"))]
        let inner_reader = CursorReader {
            cursor: inner_reader,
        };
        let mut block_reader = FileReader::from_reader(
            inner_reader,
            2,
            20,
            Duration::from_millis(100),
            instant_callback,
            4,
        );

        let size = block_reader.free_block(1);
        assert_eq!(size, 0);
        let size = block_reader.free_block(1000);
        assert_eq!(size, 0);

        // can free first block
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 1);
        let size = block_reader.free_block(0);
        assert_eq!(size, 0);
        let size = block_reader.free_block(1);
        assert_eq!(size, 20);

        // can free multiple blocks which are less than a windown size
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 2);
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 3);
        let size = block_reader.free_block(3);
        assert_eq!(size, 40);

        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 4);
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 5);
        let size = block_reader.free_block(6);
        assert_eq!(size, 0);
        let size = block_reader.free_block(5);
        assert_eq!(size, 40);
        assert!(!block_reader.is_finished(), "{:?}", block_reader);

        // free last empty block
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 6);
        assert_eq!(block.data, []);
        assert!(!block_reader.is_finished(), "{:?}", block_reader);
        let block = block_reader.next().unwrap();
        assert!(block.is_none());
        let size = block_reader.free_block(6);
        assert_eq!(size, 0);
        assert!(block_reader.is_finished(), "{:?}", block_reader);
        let block = block_reader.next().unwrap();
        assert!(block.is_none());
    }

    #[test]
    fn test_block_read_window_size_full() {
        let random_bytes: Vec<u8> = (0..100).map(|_| rand::random::<u8>()).collect();
        let inner_reader = Cursor::new(random_bytes.clone());
        #[cfg(not(feature = "std"))]
        let inner_reader = CursorReader {
            cursor: inner_reader,
        };
        let mut block_reader = FileReader::from_reader(
            inner_reader,
            2,
            20,
            Duration::from_millis(100),
            instant_callback,
            3,
        );

        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 1);
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 2);
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 3);
        let result = block_reader.next().unwrap();
        assert!(result.is_none());

        let size = block_reader.free_block(3);
        assert_eq!(size, 60);

        assert!(!block_reader.is_finished(), "{:?}", block_reader);

        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 4);
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 5);
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 6);
        let result = block_reader.next().unwrap();
        assert!(result.is_none());

        // read window again after timeout
        sleep(Duration::from_millis(101));

        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 4);
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 5);
        let block = block_reader.next().unwrap().unwrap();
        assert_eq!(block.block, 6);
        let result = block_reader.next().unwrap();
        assert!(result.is_none());
        assert!(!block_reader.is_finished(), "{:?}", block_reader);

        let size = block_reader.free_block(3);
        assert_eq!(size, 0, "{:?}", block_reader);
        let size = block_reader.free_block(4);
        assert_eq!(size, 20, "{:?}", block_reader);
        let result = block_reader.next().unwrap();
        assert!(result.is_none(), "{:?}", block_reader);

        let size = block_reader.free_block(6);
        assert_eq!(size, 20, "{:?}", block_reader);
        assert!(block_reader.is_finished(), "{:?}", block_reader);
    }

    #[test]
    fn test_block_mapper() {
        let mut mapper = BlockMapper::new();
        assert_eq!(0, mapper.block(0));
        assert_eq!(10000, mapper.block(10000));
        assert_eq!(0, mapper.index(0));
        assert_eq!(10000, mapper.index(10000));
        // rollover to next part start
        assert_eq!(u16::MAX as u64, mapper.index(u16::MAX));
        assert_eq!((u16::MAX - 2) as u64, mapper.index(u16::MAX - 2));
        assert_eq!(u16::MAX as u64 + 1, mapper.index(0));
        assert_eq!(u16::MAX as u64 + 3, mapper.index(2));

        assert_eq!(2, mapper.block(2));
        assert_eq!(u16::MAX, mapper.block(u16::MAX as u64));
        assert_eq!(0, mapper.block(u16::MAX as u64 + 1));

        // rollover finished
        assert_eq!(u16::MAX as u64 + 10001, mapper.index(10000));
        assert_eq!(u16::MAX as u64 + 10002, mapper.index(10001));
        assert_eq!(9999, mapper.block(u16::MAX as u64 + 10000));

        // rollover to next part start
        assert_eq!(
            u16::MAX as u64 + u16::MAX as u64 - 9998,
            mapper.index(u16::MAX - 9999)
        );

        assert_eq!(2 * (u16::MAX as u64) + 2, mapper.index(0));
        assert_eq!(2 * (u16::MAX as u64) + 3, mapper.index(1));

        assert_eq!(65534, mapper.block(2 * (u16::MAX as u64)));
        assert_eq!(65535, mapper.block(2 * (u16::MAX as u64) + 1));
        assert_eq!(0, mapper.block(2 * (u16::MAX as u64) + 2));
        assert_eq!(1998, mapper.block(2 * (u16::MAX as u64) + 2000));
        assert_eq!(9997, mapper.block(2 * (u16::MAX as u64) + 9999));
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

    #[cfg(not(feature = "std"))]
    impl Seek for CursorReader {
        fn seek(&mut self, pos: SeekFrom) -> crate::std_compat::io::Result<u64> {
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

    #[derive(Debug)]
    struct CursorWriter {
        cursor: Arc<Mutex<Cursor<Vec<u8>>>>,
    }
    impl Write for CursorWriter {
        fn write(&mut self, buf: &[u8]) -> crate::std_compat::io::Result<usize> {
            use std::io::Write;
            self.cursor.lock().unwrap().write(buf).map_err(|_| {
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

    impl Seek for CursorWriter {
        fn seek(&mut self, pos: SeekFrom) -> crate::std_compat::io::Result<u64> {
            use std::io::Seek;
            let pos = match pos {
                SeekFrom::Start(p) => std::io::SeekFrom::Start(p),
                SeekFrom::Current(p) => std::io::SeekFrom::Current(p),
                SeekFrom::End(p) => std::io::SeekFrom::End(p),
            };
            self.cursor.lock().unwrap().seek(pos).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::Other)
            })
        }
    }

    fn instant_callback() -> Instant {
        #[cfg(feature = "std")]
        return std::time::Instant::now();
        #[cfg(not(feature = "std"))]
        Instant::from_time(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_micros() as u64
        })
    }
}
