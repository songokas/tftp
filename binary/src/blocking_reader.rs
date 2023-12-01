use core::time::Duration;
use std::fs::File;
use std::io::prelude::Read;
use std::io::Result;
use std::io::Seek;
use std::io::SeekFrom;
use std::thread::sleep;

use tftp::error::BoxedResult;
use tftp::types::FilePath;

pub fn create_delayed_reader(
    path: &FilePath,
    block_duration: Duration,
) -> BoxedResult<(Option<u64>, BlockingFile)> {
    let file = File::open(path.as_str())?;
    let file = BlockingFile::new(file, block_duration, 1);
    Ok((None, file))
}

pub struct BlockingFile {
    file: File,
    block_duration: Duration,
    retries: u8,
}

impl BlockingFile {
    pub fn new(file: File, block_duration: Duration, retries: u8) -> Self {
        Self {
            file,
            block_duration,
            retries,
        }
    }
}

impl Read for BlockingFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut retries = self.retries;
        while retries > 0 {
            let result = self.file.read(buf);
            match result {
                Ok(0) => {
                    retries -= 1;
                    sleep(self.block_duration);
                }
                Ok(n) => return Ok(n),
                Err(e) => return Err(e),
            }
        }
        Ok(0)
    }
}

impl Seek for BlockingFile {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        self.file.seek(pos)
    }
}
