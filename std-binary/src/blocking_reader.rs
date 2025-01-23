use std::fs::File;
use std::io::prelude::Read;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::io::Seek;
use std::io::SeekFrom;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use log::trace;
use tftp_dus::error::BoxedResult;
use tftp_dus::types::FilePath;

pub fn create_delayed_reader(
    path: &FilePath,
    finished: Arc<AtomicBool>,
) -> BoxedResult<(Option<u64>, BlockingReader<File>)> {
    let file = File::open(path.as_str())?;
    let file = BlockingReader::new(file, finished);
    Ok((None, file))
}

pub struct BlockingReader<R> {
    file: R,
    finished: Arc<AtomicBool>,
    // store read data in temporary buffer
    temp_buf: Vec<u8>,
}

impl<R> BlockingReader<R> {
    pub fn new(file: R, finished: Arc<AtomicBool>) -> Self {
        Self {
            file,
            finished,
            temp_buf: Vec::new(),
        }
    }
}

impl<R: Read> Read for BlockingReader<R> {
    // reader will error with WouldBlock if there is no data to read
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let expected_size = buffer.len();
        let result = if !self.temp_buf.is_empty() {
            let temp_len = self.temp_buf.len();
            for (to_buf, data) in buffer.iter_mut().zip(self.temp_buf.iter()) {
                *to_buf = *data
            }
            self.temp_buf.clear();

            self.file
                .read(buffer.get_mut(temp_len..).ok_or(ErrorKind::InvalidData)?)
                .map(|s| temp_len + s)
        } else {
            self.file.read(buffer)
        };
        match result {
            Ok(0) => {
                if self.finished.load(Ordering::Relaxed) {
                    return Ok(0);
                }

                trace!("Not enough data: read 0 expected {expected_size}");

                Err(Error::from(ErrorKind::WouldBlock))
            }
            Ok(n) if expected_size == n => Ok(n),
            Ok(n) => {
                if self.finished.load(Ordering::Relaxed) {
                    return Ok(n);
                }

                self.temp_buf = buffer[..n].to_vec();

                trace!("Not enough data: read {n} expected {expected_size}");

                Err(Error::from(ErrorKind::WouldBlock))
            }
            Err(e) => Err(e),
        }
    }
}

impl<S: Seek> Seek for BlockingReader<S> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        self.temp_buf.clear();
        self.file.seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn test_blocking_read() {
        let bytes_to_send = [1, 2, 3, 4, 5];
        let bytes_expected = vec![1, 2, 3, 4, 5];
        let mut cursor = CursorMutex {
            cursor: Arc::new(Mutex::new(vec![])),
            pos: 0,
        };
        let mut received: Vec<u8> = Vec::new();
        let finished = Arc::new(AtomicBool::new(false));
        let mut blocking_reader = BlockingReader::new(cursor.clone(), finished.clone());

        let mut buff: [u8; 2] = [0; 2];
        let result = blocking_reader.read(&mut buff);
        assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::WouldBlock));
        assert_eq!(blocking_reader.temp_buf.len(), 0);

        let _ = cursor.write(&[bytes_to_send[0]]).unwrap();
        let result = blocking_reader.read(&mut buff);
        assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::WouldBlock));
        assert_eq!(blocking_reader.temp_buf.len(), 1);

        let _ = cursor.write(&[bytes_to_send[1]]).unwrap();
        let read = blocking_reader.read(&mut buff).unwrap();
        assert_eq!(read, 2);
        assert_eq!(blocking_reader.temp_buf.len(), 0);
        received.extend(&buff[..read]);

        let _ = cursor.write(&[bytes_to_send[2]]).unwrap();
        let _ = cursor.write(&[bytes_to_send[3]]).unwrap();
        let _ = cursor.write(&[bytes_to_send[4]]).unwrap();

        let read = blocking_reader.read(&mut buff).unwrap();
        assert_eq!(blocking_reader.temp_buf.len(), 0);
        assert_eq!(read, 2);
        received.extend(&buff[..read]);

        let result = blocking_reader.read(&mut buff);
        assert_eq!(blocking_reader.temp_buf.len(), 1);
        assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::WouldBlock));

        finished.store(true, Ordering::Relaxed);

        let read = blocking_reader.read(&mut buff).unwrap();
        assert_eq!(read, 1);
        received.extend(&buff[..read]);

        assert_eq!(bytes_expected, received);
    }

    #[derive(Debug, Clone)]
    struct CursorMutex {
        cursor: Arc<Mutex<Vec<u8>>>,
        pos: usize,
    }
    impl Read for CursorMutex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let d = self.cursor.lock().unwrap();
            let read = d.as_slice()[self.pos..].as_ref().read(buf).unwrap();
            self.pos += read;
            Ok(read)
        }
    }

    impl Write for CursorMutex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.cursor.lock().unwrap().write(buf)
        }
        fn write_fmt(&mut self, _: core::fmt::Arguments<'_>) -> io::Result<()> {
            todo!()
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
