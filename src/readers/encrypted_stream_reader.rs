use log::error;
use log::trace;

use crate::buffer::new_stream_block;
use crate::buffer::resize_stream_block;
use crate::buffer::SliceMutExt;
use crate::config::ENCRYPTION_TAG_SIZE;
use crate::config::MAX_DATA_BLOCK_SIZE;
use crate::encryption::StreamEncryptor;
use crate::encryption::StreamNonce;
use crate::encryption::MIN_STREAM_CAPACITY;
use crate::error::EncryptionError;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::io::Read;
use crate::std_compat::io::Result;
use crate::std_compat::io::Seek;
use crate::std_compat::io::SeekFrom;
use crate::types::StreamBlock;

// layout: block size 2, nonce 19, blocks with encryption tag 16
pub struct StreamReader<R> {
    stream_encryptor: StreamEncryptor,
    reader: R,
    nonce: Option<StreamNonce>,
    buffer: Option<StreamBlock>,
}

impl<R> StreamReader<R> {
    pub fn new(stream_encryptor: StreamEncryptor, reader: R, nonce: StreamNonce) -> Self {
        Self {
            stream_encryptor,
            reader,
            nonce: nonce.into(),
            buffer: None,
        }
    }
}

/// Number of bytes `StreamReader` produces from `plain_size` bytes when it is
/// read `block_size` bytes at a time. `None` if the block size can not hold a stream.
pub fn encrypted_stream_size(plain_size: u64, block_size: u16) -> Option<u64> {
    if !(MIN_STREAM_CAPACITY as u16..=MAX_DATA_BLOCK_SIZE).contains(&block_size) {
        return None;
    }
    let block_size = block_size as u64;
    let tag_size = ENCRYPTION_TAG_SIZE as u64;
    let first_block_capacity = block_size - MIN_STREAM_CAPACITY as u64;
    let Some(remaining) = plain_size.checked_sub(first_block_capacity) else {
        return plain_size.checked_add(MIN_STREAM_CAPACITY as u64);
    };
    let block_capacity = block_size - tag_size;
    // the last block is never full, it is empty when the data ends on a block boundary
    (remaining / block_capacity)
        .checked_add(1)?
        .checked_mul(block_size)?
        .checked_add(remaining % block_capacity + tag_size)
}

impl<R: Read> Read for StreamReader<R> {
    fn read(&mut self, data: &mut [u8]) -> Result<usize> {
        if !(MIN_STREAM_CAPACITY as usize..=MAX_DATA_BLOCK_SIZE as usize).contains(&data.len()) {
            return Err(ErrorKind::Unsupported.into());
        }

        let from = if let Some(nonce) = self.nonce.as_ref() {
            let block_size = data.len() as u16;
            let s = data
                .write_bytes(block_size.to_be_bytes(), 0_usize)
                .ok_or(ErrorKind::InvalidData)?;

            // we do not expect the buffer size to change
            if self.buffer.is_none() {
                self.buffer = new_stream_block(block_size).into();
            }

            data.write_bytes(nonce, s).ok_or(ErrorKind::InvalidData)?
        } else {
            0
        };

        let buffer = self.buffer.as_mut().ok_or(ErrorKind::Unsupported)?;
        let block_size = data.len() - ENCRYPTION_TAG_SIZE as usize - from;
        resize_stream_block(buffer, block_size);

        let read_count = self
            .reader
            .read(buffer.get_mut(..block_size).ok_or(ErrorKind::InvalidData)?)?;
        buffer.truncate(read_count);

        trace!("Encrypting file block {buffer:x?}");

        self.stream_encryptor
            .encrypt(buffer, block_size)
            .map_err(|e| {
                if matches!(e, EncryptionError::NoStream) {
                    ErrorKind::Unsupported
                } else {
                    ErrorKind::InvalidData
                }
            })?;

        let written = data
            .write_bytes(buffer, from)
            .ok_or(ErrorKind::InvalidData)?;

        self.nonce.take();

        Ok(written)
    }
}

impl<S: Seek> Seek for StreamReader<S> {
    fn seek(&mut self, _pos: SeekFrom) -> Result<u64> {
        error!("Can not seek streaming encryption");
        Err(ErrorKind::Unsupported.into())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::vec::Vec;

    use super::*;
    use crate::std_compat::io::ErrorKind;
    use crate::std_compat::io::Read;
    use crate::std_compat::io::Result;

    #[test]
    fn test_read() {
        let data: Vec<u8> = (1..200).collect();
        const BLOCK_SIZE: usize = 90;
        let cursor = Cursor::new(data);
        let encryptor = create_stream_encryptor();
        let mut reader = StreamReader::new(
            encryptor,
            cursor,
            [1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3],
        );

        let mut buffer: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let s = reader.read(&mut buffer).unwrap();
        assert_eq!(s, BLOCK_SIZE);

        let s = reader.read(&mut buffer).unwrap();
        assert_eq!(s, BLOCK_SIZE);

        let s = reader.read(&mut buffer).unwrap();
        assert_eq!(s, 88);

        let err = reader.read(&mut buffer).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn test_encrypted_stream_size_matches_reader() {
        const NONCE: [u8; 19] = [1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3];
        for block_size in [MIN_STREAM_CAPACITY as u16, 38, 90, 512] {
            let first_block = block_size as usize - MIN_STREAM_CAPACITY as usize;
            let next_block = block_size as usize - ENCRYPTION_TAG_SIZE as usize;
            let boundary = first_block + next_block * 2;
            for plain_size in (0..200).chain(boundary - 2..boundary + 3) {
                let mut reader = StreamReader::new(
                    create_stream_encryptor(),
                    Cursor::new(vec![7_u8; plain_size]),
                    NONCE,
                );
                let mut buffer = vec![0_u8; block_size as usize];
                let mut total = 0;
                loop {
                    let read = reader.read(&mut buffer).unwrap();
                    total += read;
                    if read < block_size as usize {
                        break;
                    }
                }
                assert_eq!(
                    encrypted_stream_size(plain_size as u64, block_size),
                    Some(total as u64),
                    "plain size {plain_size} block size {block_size}"
                );
            }
        }
    }

    #[test]
    fn test_encrypted_stream_size_limits() {
        assert_eq!(
            encrypted_stream_size(10, MIN_STREAM_CAPACITY as u16 - 1),
            None
        );
        assert_eq!(encrypted_stream_size(u64::MAX, 90), None);
    }

    #[test]
    fn test_read_invalid() {
        let data: Vec<u8> = (1..200).collect();
        let cursor = Cursor::new(data);
        let encryptor = create_stream_encryptor();
        let mut reader = StreamReader::new(
            encryptor,
            cursor,
            [1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3],
        );

        let result = reader.read(&mut []);
        assert!(result.is_err());
        let mut buffer = vec![0];
        let result = reader.read(&mut buffer);
        assert!(result.is_err());
        buffer.resize(u16::MAX as usize, 0);
        let result = reader.read(&mut buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_failure() {
        let reader = AlwaysFailReader {};
        let encryptor = create_stream_encryptor();
        let mut reader = StreamReader::new(
            encryptor,
            reader,
            [1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3],
        );

        let mut buffer = [0_u8; 100];
        let result = reader.read(&mut buffer);
        assert!(matches!(result.unwrap_err().kind(), ErrorKind::Unsupported));
        assert!(reader.nonce.is_some());
    }

    fn create_stream_encryptor() -> StreamEncryptor {
        StreamEncryptor::new(
            &[
                1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233,
                200, 17, 22, 29, 93, 32, 1,
            ],
            &[1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3],
        )
    }

    struct AlwaysFailReader {}

    impl Read for AlwaysFailReader {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize> {
            Err(Into::into(ErrorKind::Unsupported))
        }
    }
}
