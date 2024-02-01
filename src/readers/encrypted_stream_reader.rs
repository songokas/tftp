use log::error;

use crate::buffer::new_data_block_07;
use crate::buffer::resize_data_block_07;
use crate::buffer::SliceMutExt;
use crate::config::ENCRYPTION_TAG_SIZE;
use crate::encryption::StreamEncryptor;
use crate::encryption::StreamNonce;
use crate::encryption::STREAM_BLOCK_SIZE;
use crate::encryption::STREAM_NONCE_SIZE;
use crate::error::EncryptionError;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::io::Read;
use crate::std_compat::io::Result;
use crate::std_compat::io::Seek;
use crate::std_compat::io::SeekFrom;
use crate::types::DataBlock07;

const MIN_CAPACITY: u8 = STREAM_BLOCK_SIZE + STREAM_NONCE_SIZE + ENCRYPTION_TAG_SIZE;

// layout: block size 2, nonce 19, blocks with encryption tag 16
pub struct StreamReader<R> {
    stream_encryptor: StreamEncryptor,
    reader: R,
    nonce: Option<StreamNonce>,
    buffer: Option<DataBlock07>,
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

impl<R: Read> Read for StreamReader<R> {
    fn read(&mut self, data: &mut [u8]) -> Result<usize> {
        if !(MIN_CAPACITY as usize..u16::MAX as usize).contains(&data.len()) {
            return Err(ErrorKind::Unsupported.into());
        }

        let from = if let Some(nonce) = self.nonce.take() {
            let block_size = data.len() as u16;
            let s = data
                .write_bytes(block_size.to_be_bytes(), 0_usize)
                .ok_or(ErrorKind::InvalidData)?;
            self.buffer = new_data_block_07(block_size).into();
            data.write_bytes(nonce, s).ok_or(ErrorKind::InvalidData)?
        } else {
            0
        };

        let buffer = self.buffer.as_mut().ok_or(ErrorKind::Unsupported)?;
        let block_size = data.len() - ENCRYPTION_TAG_SIZE as usize - from;
        resize_data_block_07(buffer, block_size);

        let read_count = self
            .reader
            .read(buffer.get_mut(..block_size).ok_or(ErrorKind::InvalidData)?)?;
        buffer.truncate(read_count);
        
        self.stream_encryptor
            .encrypt(buffer, block_size)
            .map_err(|e| {
                if matches!(e, EncryptionError::NoStream) {
                    ErrorKind::Unsupported
                } else {
                    ErrorKind::InvalidData
                }
            })?;

        data.write_bytes(buffer, from)
            .ok_or(ErrorKind::InvalidData)
            .map_err(Into::into)
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

    fn create_stream_encryptor() -> StreamEncryptor {
        StreamEncryptor::new(
            &[
                1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233,
                200, 17, 22, 29, 93, 32, 1,
            ],
            &[1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3],
        )
    }
}
