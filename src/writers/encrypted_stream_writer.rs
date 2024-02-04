use log::error;
use log::trace;

use crate::buffer::new_data_block_07;
use crate::buffer::resize_data_block_07;
use crate::buffer::SliceExt;
use crate::buffer::SliceMutExt;
use crate::config::ENCRYPTION_TAG_SIZE;
use crate::config::MAX_DATA_BLOCK_SIZE;
use crate::encryption::EncryptionKey;
use crate::encryption::StreamDecryptor;
use crate::encryption::MIN_STREAM_CAPACITY;
use crate::error::EncryptionError;
use crate::std_compat::io::ErrorKind;
use crate::std_compat::io::Result;
use crate::std_compat::io::Write;
use crate::types::DataBlock07;

pub struct StreamWriter<W> {
    stream_decryptor: Option<StreamDecryptor>,
    writer: W,
    key: Option<EncryptionKey>,
    block_size: Option<u16>,
    buffer: Option<DataBlock07>,
}

impl<W> StreamWriter<W> {
    pub fn new(writer: W, key: EncryptionKey) -> Self {
        Self {
            stream_decryptor: None,
            writer,
            key: key.into(),
            block_size: None,
            buffer: None,
        }
    }
}

impl<W: Write> Write for StreamWriter<W> {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        let from = if let Some(key) = self.key.as_ref() {
            let block_size_bytes = data.slice_to_array(0_usize).ok_or(ErrorKind::InvalidData)?;
            let block_size = u16::from_be_bytes(block_size_bytes);

            if !(MIN_STREAM_CAPACITY as u16..=MAX_DATA_BLOCK_SIZE).contains(&block_size) {
                error!(
                    "Invalid block size received {block_size} expected from {} to {}",
                    MIN_STREAM_CAPACITY, MAX_DATA_BLOCK_SIZE
                );
                return Err(ErrorKind::InvalidData.into());
            }

            let nonce = data
                .slice_to_array(block_size_bytes.len())
                .ok_or(ErrorKind::InvalidData)?;

            self.stream_decryptor = StreamDecryptor::new(key, &nonce).into();
            self.block_size = block_size.into();
            self.buffer = new_data_block_07(block_size).into();

            nonce.len() + block_size_bytes.len()
        } else {
            0
        };

        let provided_block_size = self.block_size.ok_or(ErrorKind::Unsupported)?;
        let buffer = self.buffer.as_mut().ok_or(ErrorKind::Unsupported)?;
        resize_data_block_07(buffer, provided_block_size);

        let size = buffer
            .write_bytes(data.get(from..).ok_or(ErrorKind::InvalidData)?, 0_usize)
            .ok_or(ErrorKind::InvalidData)?;
        buffer.truncate(size);

        let block_size = (provided_block_size - from as u16) as usize;

        trace!("Decrypting file block {buffer:x?}");

        self.stream_decryptor
            .as_mut()
            .ok_or(ErrorKind::Unsupported)?
            .decrypt(buffer, block_size)
            .map_err(|e| {
                if matches!(e, EncryptionError::NoStream) {
                    ErrorKind::Unsupported
                } else {
                    error!("Unable to decrypt data. Data length {}, block size {block_size}. Client block size must be {provided_block_size} (adding encryption headers if necessary)", buffer.len());
                    ErrorKind::InvalidData
                }
            })?;

        let written = self
            .writer
            .write(buffer)
            .map(|s| s + from + ENCRYPTION_TAG_SIZE as usize)?;

        self.key.take();

        Ok(written)
    }

    fn write_fmt(&mut self, _fmt: core::fmt::Arguments<'_>) -> Result<()> {
        unimplemented!()
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::vec::Vec;

    use super::*;

    #[test]
    fn test_write() {
        const BLOCK_SIZE: usize = 90;
        let cursor = Cursor::new(Vec::new());
        let mut writer = StreamWriter::new(
            cursor,
            [
                1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233,
                200, 17, 22, 29, 93, 32, 1,
            ],
        );
        let buffer = create_data();
        let s = writer.write(&buffer[..BLOCK_SIZE]).unwrap();
        assert_eq!(s, BLOCK_SIZE);

        let s = writer
            .write(&buffer[BLOCK_SIZE..BLOCK_SIZE + BLOCK_SIZE])
            .unwrap();
        assert_eq!(s, BLOCK_SIZE);

        let s = writer.write(&buffer[BLOCK_SIZE + BLOCK_SIZE..]).unwrap();
        assert_eq!(s, BLOCK_SIZE - 2);

        let err = writer.write(&buffer).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);

        let err = writer.write(&buffer[..BLOCK_SIZE]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn test_write_invalid() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = StreamWriter::new(
            cursor,
            [
                1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233,
                200, 17, 22, 29, 93, 32, 1,
            ],
        );
        let result = writer.write(&[]);
        assert!(result.is_err());
        let buffer = create_data();
        let result = writer.write(&buffer);
        assert!(result.is_err());

        let result = writer.write(&buffer[3..4]);
        assert!(result.is_err());

        let result = writer.write(&buffer[..200]);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_invalid_block_size() {
        const BLOCK_SIZE: usize = 90;
        let cursor = Cursor::new(Vec::new());
        let mut writer = StreamWriter::new(
            cursor,
            [
                1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233,
                200, 17, 22, 29, 93, 32, 1,
            ],
        );
        let buffer = create_data();
        let s = writer.write(&buffer[..BLOCK_SIZE]).unwrap();
        assert_eq!(s, BLOCK_SIZE);

        let err = writer.write(&buffer[..BLOCK_SIZE]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);

        let err = writer.write(&buffer).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn test_write_failure() {
        let writer = AlwaysFailWriter {};
        const BLOCK_SIZE: usize = 90;
        let mut writer = StreamWriter::new(
            writer,
            [
                1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233,
                200, 17, 22, 29, 93, 32, 1,
            ],
        );

        let buffer = create_data();
        let err = writer.write(&buffer[..BLOCK_SIZE]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(writer.key.is_some());
    }

    fn create_data() -> [u8; 268] {
        [
            0, 90, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 129, 194, 13, 194,
            245, 92, 95, 109, 177, 152, 198, 220, 54, 46, 204, 2, 204, 55, 86, 16, 113, 193, 145,
            101, 49, 250, 228, 60, 191, 219, 59, 170, 104, 96, 189, 21, 193, 228, 238, 154, 139,
            137, 132, 136, 206, 158, 68, 29, 229, 204, 82, 130, 220, 180, 167, 173, 10, 192, 140,
            32, 107, 208, 44, 17, 165, 69, 182, 26, 144, 129, 244, 62, 205, 9, 75, 147, 108, 246,
            140, 184, 37, 147, 139, 57, 150, 244, 157, 29, 30, 100, 143, 245, 120, 195, 75, 96, 34,
            98, 100, 72, 144, 219, 28, 169, 187, 126, 45, 24, 61, 137, 243, 17, 62, 218, 39, 203,
            15, 45, 141, 65, 220, 165, 52, 149, 212, 28, 97, 87, 254, 240, 117, 240, 229, 74, 11,
            155, 130, 132, 220, 75, 128, 230, 195, 190, 249, 1, 96, 143, 130, 171, 245, 237, 97,
            241, 91, 224, 242, 8, 134, 226, 135, 240, 151, 189, 20, 2, 165, 47, 176, 168, 145, 240,
            118, 117, 31, 109, 226, 97, 47, 206, 26, 194, 54, 232, 173, 29, 73, 87, 189, 131, 100,
            207, 113, 66, 190, 193, 246, 255, 70, 211, 108, 107, 152, 164, 13, 102, 90, 172, 219,
            3, 183, 138, 7, 86, 110, 72, 2, 163, 249, 173, 66, 99, 117, 102, 101, 98, 11, 43, 118,
            77, 23, 204, 198, 196, 229, 144, 40, 38, 12, 244, 157, 169, 98, 14, 196, 180, 221,
        ]
    }

    #[cfg(not(feature = "std"))]
    impl Write for Cursor<Vec<u8>> {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            std::io::Write::write(self, buf).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::Other)
            })
        }
        fn write_fmt(&mut self, _: core::fmt::Arguments<'_>) -> Result<()> {
            todo!()
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    struct AlwaysFailWriter {}

    impl Write for AlwaysFailWriter {
        fn write(&mut self, _buf: &[u8]) -> Result<usize> {
            Err(Into::into(ErrorKind::Unsupported))
        }

        fn write_fmt(&mut self, _fmt: core::fmt::Arguments<'_>) -> Result<()> {
            Err(Into::into(ErrorKind::Unsupported))
        }

        fn flush(&mut self) -> Result<()> {
            Err(Into::into(ErrorKind::Unsupported))
        }
    }
}
