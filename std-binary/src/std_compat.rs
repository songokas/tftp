pub mod fs {

    use std::fs::File as StdFile;
    use std::io::SeekFrom as StdSeekFrom;

    use tftp_dus::std_compat::io;

    use crate::std_compat::io::from_io_err;

    pub struct File(StdFile);

    impl io::Write for File {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            std::io::Write::write(&mut self.0, buf).map_err(from_io_err)
        }

        fn write_fmt(&mut self, fmt: core::fmt::Arguments<'_>) -> io::Result<()> {
            std::io::Write::write_fmt(&mut self.0, fmt).map_err(from_io_err)
        }

        fn flush(&mut self) -> io::Result<()> {
            std::io::Write::flush(&mut self.0).map_err(from_io_err)
        }
    }

    impl io::Seek for File {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            let pos = match pos {
                io::SeekFrom::Start(p) => StdSeekFrom::Start(p),
                io::SeekFrom::Current(p) => StdSeekFrom::Current(p),
                io::SeekFrom::End(p) => StdSeekFrom::End(p),
            };
            std::io::Seek::seek(&mut self.0, pos).map_err(|_| io::Error::from(io::ErrorKind::Other))
        }
    }

    impl io::Read for File {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            std::io::Read::read(&mut self.0, buf).map_err(from_io_err)
        }
    }

    impl Into<File> for StdFile {
        fn into(self) -> File {
            File(self)
        }
    }
}

pub mod io {

    use std::io::BufReader as StdBufReader;
    use std::io::Cursor as StdCursor;
    use std::io::Error as StdError;
    use std::io::ErrorKind as StdErrorKind;
    use std::io::SeekFrom as StdSeekFrom;
    use std::vec::Vec as StdVec;

    use tftp_dus::std_compat::io;
    use tftp_dus::types::DefaultString;

    use crate::std_compat::fs::File;

    pub struct BytesCursor(StdCursor<StdVec<u8>>);

    impl BytesCursor {
        pub fn new(c: StdVec<u8>) -> Self {
            Self(StdCursor::new(c))
        }
    }

    impl io::Read for BytesCursor {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            std::io::Read::read(&mut self.0, buf).map_err(from_io_err)
        }
    }

    impl io::Seek for BytesCursor {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            let pos = match pos {
                io::SeekFrom::Start(p) => StdSeekFrom::Start(p),
                io::SeekFrom::Current(p) => StdSeekFrom::Current(p),
                io::SeekFrom::End(p) => StdSeekFrom::End(p),
            };
            std::io::Seek::seek(&mut self.0, pos).map_err(|_| io::Error::from(io::ErrorKind::Other))
        }
    }

    pub struct BufReader<T>(StdBufReader<T>);

    impl<T: std::io::Read> BufReader<T> {
        pub fn new(file: T) -> Self {
            Self(StdBufReader::new(file))
        }
    }

    impl<T: std::io::Read> io::BufRead for BufReader<T> {
        fn read_line(&mut self, buf: &mut DefaultString) -> io::Result<usize> {
            // TODO alloc in stack
            let mut s = String::with_capacity(buf.capacity());
            let result = std::io::BufRead::read_line(&mut self.0, &mut s).map_err(from_io_err);
            let _result = buf.push_str(s.as_str());
            #[cfg(not(feature = "alloc"))]
            _result.map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            result
        }
    }

    pub enum BoxedReader {
        File(File),
        List(BytesCursor),
    }

    impl io::Seek for BoxedReader {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            match self {
                Self::File(f) => f.seek(pos),
                Self::List(f) => f.seek(pos),
            }
        }
    }

    impl io::Read for BoxedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self {
                Self::File(f) => f.read(buf),
                Self::List(f) => f.read(buf),
            }
        }
    }

    pub fn from_io_err(err: StdError) -> io::Error {
        io::Error::from(match err.kind() {
            StdErrorKind::NotFound => io::ErrorKind::NotFound,
            StdErrorKind::PermissionDenied => io::ErrorKind::PermissionDenied,
            StdErrorKind::ConnectionRefused => io::ErrorKind::ConnectionRefused,
            StdErrorKind::ConnectionReset => io::ErrorKind::ConnectionReset,
            StdErrorKind::ConnectionAborted => io::ErrorKind::ConnectionAborted,
            StdErrorKind::NotConnected => io::ErrorKind::NotConnected,
            StdErrorKind::AddrInUse => io::ErrorKind::AddrInUse,
            StdErrorKind::BrokenPipe => io::ErrorKind::BrokenPipe,
            StdErrorKind::AlreadyExists => io::ErrorKind::AlreadyExists,
            StdErrorKind::WouldBlock => io::ErrorKind::WouldBlock,
            StdErrorKind::InvalidInput => io::ErrorKind::InvalidInput,
            StdErrorKind::InvalidData => io::ErrorKind::InvalidData,
            StdErrorKind::TimedOut => io::ErrorKind::TimedOut,
            StdErrorKind::WriteZero => io::ErrorKind::WriteZero,
            StdErrorKind::Interrupted => io::ErrorKind::Interrupted,
            StdErrorKind::UnexpectedEof => io::ErrorKind::UnexpectedEof,
            StdErrorKind::OutOfMemory => io::ErrorKind::OutOfMemory,
            _ => io::ErrorKind::Other,
        })
    }
}
