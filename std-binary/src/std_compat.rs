pub mod fs {
    pub use tftp_binary_common::io::File;
}

pub mod io {

    use std::io::Cursor as StdCursor;
    use std::io::SeekFrom as StdSeekFrom;
    use std::vec::Vec as StdVec;

    pub use tftp_binary_common::io::from_io_err;
    use tftp_dus::std_compat::io;

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
}
