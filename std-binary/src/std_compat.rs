pub mod fs {
    pub use tftp_binary_common::io::File;
}

pub mod io {
    use std::io::Cursor;

    pub use tftp_binary_common::io::from_io_err;
    use tftp_dus::std_compat::io;
    use tftp_dus::types::DataBuffer;

    use crate::std_compat::fs::File;

    pub type BytesCursor = Cursor<DataBuffer>;

    // boxing the list would allocate for every download
    #[allow(clippy::large_enum_variant)]
    pub enum ServerReader {
        File(File),
        List(BytesCursor),
    }

    impl io::Seek for ServerReader {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            match self {
                Self::File(f) => io::Seek::seek(f, pos),
                Self::List(f) => io::Seek::seek(f, pos),
            }
        }
    }

    impl io::Read for ServerReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self {
                Self::File(f) => io::Read::read(f, buf),
                Self::List(f) => io::Read::read(f, buf),
            }
        }
    }
}
