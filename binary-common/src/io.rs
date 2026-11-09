use tftp_dus::std_compat::io;

#[cfg(feature = "std")]
mod implementation {
    use std::fs::File as StdFile;
    pub use std::fs::File;
    use std::io::BufReader;

    use super::io;

    pub type LineReader = BufReader<StdFile>;

    pub fn from_io_err(err: std::io::Error) -> io::Error {
        err
    }

    pub fn create_line_reader(path: &str) -> io::Result<LineReader> {
        Ok(BufReader::new(StdFile::open(path)?))
    }
}

#[cfg(not(feature = "std"))]
mod implementation {
    use std::fs::File as StdFile;

    use tftp_dus::types::DefaultString;

    use super::io;

    const LINE_BUFFER_SIZE: usize = 512;

    /// std::io::Error must not be displayed by callers without `std`: formatting
    /// an OS error allocates, while the kind returned here does not.
    pub fn from_io_err(err: std::io::Error) -> io::Error {
        use std::io::ErrorKind as Std;
        io::Error::from(match err.kind() {
            Std::NotFound => io::ErrorKind::NotFound,
            Std::PermissionDenied => io::ErrorKind::PermissionDenied,
            Std::ConnectionRefused => io::ErrorKind::ConnectionRefused,
            Std::ConnectionReset => io::ErrorKind::ConnectionReset,
            Std::ConnectionAborted => io::ErrorKind::ConnectionAborted,
            Std::NotConnected => io::ErrorKind::NotConnected,
            Std::AddrInUse => io::ErrorKind::AddrInUse,
            Std::AddrNotAvailable => io::ErrorKind::AddrNotAvailable,
            Std::BrokenPipe => io::ErrorKind::BrokenPipe,
            Std::AlreadyExists => io::ErrorKind::AlreadyExists,
            Std::WouldBlock => io::ErrorKind::WouldBlock,
            Std::InvalidInput => io::ErrorKind::InvalidInput,
            Std::InvalidData => io::ErrorKind::InvalidData,
            Std::TimedOut => io::ErrorKind::TimedOut,
            Std::WriteZero => io::ErrorKind::WriteZero,
            Std::Interrupted => io::ErrorKind::Interrupted,
            Std::UnexpectedEof => io::ErrorKind::UnexpectedEof,
            Std::OutOfMemory => io::ErrorKind::OutOfMemory,
            _ => io::ErrorKind::Other,
        })
    }

    pub struct File(StdFile);

    impl From<StdFile> for File {
        fn from(file: StdFile) -> Self {
            Self(file)
        }
    }

    impl io::Read for File {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            std::io::Read::read(&mut self.0, buf).map_err(from_io_err)
        }
    }

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
                io::SeekFrom::Start(p) => std::io::SeekFrom::Start(p),
                io::SeekFrom::Current(p) => std::io::SeekFrom::Current(p),
                io::SeekFrom::End(p) => std::io::SeekFrom::End(p),
            };
            std::io::Seek::seek(&mut self.0, pos).map_err(from_io_err)
        }
    }

    /// Fixed buffer replacement for std::io::BufReader, which allocates.
    pub struct LineReader {
        reader: StdFile,
        buffer: [u8; LINE_BUFFER_SIZE],
        position: usize,
        length: usize,
    }

    impl LineReader {
        fn next_byte(&mut self) -> io::Result<Option<u8>> {
            if self.position == self.length {
                self.position = 0;
                self.length = loop {
                    match std::io::Read::read(&mut self.reader, &mut self.buffer) {
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        result => break result.map_err(from_io_err)?,
                    }
                };
                if self.length == 0 {
                    return Ok(None);
                }
            }
            let byte = self.buffer[self.position];
            self.position += 1;
            Ok(Some(byte))
        }
    }

    impl io::BufRead for LineReader {
        fn read_line(&mut self, buff: &mut DefaultString) -> io::Result<usize> {
            let mut line = [0_u8; LINE_BUFFER_SIZE];
            let mut total = 0;
            // an overlong line is consumed whole so the next call starts on a new line
            while let Some(byte) = self.next_byte()? {
                if let Some(slot) = line.get_mut(total) {
                    *slot = byte;
                }
                total += 1;
                if byte == b'\n' {
                    break;
                }
            }
            let text = line
                .get(..total)
                .and_then(|l| core::str::from_utf8(l).ok())
                .ok_or(io::Error::from(io::ErrorKind::InvalidData))?;
            buff.push_str(text)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            Ok(total)
        }
    }

    pub fn create_line_reader(path: &str) -> io::Result<LineReader> {
        Ok(LineReader {
            reader: StdFile::open(path).map_err(from_io_err)?,
            buffer: [0; LINE_BUFFER_SIZE],
            position: 0,
            length: 0,
        })
    }
}

pub use implementation::*;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tftp_dus::std_compat::io::BufRead;

    use super::*;

    fn write_sample(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("tftp-common-{}-{name}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn test_line_reader_reads_lines_without_terminator_on_last() {
        let path = write_sample("lines", "first\r\n\nlast");
        let reader = create_line_reader(path.to_str().unwrap()).unwrap();
        let lines: Vec<_> = reader.lines().map(|l| l.unwrap()).collect();
        std::fs::remove_file(path).unwrap();
        let lines: Vec<&str> = lines.iter().map(|l| l.as_str()).collect();
        assert_eq!(lines, ["first", "", "last"]);
    }

    #[test]
    fn test_create_line_reader_missing_file() {
        let result = create_line_reader("/nonexistent/tftp-common");
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::NotFound);
    }

    #[cfg(not(feature = "std"))]
    #[test]
    fn test_overlong_line_is_rejected_and_next_line_is_intact() {
        let contents = format!("{}\nshort\n", "a".repeat(2000));
        let path = write_sample("long", &contents);
        let mut lines = create_line_reader(path.to_str().unwrap()).unwrap().lines();
        let first = lines.next().unwrap();
        let second = lines.next().unwrap().unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(first.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(second.as_str(), "short");
    }
}
