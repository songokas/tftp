use std::{fs::File, path::PathBuf};

use tftp::{
    config::{ConnectionOptions, MAX_EXTENSION_VALUE_SIZE},
    encryption::{decode_private_key, PrivateKey},
    error::{BoxedResult, EncryptionError, FileError},
    server::ServerConfig,
    std_compat::io,
    types::FilePath,
};

pub fn create_writer(path: &FilePath) -> BoxedResult<StdCompatFile> {
    let file = File::create(path.as_str()).map_err(from_io_err)?;
    #[cfg(not(feature = "std"))]
    let file = StdCompatFile(file);
    Ok(file)
}

pub fn create_reader(path: &FilePath) -> BoxedResult<(Option<u64>, StdCompatFile)> {
    let file = File::open(path.as_str()).map_err(from_io_err)?;
    let file_size = file.metadata().map_err(from_io_err)?.len();
    #[cfg(not(feature = "std"))]
    let file = StdCompatFile(file);
    Ok(((file_size > 0).then(|| file_size), file))
}

pub fn create_server_reader(
    path: &FilePath,
    config: &ServerConfig,
) -> BoxedResult<(Option<u64>, StdCompatFile)> {
    use std::fs::canonicalize;
    let dir: PathBuf = config.directory.as_str().parse()?;
    let path = dir.join(path.as_str());
    let real_dir = canonicalize(dir);
    let real_path = canonicalize(path);
    if let (Ok(d), Ok(p)) = (real_dir, real_path) {
        if p.starts_with(d) {
            return create_reader(&std_into_path(p));
        }
    }
    Err(FileError::InvalidFileName.into())
}

pub fn create_server_writer(path: &FilePath, config: &ServerConfig) -> BoxedResult<StdCompatFile> {
    use std::fs::{canonicalize, create_dir_all, OpenOptions};
    // TODO alloc in stack PathBuf
    let dir: PathBuf = config.directory.as_str().parse()?;
    let path: PathBuf = dir.join(path.as_str());
    if !path.starts_with(&dir) {
        return Err(FileError::InvalidFileName.into());
    }
    if let Some(dir) = path.parent() {
        if !dir.is_dir() {
            create_dir_all(dir).map_err(from_io_err)?
        }
    };

    let file = if config.allow_overwrite {
        let mut options = OpenOptions::new();
        // while path is not resolved do not truncate, but create if it does not exist
        options.write(true).create(true);
        options.open(&path).map_err(from_io_err)?
    } else {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        options.open(&path).map_err(from_io_err)?
    };

    let real_dir = canonicalize(dir);
    let real_path = canonicalize(path);
    if let (Ok(d), Ok(p)) = (real_dir, real_path) {
        if p.starts_with(d) {
            if config.allow_overwrite {
                drop(file);
                let mut options = OpenOptions::new();
                options.write(true).create(true).truncate(true);
                let file = options.open(&p).map_err(from_io_err)?;
                #[cfg(not(feature = "std"))]
                let file = StdCompatFile(file);
                return Ok(file);
            }
            #[cfg(not(feature = "std"))]
            let file = StdCompatFile(file);
            return Ok(file);
        }
    }
    Err(FileError::InvalidFileName.into())
}

#[allow(dead_code)]
pub fn create_simple_reader(path: &str) -> BoxedResult<StdCompatFile> {
    let file = File::open(path).map_err(from_io_err)?;
    #[cfg(not(feature = "std"))]
    let file = StdCompatFile(file);
    Ok(file)
}

#[cfg(feature = "encryption")]
pub fn read_private_value_or_file(private: &str) -> Result<PrivateKey, EncryptionError> {
    #[cfg(feature = "std")]
    use std::io::Read;

    #[cfg(not(feature = "std"))]
    use tftp::std_compat::io::Read;
    let result = decode_private_key(private.as_bytes());

    if result.is_err() {
        if let Ok(mut reader) = create_simple_reader(private) {
            let mut buf = [0; MAX_EXTENSION_VALUE_SIZE as usize];
            if let Ok(read) = reader.read(&mut buf) {
                if let Ok(p) = decode_private_key(&buf[..read]) {
                    return Ok(p);
                }
            }
        }
    }
    result
}

#[cfg(feature = "std")]
pub type StdCompatFile = std::fs::File;
#[cfg(not(feature = "std"))]
pub struct StdCompatFile(pub std::fs::File);

#[cfg(not(feature = "std"))]
impl io::Write for StdCompatFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use std::io::Write;
        self.0.write(buf).map_err(from_io_err)
    }

    fn write_fmt(&mut self, fmt: core::fmt::Arguments<'_>) -> io::Result<()> {
        use std::io::Write;
        self.0.write_fmt(fmt).map_err(from_io_err)
    }

    fn flush(&mut self) -> io::Result<()> {
        use std::io::Write;
        self.0.flush().map_err(from_io_err)
    }
}

#[cfg(not(feature = "std"))]
impl io::Seek for StdCompatFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        use std::io::Seek;
        let pos = match pos {
            io::SeekFrom::Start(p) => std::io::SeekFrom::Start(p),
            io::SeekFrom::Current(p) => std::io::SeekFrom::Current(p),
            io::SeekFrom::End(p) => std::io::SeekFrom::End(p),
        };
        self.0
            .seek(pos)
            .map_err(|_| tftp::std_compat::io::Error::from(tftp::std_compat::io::ErrorKind::Other))
    }
}

#[cfg(not(feature = "std"))]
impl io::Read for StdCompatFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        self.0.read(buf).map_err(from_io_err)
    }
}

pub fn from_io_err(err: std::io::Error) -> io::Error {
    #[cfg(feature = "std")]
    return err;
    #[cfg(not(feature = "std"))]
    io::Error::from(match err.kind() {
        std::io::ErrorKind::NotFound => io::ErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::ConnectionRefused => io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset => io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionAborted => io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::NotConnected => io::ErrorKind::NotConnected,
        std::io::ErrorKind::AddrInUse => io::ErrorKind::AddrInUse,
        std::io::ErrorKind::BrokenPipe => io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::AlreadyExists => io::ErrorKind::AlreadyExists,
        std::io::ErrorKind::WouldBlock => io::ErrorKind::WouldBlock,
        std::io::ErrorKind::InvalidInput => io::ErrorKind::InvalidInput,
        std::io::ErrorKind::InvalidData => io::ErrorKind::InvalidData,
        std::io::ErrorKind::TimedOut => io::ErrorKind::TimedOut,
        std::io::ErrorKind::WriteZero => io::ErrorKind::WriteZero,
        std::io::ErrorKind::Interrupted => io::ErrorKind::Interrupted,
        std::io::ErrorKind::UnexpectedEof => io::ErrorKind::UnexpectedEof,
        std::io::ErrorKind::OutOfMemory => io::ErrorKind::OutOfMemory,
        _ => io::ErrorKind::Other,
    })
}

#[allow(dead_code)]
pub fn create_buff_reader(path: &str) -> io::Result<StdBufReader> {
    let file = std::io::BufReader::new(
        File::options()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .map_err(from_io_err)?,
    );
    #[cfg(not(feature = "std"))]
    let file = StdBufReader(file);
    Ok(file)
}

#[cfg(feature = "std")]
pub type StdBufReader = std::io::BufReader<File>;
#[cfg(not(feature = "std"))]
pub struct StdBufReader(std::io::BufReader<File>);

#[cfg(not(feature = "std"))]
impl tftp::std_compat::io::BufRead for StdBufReader {
    fn read_line(
        &mut self,
        buf: &mut tftp::types::DefaultString,
    ) -> tftp::std_compat::io::Result<usize> {
        use std::io::BufRead;
        // TODO alloc in stack
        let mut s = std::string::String::with_capacity(buf.capacity());
        let result = self.0.read_line(&mut s).map_err(from_io_err);
        let _result = buf.push_str(s.as_str());
        #[cfg(not(feature = "alloc"))]
        _result.map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        result
    }
}

#[allow(unused_must_use)]
pub fn std_into_path(path: PathBuf) -> FilePath {
    let mut f = FilePath::new();
    // TODO alloc in stack
    let _result = f.push_str(&path.to_string_lossy().to_string());
    f
}
