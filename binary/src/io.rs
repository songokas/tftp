use std::fs::canonicalize;
use std::fs::create_dir_all;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;

use env_logger::Builder;
use env_logger::Env;
use log::error;
use tftp::encryption::PublicKey;
use tftp::error::BoxedResult;
use tftp::error::FileError;
use tftp::server::ServerConfig;
use tftp::std_compat::io;
use tftp::std_compat::time::Instant;
use tftp::types::FilePath;

use crate::macros::cfg_encryption;
use crate::macros::cfg_no_std;

cfg_encryption! {
    use tftp::encryption::decode_private_key;
    use tftp::encryption::PrivateKey;
    use tftp::error::EncryptionError;
    use tftp::key_management::append_to_known_hosts;
    use tftp::key_management::get_from_known_hosts;
    use log::warn;
}

cfg_no_std! {
    use tftp::types::DefaultString;
    use tftp::std_compat::io::BufRead;
    use std::io::ErrorKind as StdErrorKind;
    use std::string::String;
    use std::io::SeekFrom as StdSeekFrom;
    use std::time::UNIX_EPOCH;
    use std::time::SystemTime;
}

pub fn create_writer(path: &FilePath) -> BoxedResult<StdCompatFile> {
    let file = match File::create(path.as_str()).map_err(from_io_err) {
        Ok(f) => f,
        Err(e) => {
            error!("Unable to open {path}");
            return Err(Into::into(e));
        }
    };
    #[cfg(not(feature = "std"))]
    let file = StdCompatFile(file);
    Ok(file)
}

pub fn create_reader(path: &FilePath) -> BoxedResult<(Option<u64>, StdCompatFile)> {
    let file = match File::open(path.as_str()).map_err(from_io_err) {
        Ok(f) => f,
        Err(e) => {
            error!("Unable to open {path}");
            return Err(Into::into(e));
        }
    };
    let file_size = file.metadata().ok().map(|m| m.len());
    #[cfg(not(feature = "std"))]
    let file = StdCompatFile(file);
    Ok((file_size, file))
}

pub fn create_server_reader(
    path: &FilePath,
    config: &ServerConfig,
) -> BoxedResult<(Option<u64>, StdCompatFile)> {
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

#[cfg(feature = "encryption")]
pub fn read_private_value_or_file(private: &str) -> Result<PrivateKey, EncryptionError> {
    #[cfg(feature = "std")]
    use std::io::BufRead;
    let result = decode_private_key(private.as_bytes());

    if result.is_err() {
        if let Ok(mut reader) = create_buff_reader(private) {
            #[cfg(not(feature = "std"))]
            let mut buf = tftp::types::DefaultString::new();
            #[cfg(feature = "std")]
            let mut buf = String::new();
            if reader.read_line(&mut buf).is_ok() {
                if let Ok(p) = decode_private_key(buf.trim_end().as_bytes()) {
                    return Ok(p);
                }
            }
        }
    }
    result
}

#[cfg(feature = "std")]
pub type StdCompatFile = File;
#[cfg(not(feature = "std"))]
pub struct StdCompatFile(pub File);

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
            io::SeekFrom::Start(p) => StdSeekFrom::Start(p),
            io::SeekFrom::Current(p) => StdSeekFrom::Current(p),
            io::SeekFrom::End(p) => StdSeekFrom::End(p),
        };
        self.0
            .seek(pos)
            .map_err(|_| io::Error::from(io::ErrorKind::Other))
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

#[allow(dead_code)]
pub fn create_buff_reader(path: &str) -> io::Result<StdBufReader> {
    let file = match File::options().read(true).open(path).map_err(from_io_err) {
        Ok(f) => f,
        Err(e) => {
            // error!("Unable to open {path}");
            return Err(e);
        }
    };
    let file = BufReader::new(file);
    #[cfg(not(feature = "std"))]
    let file = StdBufReader(file);
    Ok(file)
}

#[cfg(feature = "std")]
pub type StdBufReader = BufReader<File>;
#[cfg(not(feature = "std"))]
pub struct StdBufReader(BufReader<File>);

#[cfg(not(feature = "std"))]
impl BufRead for StdBufReader {
    fn read_line(&mut self, buf: &mut DefaultString) -> io::Result<usize> {
        use std::io::BufRead;
        // TODO alloc in stack
        let mut s = String::with_capacity(buf.capacity());
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
    f.push_str(&path.to_string_lossy());
    f
}

#[allow(unused_variables)]
pub fn handle_hosts_file(
    known_hosts_file: Option<&str>,
    remote_key: Option<PublicKey>,
    endpoint: &str,
) {
    #[cfg(feature = "encryption")]
    match known_hosts_file
        .zip(remote_key)
        .map(|(f, k)| {
            if let Ok(r) = create_buff_reader(f) {
                if let Ok(Some(_)) = get_from_known_hosts(r, endpoint) {
                    return Ok(());
                }
            };

            let file = File::options()
                .create(true)
                .append(true)
                .open(f)
                .map_err(from_io_err)?;
            #[cfg(not(feature = "std"))]
            let file = StdCompatFile(file);
            append_to_known_hosts(file, endpoint, &k)
        })
        .transpose()
    {
        Ok(_) => (),
        Err(e) => warn!("Failed to append to known hosts {}", e),
    };
}

#[allow(dead_code)]
pub fn init_logger(local_addr: SocketAddr) {
    #[allow(unused_imports)]
    use std::io::Write;
    // builder using box
    Builder::from_env(Env::default().default_filter_or("debug"))
        .format(move |buf, record| {
            writeln!(
                buf,
                "[{local_addr} {} {}]: {}",
                record.level(),
                buf.timestamp_micros(),
                record.args()
            )
        })
        .try_init()
        .unwrap_or_default();
}

pub fn instant_callback() -> Instant {
    #[cfg(feature = "std")]
    return Instant::now();
    #[cfg(not(feature = "std"))]
    Instant::from_time(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_micros() as u64
    })
}
