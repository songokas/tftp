use std::fs::canonicalize;
use std::fs::create_dir_all;
use std::fs::read_dir;
use std::fs::File as StdFile;
use std::fs::OpenOptions;
use std::net::SocketAddr;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

// use crate::macros::cfg_encryption;
use crate::macros::cfg_no_std;
use crate::std_compat::fs::File;
use crate::std_compat::io::from_io_err;
use crate::std_compat::io::BoxedReader;
use crate::std_compat::io::BufReader;
use crate::std_compat::io::BytesCursor;

use env_logger::Builder;
use env_logger::Env;
use log::error;
// use tftp::encryption::PublicKey;
use tftp::error::BoxedResult;
use tftp::error::FileError;
use tftp::server::ServerConfig;
use tftp::std_compat::io;
use tftp::std_compat::time::Instant;
use tftp::types::FilePath;

// cfg_encryption! {
//     use tftp::encryption::PrivateKey;
//     use tftp::encryption::STREAM_NONCE_SIZE;
//     use tftp::std_compat::io::Read;
//     use tftp::std_compat::io::Seek;
//     use tftp::std_compat::io::Write;
//     use tftp::encryption::StreamEncryptor;
//     use tftp::encryption::decode_private_key;
//     use tftp::error::EncryptionError;
//     use tftp::key_management::append_to_known_hosts;
//     use tftp::key_management::get_from_known_hosts;
//     use tftp::readers::encrypted_stream_reader::StreamReader;
//     use tftp::writers::encrypted_stream_writer::StreamWriter;
//     use tftp::encryption::EncryptionKey;

//     use rand::CryptoRng;
//     use rand::RngCore;
//     use log::warn;
// }

cfg_no_std! {
    use std::time::UNIX_EPOCH;
    use std::time::SystemTime;
}

pub fn create_writer(path: &FilePath) -> BoxedResult<File> {
    let file = match StdFile::create(path.as_str()).map_err(from_io_err) {
        Ok(f) => f,
        Err(e) => {
            error!("Unable to open {path}");
            return Err(Into::into(e));
        }
    };
    Ok(file.into())
}

pub fn create_reader(path: &FilePath) -> BoxedResult<(Option<u64>, File)> {
    let file = match StdFile::open(path.as_str()).map_err(from_io_err) {
        Ok(f) => f,
        Err(e) => {
            error!("Unable to open {path}");
            return Err(Into::into(e));
        }
    };
    let file_size = file.metadata().ok().map(|m| m.len());
    Ok((file_size, file.into()))
}

pub fn create_server_reader(
    requested_path: &FilePath,
    config: &ServerConfig,
) -> BoxedResult<(Option<u64>, BoxedReader)> {
    validate_path(requested_path, config.max_directory_depth as usize)?;

    let dir: PathBuf = config.directory.as_str().parse()?;

    let path = dir.join(requested_path.as_str());
    let real_dir = canonicalize(dir);

    let (real_path, list_dir) = match &config.directory_list {
        Some(d) if path.ends_with(d.as_str()) => (
            canonicalize(path.parent().ok_or(FileError::InvalidFileName)?),
            true,
        ),
        _ => (canonicalize(path), false),
    };

    if let (Ok(d), Ok(p)) = (real_dir, real_path) {
        if p.starts_with(&d) {
            return if list_dir {
                list_directory(&d, &p).map(|(s, l)| (s, ReaderCreator::from_list(l)))
            } else {
                create_reader(&std_into_path(p)).map(|(s, f)| (s, ReaderCreator::from_file(f)))
            };
        }
    }
    Err(FileError::InvalidFileName.into())
}

pub fn create_server_writer(requested_path: &FilePath, config: &ServerConfig) -> BoxedResult<File> {
    validate_path(requested_path, config.max_directory_depth as usize)?;
    // TODO alloc in stack PathBuf
    let dir: PathBuf = config.directory.as_str().parse()?;
    let path: PathBuf = dir.join(requested_path.as_str());

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
                return Ok(file.into());
            }
            return Ok(file.into());
        }
    }
    Err(FileError::InvalidFileName.into())
}

#[allow(dead_code)]
pub fn create_buff_reader(path: &str) -> io::Result<BufReader<StdFile>> {
    let file = match StdFile::options()
        .read(true)
        .open(path)
        .map_err(from_io_err)
    {
        Ok(f) => f,
        Err(e) => {
            return Err(e);
        }
    };
    let file = BufReader::new(file);
    Ok(file)
}

#[allow(unused_must_use)]
pub fn std_into_path(path: PathBuf) -> FilePath {
    let mut f = FilePath::new();
    // TODO alloc in stack
    f.push_str(&path.to_string_lossy());
    f
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

struct ReaderCreator {}

impl ReaderCreator {
    fn from_file(file: File) -> BoxedReader {
        #[cfg(feature = "std")]
        return Box::new(file);
        #[cfg(not(feature = "std"))]
        BoxedReader::File(file)
    }

    fn from_list(file: BytesCursor) -> BoxedReader {
        #[cfg(feature = "std")]
        return Box::new(file);
        #[cfg(not(feature = "std"))]
        BoxedReader::List(file)
    }
}

// TODO alloc in stack Vec
fn list_directory(server_dir: &Path, dir: &Path) -> BoxedResult<(Option<u64>, BytesCursor)> {
    let paths = read_dir(dir).map_err(|_| FileError::InvalidFileName)?;
    let mut bytes = Vec::new();
    for path in paths {
        let entry = path.map_err(|_| FileError::InvalidFileName)?;
        let sep = entry
            .file_type()
            .ok()
            .and_then(|f| f.is_dir().then_some("/"))
            .unwrap_or_default();
        let full_path = entry.path();
        let name = full_path
            .strip_prefix(server_dir)
            .map_err(|_| FileError::InvalidFileName)?;
        bytes.extend(format!("{}{sep}\n", name.to_string_lossy()).into_bytes());
    }
    let size = bytes.len() as u64;
    Ok((size.into(), BytesCursor::new(bytes)))
}

fn validate_path(requested_path: &FilePath, max_depth: usize) -> Result<(), FileError> {
    let component_count = Path::new(requested_path.as_str())
        .components()
        .filter(|c| {
            matches!(
                c,
                Component::Normal(_) | Component::ParentDir | Component::CurDir
            )
        })
        .count();
    if component_count.saturating_sub(1) <= max_depth {
        return Ok(());
    }
    Err(FileError::InvalidFileName)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_path() {
        let data = [
            ("filename", 0, true),
            ("filename", 1, true),
            ("dir/file", 0, false),
            ("dir/file", 1, true),
            ("/file", 1, true),
            ("", 1, true),
            ("../../a", 1, false),
            ("../../a", 3, true),
        ];
        for (p, count, result) in data {
            let p: FilePath = p.parse().unwrap();
            assert_eq!(validate_path(&p, count).is_ok(), result, "{p} {count}");
        }
    }
}
