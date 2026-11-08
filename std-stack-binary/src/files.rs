use core::mem::MaybeUninit;
use std::ffi::CStr;
use std::ffi::OsStr;
use std::fs::create_dir_all;
use std::fs::File as StdFile;
use std::fs::OpenOptions;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use log::error;
use tftp_binary_common::io::File;
use tftp_binary_common::path::validate_path;
use tftp_dus::config::MAX_FILE_PATH_SIZE;
use tftp_dus::error::BoxedResult;
use tftp_dus::error::FileError;
use tftp_dus::server::ServerConfig;
use tftp_dus::std_compat::io;
use tftp_dus::types::FilePath;

use crate::error::from_io_err;
use crate::error::last_os_error;

/// directory + separator + requested path
const JOINED_PATH_SIZE: usize = MAX_FILE_PATH_SIZE as usize * 2 + 1;
const PATH_BUFFER_SIZE: usize = libc::PATH_MAX as usize;

type JoinedPath = heapless::String<JOINED_PATH_SIZE>;

/// Canonical path resolved into a stack buffer. It stays NUL terminated and is
/// opened through libc because std allocates for paths of 384 bytes or more.
struct RealPath {
    buffer: [MaybeUninit<u8>; PATH_BUFFER_SIZE],
    length: usize,
}

impl RealPath {
    fn resolve(path: &str) -> Option<Self> {
        let mut input = [0_u8; JOINED_PATH_SIZE + 1];
        // a NUL inside the name would silently truncate the path passed to C
        if path.len() > JOINED_PATH_SIZE || path.as_bytes().contains(&0) {
            return None;
        }
        input[..path.len()].copy_from_slice(path.as_bytes());

        let mut buffer = [MaybeUninit::uninit(); PATH_BUFFER_SIZE];
        let resolved = unsafe { libc::realpath(input.as_ptr().cast(), buffer.as_mut_ptr().cast()) };
        if resolved.is_null() {
            return None;
        }
        let length = unsafe { CStr::from_ptr(resolved) }.to_bytes().len();
        Some(Self { buffer, length })
    }

    fn as_path(&self) -> &Path {
        let bytes =
            unsafe { core::slice::from_raw_parts(self.buffer.as_ptr().cast::<u8>(), self.length) };
        Path::new(OsStr::from_bytes(bytes))
    }

    fn is_within(&self, directory: &RealPath) -> bool {
        self.as_path().starts_with(directory.as_path())
    }

    fn open(&self, flags: i32) -> io::Result<StdFile> {
        let fd = unsafe {
            libc::open(
                self.buffer.as_ptr().cast(),
                flags | libc::O_CLOEXEC,
                0o666 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(last_os_error());
        }
        Ok(unsafe { StdFile::from_raw_fd(fd) })
    }
}

pub fn create_writer(path: &FilePath) -> BoxedResult<File> {
    let file = StdFile::create(path.as_str()).map_err(|e| {
        error!("Unable to open {path}");
        from_io_err(e)
    })?;
    Ok(file.into())
}

pub fn create_reader(path: &FilePath) -> BoxedResult<(Option<u64>, File)> {
    let file = StdFile::open(path.as_str()).map_err(|e| {
        error!("Unable to open {path}");
        from_io_err(e)
    })?;
    let file_size = file.metadata().ok().map(|m| m.len());
    Ok((file_size, file.into()))
}

pub fn create_server_reader(
    requested_path: &FilePath,
    config: &ServerConfig,
) -> BoxedResult<(Option<u64>, File)> {
    validate_path(requested_path, config.max_directory_depth as usize)?;
    let path = join_path(&config.directory, requested_path)?;

    if let (Some(directory), Some(real_path)) = (
        RealPath::resolve(&config.directory),
        RealPath::resolve(&path),
    ) {
        if real_path.is_within(&directory) {
            let file = real_path.open(libc::O_RDONLY)?;
            let file_size = file.metadata().ok().map(|m| m.len());
            return Ok((file_size, file.into()));
        }
    }
    Err(FileError::InvalidFileName.into())
}

pub fn create_server_writer(requested_path: &FilePath, config: &ServerConfig) -> BoxedResult<File> {
    validate_path(requested_path, config.max_directory_depth as usize)?;
    let path = join_path(&config.directory, requested_path)?;

    if !Path::new(path.as_str()).starts_with(config.directory.as_str()) {
        return Err(FileError::InvalidFileName.into());
    }
    if let Some(parent) = Path::new(path.as_str()).parent() {
        if !parent.is_dir() {
            create_dir_all(parent).map_err(from_io_err)?;
        }
    }

    let mut options = OpenOptions::new();
    if config.allow_overwrite {
        // while path is not resolved do not truncate, but create if it does not exist
        options.write(true).create(true);
    } else {
        options.write(true).create_new(true);
    }
    let file = options.open(path.as_str()).map_err(from_io_err)?;

    if let (Some(directory), Some(real_path)) = (
        RealPath::resolve(&config.directory),
        RealPath::resolve(&path),
    ) {
        if real_path.is_within(&directory) {
            if config.allow_overwrite {
                drop(file);
                let file = real_path.open(libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC)?;
                return Ok(file.into());
            }
            return Ok(file.into());
        }
    }
    Err(FileError::InvalidFileName.into())
}

/// Same semantics as Path::join: an absolute requested path replaces the directory.
fn join_path(directory: &str, requested: &str) -> Result<JoinedPath, FileError> {
    let mut joined = JoinedPath::new();
    let appended = if requested.starts_with('/') {
        Ok(())
    } else {
        joined.push_str(directory).and_then(|_| {
            if directory.is_empty() || directory.ends_with('/') {
                Ok(())
            } else {
                joined.push('/')
            }
        })
    };
    appended
        .and_then(|_| joined.push_str(requested))
        .map_err(|_| FileError::InvalidFileName)?;
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_join_path() {
        assert_eq!(join_path("/srv", "a/b").unwrap().as_str(), "/srv/a/b");
        assert_eq!(join_path("/srv/", "a").unwrap().as_str(), "/srv/a");
        assert_eq!(join_path("", "a").unwrap().as_str(), "a");
        assert_eq!(join_path("/srv", "/etc/a").unwrap().as_str(), "/etc/a");
    }

    #[test]
    fn test_real_path_rejects_interior_nul() {
        assert!(RealPath::resolve("/tmp\0/x").is_none());
    }

    #[test]
    fn test_real_path_within() {
        let root = RealPath::resolve("/").unwrap();
        let tmp = RealPath::resolve("/tmp").unwrap();
        assert!(tmp.is_within(&root));
        assert!(!root.is_within(&tmp));
    }
}
