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
    fn resolve(path: &str) -> io::Result<Self> {
        let mut input = [0_u8; JOINED_PATH_SIZE + 1];
        // a NUL inside the name would silently truncate the path passed to C
        if path.len() > JOINED_PATH_SIZE || path.as_bytes().contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        input[..path.len()].copy_from_slice(path.as_bytes());

        let mut buffer = [MaybeUninit::uninit(); PATH_BUFFER_SIZE];
        let resolved = unsafe { libc::realpath(input.as_ptr().cast(), buffer.as_mut_ptr().cast()) };
        if resolved.is_null() {
            return Err(last_os_error());
        }
        let length = unsafe { CStr::from_ptr(resolved) }.to_bytes().len();
        Ok(Self { buffer, length })
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

    let directory = RealPath::resolve(&config.directory)?;
    let real_path = RealPath::resolve(&path)?;
    if real_path.is_within(&directory) {
        let file = real_path.open(libc::O_RDONLY)?;
        let file_size = file.metadata().ok().map(|m| m.len());
        return Ok((file_size, file.into()));
    }
    Err(FileError::InvalidFileName.into())
}

pub fn create_server_writer(requested_path: &FilePath, config: &ServerConfig) -> BoxedResult<File> {
    validate_path(requested_path, config.max_directory_depth as usize)?;
    let path = join_path(&config.directory, requested_path)?;

    if !Path::new(path.as_str()).starts_with(config.directory.as_str()) {
        return Err(FileError::InvalidFileName.into());
    }
    if !stays_within_directory(&config.directory, &path) {
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

    if let (Ok(directory), Ok(real_path)) = (
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

/// Resolves the part of `path` that already exists, so that nothing is created
/// through a symlink leading outside `directory`.
fn stays_within_directory(directory: &str, path: &str) -> bool {
    // symlink_metadata also finds a dangling symlink, which realpath refuses
    let Some(existing) = Path::new(path)
        .ancestors()
        .find(|a| a.symlink_metadata().is_ok())
    else {
        return true;
    };
    let Some(real_existing) = existing.to_str().and_then(|p| RealPath::resolve(p).ok()) else {
        return false;
    };
    match RealPath::resolve(directory) {
        Ok(real_directory) => real_existing.is_within(&real_directory),
        // the served directory is yet to be created, so nothing below it exists
        Err(_) => true,
    }
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
    use std::path::PathBuf;

    use super::*;

    fn writer_config(directory: &Path, allow_overwrite: bool) -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            directory: directory.to_str().unwrap().parse().unwrap(),
            allow_overwrite,
            max_window_size: 1,
            request_timeout: core::time::Duration::from_secs(1),
            max_connections: 1,
            max_file_size: 1,
            max_block_size: 512,
            authorized_keys: None,
            private_key: None,
            require_full_encryption: false,
            require_server_port_change: false,
            prefer_seek: false,
            directory_list: None,
            max_directory_depth: 8,
            error_to_authorized_only: false,
        }
    }

    /// A served directory holding `link`, a symlink to a directory outside it.
    fn root_with_link_outside(name: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("tftp-writer-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        (root, outside)
    }

    #[cfg(unix)]
    #[test]
    fn test_writer_through_symlink_creates_nothing_outside_root() {
        let (root, outside) = root_with_link_outside("escape");
        for allow_overwrite in [false, true] {
            let config = writer_config(&root, allow_overwrite);

            let new_file = create_server_writer(&"link/new".parse().unwrap(), &config);
            let new_dir = create_server_writer(&"link/sub/new".parse().unwrap(), &config);

            assert!(new_file.is_err());
            assert!(new_dir.is_err());
            assert!(!outside.join("new").exists());
            assert!(!outside.join("sub").exists());
        }
        std::fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_writer_through_dangling_symlink_creates_nothing_outside_root() {
        let (root, outside) = root_with_link_outside("dangling");
        std::os::unix::fs::symlink(outside.join("target"), root.join("dangling")).unwrap();

        let result =
            create_server_writer(&"dangling".parse().unwrap(), &writer_config(&root, true));

        assert!(result.is_err());
        assert!(!outside.join("target").exists());
        std::fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_writer_inside_root_creates_directories_and_file() {
        let (root, _) = root_with_link_outside("inside");

        let result =
            create_server_writer(&"a/b/new".parse().unwrap(), &writer_config(&root, false));

        assert!(result.is_ok());
        assert!(root.join("a/b/new").is_file());
        std::fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[test]
    fn test_join_path() {
        assert_eq!(join_path("/srv", "a/b").unwrap().as_str(), "/srv/a/b");
        assert_eq!(join_path("/srv/", "a").unwrap().as_str(), "/srv/a");
        assert_eq!(join_path("", "a").unwrap().as_str(), "a");
        assert_eq!(join_path("/srv", "/etc/a").unwrap().as_str(), "/etc/a");
    }

    #[test]
    fn test_real_path_rejects_interior_nul() {
        assert!(RealPath::resolve("/tmp\0/x").is_err());
    }

    #[test]
    fn test_real_path_within() {
        let root = RealPath::resolve("/").unwrap();
        let tmp = RealPath::resolve("/tmp").unwrap();
        assert!(tmp.is_within(&root));
        assert!(!root.is_within(&tmp));
    }
}
