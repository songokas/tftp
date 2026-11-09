use std::fs::canonicalize;
use std::fs::create_dir_all;
use std::fs::read_dir;
use std::fs::File as StdFile;
use std::fs::OpenOptions;
use std::net::SocketAddr;
use std::path::Path;

use env_logger::Builder;
use env_logger::Env;
use log::error;
use tftp_binary_common::path::validate_path;
use tftp_dus::error::BoxedResult;
use tftp_dus::error::FileError;
use tftp_dus::extend_from_slice;
use tftp_dus::server::ServerConfig;
use tftp_dus::types::DataBuffer;
use tftp_dus::types::FilePath;

use crate::std_compat::fs::File;
use crate::std_compat::io::from_io_err;
use crate::std_compat::io::BytesCursor;
use crate::std_compat::io::ServerReader;

pub fn create_writer(path: &FilePath) -> BoxedResult<File> {
    let file = match StdFile::create(path.as_str()).map_err(from_io_err) {
        Ok(f) => f,
        Err(e) => {
            error!("Unable to open {path}");
            return Err(Into::into(e));
        }
    };
    Ok(file)
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
    Ok((file_size, file))
}

pub fn create_server_reader(
    requested_path: &FilePath,
    config: &ServerConfig,
) -> BoxedResult<(Option<u64>, ServerReader)> {
    validate_path(requested_path, config.max_directory_depth as usize)?;

    let dir = Path::new(config.directory.as_str());

    let path = dir.join(requested_path.as_str());
    let real_dir = canonicalize(dir).map_err(from_io_err)?;

    let (real_path, list_dir) = match &config.directory_list {
        Some(d) if path.ends_with(d.as_str()) => (
            canonicalize(path.parent().ok_or(FileError::InvalidFileName)?),
            true,
        ),
        _ => (canonicalize(path), false),
    };
    let real_path = real_path.map_err(from_io_err)?;

    if real_path.starts_with(&real_dir) {
        return if list_dir {
            list_directory(&real_dir, &real_path).map(|(s, l)| (s, ServerReader::List(l)))
        } else {
            let file_path = real_path
                .to_str()
                .and_then(|s| s.parse().ok())
                .ok_or(FileError::InvalidFileName)?;
            create_reader(&file_path).map(|(s, f)| (s, ServerReader::File(f)))
        };
    }
    Err(FileError::InvalidFileName.into())
}

pub fn create_server_writer(requested_path: &FilePath, config: &ServerConfig) -> BoxedResult<File> {
    validate_path(requested_path, config.max_directory_depth as usize)?;
    let dir = Path::new(config.directory.as_str());
    // canonicalize below returns a PathBuf, so a stack buffer here would not make this heap free
    let path = dir.join(requested_path.as_str());

    if !path.starts_with(dir) {
        return Err(FileError::InvalidFileName.into());
    }
    if !stays_within_directory(dir, &path) {
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
                return Ok(file);
            }
            return Ok(file);
        }
    }
    Err(FileError::InvalidFileName.into())
}

/// Resolves the part of `path` that already exists, so that nothing is created
/// through a symlink leading outside `directory`.
fn stays_within_directory(directory: &Path, path: &Path) -> bool {
    // symlink_metadata also finds a dangling symlink, which canonicalize refuses
    let Some(existing) = path.ancestors().find(|a| a.symlink_metadata().is_ok()) else {
        return true;
    };
    let Ok(real_existing) = canonicalize(existing) else {
        return false;
    };
    match canonicalize(directory) {
        Ok(real_directory) => real_existing.starts_with(real_directory),
        // the served directory is yet to be created, so nothing below it exists
        Err(_) => true,
    }
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

/// Without `alloc` the list has to fit in one `DataBuffer`, so that a reader
/// costs at most one more block. A longer list is refused, not cut short.
///
/// `read_dir` and `DirEntry::path` allocate inside the standard library.
fn list_directory(server_dir: &Path, dir: &Path) -> BoxedResult<(Option<u64>, BytesCursor)> {
    let paths = read_dir(dir).map_err(|_| FileError::InvalidFileName)?;
    let mut bytes = DataBuffer::new();
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
            .map_err(|_| FileError::InvalidFileName)?
            .to_string_lossy();
        for part in [name.as_bytes(), sep.as_bytes(), b"\n".as_slice()] {
            extend_from_slice(&mut bytes, part, FileError::InvalidFileName).inspect_err(|_| {
                error!("Directory list of {} does not fit", dir.display());
            })?;
        }
    }
    let size = bytes.len() as u64;
    Ok((size.into(), BytesCursor::new(bytes)))
}

#[cfg(test)]
mod tests {
    use std::fs::create_dir_all;
    use std::fs::remove_dir_all;
    use std::fs::write;
    use std::path::PathBuf;

    use super::*;

    fn sample_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tftp-list-{}-{name}", std::process::id()));
        create_dir_all(dir.join("samples")).unwrap();
        canonicalize(dir).unwrap()
    }

    #[cfg(unix)]
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
    #[cfg(unix)]
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
    fn test_list_directory_marks_directories() {
        let dir = sample_dir("marks");
        write(dir.join("a"), "").unwrap();

        let (size, cursor) = list_directory(&dir, &dir).unwrap();

        remove_dir_all(&dir).unwrap();
        let contents = core::str::from_utf8(cursor.get_ref()).unwrap();
        let mut lines: Vec<_> = contents.lines().collect();
        lines.sort();
        assert_eq!(lines, ["a", "samples/"]);
        assert_eq!(size, Some(contents.len() as u64));
    }

    #[cfg(not(feature = "alloc"))]
    #[test]
    fn test_list_directory_that_does_not_fit_is_refused() {
        let dir = sample_dir("long");
        let entries = tftp_dus::config::MAX_BUFFER_SIZE as usize / 40 + 1;
        for index in 0..entries {
            write(dir.join(format!("{index:040}")), "").unwrap();
        }

        let result = list_directory(&dir, &dir);

        remove_dir_all(&dir).unwrap();
        assert!(result.is_err());
    }
}
