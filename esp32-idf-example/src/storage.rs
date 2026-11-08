//! Files for the server, through `std::fs`.

use std::fs::File;
use std::fs::OpenOptions;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use tftp_dus::error::BoxedResult;
use tftp_dus::error::FileError;
use tftp_dus::server::ServerConfig;
use tftp_dus::types::FilePath;

/// SPIFFS has no directories and no way to resolve a path, so only plain file names are accepted.
fn resolve(requested: &FilePath, config: &ServerConfig) -> Result<PathBuf, FileError> {
    let mut components = Path::new(requested.as_str()).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => {
            Ok(Path::new(config.directory.as_str()).join(name))
        }
        _ => Err(FileError::InvalidFileName),
    }
}

pub fn open_reader(
    requested: &FilePath,
    config: &ServerConfig,
) -> BoxedResult<(Option<u64>, File)> {
    let file = File::open(resolve(requested, config)?)?;
    let size = file.metadata().ok().map(|m| m.len());
    Ok((size, file))
}

pub fn open_writer(requested: &FilePath, config: &ServerConfig) -> BoxedResult<File> {
    let path = resolve(requested, config)?;
    let mut options = OpenOptions::new();
    options.write(true);
    if config.allow_overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    Ok(options.open(path)?)
}
