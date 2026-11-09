use log::error;

use super::config::ServerConfig;
use crate::config::ConnectionOptions;
use crate::error::BoxedError;
use crate::error::ExtensionError;
use crate::error::FileError;
use crate::packet::ErrorCode;
use crate::packet::ErrorPacket;
use crate::packet::Extension;
use crate::string::format_str;
use crate::types::FilePath;

/// On failure also returns the error to send, so that the caller can apply the
/// connection's encryption and its rules on who gets errors.
pub fn validate_request_options(
    file_name: &FilePath,
    options: &ConnectionOptions,
    config: &ServerConfig,
) -> Result<FilePath, (ErrorPacket, BoxedError)> {
    if let Err(e) = handle_file_size(options.file_size.unwrap_or(0), config.max_file_size) {
        return Err((
            e,
            ExtensionError::InvalidExtension(Extension::TransferSize).into(),
        ));
    }

    validate_file_name(file_name).map_err(|e| (e, FileError::InvalidFileName.into()))
}

pub fn handle_file_size(received_size: u64, max_file_size: u64) -> Result<(), ErrorPacket> {
    if received_size > max_file_size {
        error!(
            "Invalid file size received {} expected {}",
            received_size, max_file_size,
        );
        let message = format_str!(
            DefaultString,
            "Invalid file size received {}",
            received_size,
        );
        return Err(ErrorPacket::new(ErrorCode::DiskFull, message));
    }
    Ok(())
}

pub fn validate_file_name(file_name: &FilePath) -> Result<FilePath, ErrorPacket> {
    let local_file_path = match normalize_remote_name(file_name) {
        Ok(p) => p,
        Err(e) => {
            error!("Invalid file name received {} {}", file_name.as_str(), e);
            return Err(ErrorPacket::new(
                ErrorCode::AccessViolation,
                format_str!(DefaultString, "Invalid file name received {}", file_name),
            ));
        }
    };
    Ok(local_file_path)
}

fn normalize_remote_name(file_path: &FilePath) -> Result<FilePath, FileError> {
    #[allow(unused_must_use)]
    let result = file_path
        .as_str()
        .trim_start_matches('/')
        .split('/')
        .filter(|c| !matches!(c.trim(), "." | ".." | "/" | ""))
        .fold(FilePath::new(), |mut f, c| {
            if !f.is_empty() {
                f.push('/');
            }
            f.push_str(c);
            f
        });
    #[allow(clippy::redundant_as_str)]
    if result.as_str().is_empty() {
        return Err(FileError::InvalidFileName);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::config::MAX_FILE_PATH_SIZE;

    #[test]
    fn test_normalize_name() {
        let data = [
            ("a", "a"),
            ("a", "./a"),
            ("a", "/a"),
            ("root/a", "root/a"),
            ("root/a", "/root/a"),
            ("root/a/b", "root/a/../b"),
            ("a", "../../a"),
            ("b", "../b/../."),
            (".b.", "./.b."),
            (" s", "/ / / / s"),
            ("s", "//s"),
            ("s", "///s"),
        ];
        for (i, (expected, file_path)) in data.into_iter().enumerate() {
            assert_eq!(
                FilePath::from_str(expected).unwrap(),
                normalize_remote_name(&FilePath::from_str(file_path).unwrap()).unwrap(),
                "{i}"
            );
        }
    }

    #[test]
    fn test_normalize_name_keeps_a_name_of_the_longest_size() {
        let name = "x".repeat(MAX_FILE_PATH_SIZE as usize);
        let file_path: FilePath = name.parse().unwrap();

        assert_eq!(normalize_remote_name(&file_path).unwrap(), file_path);
    }

    #[test]
    fn test_normalize_name_failures() {
        let data = ["", ".", "/../.", "/////"];
        for (i, file_path) in data.into_iter().enumerate() {
            assert!(
                normalize_remote_name(&FilePath::from_str(file_path).unwrap()).is_err(),
                "{}",
                i
            );
        }
    }

    #[test]
    fn test_invalid_name_of_the_longest_size_fits_the_error() {
        let file_path: FilePath = "/".repeat(MAX_FILE_PATH_SIZE as usize).parse().unwrap();

        let packet = validate_file_name(&file_path).unwrap_err();

        let full = format!("Invalid file name received {file_path}");
        assert!(!packet.message.is_empty());
        assert!(full.starts_with(packet.message.as_str()));
    }

    #[cfg(not(feature = "alloc"))]
    #[test]
    fn test_capacity_reached() {
        let file_path = "very-long-file-segment-very-long-file/very-long-file-segment-very-long-file-segment-very-long-file-segment-very-long-file-segment-very-long-file-segment";
        assert!(file_path.parse::<FilePath>().is_err(),);
    }
}
