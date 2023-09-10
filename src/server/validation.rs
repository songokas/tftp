use log::error;

use super::config::ServerConfig;
use crate::config::ConnectionOptions;
use crate::error::BoxedResult;
use crate::error::ExtensionError;
use crate::error::FileError;
use crate::packet::ByteConverter;
use crate::packet::ErrorCode;
use crate::packet::ErrorPacket;
use crate::packet::Extension;
use crate::packet::Packet;
use crate::packet::PacketExtensions;
use crate::socket::Socket;
use crate::std_compat::net::SocketAddr;
use crate::string::format_str;
use crate::types::FilePath;

pub fn validate_request_options(
    socket: &impl Socket,
    client: SocketAddr,
    file_name: &FilePath,
    options: &ConnectionOptions,
    _extensions: &PacketExtensions,
    config: &ServerConfig,
) -> BoxedResult<FilePath> {
    #[cfg(feature = "encryption")]
    if _extensions.get(&Extension::PublicKey).is_some()
        != _extensions.get(&Extension::Nonce).is_some()
    {
        let (missing, provided) = if _extensions.get(&Extension::Nonce).is_some() {
            ("public key", "nonce")
        } else {
            ("nonce", "public key")
        };

        let packet = Packet::Error(ErrorPacket::new(
            ErrorCode::IllegalOperation,
            format_str!(
                DefaultString,
                "Missing extension {} while {} provided",
                missing,
                provided
            ),
        ));
        socket.send_to(&mut packet.to_bytes(), client)?;
        return Err(if _extensions.get(&Extension::Nonce).is_some() {
            ExtensionError::InvalidPublicKey.into()
        } else {
            ExtensionError::InvalidNonce.into()
        });
    }

    if let Err(e) = handle_file_size(options.file_size.unwrap_or(0), config.max_file_size) {
        let packet = Packet::Error(e);
        socket.send_to(&mut packet.to_bytes(), client)?;
        return Err(ExtensionError::InvalidExtension(Extension::TransferSize).into());
    }

    match validate_file_name(file_name) {
        Ok(p) => Ok(p),
        Err(e) => {
            let packet = Packet::Error(e);
            socket.send_to(&mut packet.to_bytes(), client)?;
            Err(FileError::InvalidFileName.into())
        }
    }
}

pub fn handle_file_size(received_size: u64, max_file_size: u64) -> Result<(), ErrorPacket> {
    if received_size > max_file_size {
        error!(
            "Invalid file size received {} expected {}",
            received_size, max_file_size,
        );
        let message = format_str!(
            DefaultString,
            "Invalid file size received {} expected {}",
            received_size,
            max_file_size
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
                ErrorCode::AccessVioliation,
                format_str!(DefaultString, "Invalid file name received {}", file_name),
            ));
        }
    };
    Ok(local_file_path)
}

fn normalize_remote_name(file_path: &FilePath) -> Result<FilePath, FileError> {
    #[allow(unused_must_use)]
    let mut result = file_path
        .as_str()
        .trim_start_matches('/')
        .split('/')
        .filter(|c| !matches!(c.trim(), "." | ".." | "/" | ""))
        .fold(FilePath::new(), |mut f, c| {
            f.push_str(c);
            f.push('/');
            f
        });
    result.pop();
    if result.as_str().is_empty() {
        return Err(FileError::InvalidFileName);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

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

    #[cfg(not(feature = "alloc"))]
    #[test]
    fn test_capacity_reached() {
        let file_path = "very-long-file-segment-very-long-file/very-long-file-segment-very-long-file-segment-very-long-file-segment-very-long-file-segment-very-long-file-segment";
        assert!(file_path.parse::<FilePath>().is_err(),);
    }
}
