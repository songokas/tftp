use core::fmt::Display;
use core::fmt::Formatter;
use core::hash::Hash;
use core::mem::size_of;
use core::mem::size_of_val;
use core::str::from_utf8;
use core::str::FromStr;

use crate::buffer::SliceMutExt;
use crate::error::PacketError;
use crate::error::PacketResult;
use crate::map::Map;
use crate::types::DataBuffer;
use crate::types::DefaultString;
use crate::types::ExtensionValue;
use crate::types::FilePath;
use crate::types::PacketBlock;

#[cfg(feature = "alloc")]
pub type PacketExtensions = Map<Extension, ExtensionValue>;
#[cfg(not(feature = "alloc"))]
pub type PacketExtensions = Map<Extension, ExtensionValue, { Extension::SIZE as usize }>;

pub trait ByteConverter<'a> {
    fn from_bytes(bytes: &'a [u8]) -> PacketResult<Self>
    where
        Self: Sized;
    fn to_bytes(self) -> PacketBlock;
    fn to_buffer(self, buffer: &mut [u8]) -> Option<usize>;
}

#[derive(Debug, Clone)]
pub enum Packet<'a> {
    Read(RequestPacket),
    Write(RequestPacket),
    Data(DataPacket<'a>),
    Ack(AckPacket),
    Error(ErrorPacket),
    OptionalAck(OptionalAck),
}

impl<'a> Packet<'a> {
    pub fn packet_type(&self) -> PacketType {
        match self {
            Packet::Read(_) => PacketType::Read,
            Packet::Write(_) => PacketType::Write,
            Packet::Ack(_) => PacketType::Ack,
            Packet::Data(_) => PacketType::Data,
            Packet::Error(_) => PacketType::Error,
            Packet::OptionalAck(_) => PacketType::OptionalAck,
        }
    }
}

impl<'a> ByteConverter<'a> for Packet<'a> {
    fn from_bytes(bytes: &'a [u8]) -> PacketResult<Self> {
        let opcode = PacketType::from_bytes(bytes)?;
        let remaining = bytes
            .get(size_of_val(&opcode)..)
            .ok_or(PacketError::Invalid)?;
        Ok(match opcode {
            PacketType::Read => Packet::Read(RequestPacket::from_bytes(remaining)?),
            PacketType::Write => Packet::Write(RequestPacket::from_bytes(remaining)?),
            PacketType::Data => Packet::Data(DataPacket::from_bytes(remaining)?),
            PacketType::Ack => Packet::Ack(AckPacket::from_bytes(remaining)?),
            PacketType::Error => Packet::Error(ErrorPacket::from_bytes(remaining)?),
            PacketType::OptionalAck => Packet::OptionalAck(OptionalAck::from_bytes(remaining)?),
        })
    }

    fn to_buffer(self, buffer: &mut [u8]) -> Option<usize> {
        match self {
            Packet::Read(p) => {
                let size = buffer.write_bytes(PacketType::Read.to_bytes(), 0_usize)?;
                p.to_buffer(buffer.get_mut(size..)?).map(|s| size + s)
            }
            Packet::Write(p) => {
                let size = buffer.write_bytes(PacketType::Write.to_bytes(), 0_usize)?;
                p.to_buffer(buffer.get_mut(size..)?).map(|s| size + s)
            }
            Packet::Data(p) => {
                let size = buffer.write_bytes(PacketType::Data.to_bytes(), 0_usize)?;
                p.to_buffer(buffer.get_mut(size..)?).map(|s| size + s)
            }
            Packet::Ack(p) => {
                let size = buffer.write_bytes(PacketType::Ack.to_bytes(), 0_usize)?;
                p.to_buffer(buffer.get_mut(size..)?).map(|s| size + s)
            }
            Packet::Error(p) => {
                let size = buffer.write_bytes(PacketType::Error.to_bytes(), 0_usize)?;
                p.to_buffer(buffer.get_mut(size..)?).map(|s| size + s)
            }
            Packet::OptionalAck(p) => {
                let size = buffer.write_bytes(PacketType::OptionalAck.to_bytes(), 0_usize)?;
                p.to_buffer(buffer.get_mut(size..)?).map(|s| size + s)
            }
        }
    }

    fn to_bytes(self) -> PacketBlock {
        match self {
            Packet::Read(p) => PacketType::Read
                .to_bytes()
                .into_iter()
                .chain(p.to_bytes())
                .collect(),
            Packet::Write(p) => PacketType::Write
                .to_bytes()
                .into_iter()
                .chain(p.to_bytes())
                .collect(),
            Packet::Data(p) => PacketType::Data
                .to_bytes()
                .into_iter()
                .chain(p.to_bytes())
                .collect(),
            Packet::Ack(p) => PacketType::Ack
                .to_bytes()
                .into_iter()
                .chain(p.to_bytes())
                .collect(),
            Packet::Error(p) => PacketType::Error
                .to_bytes()
                .into_iter()
                .chain(p.to_bytes())
                .collect(),
            Packet::OptionalAck(p) => PacketType::OptionalAck
                .to_bytes()
                .into_iter()
                .chain(p.to_bytes())
                .collect(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum PacketType {
    Read = 1,
    Write,
    Data,
    Ack,
    Error,
    OptionalAck,
}

impl PacketType {
    fn from_repr(s: u16) -> PacketResult<Self> {
        Ok(match s {
            1 => PacketType::Read,
            2 => PacketType::Write,
            3 => PacketType::Data,
            4 => PacketType::Ack,
            5 => PacketType::Error,
            6 => PacketType::OptionalAck,
            _ => return Err(PacketError::Invalid),
        })
    }
}

impl PacketType {
    pub fn from_bytes(bytes: &[u8]) -> PacketResult<Self> {
        Self::from_repr(try_from(bytes)?)
    }

    pub fn to_bytes(self) -> [u8; size_of::<Self>()] {
        (self as u16).to_be_bytes()
    }
}

impl Display for PacketType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PacketType::Read => write!(f, "read packet"),
            PacketType::Write => write!(f, "read packet"),
            PacketType::Ack => write!(f, "ack packet"),
            PacketType::Data => write!(f, "data packet"),
            PacketType::Error => write!(f, "error packet"),
            PacketType::OptionalAck => write!(f, "optional ack packet"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Octet,
}

impl Mode {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Octet => "octet",
        }
    }
}

impl FromStr for Mode {
    type Err = PacketError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "octet" => Self::Octet,
            _ => return Err(PacketError::Invalid),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd)]
#[repr(u8)]
pub enum Extension {
    // "8" and "65464"
    BlockSize,
    // "1" and "255"
    Timeout,
    // file size
    TransferSize,
    // client/server public key
    PublicKey,
    // required encryption level
    EncryptionLevel,
    // "1" and "65535"
    WindowSize,
}

#[cfg(not(feature = "alloc"))]
impl hash32::Hash for Extension {
    fn hash<H>(&self, state: &mut H)
    where
        H: hash32::Hasher,
    {
        let t = self.clone() as u8;
        state.write(&[t]);
    }
}

impl Extension {
    pub const SIZE: u8 = 6;

    pub fn as_str(&self) -> &str {
        match self {
            Self::BlockSize => "blksize",
            Self::Timeout => "timeout",
            Self::TransferSize => "tsize",
            Self::PublicKey => "pkey",
            Self::EncryptionLevel => "enclevel",
            Self::WindowSize => "windowsize",
        }
    }
}

impl Display for Extension {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Extension {
    type Err = PacketError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "blksize" | "BLKSIZE" => Self::BlockSize,
            "timeout" | "TIMEOUT" => Self::Timeout,
            "tsize" | "TSIZE" => Self::TransferSize,
            "pkey" | "PKEY" => Self::PublicKey,
            "enclevel" | "ENCLEVEL" => Self::EncryptionLevel,
            "windowsize" | "WINDOWSIZE" => Self::WindowSize,
            _ => return Err(PacketError::Invalid),
        })
    }
}

#[derive(Debug, Clone)]
pub struct OptionalAck {
    pub extensions: PacketExtensions,
}

impl<'a> ByteConverter<'a> for OptionalAck {
    fn from_bytes(bytes: &[u8]) -> PacketResult<Self> {
        let mut rest = bytes;
        let mut extensions = PacketExtensions::new();
        while extensions.len() < Extension::SIZE as usize {
            let (next, name) = match rest.iter().position(|&c| c == b'\0') {
                Some(n) => (rest.get(n + 1..), from_utf8(&rest[0..n])?),
                _ => return Err(PacketError::Invalid),
            };

            let Some(next) = next else {
                return Err(PacketError::Invalid);
            };

            let (next, value) = match next.iter().position(|&c| c == b'\0') {
                Some(n) => (next.get(n + 1..), from_utf8(&next[0..n])?),
                _ => return Err(PacketError::Invalid),
            };

            if let (Ok(extension), Ok(value)) = (name.parse(), value.parse()) {
                let _ = extensions.insert(extension, value);
            };

            match next {
                Some(r) if !r.is_empty() => rest = r,
                _ => break,
            };
        }
        Ok(Self { extensions })
    }

    fn to_bytes(self) -> PacketBlock {
        self.extensions
            .into_iter()
            .fold(PacketBlock::new(), |mut v, (key, value)| {
                let bytes = key
                    .as_str()
                    .as_bytes()
                    .iter()
                    .copied()
                    .chain([0])
                    .chain(value.as_bytes().iter().copied())
                    .chain([0]);
                v.extend(bytes);
                v
            })
    }

    fn to_buffer(self, buffer: &mut [u8]) -> Option<usize> {
        let mut size = 0;
        for (key, value) in self.extensions {
            size = buffer.write_bytes(key.as_str().as_bytes(), size)?;
            size = buffer.write_bytes([0], size)?;
            size = buffer.write_bytes(value.as_bytes(), size)?;
            size = buffer.write_bytes([0], size)?;
        }
        Some(size)
    }
}

#[derive(Debug, Clone)]
pub struct RequestPacket {
    pub file_name: FilePath,
    pub mode: Mode,
    pub extensions: PacketExtensions,
}

impl<'a> ByteConverter<'a> for RequestPacket {
    fn from_bytes(bytes: &[u8]) -> PacketResult<Self> {
        let (rest, name) = match bytes.iter().position(|&c| c == b'\0') {
            Some(n) => (
                bytes.get(n + 1..).ok_or(PacketError::Invalid)?,
                from_utf8(&bytes[0..n])?,
            ),
            _ => return Err(PacketError::Invalid),
        };
        let file_name = name.parse().map_err(|_duration| PacketError::Invalid)?;

        let (rest, octet) = match rest.iter().position(|&c| c == b'\0') {
            Some(n) => (rest.get(n + 1..), from_utf8(&rest[..n])?),
            _ => return Err(PacketError::Invalid),
        };
        let mode = octet.parse().map_err(|_duration| PacketError::Invalid)?;

        let extensions = match rest {
            Some(b) if !b.is_empty() => OptionalAck::from_bytes(b)?.extensions,
            _ => PacketExtensions::new(),
        };

        Ok(Self {
            file_name,
            mode,
            extensions,
        })
    }

    fn to_buffer(self, buffer: &mut [u8]) -> Option<usize> {
        let optional = OptionalAck {
            extensions: self.extensions,
        };

        let mut size = buffer.write_bytes(self.file_name.as_bytes(), 0_usize)?;
        size = buffer.write_bytes([0], size)?;
        size = buffer.write_bytes(self.mode.as_str().as_bytes(), size)?;
        size = buffer.write_bytes([0], size)?;
        optional
            .to_buffer(buffer.get_mut(size..)?)
            .map(|s| size + s)
    }

    fn to_bytes(self) -> PacketBlock {
        let name = self.file_name.as_str();
        let optional = OptionalAck {
            extensions: self.extensions,
        };
        name.as_bytes()
            .iter()
            .copied()
            .chain([0])
            .chain(self.mode.as_str().as_bytes().iter().copied())
            .chain([0])
            .chain(optional.to_bytes())
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct DataPacket<'a> {
    pub block: u16,
    pub data: &'a [u8],
}

impl<'a> ByteConverter<'a> for DataPacket<'a> {
    fn from_bytes(bytes: &'a [u8]) -> PacketResult<Self> {
        let block = try_from(bytes)?;
        Ok(Self {
            block,
            data: bytes
                .get(size_of_val(&block)..)
                .ok_or(PacketError::Invalid)?,
        })
    }

    fn to_bytes(self) -> PacketBlock {
        self.block
            .to_be_bytes()
            .into_iter()
            .chain(self.data.iter().copied())
            .collect()
    }

    fn to_buffer(self, buffer: &mut [u8]) -> Option<usize> {
        let mut size = buffer.write_bytes(self.block.to_be_bytes(), 0_usize)?;
        size = buffer.write_bytes(self.data, size)?;
        Some(size)
    }
}

#[derive(Debug, Clone)]
pub struct AckPacket {
    pub block: u16,
}

impl<'a> ByteConverter<'a> for AckPacket {
    fn from_bytes(bytes: &[u8]) -> PacketResult<Self> {
        Ok(Self {
            block: try_from(bytes)?,
        })
    }

    fn to_bytes(self) -> PacketBlock {
        self.block.to_be_bytes().into_iter().collect()
    }

    fn to_buffer(self, buffer: &mut [u8]) -> Option<usize> {
        buffer.write_bytes(self.block.to_be_bytes(), 0_usize)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum ErrorCode {
    Undefined,
    FileNotFound,
    AccessVioliation,
    DiskFull,
    IllegalOperation,
    UnknownId,
    FileAlreadyExists,
    NotSuchUser,
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ErrorCode::Undefined => write!(f, "Undefined"),
            ErrorCode::FileNotFound => write!(f, "FileNotFound"),
            ErrorCode::AccessVioliation => write!(f, "AccessVioliation"),
            ErrorCode::DiskFull => write!(f, "DiskFull"),
            ErrorCode::IllegalOperation => write!(f, "IllegalOperation"),
            ErrorCode::UnknownId => write!(f, "UnknownId"),
            ErrorCode::FileAlreadyExists => write!(f, "FileAlreadyExists"),
            ErrorCode::NotSuchUser => write!(f, "NotSuchUser"),
        }
    }
}

impl ErrorCode {
    fn from_repr(s: u16) -> Option<Self> {
        match s {
            0 => ErrorCode::Undefined,
            1 => ErrorCode::FileNotFound,
            2 => ErrorCode::AccessVioliation,
            3 => ErrorCode::DiskFull,
            4 => ErrorCode::IllegalOperation,
            5 => ErrorCode::UnknownId,
            6 => ErrorCode::FileAlreadyExists,
            7 => ErrorCode::NotSuchUser,
            _ => return None,
        }
        .into()
    }
}

#[derive(Debug, Clone)]
pub struct ErrorPacket {
    pub code: ErrorCode,
    pub message: DefaultString,
}

impl ErrorPacket {
    pub fn new(code: ErrorCode, message: DefaultString) -> Self {
        Self { code, message }
    }
}

impl<'a> ByteConverter<'a> for ErrorPacket {
    fn from_bytes(bytes: &[u8]) -> PacketResult<Self> {
        let code = try_from(bytes)?;
        let code = ErrorCode::from_repr(code).ok_or(PacketError::Invalid)?;
        let message_bytes = bytes
            .get(size_of_val(&code)..)
            .ok_or(PacketError::Invalid)?;
        let message = match message_bytes.iter().position(|&c| c == b'\0') {
            Some(n) => from_utf8(&message_bytes[..n])?,
            _ => return Err(PacketError::Invalid),
        };
        Ok(Self {
            code,
            message: message.parse().map_err(|_| PacketError::Invalid)?,
        })
    }

    fn to_bytes(self) -> PacketBlock {
        (self.code as u16)
            .to_be_bytes()
            .into_iter()
            .chain(self.message.as_bytes().iter().copied())
            .chain([0])
            .collect()
    }

    fn to_buffer(self, buffer: &mut [u8]) -> Option<usize> {
        let mut size = buffer.write_bytes((self.code as u16).to_be_bytes(), 0_usize)?;
        size = buffer.write_bytes(self.message.as_bytes(), size)?;
        size = buffer.write_bytes([0], size)?;
        Some(size)
    }
}

pub fn prepend_data_header(block: u16, buffer: &mut DataBuffer) {
    let size = buffer
        .write_bytes(PacketType::Data.to_bytes(), 0_usize)
        .expect("packet buffer for data packet");
    buffer
        .write_bytes(block.to_be_bytes(), size)
        .expect("packet buffer for data packet");
}

fn try_from(bytes: &[u8]) -> Result<u16, PacketError> {
    Ok(u16::from_be_bytes(
        bytes
            .get(..size_of::<u16>())
            .ok_or(PacketError::Invalid)?
            .try_into()?,
    ))
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::string::format_str;

    #[test]
    fn test_read() {
        let data = [
            (true, b"\x00\x01foobar.txt\x00octet\x00".to_vec()),
            (false, b"\x00\x01foobar.txtoctet\x00".to_vec()),
            (false, b"\x00\x01foobar.txt\x00octet".to_vec()),
            (false, b"\x00\x01foobar.txtoctet".to_vec()),
            // extensions
            (true, b"\x00\x01foobar.txt\x00octet\x00blksize\x001252\x00".to_vec()),
            (true, b"\x00\x01foobar.txt\x00octet\x00blksize\x001252\x00tsize\x002000\x00timeout\x001\x00windowsize\x008\x00".to_vec()),
            (false, b"\x00\x01foobar.txt\x00octet\x00blksize\x001252\x00tsize\x002000\x00timeout\x00".to_vec()),
        ];

        for (index, (expected, request)) in data.into_iter().enumerate() {
            let packet = Packet::from_bytes(&request);
            assert_eq!(packet.is_ok(), expected, "{index} {packet:?}");
            if expected {
                assert!(matches!(packet, Ok(Packet::Read(RequestPacket { .. }))));
            }
        }

        assert_eq!(
            Packet::Read(RequestPacket {
                file_name: "foobar.txt".parse().unwrap(),
                mode: Mode::Octet,
                extensions: Default::default(),
            })
            .to_bytes()
            .as_slice(),
            b"\x00\x01foobar.txt\x00octet\x00"
        );
    }

    #[test]
    fn test_write() {
        let data = [
            (true, b"\x00\x02foobar.txt\x00octet\x00".to_vec()),
            (false, b"\x00\x02foobar.txtoctet\x00".to_vec()),
            (false, b"\x00\x02foobar.txt\x00octet".to_vec()),
            (false, b"\x00\x02foobar.txtoctet".to_vec()),
        ];

        for (index, (expected, request)) in data.into_iter().enumerate() {
            let packet = Packet::from_bytes(&request);
            assert_eq!(packet.is_ok(), expected, "{index} {packet:?}");
            if expected {
                assert!(matches!(packet, Ok(Packet::Write(RequestPacket { .. }))));
            }
        }

        assert_eq!(
            Packet::Write(RequestPacket {
                file_name: "foobar.txt".parse().unwrap(),
                mode: Mode::Octet,
                extensions: Default::default(),
            })
            .to_bytes()
            .as_slice(),
            b"\x00\x02foobar.txt\x00octet\x00"
        );
    }

    #[test]
    fn test_data() {
        let data = [
            (true, b"\x00\x03\x00\x01".to_vec()),
            (true, b"\x00\x03\x00\x01\x33\x55".to_vec()),
            (false, b"\x00\x03\x00".to_vec()),
            (false, b"\x00\x03".to_vec()),
            (false, b"".to_vec()),
        ];

        for (index, (expected, request)) in data.into_iter().enumerate() {
            let packet = Packet::from_bytes(&request);
            assert_eq!(packet.is_ok(), expected, "{index} {packet:?}");
            if expected {
                assert!(matches!(packet, Ok(Packet::Data(DataPacket { .. }))));
            }
        }

        assert_eq!(
            Packet::Data(DataPacket {
                block: 1,
                data: &[0x30, 0x31],
            })
            .to_bytes()
            .as_slice(),
            b"\x00\x03\x00\x01\x30\x31"
        );
    }

    #[test]
    fn test_ack() {
        let data = [
            (true, b"\x00\x04\x00\x01".to_vec()),
            (false, b"\x00\x04\x00".to_vec()),
            (false, b"\x00\x04".to_vec()),
            (false, b"".to_vec()),
        ];

        for (index, (expected, request)) in data.into_iter().enumerate() {
            let packet = Packet::from_bytes(&request);
            assert_eq!(packet.is_ok(), expected, "{index} {packet:?}");
            if expected {
                assert!(matches!(packet, Ok(Packet::Ack(AckPacket { .. }))));
            }
        }

        assert_eq!(
            Packet::Ack(AckPacket { block: 1 }).to_bytes().as_slice(),
            b"\x00\x04\x00\x01"
        );
    }

    #[test]
    fn test_error() {
        let data = [
            (true, b"\x00\x05\x00\x01File not found\x00".to_vec()),
            (cfg!(feature = "alloc"), b"\x00\x05\x00\x01File not found File not found File not found File not found File not found File not found File
             not found File not found File not found File not found File not found File not found\x00".to_vec()),
            (false, b"\x00\x05\x00\x09File not found\x00".to_vec()),
            (false, b"\x00\x05File not found\x00".to_vec()),
            (false, b"\x00\x05\x00\x01File not found".to_vec()),
        ];

        for (index, (expected, request)) in data.into_iter().enumerate() {
            let packet = Packet::from_bytes(&request);
            assert_eq!(packet.is_ok(), expected, "{index} {packet:?}");
            if expected {
                assert!(matches!(packet, Ok(Packet::Error(ErrorPacket { .. }))));
            }
        }

        let packet =
            ErrorPacket::from_bytes(b"\x00\x01Testing long meesage where file is not found\x00")
                .unwrap();
        assert_eq!(ErrorCode::FileNotFound, packet.code);
        assert_eq!(
            "Testing long meesage where file is not found",
            packet.message
        );

        assert_eq!(
            Packet::Error(ErrorPacket {
                code: ErrorCode::FileNotFound,
                message: "File not found".parse().unwrap()
            })
            .to_bytes()
            .as_slice(),
            b"\x00\x05\x00\x01File not found\x00"
        );

        assert_eq!(
            Packet::Error(ErrorPacket::new(
                ErrorCode::DiskFull,
                format_str!(
                    DefaultString,
                    "Unable to write file {}",
                    "some-file-to-test.bin"
                ),
            ))
            .to_bytes()
            .as_slice(),
            b"\x00\x05\x00\x03Unable to write file some-file-to-test.bin\x00"
        );
    }

    #[test]
    fn test_optional_ack() {
        let data = [
            (true, b"\x00\x06blksize\x001252\x00".to_vec()),
            (
                true,
                b"\x00\x06blksize\x001252\x00timeout\x001252\x00tsize\x001252\x00".to_vec(),
            ),
            (true, b"\x00\x06blks\x001252\x00".to_vec()),
            (
                true,
                b"\x00\x06blksize\x001252\x00unknown\x001252\x00tsize\x001252\x00".to_vec(),
            ),
            (
                false,
                b"\x00\x06blksize\x001252\x00unknown\x001252\x00tsize\x001252".to_vec(),
            ),
            (
                false,
                b"\x00\x06blksize\x001252\x00unknown\x001252\x00tsize\x00".to_vec(),
            ),
        ];

        for (index, (expected, request)) in data.into_iter().enumerate() {
            let packet = Packet::from_bytes(&request);
            assert_eq!(packet.is_ok(), expected, "{index} {packet:?}");
            if expected {
                assert!(matches!(
                    packet,
                    Ok(Packet::OptionalAck(OptionalAck { .. }))
                ));
            }
        }

        assert_eq!(
            Packet::OptionalAck(OptionalAck {
                extensions: [
                    (Extension::Timeout, format_str!(ExtensionValue, "{}", 123)),
                    (
                        Extension::TransferSize,
                        format_str!(ExtensionValue, "{}", 123)
                    ),
                ]
                .into_iter()
                .collect()
            })
            .to_bytes()
            .as_slice(),
            b"\x00\x06timeout\x00123\x00tsize\x00123\x00",
        );

        assert_eq!(
            Packet::OptionalAck(OptionalAck {
                extensions: Default::default(),
            })
            .to_bytes()
            .as_slice(),
            b"\x00\x06"
        );
    }

    #[test]
    fn test_unknown_extensions_ignored() {
        let packet =
            OptionalAck::from_bytes(b"BLKSIZE\x001252\x00unknown\x001252\x00TSIZE\x0012\x00")
                .unwrap();
        assert_eq!(packet.extensions.len(), 2, "{packet:?}");
        assert_eq!(
            packet.extensions[&Extension::BlockSize],
            ExtensionValue::from_str("1252").unwrap()
        );
        assert_eq!(
            packet.extensions[&Extension::TransferSize],
            ExtensionValue::from_str("12").unwrap()
        );
    }

    #[test]
    fn test_byte_retrieval() {
        let bytes = b"\x01\x02\x03\x04\x05\x06";
        assert_eq!(Some([1, 2, 3].as_slice()), bytes.get(0..3));
        assert_eq!(Some([1, 2, 3].as_slice()), bytes.get(..3));
        assert_eq!(Some([4, 5, 6].as_slice()), bytes.get(3..));
        assert_eq!(Some([4, 5, 6].as_slice()), bytes.get(3..6));
        assert_eq!(Some([].as_slice()), bytes.get(6..));
        assert_eq!(None, bytes.get(7..));
        assert_eq!(Some(&1_u8), bytes.first());
        assert_eq!(None, bytes.get(6));
    }

    #[test]
    fn test_error_code() {
        assert_eq!(ErrorCode::from_repr(1), Some(ErrorCode::FileNotFound));
        assert_eq!(1, ErrorCode::FileNotFound as u16);
    }
}
