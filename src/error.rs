use core::array::TryFromSliceError;
use core::fmt::Display;
use core::fmt::Formatter;
use core::str::Utf8Error;
use core::time::Duration;

use crate::encryption::EncryptionLevel;
use crate::packet::Extension;
use crate::std_compat::error::Error;
use crate::types::DefaultString;

#[cfg(all(feature = "std", feature = "alloc"))]
pub type BoxedError = alloc::boxed::Box<dyn std::error::Error + Send + Sync>;
#[cfg(not(all(feature = "std", feature = "alloc")))]
pub type BoxedError = GeneralError;
pub type BoxedResult<T> = Result<T, BoxedError>;
pub type DefaultBoxedResult = Result<(), BoxedError>;

#[cfg(not(all(feature = "std", feature = "alloc")))]
#[derive(Debug)]
pub enum GeneralError {
    PacketError(PacketError),
    FileError(FileError),
    StorageError(StorageError),
    EncryptionError(EncryptionError),
    ExtensionError(ExtensionError),
    IoError(crate::std_compat::io::Error),
    FmtError(core::fmt::Error),
    AvailabilityError(AvailabilityError),
    Infallible,
}

#[cfg(not(all(feature = "std", feature = "alloc")))]
impl Display for GeneralError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            GeneralError::PacketError(s) => s.fmt(f),
            GeneralError::FileError(s) => s.fmt(f),
            GeneralError::StorageError(s) => s.fmt(f),
            GeneralError::EncryptionError(s) => s.fmt(f),
            GeneralError::ExtensionError(s) => s.fmt(f),
            GeneralError::IoError(s) => s.fmt(f),
            GeneralError::FmtError(s) => s.fmt(f),
            GeneralError::AvailabilityError(s) => s.fmt(f),
            GeneralError::Infallible => write!(f, "unknown error"),
        }
    }
}

#[cfg(not(all(feature = "std", feature = "alloc")))]
impl From<PacketError> for GeneralError {
    fn from(source: PacketError) -> Self {
        GeneralError::PacketError(source)
    }
}

#[cfg(not(all(feature = "std", feature = "alloc")))]
impl From<FileError> for GeneralError {
    fn from(source: FileError) -> Self {
        GeneralError::FileError(source)
    }
}

#[cfg(not(all(feature = "std", feature = "alloc")))]
impl From<StorageError> for GeneralError {
    fn from(source: StorageError) -> Self {
        GeneralError::StorageError(source)
    }
}

#[cfg(not(all(feature = "std", feature = "alloc")))]
impl From<EncryptionError> for GeneralError {
    fn from(source: EncryptionError) -> Self {
        GeneralError::EncryptionError(source)
    }
}

#[cfg(not(all(feature = "std", feature = "alloc")))]
impl From<ExtensionError> for GeneralError {
    fn from(source: ExtensionError) -> Self {
        GeneralError::ExtensionError(source)
    }
}

#[cfg(not(all(feature = "std", feature = "alloc")))]
impl From<crate::std_compat::io::Error> for GeneralError {
    fn from(source: crate::std_compat::io::Error) -> Self {
        GeneralError::IoError(source)
    }
}

#[cfg(not(all(feature = "std", feature = "alloc")))]
impl From<core::fmt::Error> for GeneralError {
    fn from(source: core::fmt::Error) -> Self {
        GeneralError::FmtError(source)
    }
}

#[cfg(not(all(feature = "std", feature = "alloc")))]
impl From<core::convert::Infallible> for GeneralError {
    fn from(_: core::convert::Infallible) -> Self {
        GeneralError::Infallible
    }
}

#[cfg(not(all(feature = "std", feature = "alloc")))]
impl From<AvailabilityError> for GeneralError {
    fn from(source: AvailabilityError) -> Self {
        GeneralError::AvailabilityError(source)
    }
}

#[derive(Debug)]
pub enum PacketError {
    Invalid,
    RemoteError(DefaultString),
    Timeout(Duration),
    InvalidString(Utf8Error),
    InvalidData(TryFromSliceError),
    InvalidMode,
}

impl Display for PacketError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            PacketError::Invalid => write!(f, "Invalid packet received"),
            PacketError::InvalidMode => write!(
                f,
                "Invalid mode received. Only octet/binary mode is supported"
            ),
            PacketError::RemoteError(s) => write!(f, "{s}"),
            PacketError::Timeout(s) => write!(f, "Timeout occured {}", s.as_secs_f32()),
            PacketError::InvalidString(s) => s.fmt(f),
            PacketError::InvalidData(s) => s.fmt(f),
        }
    }
}

impl Error for PacketError {}

impl From<Utf8Error> for PacketError {
    fn from(source: Utf8Error) -> Self {
        PacketError::InvalidString(source)
    }
}

impl From<TryFromSliceError> for PacketError {
    fn from(source: TryFromSliceError) -> Self {
        PacketError::InvalidData(source)
    }
}

pub type PacketResult<T> = Result<T, PacketError>;

#[derive(Debug)]
pub struct ExistingBlock {
    pub current: u16,
    pub current_index: u64,
}

#[derive(Debug)]
pub enum StorageError {
    File(crate::std_compat::io::Error),
    AlreadyWritten(ExistingBlock),
    ExpectedBlock(ExistingBlock),
    InvalidBuffer { actual: usize, expected: usize },
}

impl From<crate::std_compat::io::Error> for StorageError {
    fn from(source: crate::std_compat::io::Error) -> Self {
        StorageError::File(source)
    }
}

impl Error for StorageError {}

impl Display for StorageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            // StorageError::CapacityReached => write!(f, "Buffer capacity reached"),
            StorageError::File(s) => s.fmt(f),
            StorageError::AlreadyWritten(_) => write!(f, "Block has been already written"),
            StorageError::InvalidBuffer { actual, expected } => {
                write!(f, "Invalid buffer len {actual} expected {expected}")
            }
            // StorageError::FileTooBig => write!(f, "File is too big"),
            StorageError::ExpectedBlock(e) => {
                write!(f, "Expecting block after {}", e.current)
            }
        }
    }
}

#[derive(Debug)]
pub enum FileError {
    InvalidFileName,
}

impl Error for FileError {}

impl Display for FileError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            FileError::InvalidFileName => write!(f, "Invalid file name specified"),
        }
    }
}

#[derive(Debug)]
pub enum ExtensionError {
    ClientRequiredEncryption(EncryptionLevel),
    ServerRequiredEncryption(EncryptionLevel),
    InvalidPublicKey,
    InvalidNonce,
    NotAuthorized,
    InvalidSignature,
    EncryptionError(EncryptionError),
    InvalidExtension(Extension),
}

impl Error for ExtensionError {}

impl Display for ExtensionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            ExtensionError::ClientRequiredEncryption(l) => write!(
                f,
                "Server does not provide encryption however client requested encryption level {l}",
            ),
            ExtensionError::ServerRequiredEncryption(l) => {
                write!(f, "Server requires {l} encryption",)
            }
            ExtensionError::InvalidPublicKey => write!(f, "Invalid public key received",),
            ExtensionError::NotAuthorized => write!(f, "Not Authorized",),
            ExtensionError::InvalidNonce => write!(f, "Invalid nonce received",),
            ExtensionError::EncryptionError(s) => {
                write!(f, "Invalid extension parsing error {s}")
            }
            ExtensionError::InvalidExtension(s) => {
                write!(f, "Invalid extension {s}")
            }
            ExtensionError::InvalidSignature => write!(f, "Invalid signature received",),
        }
    }
}

impl From<EncryptionError> for ExtensionError {
    fn from(source: EncryptionError) -> Self {
        ExtensionError::EncryptionError(source)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EncodingErrorType {
    PrivateKey,
    PublicKey,
    Nonce,
    Signature,
}

impl Display for EncodingErrorType {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            EncodingErrorType::PrivateKey => write!(f, "private key"),
            EncodingErrorType::PublicKey => write!(f, "public key"),
            EncodingErrorType::Nonce => write!(f, "nonce"),
            EncodingErrorType::Signature => write!(f, "signature"),
        }
    }
}

#[derive(Debug)]
pub enum PaddingError {
    EmptyBuffer,
    MissingPaddingByte,
    InvalidSizeProvided,
}

impl Display for PaddingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            PaddingError::EmptyBuffer => write!(f, "Empty buffer provided"),
            PaddingError::MissingPaddingByte => write!(f, "Missing padding byte"),
            PaddingError::InvalidSizeProvided => write!(f, "Invalid padding size provided"),
        }
    }
}

#[derive(Debug)]
pub enum EncryptionError {
    Encrypt,
    Decrypt,
    Nonce,
    NoStream,
    Tag,
    Encode(EncodingErrorType),
    Decode(EncodingErrorType),
    Padding(PaddingError),
}

impl Error for EncryptionError {}

impl Display for EncryptionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            EncryptionError::Encrypt => write!(f, "Failed to encrypt"),
            EncryptionError::Decrypt => write!(f, "Failed to decrypt"),
            EncryptionError::Nonce => write!(f, "Invalid nonce"),
            EncryptionError::Tag => write!(f, "Invalid tag"),
            EncryptionError::NoStream => write!(f, "Stream has been used"),
            EncryptionError::Encode(t) => write!(f, "Failed to encode {t}"),
            EncryptionError::Decode(t) => write!(f, "Failed to decode {t}"),
            EncryptionError::Padding(t) => write!(f, "Failed to pad {t}"),
        }
    }
}

#[derive(Debug)]
pub enum AvailabilityError {
    NoReaderAvailable,
}

impl Error for AvailabilityError {}

impl Display for AvailabilityError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            AvailabilityError::NoReaderAvailable => write!(f, "No reader available"),
        }
    }
}

#[derive(Debug)]
pub enum EncryptedPacketError {
    Padding(PaddingError),
    PublicKey,
    Nonce,
    InvalidData,
    Tag,
    CipherText,
    Encryption(EncryptionError),
}

impl Error for EncryptedPacketError {}

impl From<PaddingError> for EncryptedPacketError {
    fn from(source: PaddingError) -> Self {
        EncryptedPacketError::Padding(source)
    }
}

impl From<EncryptionError> for EncryptedPacketError {
    fn from(source: EncryptionError) -> Self {
        EncryptedPacketError::Encryption(source)
    }
}

impl Display for EncryptedPacketError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            EncryptedPacketError::Padding(t) => t.fmt(f),
            EncryptedPacketError::PublicKey => write!(f, "Invalid public key"),
            EncryptedPacketError::Nonce => write!(f, "Invalid nonce"),
            EncryptedPacketError::CipherText => write!(f, "Invalid cipher text"),
            EncryptedPacketError::InvalidData => write!(f, "Invalid data"),
            EncryptedPacketError::Tag => write!(f, "Invalid encryption tag"),
            EncryptedPacketError::Encryption(t) => t.fmt(f),
        }
    }
}
