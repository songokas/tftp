use core::fmt::Display;
use core::fmt::Formatter;

use tftp_binary_common::client::OptionsError;
pub use tftp_binary_common::io::from_io_err;
use tftp_dus::error::BoxedError;
use tftp_dus::std_compat::io;

#[derive(Debug)]
pub enum BinError {
    Message(&'static str),
    Library(BoxedError),
    Options(OptionsError),
}

pub type BinResult<T> = Result<T, BinError>;

impl Display for BinError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            BinError::Message(m) => f.write_str(m),
            BinError::Library(e) => e.fmt(f),
            BinError::Options(e) => e.fmt(f),
        }
    }
}

impl From<&'static str> for BinError {
    fn from(message: &'static str) -> Self {
        BinError::Message(message)
    }
}

impl From<OptionsError> for BinError {
    fn from(source: OptionsError) -> Self {
        BinError::Options(source)
    }
}

impl From<BoxedError> for BinError {
    fn from(source: BoxedError) -> Self {
        BinError::Library(source)
    }
}

impl From<io::Error> for BinError {
    fn from(source: io::Error) -> Self {
        BinError::Library(source.into())
    }
}

pub fn last_os_error() -> io::Error {
    from_io_err(std::io::Error::last_os_error())
}
