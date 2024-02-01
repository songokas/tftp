pub mod time {
    // time in microseconds
    pub type CurrentTimeCallback = fn() -> u64;

    #[derive(Debug)]
    pub struct Instant {
        time: CurrentTimeCallback,
        init: core::time::Duration,
    }
    impl Instant {
        pub fn from_time(time: CurrentTimeCallback) -> Instant {
            Self {
                time,
                init: core::time::Duration::from_micros(time()),
            }
        }
        pub fn elapsed(&self) -> core::time::Duration {
            core::time::Duration::from_micros((self.time)()) - self.init
        }
    }
}

pub mod io {
    use crate::types::DefaultString;

    pub trait Read {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    }

    pub trait Write {
        fn write(&mut self, buf: &[u8]) -> Result<usize>;
        fn write_fmt(&mut self, fmt: core::fmt::Arguments<'_>) -> Result<()>;
        fn flush(&mut self) -> Result<()>;
    }

    pub trait Seek {
        fn seek(&mut self, pos: SeekFrom) -> Result<u64>;
    }

    pub enum SeekFrom {
        Start(u64),
        End(i64),
        Current(i64),
    }

    pub trait BufRead {
        fn lines(self) -> Lines<Self>
        where
            Self: Sized,
        {
            Lines { buf: self }
        }
        fn read_line(&mut self, buff: &mut DefaultString) -> Result<usize>;
    }

    #[derive(Debug)]
    pub struct Lines<B> {
        buf: B,
    }

    impl<B: BufRead> Iterator for Lines<B> {
        type Item = Result<DefaultString>;

        fn next(&mut self) -> Option<Result<DefaultString>> {
            let mut buf = DefaultString::new();
            match self.buf.read_line(&mut buf) {
                Ok(0) => None,
                Ok(_n) => {
                    if buf.ends_with('\n') {
                        buf.pop();
                        if buf.ends_with('\r') {
                            buf.pop();
                        }
                    }
                    Some(Ok(buf))
                }
                Err(e) => Some(Err(e)),
            }
        }
    }

    pub type Result<T> = core::result::Result<T, Error>;

    #[derive(Debug)]
    pub struct Error {
        kind: ErrorKind,
    }

    impl From<ErrorKind> for Error {
        fn from(kind: ErrorKind) -> Self {
            Self { kind }
        }
    }

    impl Error {
        pub fn kind(&self) -> ErrorKind {
            self.kind
        }
    }

    impl core::fmt::Display for Error {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{}", self.kind().as_str())
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Copy)]
    pub enum ErrorKind {
        NotFound,
        PermissionDenied,
        ConnectionRefused,
        ConnectionReset,
        ConnectionAborted,
        NotConnected,
        AddrInUse,
        AddrNotAvailable,
        BrokenPipe,
        AlreadyExists,
        WouldBlock,
        InvalidInput,
        InvalidData,
        TimedOut,
        WriteZero,
        Interrupted,
        UnexpectedEof,
        OutOfMemory,
        Other,
        Unsupported,
    }

    impl ErrorKind {
        pub(crate) fn as_str(&self) -> &'static str {
            use ErrorKind::*;
            match *self {
                NotFound => "entity not found",
                PermissionDenied => "permission denied",
                ConnectionRefused => "connection refused",
                ConnectionReset => "connection reset",
                ConnectionAborted => "connection aborted",
                NotConnected => "not connected",
                AddrInUse => "address in use",
                AddrNotAvailable => "address not available",
                BrokenPipe => "broken pipe",
                AlreadyExists => "entity already exists",
                WouldBlock => "operation would block",
                InvalidInput => "invalid input parameter",
                InvalidData => "invalid dat",
                TimedOut => "timed out",
                WriteZero => "write zero",
                Interrupted => "operation interrupted",
                UnexpectedEof => "unexpected end of file",
                OutOfMemory => "out of memory",
                Other => "other error",
                Unsupported => "operation not supported",
            }
        }
    }
}

pub mod error {
    pub trait Error {}
}

pub mod net {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
    pub struct SocketAddr {
        pub ip: IpVersion,
        pub port: u16,
    }

    impl SocketAddr {
        pub fn ip(&self) -> IpVersion {
            self.ip
        }

        pub fn port(&self) -> u16 {
            self.port
        }
    }
    #[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
    pub enum IpVersion {
        Ipv4([u8; 4]),
        Ipv6([u8; 16]),
    }

    impl core::fmt::Display for IpVersion {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                IpVersion::Ipv4(b) => {
                    write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3])
                }
                IpVersion::Ipv6(b) => write!(
                    f,
                    "{}.{}.{}.{}.{}.{}.{}.{}.{}.{}.{}.{}.{}.{}.{}.{}",
                    b[0],
                    b[1],
                    b[2],
                    b[3],
                    b[4],
                    b[5],
                    b[6],
                    b[7],
                    b[8],
                    b[9],
                    b[10],
                    b[11],
                    b[12],
                    b[13],
                    b[14],
                    b[15],
                ),
            }
        }
    }

    impl core::fmt::Display for SocketAddr {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{}:{}", self.ip, self.port)
        }
    }
}
