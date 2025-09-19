#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::result_large_err)]

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;
extern crate core;

#[cfg(feature = "alloc")]
pub mod types {
    pub type DataBuffer = alloc::vec::Vec<u8>;
    pub type DataBlock = alloc::vec::Vec<u8>;
    // TODO remove with heapless 0.7
    pub type DataBlock07 = alloc::vec::Vec<u8>;
    pub type PacketBlock = alloc::vec::Vec<u8>;
    pub type PacketExtensionNames<'a> = alloc::vec::Vec<&'a str>;
    pub type DefaultString = alloc::string::String;
    pub type ExtensionValue = alloc::string::String;
    pub type ShortString = alloc::string::String;
    pub type FilePath = alloc::string::String;
}

#[cfg(not(feature = "alloc"))]
pub mod types {
    pub type DataBuffer = heapless::Vec<u8, { crate::config::MAX_BUFFER_SIZE as usize }>;
    pub type PacketBlock = DataBuffer;
    pub type DataBlock = heapless::Vec<u8, { crate::config::MAX_DATA_BLOCK_SIZE as usize }>;
    // TODO remove with heapless 0.7
    pub type DataBlock07 = heapless_07::Vec<u8, { crate::config::MAX_DATA_BLOCK_SIZE as usize }>;
    pub type PacketExtensionNames<'a> =
        heapless::Vec<&'a str, { crate::packet::Extension::SIZE as usize }>;
    pub type DefaultString = heapless::String<{ crate::config::MAX_DEFAULT_STRING_SIZE as usize }>;
    // max possible extension value (largest public key 45 bytes)
    pub type ExtensionValue =
        heapless::String<{ crate::config::MAX_EXTENSION_VALUE_SIZE as usize }>;
    pub type ShortString = ExtensionValue;
    pub type FilePath = heapless::String<{ crate::config::MAX_FILE_PATH_SIZE as usize }>;
}

mod string {
    macro_rules! format_str {
        ($stype:ident, $($t:tt)*) => {{
            use core::fmt::Write;
            let mut s = crate::types::$stype::new();
            write!(&mut s, $($t)*).expect("number must fit");
            s
        }};
    }
    pub(crate) use format_str;

    pub fn ensure_size(s: &str, max_size: usize) -> &str {
        if s.len() > max_size {
            let (f, _) = s.split_at(max_size);
            return f;
        }
        s
    }
}

pub mod time {
    use crate::std_compat::time::Instant;
    pub type InstantCallback = fn() -> Instant;
}

#[cfg(feature = "alloc")]
mod map {
    pub use alloc::collections::btree_map::Entry;
    pub use alloc::collections::BTreeMap as Map;
}

#[cfg(not(feature = "alloc"))]
mod map {
    pub use heapless::Entry;
    pub use heapless::FnvIndexMap as Map;
}

#[cfg(feature = "std")]
pub mod std_compat {
    pub mod time {
        pub use std::time::Instant;
    }

    pub mod io {
        pub use std::io::BufRead;
        pub use std::io::Error;
        pub use std::io::ErrorKind;
        pub use std::io::Read;
        pub use std::io::Result;
        pub use std::io::Seek;
        pub use std::io::SeekFrom;
        pub use std::io::Write;
    }

    pub mod error {
        pub use std::error::Error;
    }

    pub mod net {
        pub use std::net::SocketAddr;
    }
}

mod buffer;
pub mod client;
pub mod config;
#[cfg(feature = "encryption")]
pub mod encrypted_packet;
#[cfg(feature = "encryption")]
pub mod encryption;
mod macros;
#[cfg(not(feature = "encryption"))]
pub mod encryption {
    use core::marker::PhantomData;

    pub type PublicKey = ();
    pub type Nonce = ();
    pub type PrivateKey = ();
    pub type VerifyingKey = ();
    pub type SigningKey = ();
    pub type EncryptionKey = ();
    pub type InitialKeys = ();
    pub struct PublicKeyPair {
        pub auth: Option<()>,
        pub session: (),
    }

    pub type Encryptor<Rng> = PhantomData<Rng>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EncryptionLevel {
        Data,
        Protocol,
        Full,
        OptionalData,
        OptionalProtocol,
        None,
    }
    impl core::fmt::Display for EncryptionLevel {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "none")
        }
    }
}
pub mod error;

mod block_mapper;
mod flow_control;
pub mod packet;
pub mod readers;
pub mod server;
pub mod socket;
#[cfg(not(feature = "std"))]
pub mod std_compat;
pub mod writers;

#[cfg(feature = "encryption")]
pub mod key_management;
#[cfg(not(feature = "encryption"))]
pub mod key_management {
    pub fn append_to_known_hosts() {}
    pub fn get_from_known_hosts() {}
    pub fn read_authorized_keys() {}
    pub fn create_finalized_keys() {}
    pub fn create_initial_keys() {}
    pub type AuthorizedKeys = ();
}

#[cfg(feature = "metrics")]
mod metrics {
    pub use metrics::counter;
    pub use metrics::gauge;
    pub use metrics::histogram;
}
#[cfg(not(feature = "metrics"))]
mod metrics {
    pub struct Counter;
    impl Counter {
        pub fn increment(&self, _: u64) {}
    }
    pub struct Gauge;
    impl Gauge {
        pub fn set(&self, _: f64) {}
    }
    pub struct Histogram;
    impl Histogram {
        pub fn record(&self, _: core::time::Duration) {}
    }

    macro_rules! counter {
        (target: $target:expr, level: $level:expr, $name:expr $(, $label_key:expr $(=> $label_value:expr)?)* $(,)?) => {{
            crate::metrics::Counter {}
        }};
        (target: $target:expr, $name:expr $(, $label_key:expr $(=> $label_value:expr)?)* $(,)?) => {
            crate::metrics::Counter {}
        };
        (level: $level:expr, $name:expr $(, $label_key:expr $(=> $label_value:expr)?)* $(,)?) => {
            crate::metrics::Counter {}
        };
        ($name:expr $(, $label_key:expr $(=> $label_value:expr)?)* $(,)?) => {
            crate::metrics::Counter {}
        };
    }
    macro_rules! gauge {
        (target: $target:expr, level: $level:expr, $name:expr $(, $label_key:expr $(=> $label_value:expr)?)* $(,)?) => {{
            crate::metrics::Gauge {}
        }};
        (target: $target:expr, $name:expr $(, $label_key:expr $(=> $label_value:expr)?)* $(,)?) => {
            crate::metrics::Gauge {}
        };
        (level: $level:expr, $name:expr $(, $label_key:expr $(=> $label_value:expr)?)* $(,)?) => {
            crate::metrics::Gauge {}
        };
        ($name:expr $(, $label_key:expr $(=> $label_value:expr)?)* $(,)?) => {
            crate::metrics::Gauge {}
        };
    }
    macro_rules! histogram {
        (target: $target:expr, level: $level:expr, $name:expr $(, $label_key:expr $(=> $label_value:expr)?)* $(,)?) => {{
            crate::metrics::Histogram {}
        }};
        (target: $target:expr, $name:expr $(, $label_key:expr $(=> $label_value:expr)?)* $(,)?) => {
            crate::metrics::Histogram {}
        };
        (level: $level:expr, $name:expr $(, $label_key:expr $(=> $label_value:expr)?)* $(,)?) => {
            crate::metrics::Histogram {}
        };
        ($name:expr $(, $label_key:expr $(=> $label_value:expr)?)* $(,)?) => {
            crate::metrics::Histogram {}
        };
    }
    pub(crate) use counter;
    pub(crate) use gauge;
    pub(crate) use histogram;
}
