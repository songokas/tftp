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
    pub type EncryptionKey = ();

    pub type Encryptor<Rng> = PhantomData<Rng>;
    pub struct FinalizedKeys<Rng> {
        pub encryptor: Encryptor<Rng>,
    }

    #[derive(Clone, Debug)]
    pub enum EncryptionKeys {
        ClientKey(PublicKey),
        ServerKey(PublicKey, Nonce),
        LocalToRemote(PublicKey, PublicKey),
    }

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
#[cfg(not(feature = "alloc"))]
mod map;

mod block_mapper;
mod flow_control;
mod packet;
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
