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
    /// `N` is the capacity of the fixed size list used without `alloc`.
    pub type List<T, const N: usize> = alloc::vec::Vec<T>;
    pub type DataBuffer = alloc::vec::Vec<u8>;
    pub type DataBlock = alloc::vec::Vec<u8>;
    pub type StreamBlock = alloc::vec::Vec<u8>;
    pub type PacketBlock = alloc::vec::Vec<u8>;
    pub type PacketExtensionNames<'a> = alloc::vec::Vec<&'a str>;
    pub type DefaultString = alloc::string::String;
    pub type ExtensionValue = alloc::string::String;
    pub type ShortString = alloc::string::String;
    pub type FilePath = alloc::string::String;
}

#[cfg(not(feature = "alloc"))]
pub mod types {
    pub type List<T, const N: usize> = heapless::Vec<T, N>;
    pub type DataBuffer = heapless::Vec<u8, { crate::config::MAX_BUFFER_SIZE as usize }>;
    pub type PacketBlock = DataBuffer;
    pub type DataBlock = heapless::Vec<u8, { crate::config::MAX_DATA_BLOCK_SIZE as usize }>;
    pub type StreamBlock = crate::buffer::StreamBlock;
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
    use crate::macros::cfg_stack;

    #[cfg(feature = "alloc")]
    macro_rules! format_str {
        ($stype:ident, $($t:tt)*) => {{
            use core::fmt::Write;
            let mut s = crate::types::$stype::new();
            write!(&mut s, $($t)*).expect("string must be written");
            s
        }};
    }

    /// Text that does not fit the capacity of `$stype` is cut, because it can
    /// echo what a remote peer sent.
    #[cfg(not(feature = "alloc"))]
    macro_rules! format_str {
        ($stype:ident, $($t:tt)*) => {{
            use core::fmt::Write;
            let mut s = crate::types::$stype::new();
            let _ = write!(crate::string::Truncating(&mut s), $($t)*);
            s
        }};
    }
    pub(crate) use format_str;

    cfg_stack! {
        pub(crate) struct Truncating<'a, const N: usize>(pub(crate) &'a mut heapless::String<N>);

        impl<const N: usize> core::fmt::Write for Truncating<'_, N> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let room = self.0.capacity() - self.0.len();
                self.0
                    .push_str(ensure_size(s, room))
                    .map_err(|_| core::fmt::Error)
            }
        }
    }

    pub(crate) fn ensure_size(s: &str, max_size: usize) -> &str {
        if s.len() > max_size {
            let end = (0..=max_size)
                .rev()
                .find(|&i| s.is_char_boundary(i))
                .unwrap_or(0);
            return &s[..end];
        }
        s
    }

    /// The part of an ASCII `message` that an error packet carries.
    #[cfg(test)]
    pub(crate) fn expected_message(message: &str) -> &str {
        let limit = crate::config::ConnectionOptions::default().max_error_message_size(false);
        &message[..limit.min(message.len())]
    }

    #[cfg(test)]
    mod tests {
        use super::ensure_size;

        #[test]
        fn test_ensure_size_keeps_a_string_that_fits() {
            assert_eq!(ensure_size("", 0), "");
            assert_eq!(ensure_size("abc", 4), "abc");
            assert_eq!(ensure_size("abc", 3), "abc");
        }

        #[test]
        fn test_ensure_size_cuts_a_longer_string() {
            assert_eq!(ensure_size("abc", 2), "ab");
            assert_eq!(ensure_size("abc", 0), "");
        }

        #[test]
        fn test_ensure_size_does_not_split_a_character() {
            // é takes two bytes, at positions 1 and 2
            assert_eq!(ensure_size("aéb", 3), "aé");
            assert_eq!(ensure_size("aéb", 2), "a");
            assert_eq!(ensure_size("éb", 1), "");
        }
    }

    #[cfg(all(test, not(feature = "alloc")))]
    mod stack_tests {
        use crate::config::MAX_DEFAULT_STRING_SIZE;

        #[test]
        fn test_format_str_keeps_text_that_fits() {
            assert_eq!(format_str!(ExtensionValue, "{}-{}", 1, "a").as_str(), "1-a");
        }

        #[test]
        fn test_format_str_cuts_at_the_capacity_of_the_type() {
            let long = "x".repeat(MAX_DEFAULT_STRING_SIZE as usize * 2);

            let message = format_str!(DefaultString, "prefix {long}");

            let expected = format!("prefix {long}");
            assert_eq!(
                message.as_str(),
                &expected[..MAX_DEFAULT_STRING_SIZE as usize]
            );
        }

        #[test]
        fn test_format_str_does_not_split_a_character() {
            let long = "é".repeat(MAX_DEFAULT_STRING_SIZE as usize);

            let message = format_str!(DefaultString, "a{long}");

            // 1 + 69 * 2 bytes, the next character would end past the capacity of 140
            assert_eq!(message.as_str(), format!("a{}", "é".repeat(69)));
        }
    }
}

pub mod time {
    use crate::std_compat::time::Instant;
    pub type InstantCallback = fn() -> Instant;

    #[cfg(all(test, feature = "std"))]
    pub fn test_now() -> Instant {
        Instant::now()
    }

    #[cfg(all(test, not(feature = "std")))]
    pub fn test_now() -> Instant {
        use std::sync::OnceLock;

        static START: OnceLock<std::time::Instant> = OnceLock::new();
        Instant::from_time(|| {
            START
                .get_or_init(std::time::Instant::now)
                .elapsed()
                .as_micros() as u64
        })
    }
}

#[cfg(feature = "alloc")]
pub mod map {
    pub use alloc::collections::btree_map::Entry;
    use alloc::collections::btree_map::VacantEntry;
    use alloc::collections::BTreeMap;

    /// `N` is the capacity of the fixed size map used without `alloc`.
    pub type Map<K, V, const N: usize> = BTreeMap<K, V>;

    #[allow(dead_code)]
    pub fn insert_vacant<K: Ord, V>(entry: VacantEntry<'_, K, V>, value: V) -> bool {
        entry.insert(value);
        true
    }
}

#[cfg(not(feature = "alloc"))]
pub mod map {
    pub use heapless::Entry;
    pub use heapless::FnvIndexMap as Map;
    use heapless::VacantEntry;

    #[allow(dead_code)]
    pub fn insert_vacant<K: Eq + core::hash::Hash, V, const N: usize>(
        entry: VacantEntry<'_, K, V, N>,
        value: V,
    ) -> bool {
        entry.insert(value).is_ok()
    }
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
pub use buffer::extend_from_slice;
pub mod client;
pub mod config;
#[cfg(feature = "encryption")]
pub mod encrypted_packet;
#[cfg(feature = "encryption")]
pub mod encryption;
mod macros;
#[cfg(not(feature = "encryption"))]
pub use features::no_encryption as encryption;
pub mod error;
pub mod features;

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
pub use features::no_key_management as key_management;

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
