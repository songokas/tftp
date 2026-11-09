use core::cmp::max;

use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::config::MAX_BUFFER_SIZE;
use crate::config::MIN_BUFFER_SIZE;
use crate::types;
use crate::types::DataBlock;
use crate::types::DataBuffer;

pub trait SliceMutExt {
    fn write_bytes(self, data: impl AsRef<[u8]>, from_index: impl Into<usize>) -> Option<usize>;
}

#[allow(dead_code)]
pub trait SliceExt {
    fn slice_to_array<const N: usize>(&self, position: impl Into<usize>) -> Option<[u8; N]>;

    fn slice_to_array_ref<const N: usize>(&self, position: impl Into<usize>) -> Option<&[u8; N]>;

    fn rslice_to_array<const N: usize>(&self, position: impl Into<usize>) -> Option<[u8; N]>;

    fn rslice_to_array_ref<const N: usize>(&self, position: impl Into<usize>) -> Option<&[u8; N]>;

    fn slice_at_end(&self, end: usize) -> Option<&[u8]>;
}

impl SliceMutExt for &mut [u8] {
    fn write_bytes(self, data: impl AsRef<[u8]>, from_index: impl Into<usize>) -> Option<usize> {
        let s = data.as_ref().len();
        let index = from_index.into();
        self.get_mut(index..index + s)?
            .copy_from_slice(data.as_ref());
        Some(index + s)
    }
}

impl SliceExt for [u8] {
    fn slice_to_array<const N: usize>(&self, from_position: impl Into<usize>) -> Option<[u8; N]> {
        let index = from_position.into();
        self.get(index..index + N).and_then(|v| v.try_into().ok())
    }

    fn slice_to_array_ref<const N: usize>(
        &self,
        from_position: impl Into<usize>,
    ) -> Option<&[u8; N]> {
        let index = from_position.into();
        self.get(index..index + N).and_then(|v| v.try_into().ok())
    }

    fn rslice_to_array<const N: usize>(&self, to_position: impl Into<usize>) -> Option<[u8; N]> {
        let index = to_position.into();
        let from = self
            .len()
            .checked_sub(N)
            .and_then(|s| s.checked_sub(index))?;
        self.get(from..from + N).and_then(|v| v.try_into().ok())
    }

    fn rslice_to_array_ref<const N: usize>(
        &self,
        to_position: impl Into<usize>,
    ) -> Option<&[u8; N]> {
        let index = to_position.into();
        let from = self
            .len()
            .checked_sub(N)
            .and_then(|s| s.checked_sub(index))?;
        self.get(from..from + N).and_then(|v| v.try_into().ok())
    }

    fn slice_at_end(&self, end: usize) -> Option<&[u8]> {
        let to = self.len().checked_sub(end)?;
        self.get(..to)
    }
}

/// The byte vectors differ between builds, so what they do differently is here.
trait ByteVec: Sized {
    fn with_size(size: usize) -> Self;
    fn set_size(&mut self, size: usize);
}

#[cfg(feature = "alloc")]
impl ByteVec for alloc::vec::Vec<u8> {
    fn with_size(size: usize) -> Self {
        let mut vec = Self::with_capacity(size);
        vec.set_size(size);
        vec
    }

    fn set_size(&mut self, size: usize) {
        self.resize(size, 0);
    }
}

#[cfg(not(feature = "alloc"))]
impl<const N: usize> ByteVec for heapless::Vec<u8, N> {
    fn with_size(size: usize) -> Self {
        let mut vec = Self::new();
        vec.set_size(size);
        vec
    }

    // heapless resize pushes byte by byte, which at opt-level s or z is over 100
    // times slower than this memset
    fn set_size(&mut self, size: usize) {
        assert!(size <= N, "buffer size {size} exceeds capacity {N}");
        let len = self.len();
        if size > len {
            // SAFETY: len..size is within the capacity checked above, and
            // Vec::as_mut_ptr covers the whole capacity
            unsafe { self.as_mut_ptr().add(len).write_bytes(0, size - len) };
        }
        // SAFETY: size is within capacity and every byte up to it is initialized
        unsafe { self.set_len(size) };
    }
}

/// A block `aead` can encrypt in place. It has no `Buffer` impl for this
/// heapless version, and one can only be added to a local type.
#[cfg(not(feature = "alloc"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamBlock(DataBlock);

#[cfg(not(feature = "alloc"))]
impl core::ops::Deref for StreamBlock {
    type Target = DataBlock;

    fn deref(&self) -> &DataBlock {
        &self.0
    }
}

#[cfg(not(feature = "alloc"))]
impl core::ops::DerefMut for StreamBlock {
    fn deref_mut(&mut self) -> &mut DataBlock {
        &mut self.0
    }
}

#[cfg(not(feature = "alloc"))]
impl AsRef<[u8]> for StreamBlock {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(not(feature = "alloc"))]
impl AsMut<[u8]> for StreamBlock {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[cfg(not(feature = "alloc"))]
impl FromIterator<u8> for StreamBlock {
    fn from_iter<I: IntoIterator<Item = u8>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(all(not(feature = "alloc"), feature = "encryption"))]
impl chacha20poly1305::aead::Buffer for StreamBlock {
    fn extend_from_slice(&mut self, other: &[u8]) -> chacha20poly1305::aead::Result<()> {
        self.0
            .extend_from_slice(other)
            .map_err(|_| chacha20poly1305::aead::Error)
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

#[cfg(not(feature = "alloc"))]
impl ByteVec for StreamBlock {
    fn with_size(size: usize) -> Self {
        Self(DataBlock::with_size(size))
    }

    fn set_size(&mut self, size: usize) {
        self.0.set_size(size);
    }
}

#[allow(unused)]
pub fn extend_from_slice<T>(buffer: &mut DataBuffer, data: &[u8], _error: T) -> Result<(), T> {
    #[cfg(feature = "alloc")]
    buffer.extend_from_slice(data);
    #[cfg(not(feature = "alloc"))]
    buffer.extend_from_slice(data).map_err(|_| _error)?;
    Ok(())
}

pub fn resize_buffer(buffer: &mut DataBuffer, max_buffer_size: impl Into<usize>) {
    buffer.set_size(max_buffer_size.into());
}

pub fn new_buffer(max_buffer_size: impl Into<usize>) -> DataBuffer {
    DataBuffer::with_size(max_buffer_size.into())
}

pub fn new_data_block(block_size: impl Into<usize>) -> DataBlock {
    DataBlock::with_size(block_size.into())
}

pub fn create_max_buffer(max_block_size: u16) -> DataBuffer {
    let max_buffer_size = max(
        max_block_size + DATA_PACKET_HEADER_SIZE as u16,
        MIN_BUFFER_SIZE,
    );
    assert!(max_buffer_size <= MAX_BUFFER_SIZE);
    new_buffer(max_buffer_size)
}

/// One byte larger than any valid packet, so that a datagram too large for the
/// block size is not cut down to a packet that looks valid.
pub fn create_receive_buffer(max_block_size: u16) -> DataBuffer {
    let mut buffer = create_max_buffer(max_block_size);
    let size = buffer.len() + 1;
    resize_buffer(&mut buffer, size);
    buffer
}

#[allow(unused)]
pub fn new_stream_block(block_size: impl Into<usize>) -> types::StreamBlock {
    types::StreamBlock::with_size(block_size.into())
}

#[allow(unused)]
pub fn resize_stream_block(buffer: &mut types::StreamBlock, block_size: impl Into<usize>) {
    buffer.set_size(block_size.into());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "alloc"))]
    #[test]
    #[should_panic]
    fn test_resize_past_capacity_panics() {
        let mut buffer = DataBuffer::new();
        resize_buffer(&mut buffer, MAX_BUFFER_SIZE as usize + 1);
    }

    #[test]
    fn test_slice_to_array() {
        let b: &[u8] = &[1, 2, 3, 4, 5];
        let r: [u8; 3] = b.slice_to_array(0_usize).unwrap();
        assert_eq!(&r, &b[..3]);

        let r: [u8; 5] = b.slice_to_array(0_usize).unwrap();
        assert_eq!(&r, &b);

        let r: [u8; 0] = b.slice_to_array(0_usize).unwrap();
        assert_eq!(&r, &[]);

        let r: Option<[u8; 6]> = b.slice_to_array(0_usize);
        assert!(r.is_none());
    }

    #[test]
    fn test_slice_to_array_ref() {
        let b: &[u8] = &[1, 2, 3, 4, 5];
        let r: &[u8; 3] = b.slice_to_array_ref(0_usize).unwrap();
        assert_eq!(r.as_slice(), &b[..3]);

        let r: &[u8; 5] = b.slice_to_array_ref(0_usize).unwrap();
        assert_eq!(&r, &b);

        let r: &[u8; 0] = b.slice_to_array_ref(0_usize).unwrap();
        assert_eq!(r.as_slice(), &[]);

        let r: Option<&[u8; 6]> = b.slice_to_array_ref(0_usize);
        assert!(r.is_none());
    }

    #[test]
    fn test_rslice_to_array() {
        let b: &[u8] = &[1, 2, 3, 4, 5];
        let r: [u8; 3] = b.rslice_to_array(0_usize).unwrap();
        assert_eq!(&r, &b[2..]);

        let r: [u8; 5] = b.rslice_to_array(0_usize).unwrap();
        assert_eq!(&r, &b);

        let r: [u8; 0] = b.rslice_to_array(0_usize).unwrap();
        assert_eq!(&r, &[]);

        let r: Option<[u8; 6]> = b.rslice_to_array(0_usize);
        assert!(r.is_none());
    }

    #[test]
    fn test_rslice_to_array_ref() {
        let b: &[u8] = &[1, 2, 3, 4, 5];
        let r: &[u8; 3] = b.rslice_to_array_ref(0_usize).unwrap();
        assert_eq!(r.as_slice(), &b[2..]);

        let r: &[u8; 5] = b.rslice_to_array_ref(0_usize).unwrap();
        assert_eq!(&r, &b);

        let r: &[u8; 0] = b.rslice_to_array_ref(0_usize).unwrap();
        assert_eq!(r.as_slice(), &[]);

        let r: Option<&[u8; 6]> = b.rslice_to_array_ref(0_usize);
        assert!(r.is_none());
    }

    #[test]
    fn test_slice_at_end() {
        let b: &[u8] = &[1, 2, 3, 4, 5];
        let r = b.slice_at_end(2_usize).unwrap();
        assert_eq!(r, &b[..3]);

        let r = b.slice_at_end(0_usize).unwrap();
        assert_eq!(r, b);

        let r = b.slice_at_end(6_usize);
        assert!(r.is_none());
    }

    #[test]
    fn test_write_bytes() {
        let b: &mut [u8] = &mut [1, 2, 3, 4, 5];
        let data = &[6, 7, 8];
        let r = b.write_bytes(data, 2_usize).unwrap();
        assert_eq!(r, 5);
        assert_eq!(b, &[1, 2, 6, 7, 8]);

        let r = b.write_bytes(data, 3_usize);
        assert!(r.is_none());

        let r = b.write_bytes(data, 6_usize);
        assert!(r.is_none());
    }

    fn write_pattern<T: AsMut<[u8]>>(vec: &mut T) {
        for (index, byte) in vec.as_mut().iter_mut().enumerate() {
            *byte = index as u8 + 1;
        }
    }

    fn check_with_size_sets_length<T: ByteVec + AsRef<[u8]>>() {
        for size in [0, 1, 8] {
            assert_eq!(T::with_size(size).as_ref().len(), size);
        }
    }

    fn check_with_size_is_writable<T: ByteVec + AsRef<[u8]> + AsMut<[u8]>>() {
        let mut vec = T::with_size(4);
        write_pattern(&mut vec);
        assert_eq!(vec.as_ref(), [1, 2, 3, 4]);
    }

    fn check_set_size_grow_keeps_contents<T: ByteVec + AsRef<[u8]> + AsMut<[u8]>>() {
        let mut vec = T::with_size(4);
        write_pattern(&mut vec);
        vec.set_size(8);
        assert_eq!(vec.as_ref().len(), 8);
        assert_eq!(vec.as_ref()[..4], [1, 2, 3, 4]);
    }

    fn check_set_size_shrink_keeps_prefix<T: ByteVec + AsRef<[u8]> + AsMut<[u8]>>() {
        let mut vec = T::with_size(4);
        write_pattern(&mut vec);
        vec.set_size(2);
        assert_eq!(vec.as_ref(), [1, 2]);
    }

    fn check_set_size_same_keeps_contents<T: ByteVec + AsRef<[u8]> + AsMut<[u8]>>() {
        let mut vec = T::with_size(4);
        write_pattern(&mut vec);
        vec.set_size(4);
        assert_eq!(vec.as_ref(), [1, 2, 3, 4]);
    }

    fn check_set_size_to_zero_and_back<T: ByteVec + AsRef<[u8]> + AsMut<[u8]>>() {
        let mut vec = T::with_size(4);
        vec.set_size(0);
        assert!(vec.as_ref().is_empty());

        vec.set_size(4);
        write_pattern(&mut vec);
        assert_eq!(vec.as_ref(), [1, 2, 3, 4]);
    }

    fn check_with_size_is_zeroed<T: ByteVec + AsRef<[u8]>>() {
        assert_eq!(T::with_size(8).as_ref(), [0; 8]);
    }

    fn check_grown_bytes_are_zeroed<T: ByteVec + AsRef<[u8]> + AsMut<[u8]>>() {
        let mut vec = T::with_size(2);
        write_pattern(&mut vec);
        vec.set_size(4);
        assert_eq!(vec.as_ref(), [1, 2, 0, 0]);
    }

    fn check_shrink_then_grow_clears_old_bytes<T: ByteVec + AsRef<[u8]> + AsMut<[u8]>>() {
        let mut vec = T::with_size(4);
        write_pattern(&mut vec);
        vec.set_size(1);
        vec.set_size(4);
        assert_eq!(vec.as_ref(), [1, 0, 0, 0]);
    }

    macro_rules! test_byte_vec_types {
        ($($name:ident => $check:ident),+ $(,)?) => {
            $(
                #[test]
                fn $name() {
                    $check::<DataBuffer>();
                    $check::<DataBlock>();
                    $check::<types::StreamBlock>();
                }
            )+
        };
    }

    test_byte_vec_types! {
        test_byte_vec_with_size_sets_length => check_with_size_sets_length,
        test_byte_vec_with_size_is_writable => check_with_size_is_writable,
        test_byte_vec_set_size_grow_keeps_contents => check_set_size_grow_keeps_contents,
        test_byte_vec_set_size_shrink_keeps_prefix => check_set_size_shrink_keeps_prefix,
        test_byte_vec_set_size_same_keeps_contents => check_set_size_same_keeps_contents,
        test_byte_vec_set_size_to_zero_and_back => check_set_size_to_zero_and_back,
        test_byte_vec_with_size_is_zeroed => check_with_size_is_zeroed,
        test_byte_vec_grown_bytes_are_zeroed => check_grown_bytes_are_zeroed,
        test_byte_vec_shrink_then_grow_clears_old_bytes => check_shrink_then_grow_clears_old_bytes,
    }

    #[cfg(feature = "alloc")]
    mod byte_vec_alloc {
        use super::*;

        #[test]
        fn test_byte_vec_with_size_reserves_capacity() {
            let vec = DataBuffer::with_size(64);
            assert!(vec.capacity() >= 64);
        }

        #[test]
        fn test_byte_vec_set_size_is_not_limited_by_max_buffer_size() {
            let size = MAX_BUFFER_SIZE as usize + 1;
            let mut vec = DataBuffer::with_size(0);
            vec.set_size(size);
            assert_eq!(vec.len(), size);
        }
    }

    #[cfg(not(feature = "alloc"))]
    mod byte_vec_stack {
        use std::panic::catch_unwind;
        use std::panic::AssertUnwindSafe;

        use super::*;
        use crate::config::MAX_DATA_BLOCK_SIZE;

        const CAPACITY: usize = 4;

        type SmallVec = heapless::Vec<u8, CAPACITY>;

        #[test]
        fn test_byte_vec_with_size_at_capacity() {
            let mut vec = SmallVec::with_size(CAPACITY);
            write_pattern(&mut vec);
            assert_eq!(&vec[..], [1, 2, 3, 4]);
        }

        #[test]
        fn test_byte_vec_regrow_to_capacity_clears_tail() {
            let mut vec = SmallVec::with_size(CAPACITY);
            write_pattern(&mut vec);
            vec.set_size(1);
            vec.set_size(CAPACITY);
            assert_eq!(&vec[..], [1, 0, 0, 0]);
        }

        #[test]
        fn test_byte_vec_set_size_at_capacity() {
            let mut vec = SmallVec::with_size(0);
            vec.set_size(CAPACITY);
            assert_eq!(vec.len(), CAPACITY);
        }

        #[test]
        fn test_byte_vec_buffer_types_reach_configured_limits() {
            let max_buffer = MAX_BUFFER_SIZE as usize;
            let max_block = MAX_DATA_BLOCK_SIZE as usize;
            assert_eq!(DataBuffer::with_size(max_buffer).len(), max_buffer);
            assert_eq!(DataBlock::with_size(max_block).len(), max_block);
            assert_eq!(types::StreamBlock::with_size(max_block).len(), max_block);
        }

        #[test]
        #[should_panic(expected = "buffer size 5 exceeds capacity 4")]
        fn test_byte_vec_with_size_past_capacity_panics() {
            let _ = SmallVec::with_size(CAPACITY + 1);
        }

        #[test]
        #[should_panic(expected = "buffer size 5 exceeds capacity 4")]
        fn test_byte_vec_set_size_past_capacity_panics() {
            let mut vec = SmallVec::with_size(0);
            vec.set_size(CAPACITY + 1);
        }

        #[test]
        #[should_panic(expected = "exceeds capacity")]
        fn test_byte_vec_stream_block_with_size_past_capacity_panics() {
            let _ = types::StreamBlock::with_size(MAX_DATA_BLOCK_SIZE as usize + 1);
        }

        #[test]
        #[should_panic(expected = "exceeds capacity")]
        fn test_byte_vec_stream_block_set_size_past_capacity_panics() {
            let mut block = types::StreamBlock::with_size(0);
            block.set_size(MAX_DATA_BLOCK_SIZE as usize + 1);
        }

        #[test]
        fn test_byte_vec_failed_set_size_keeps_vec_unchanged() {
            let mut vec = SmallVec::with_size(2);
            write_pattern(&mut vec);

            let result = catch_unwind(AssertUnwindSafe(|| vec.set_size(CAPACITY + 1)));

            assert!(result.is_err());
            assert_eq!(&vec[..], [1, 2]);
        }
    }
}
