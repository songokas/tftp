use crate::types::DataBuffer;

pub trait SliceMutExt {
    fn write_bytes(self, data: impl AsRef<[u8]>, from_index: impl Into<usize>) -> Option<usize>;
}

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

#[allow(unused)]
pub fn extend_from_slice<T>(buffer: &mut DataBuffer, data: &[u8], _error: T) -> Result<(), T> {
    #[cfg(feature = "alloc")]
    buffer.extend_from_slice(data);
    #[cfg(not(feature = "alloc"))]
    buffer.extend_from_slice(data).map_err(|_| _error)?;
    Ok(())
}

pub fn resize_buffer(buffer: &mut DataBuffer, max_buffer_size: impl Into<usize>) {
    #[cfg(feature = "alloc")]
    buffer.resize(max_buffer_size.into(), 0);
    // TODO heapless vector resizing is super slow
    #[cfg(not(feature = "alloc"))]
    unsafe {
        buffer.set_len(max_buffer_size.into())
    };
}

pub fn new_buffer(max_buffer_size: impl Into<usize>) -> DataBuffer {
    let mut d = DataBuffer::new();
    resize_buffer(&mut d, max_buffer_size);
    d
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
