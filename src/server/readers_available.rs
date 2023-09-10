#[derive(Debug)]
pub struct ReadersAvailable {
    single_readers: u16,
    multi_readers: u16,
    seek_readers: u16,
}

impl ReadersAvailable {
    #[allow(unused)]
    pub fn all() -> Self {
        Self {
            single_readers: 1,
            multi_readers: 1,
            #[cfg(feature = "seek")]
            seek_readers: 1,
            #[cfg(not(feature = "seek"))]
            seek_readers: 0,
        }
    }

    #[cfg(not(feature = "alloc"))]
    #[allow(unused)]
    pub fn from_used(single_readers: usize, multi_readers: usize, _seek_readers: usize) -> Self {
        Self {
            single_readers: crate::config::MAX_SINGLE_READERS - single_readers as u16,
            multi_readers: crate::config::MAX_MULTI_READERS - multi_readers as u16,
            #[cfg(feature = "seek")]
            seek_readers: crate::config::MAX_MULTI_SEEK_READERS - _seek_readers as u16,
            #[cfg(not(feature = "seek"))]
            seek_readers: 0,
        }
    }

    #[allow(unused)]
    pub fn new(single_readers: u16, multi_readers: u16, seek_readers: u16) -> Self {
        Self {
            single_readers,
            multi_readers,
            seek_readers,
        }
    }

    pub fn single_block(&self) -> bool {
        self.single_readers > 0
    }

    pub fn multi_block(&self) -> bool {
        self.multi_readers > 0
    }

    #[allow(dead_code)]
    pub fn seek(&self) -> bool {
        self.seek_readers > 0
    }
}
