//! Where the single threaded server keeps each client's reader and writer: on
//! the heap with `alloc`, otherwise in fixed pools.

#[cfg(feature = "alloc")]
pub use heap::ClientStore;
#[cfg(not(feature = "alloc"))]
pub use pools::ClientStore;

use crate::features::FileReader;
use crate::readers::Readers;
use crate::server::connection::ClientType;
use crate::server::readers_available::ReadersAvailable;
use crate::std_compat::io::Write;
use crate::writers::Writers;

#[cfg(feature = "alloc")]
mod heap {
    use alloc::boxed::Box;
    use core::marker::PhantomData;

    use super::*;
    use crate::readers::block_reader::BlockReader;
    use crate::writers::block_writer::BlockWriter;

    pub struct ClientStore<R>(PhantomData<R>);

    impl<R: FileReader> ClientStore<R> {
        pub fn new() -> Self {
            Self(PhantomData)
        }

        pub fn available(&self) -> ReadersAvailable {
            ReadersAvailable::all()
        }

        pub fn trace_sizes(&self, _clients_size: usize) {}

        pub fn keep<'a, W: Write + 'a>(
            &'a self,
            client: ClientType<Readers<R>, Writers<W>>,
        ) -> Option<ClientType<Box<dyn BlockReader + 'a>, Box<dyn BlockWriter + 'a>>> {
            Some(match client {
                ClientType::Reader(r) => match r {
                    Readers::Single(r) => ClientType::Reader(Box::new(r)),
                    Readers::Multiple(r) => ClientType::Reader(Box::new(r)),
                    Readers::Seek(r) => ClientType::Reader(Box::new(r)),
                },
                ClientType::Writer(w) => match w {
                    Writers::Single(w) => ClientType::Writer(Box::new(w)),
                },
            })
        }
    }
}

#[cfg(not(feature = "alloc"))]
mod pools {
    use core::cell::RefCell;

    use log::*;

    use super::*;
    use crate::readers::pool_reader::MultiBlockReaders;
    use crate::readers::pool_reader::MultiBlockSeekReaders;
    use crate::readers::pool_reader::PoolReader;
    use crate::readers::pool_reader::SingleBlockReaders;
    use crate::writers::single_block_writer::SingleBlockWriter;

    pub struct ClientStore<R> {
        single_block_readers: RefCell<SingleBlockReaders<R>>,
        multi_block_readers: RefCell<MultiBlockReaders<R>>,
        multi_block_seek_readers: RefCell<MultiBlockSeekReaders<R>>,
    }

    impl<R: FileReader> ClientStore<R> {
        pub fn new() -> Self {
            Self {
                single_block_readers: RefCell::new(SingleBlockReaders::new()),
                multi_block_readers: RefCell::new(MultiBlockReaders::new()),
                multi_block_seek_readers: RefCell::new(MultiBlockSeekReaders::new()),
            }
        }

        pub fn available(&self) -> ReadersAvailable {
            ReadersAvailable::from_used(
                self.single_block_readers.borrow().len(),
                self.multi_block_readers.borrow().len(),
                self.multi_block_seek_readers.borrow().len(),
            )
        }

        pub fn trace_sizes(&self, clients_size: usize) {
            trace!(
                "Size of all clients in memory: client={} single_block={} multi_block={} bytes",
                clients_size,
                core::mem::size_of_val(&self.single_block_readers),
                core::mem::size_of_val(&self.multi_block_readers),
            );
            trace!(
                "Size of all multi_seek={} bytes",
                core::mem::size_of_val(&self.multi_block_seek_readers)
            );
        }

        /// Returns `None` if the pool for this reader is exhausted.
        pub fn keep<'a, W: Write>(
            &'a self,
            client: ClientType<Readers<R>, Writers<W>>,
        ) -> Option<ClientType<PoolReader<'a, R>, SingleBlockWriter<W>>> {
            Some(match client {
                ClientType::Reader(r) => match r {
                    Readers::Single(r) => {
                        let Some(reader) = PoolReader::from_single(r, &self.single_block_readers)
                        else {
                            error!("Exhausted single pool readers");
                            return None;
                        };
                        ClientType::Reader(reader)
                    }
                    Readers::Multiple(r) => {
                        let Some(reader) = PoolReader::from_multi(r, &self.multi_block_readers)
                        else {
                            error!("Exhausted multi pool readers");
                            return None;
                        };
                        ClientType::Reader(reader)
                    }
                    Readers::Seek(r) => {
                        let Some(reader) = PoolReader::from_seek(r, &self.multi_block_seek_readers)
                        else {
                            error!("Exhausted multi pool seek readers");
                            return None;
                        };
                        ClientType::Reader(reader)
                    }
                },
                ClientType::Writer(w) => match w {
                    Writers::Single(w) => ClientType::Writer(w),
                },
            })
        }
    }
}
