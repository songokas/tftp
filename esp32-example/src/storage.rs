//! A small fixed size file store in RAM. A real device would use flash here;
//! only `read`, `write` and the `open`/`create` functions would change.

use core::cell::RefCell;

use tftp_dus::error::BoxedResult;
use tftp_dus::std_compat::io;
use tftp_dus::types::FilePath;

pub const FILE_SLOTS: usize = 4;
pub const FILE_CAPACITY: usize = 8 * 1024;

struct Slot {
    name: Option<FilePath>,
    length: usize,
    data: [u8; FILE_CAPACITY],
}

/// Single threaded: the example runs one server loop and nothing else uses it.
pub struct RamDisk {
    slots: RefCell<[Slot; FILE_SLOTS]>,
}

// SAFETY: every access happens on the thread running the tftp server.
unsafe impl Sync for RamDisk {}

impl RamDisk {
    pub const fn new() -> Self {
        const EMPTY: Slot = Slot {
            name: None,
            length: 0,
            data: [0; FILE_CAPACITY],
        };
        Self {
            slots: RefCell::new([EMPTY; FILE_SLOTS]),
        }
    }

    /// Adds a file. Returns false if it does not fit.
    pub fn insert(&self, name: &str, contents: &[u8]) -> bool {
        let Ok(name) = name.parse() else {
            return false;
        };
        let mut slots = self.slots.borrow_mut();
        let free = slots.iter_mut().find(|slot| slot.name.is_none());
        match free {
            Some(slot) if contents.len() <= FILE_CAPACITY => {
                slot.data[..contents.len()].copy_from_slice(contents);
                slot.length = contents.len();
                slot.name = Some(name);
                true
            }
            _ => false,
        }
    }

    pub fn contents<T>(&self, name: &str, read: impl FnOnce(&[u8]) -> T) -> Option<T> {
        let slots = self.slots.borrow();
        let slot = slots.iter().find(|slot| matches_name(slot, name))?;
        Some(read(&slot.data[..slot.length]))
    }

    pub fn open(&'static self, path: &FilePath) -> BoxedResult<(Option<u64>, RamReader)> {
        let slots = self.slots.borrow();
        let index = slots
            .iter()
            .position(|slot| matches_name(slot, path))
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        let reader = RamReader {
            disk: self,
            index,
            position: 0,
        };
        Ok((Some(slots[index].length as u64), reader))
    }

    pub fn create(&'static self, path: &FilePath, overwrite: bool) -> BoxedResult<RamWriter> {
        let mut slots = self.slots.borrow_mut();
        let index = match slots.iter().position(|slot| matches_name(slot, path)) {
            Some(index) if overwrite => index,
            Some(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists).into()),
            None => slots
                .iter()
                .position(|slot| slot.name.is_none())
                .ok_or(io::Error::from(io::ErrorKind::OutOfMemory))?,
        };
        slots[index].name = Some(path.clone());
        slots[index].length = 0;
        Ok(RamWriter { disk: self, index })
    }
}

impl Default for RamDisk {
    fn default() -> Self {
        Self::new()
    }
}

fn matches_name(slot: &Slot, name: &str) -> bool {
    slot.name.as_ref().is_some_and(|n| n.as_str() == name)
}

pub struct RamReader {
    disk: &'static RamDisk,
    index: usize,
    position: usize,
}

impl io::Read for RamReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let slots = self.disk.slots.borrow();
        let slot = &slots[self.index];
        let available = &slot.data[self.position..slot.length];
        let count = available.len().min(buf.len());
        buf[..count].copy_from_slice(&available[..count]);
        self.position += count;
        Ok(count)
    }
}

pub struct RamWriter {
    disk: &'static RamDisk,
    index: usize,
}

impl io::Write for RamWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut slots = self.disk.slots.borrow_mut();
        let slot = &mut slots[self.index];
        let end = slot.length + buf.len();
        let target = slot
            .data
            .get_mut(slot.length..end)
            .ok_or(io::Error::from(io::ErrorKind::OutOfMemory))?;
        target.copy_from_slice(buf);
        slot.length = end;
        Ok(buf.len())
    }

    fn write_fmt(&mut self, _fmt: core::fmt::Arguments<'_>) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
