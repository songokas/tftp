use core::fmt;

/// Writes without std's stdout and stderr: stdout allocates its line buffer,
/// and stderr's lock allocates on platforms using pthread mutexes, like macOS.
pub struct Stderr;

impl fmt::Write for Stderr {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if write_all(2, text) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

pub fn write_all(fd: i32, mut text: &str) -> bool {
    while !text.is_empty() {
        let written = unsafe { libc::write(fd, text.as_ptr().cast(), text.len()) };
        if written <= 0 {
            return false;
        }
        text = &text[written as usize..];
    }
    true
}
