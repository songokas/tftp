use core::time::Duration;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use tftp_dus::config::MAX_CLIENTS;
use tftp_dus::std_compat::io;

use crate::error::last_os_error;

const MAX_EVENTS: usize = MAX_CLIENTS as usize + 1;

pub struct Poller {
    queue: OwnedFd,
}

impl Poller {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(last_os_error());
        }
        let queue = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(last_os_error());
        }
        Ok(Self { queue })
    }

    /// One-shot registration: a socket reports again only after `rearm`.
    pub fn add(&self, fd: i32) -> io::Result<()> {
        self.rearm(fd)
    }

    /// EV_ADD works whether or not the one-shot event has already fired, and
    /// reports immediately if the socket already has data waiting.
    pub fn rearm(&self, fd: i32) -> io::Result<()> {
        let change = libc::kevent {
            ident: fd as usize,
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD | libc::EV_ONESHOT,
            fflags: 0,
            data: 0,
            udata: core::ptr::null_mut(),
        };
        let result = unsafe {
            libc::kevent(
                self.queue.as_raw_fd(),
                &change,
                1,
                core::ptr::null_mut(),
                0,
                core::ptr::null(),
            )
        };
        if result < 0 {
            return Err(last_os_error());
        }
        Ok(())
    }

    pub fn wait(&self, timeout: Duration, mut ready: impl FnMut(i32)) -> io::Result<()> {
        let mut events: [libc::kevent; MAX_EVENTS] = unsafe { core::mem::zeroed() };
        let timeout = libc::timespec {
            tv_sec: timeout.as_secs() as _,
            tv_nsec: timeout.subsec_nanos() as _,
        };
        let count = unsafe {
            libc::kevent(
                self.queue.as_raw_fd(),
                core::ptr::null(),
                0,
                events.as_mut_ptr(),
                MAX_EVENTS as i32,
                &timeout,
            )
        };
        if count < 0 {
            let error = last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(error);
        }
        for event in events.iter().take(count as usize) {
            ready(event.ident as i32);
        }
        Ok(())
    }
}

/// macOS has no ppoll. Rounds up so that a short wait does not become a busy loop.
pub fn wait_readable(fd: i32, wait: Duration) -> io::Result<bool> {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let milliseconds = wait.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
    let result = unsafe { libc::poll(&mut poll_fd, 1, milliseconds) };
    if result < 0 {
        let error = last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(result > 0)
}
