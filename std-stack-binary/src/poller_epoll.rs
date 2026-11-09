use core::time::Duration;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use tftp_dus::config::MAX_CLIENTS;
use tftp_dus::std_compat::io;

use crate::error::last_os_error;

const MAX_EVENTS: usize = MAX_CLIENTS as usize + 1;

pub struct Poller {
    epoll: OwnedFd,
}

impl Poller {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(last_os_error());
        }
        Ok(Self {
            epoll: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// One-shot registration: a socket reports again only after `rearm`.
    pub fn add(&self, fd: i32) -> io::Result<()> {
        self.control(libc::EPOLL_CTL_ADD, fd)
    }

    pub fn rearm(&self, fd: i32) -> io::Result<()> {
        self.control(libc::EPOLL_CTL_MOD, fd)
    }

    fn control(&self, operation: i32, fd: i32) -> io::Result<()> {
        let mut event = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLONESHOT) as u32,
            u64: fd as u64,
        };
        let result = unsafe { libc::epoll_ctl(self.epoll.as_raw_fd(), operation, fd, &mut event) };
        if result < 0 {
            return Err(last_os_error());
        }
        Ok(())
    }

    pub fn wait(&self, timeout: Duration, mut ready: impl FnMut(i32)) -> io::Result<()> {
        if !wait_readable(self.epoll.as_raw_fd(), timeout)? {
            return Ok(());
        }
        let mut events: [libc::epoll_event; MAX_EVENTS] = unsafe { core::mem::zeroed() };
        let count = unsafe {
            libc::epoll_wait(
                self.epoll.as_raw_fd(),
                events.as_mut_ptr(),
                MAX_EVENTS as i32,
                0,
            )
        };
        for event in events.iter().take(count.max(0) as usize) {
            ready({ event.u64 } as i32);
        }
        Ok(())
    }
}

/// Waits with nanosecond precision, unlike epoll_wait's milliseconds.
pub fn wait_readable(fd: i32, wait: Duration) -> io::Result<bool> {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = libc::timespec {
        tv_sec: wait.as_secs() as _,
        tv_nsec: wait.subsec_nanos() as _,
    };
    let result = unsafe { libc::ppoll(&mut poll_fd, 1, &timeout, core::ptr::null()) };
    if result < 0 {
        let error = last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(result > 0)
}
