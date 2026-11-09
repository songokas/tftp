//! Fixed set of threads for the multi threaded server.
//!
//! `std::thread::spawn` allocates, so workers are created once with
//! `pthread_create` and jobs are moved to them. Only the libc pthread primitives
//! are used because `std::sync` locks allocate on platforms using pthread mutexes.
//! Stacks are left to libc, which maps them with a guard page.
//!
//! Used by builds of the library without `std`, where `ThreadSpawner` does not exist.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::size_of;
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::panic::catch_unwind;
use std::panic::AssertUnwindSafe;

use tftp_dus::config::MAX_CLIENTS;
use tftp_dus::server::Spawner;
use tftp_dus::server::TaskHandle;
use tftp_dus::types::DataBuffer;

const WORKERS: usize = MAX_CLIENTS as usize;
// macOS requires the stack size to be a multiple of the page size
const STACK_ALIGNMENT: usize = 64 * 1024;
const STACK_OVERHEAD: usize = 256 * 1024;
// measured use is about 3 copies optimized, and 13 or more unoptimized
const JOB_COPIES: usize = if cfg!(debug_assertions) { 24 } else { 4 };

type Assignment<J> = (J, fn(J));

#[derive(Clone, Copy, PartialEq)]
enum WorkerState {
    Idle,
    Assigned,
    Busy,
}

struct Worker {
    /// guarded by the pool's mutex
    state: UnsafeCell<WorkerState>,
    wake: UnsafeCell<libc::pthread_cond_t>,
    /// Number of jobs finished. A handle compares this with its value at spawn,
    /// so it stays finished after the worker moves on to another job.
    completed: AtomicU32,
}

impl Worker {
    const fn new() -> Self {
        Self {
            state: UnsafeCell::new(WorkerState::Idle),
            wake: UnsafeCell::new(libc::PTHREAD_COND_INITIALIZER),
            completed: AtomicU32::new(0),
        }
    }
}

pub struct WorkerPool<J> {
    mutex: UnsafeCell<libc::pthread_mutex_t>,
    taken: UnsafeCell<libc::pthread_cond_t>,
    /// Holds a job only until its worker moves it onto its own stack, so one
    /// slot serves every worker. Guarded by `mutex`.
    pending: UnsafeCell<MaybeUninit<Assignment<J>>>,
    workers: [Worker; WORKERS],
    next_worker: AtomicUsize,
}

// SAFETY: the cells are only accessed with `mutex` held, or are pthread
// primitives, and jobs are only moved between threads when `J` is Send.
unsafe impl<J: Send> Sync for WorkerPool<J> {}

impl<J: Send + 'static> Default for WorkerPool<J> {
    fn default() -> Self {
        Self::new()
    }
}

impl<J: Send + 'static> WorkerPool<J> {
    pub const fn new() -> Self {
        Self {
            mutex: UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER),
            taken: UnsafeCell::new(libc::PTHREAD_COND_INITIALIZER),
            pending: UnsafeCell::new(MaybeUninit::uninit()),
            workers: [const { Worker::new() }; WORKERS],
            next_worker: AtomicUsize::new(0),
        }
    }

    /// Creates the threads. Must be called once for a pool.
    pub fn start(&'static self, workers: usize) -> Result<PoolSpawner<J>, &'static str> {
        if workers > WORKERS {
            return Err("More workers requested than the build supports");
        }
        let mut attributes = MaybeUninit::<libc::pthread_attr_t>::uninit();
        // SAFETY: attributes are initialized before use and destroyed once, and
        // the argument passed to each thread is valid forever.
        unsafe {
            if libc::pthread_attr_init(attributes.as_mut_ptr()) != 0 {
                return Err("Unable to initialize thread attributes");
            }
            let stack_configured =
                libc::pthread_attr_setstacksize(attributes.as_mut_ptr(), Self::stack_size()) == 0
                    && libc::pthread_attr_setdetachstate(
                        attributes.as_mut_ptr(),
                        libc::PTHREAD_CREATE_DETACHED,
                    ) == 0;
            let created = stack_configured
                && (0..workers).all(|_| {
                    let mut thread = MaybeUninit::<libc::pthread_t>::uninit();
                    libc::pthread_create(
                        thread.as_mut_ptr(),
                        attributes.as_ptr(),
                        Self::thread_main,
                        core::ptr::from_ref(self).cast_mut().cast(),
                    ) == 0
                });
            libc::pthread_attr_destroy(attributes.as_mut_ptr());
            if !created {
                return Err("Unable to create worker threads");
            }
        }
        Ok(PoolSpawner {
            pool: self,
            workers,
        })
    }

    /// Scales with the job because every frame it is moved through can hold a
    /// copy of it. Unreached pages are never committed.
    fn stack_size() -> usize {
        ((size_of::<J>() + 4 * size_of::<DataBuffer>()) * JOB_COPIES + STACK_OVERHEAD)
            .next_multiple_of(STACK_ALIGNMENT)
    }

    extern "C" fn thread_main(argument: *mut c_void) -> *mut c_void {
        // SAFETY: `start` passes a pointer derived from a 'static pool.
        let pool = unsafe { &*argument.cast_const().cast::<Self>() };
        pool.work();
        null_mut()
    }

    fn work(&self) {
        let worker = &self.workers[self.next_worker.fetch_add(1, Ordering::Relaxed)];
        loop {
            // SAFETY: state and pending are accessed with the mutex held, and
            // pending is initialized whenever a worker is Assigned.
            let (job, run) = unsafe {
                libc::pthread_mutex_lock(self.mutex.get());
                while *worker.state.get() != WorkerState::Assigned {
                    libc::pthread_cond_wait(worker.wake.get(), self.mutex.get());
                }
                let assigned = (*self.pending.get()).assume_init_read();
                *worker.state.get() = WorkerState::Busy;
                libc::pthread_cond_signal(self.taken.get());
                libc::pthread_mutex_unlock(self.mutex.get());
                assigned
            };

            // unwinding out of the thread entry would abort, and the worker must
            // be released either way
            let _ = catch_unwind(AssertUnwindSafe(|| run(job)));

            // SAFETY: state is accessed with the mutex held.
            unsafe {
                libc::pthread_mutex_lock(self.mutex.get());
                *worker.state.get() = WorkerState::Idle;
                worker.completed.fetch_add(1, Ordering::Release);
                libc::pthread_mutex_unlock(self.mutex.get());
            }
        }
    }
}

pub struct PoolSpawner<J: 'static> {
    pool: &'static WorkerPool<J>,
    workers: usize,
}

pub struct WorkerHandle {
    worker: &'static Worker,
    started_after: u32,
}

impl TaskHandle for WorkerHandle {
    fn is_finished(&self) -> bool {
        self.worker.completed.load(Ordering::Acquire) != self.started_after
    }
}

impl<J: Send + 'static> Spawner<J> for PoolSpawner<J> {
    type Handle = WorkerHandle;

    fn spawn(&mut self, job: J, run: fn(J)) -> Result<Self::Handle, J> {
        let pool = self.pool;
        // SAFETY: state and pending are accessed with the mutex held, and
        // pending is only written while no worker is Assigned: this method has
        // exclusive access to the spawner and waits for the job to be taken.
        unsafe {
            libc::pthread_mutex_lock(pool.mutex.get());
            let Some(worker) = pool.workers[..self.workers]
                .iter()
                .find(|worker| *worker.state.get() == WorkerState::Idle)
            else {
                libc::pthread_mutex_unlock(pool.mutex.get());
                return Err(job);
            };
            (*pool.pending.get()).write((job, run));
            *worker.state.get() = WorkerState::Assigned;
            let started_after = worker.completed.load(Ordering::Relaxed);
            libc::pthread_cond_signal(worker.wake.get());
            while *worker.state.get() == WorkerState::Assigned {
                libc::pthread_cond_wait(pool.taken.get(), pool.mutex.get());
            }
            libc::pthread_mutex_unlock(pool.mutex.get());
            Ok(WorkerHandle {
                worker,
                started_after,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::boxed::Box;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    use tftp_dus::server::Spawner;
    use tftp_dus::server::TaskHandle;

    use super::*;

    #[derive(Default)]
    struct Gate {
        started: AtomicBool,
        release: AtomicBool,
    }

    fn wait_until(condition: impl Fn() -> bool) {
        for _ in 0..1000 {
            if condition() {
                return;
            }
            sleep(Duration::from_millis(5));
        }
        panic!("condition was not reached in time");
    }

    fn run_until_released(gate: Arc<Gate>) {
        gate.started.store(true, Ordering::SeqCst);
        wait_until(|| gate.release.load(Ordering::SeqCst));
    }

    fn start(workers: usize) -> PoolSpawner<Arc<Gate>> {
        let pool: &'static WorkerPool<Arc<Gate>> = Box::leak(Box::new(WorkerPool::new()));
        pool.start(workers).unwrap()
    }

    #[test]
    fn test_job_runs_and_handle_finishes() {
        let mut spawner = start(1);
        let gate = Arc::new(Gate::default());
        let handle = spawner
            .spawn(gate.clone(), run_until_released)
            .ok()
            .unwrap();

        wait_until(|| gate.started.load(Ordering::SeqCst));
        assert!(!handle.is_finished());

        gate.release.store(true, Ordering::SeqCst);
        wait_until(|| handle.is_finished());
    }

    #[test]
    fn test_job_is_returned_when_every_worker_is_busy() {
        let mut spawner = start(1);
        let running = Arc::new(Gate::default());
        let _handle = spawner
            .spawn(running.clone(), run_until_released)
            .ok()
            .unwrap();

        let rejected = Arc::new(Gate::default());
        let returned = spawner.spawn(rejected.clone(), run_until_released).err();

        assert!(Arc::ptr_eq(&returned.unwrap(), &rejected));
        running.release.store(true, Ordering::SeqCst);
    }

    #[test]
    fn test_finished_worker_accepts_another_job() {
        let mut spawner = start(1);
        let first = Arc::new(Gate::default());
        first.release.store(true, Ordering::SeqCst);
        let handle = spawner
            .spawn(first.clone(), run_until_released)
            .ok()
            .unwrap();
        wait_until(|| handle.is_finished());

        let second = Arc::new(Gate::default());
        second.release.store(true, Ordering::SeqCst);
        let handle = spawner
            .spawn(second.clone(), run_until_released)
            .ok()
            .unwrap();
        wait_until(|| handle.is_finished());
        assert!(second.started.load(Ordering::SeqCst));
    }

    #[test]
    fn test_old_handle_stays_finished_when_worker_is_reused() {
        let mut spawner = start(1);
        let first = Arc::new(Gate::default());
        first.release.store(true, Ordering::SeqCst);
        let old_handle = spawner.spawn(first, run_until_released).ok().unwrap();
        wait_until(|| old_handle.is_finished());

        let second = Arc::new(Gate::default());
        let _new_handle = spawner
            .spawn(second.clone(), run_until_released)
            .ok()
            .unwrap();
        wait_until(|| second.started.load(Ordering::SeqCst));

        assert!(old_handle.is_finished());
        second.release.store(true, Ordering::SeqCst);
    }

    fn panic_job(_gate: Arc<Gate>) {
        panic!("job failure expected by the test");
    }

    #[test]
    fn test_panicking_job_finishes_and_worker_is_reused() {
        let mut spawner = start(1);
        let handle = spawner
            .spawn(Arc::new(Gate::default()), panic_job)
            .ok()
            .unwrap();
        wait_until(|| handle.is_finished());

        let next = Arc::new(Gate::default());
        next.release.store(true, Ordering::SeqCst);
        let handle = spawner
            .spawn(next.clone(), run_until_released)
            .ok()
            .unwrap();
        wait_until(|| handle.is_finished());
        assert!(next.started.load(Ordering::SeqCst));
    }

    #[test]
    fn test_more_workers_than_capacity_is_an_error() {
        let pool: &'static WorkerPool<Arc<Gate>> = Box::leak(Box::new(WorkerPool::new()));
        assert!(pool.start(MAX_CLIENTS as usize + 1).is_err());
    }
}
