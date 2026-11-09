#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Mutex;

/// Runs each accepted connection concurrently with the server loop.
///
/// `J` and `run` are passed separately, rather than as a closure, so an
/// implementation can store a job without boxing it.
pub trait Spawner<J: Send + 'static> {
    type Handle: TaskHandle;

    /// Calls `run(job)` on another thread of execution, which may block.
    /// Returns the job if it can not be started.
    fn spawn(&mut self, job: J, run: fn(J)) -> Result<Self::Handle, J>;
}

pub trait TaskHandle {
    /// Must only become true once the spawner can accept another job in place
    /// of this one, because the server decides on capacity from these handles.
    fn is_finished(&self) -> bool;
}

/// Runs every job on a new `std` thread.
#[cfg(feature = "std")]
pub struct ThreadSpawner;

#[cfg(feature = "std")]
impl<J: Send + 'static> Spawner<J> for ThreadSpawner {
    type Handle = std::thread::JoinHandle<()>;

    fn spawn(&mut self, job: J, run: fn(J)) -> Result<Self::Handle, J> {
        start_job(job, run, |task| std::thread::Builder::new().spawn(task))
    }
}

/// Hands `start` a task that runs the job, and returns the job if `start` fails.
#[cfg(feature = "std")]
fn start_job<J: Send + 'static, H, E>(
    job: J,
    run: fn(J),
    start: impl FnOnce(Box<dyn FnOnce() + Send>) -> Result<H, E>,
) -> Result<H, J> {
    let slot = Arc::new(Mutex::new(Some(job)));
    let task_slot = slot.clone();
    let task: Box<dyn FnOnce() + Send> = Box::new(move || {
        let job = task_slot.lock().expect("job is only moved").take();
        if let Some(job) = job {
            run(job);
        }
    });
    start(task).map_err(|_| {
        slot.lock()
            .expect("job is only moved")
            .take()
            .expect("job that did not start is still there")
    })
}

#[cfg(feature = "std")]
impl TaskHandle for std::thread::JoinHandle<()> {
    fn is_finished(&self) -> bool {
        std::thread::JoinHandle::is_finished(self)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use super::*;

    static RAN: AtomicUsize = AtomicUsize::new(0);

    fn record(job: usize) {
        RAN.store(job, Ordering::SeqCst);
    }

    #[test]
    fn test_job_comes_back_when_a_thread_cannot_start() {
        let result = start_job(7_usize, record, |_| Err::<(), _>(()));
        assert!(matches!(result, Err(7)));
    }

    #[test]
    fn test_started_thread_runs_the_job() {
        let result = start_job(9_usize, record, |task| {
            task();
            Ok::<(), ()>(())
        });
        assert!(result.is_ok());
        assert_eq!(RAN.load(Ordering::SeqCst), 9);
    }
}
