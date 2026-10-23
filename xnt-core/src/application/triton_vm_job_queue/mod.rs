use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use super::job_queue::JobQueue;

// todo: maybe we want to have more levels or just make it an integer eg u8.
// or maybe name the levels by type/usage of job/proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum TritonVmJobPriority {
    Lowest = 1,
    Low = 2,
    #[default]
    Normal = 3,
    High = 4,
    Highest = 5,
}

#[derive(Debug)]
pub struct TritonVmJobQueue(JobQueue<TritonVmJobPriority>);

impl Deref for TritonVmJobQueue {
    type Target = JobQueue<TritonVmJobPriority>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TritonVmJobQueue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TritonVmJobQueue {
    /// returns the triton vm job queue (singleton).
    ///
    /// callers should execute resource intensive triton-vm tasks in this
    /// queue to avoid running simultaneous tasks that could exceed hardware
    /// capabilities.
    pub fn get_instance() -> Arc<Self> {
        use std::sync::OnceLock;
        static INSTANCE: OnceLock<Arc<TritonVmJobQueue>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                // Started on the queue's own runtime, not the caller's.
                //
                // `JobQueue::start` spawns its worker with `tokio::spawn`, so the
                // worker lives on whichever runtime is current at first use. That
                // is right for a queue whose lifetime is the caller's, but wrong
                // for *this* queue, which is a process-wide singleton: the first
                // caller's runtime is an arbitrary one, and when it goes so does
                // the worker, leaving every later `add_job` to fail with
                // `AddJobError(SendError)` -- a queue that exists but cannot be
                // reached.
                //
                // Where it bites is `#[tokio::test]`: each test builds its own
                // runtime and drops it at test end, so whichever test touches the
                // queue first takes the worker down with it. It surfaces only when
                // a test actually has to prove, since a proof-cache hit submits no
                // job, which is what makes it look like a flake.
                //
                // So the singleton brings a runtime of matching lifetime. It is a
                // `static`, hence never dropped, which also means `Runtime::drop`,
                // which panics inside an async context, can never run.
                let _guard = worker_runtime().enter();

                Arc::new(Self(JobQueue::<TritonVmJobPriority>::start()))
            })
            .clone()
    }
}

/// The runtime hosting the singleton queue's worker task, built on first use and
/// never torn down. See [`TritonVmJobQueue::get_instance`].
fn worker_runtime() -> &'static tokio::runtime::Runtime {
    use std::sync::OnceLock;
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("triton-vm-job-queue")
            .build()
            .expect("the Triton VM job queue's runtime must build")
    })
}

/// returns a clonable reference to the single (per process) VM job queue.
pub fn vm_job_queue() -> Arc<TritonVmJobQueue> {
    TritonVmJobQueue::get_instance()
}
