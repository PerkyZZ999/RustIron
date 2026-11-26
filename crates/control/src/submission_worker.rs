//! Bounded local ownership of a signed submission, independent of its waiter.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use rustiron_contracts::{
    Id,
    execution::{SubmissionReply, encode_submission},
};

use crate::executor_transport::{ExecutorTransport, SubmitFailure};

/// Failure before a worker could take ownership of a submission.
#[derive(Debug, Eq, PartialEq)]
pub enum StartFailure {
    /// The signed envelope is malformed or exceeds the transport bound.
    InvalidInput,
    /// This pool already has an active submission; no request was queued.
    Busy,
    /// A worker could not be started; no request was sent.
    Unavailable,
}

/// A pool with at most one local worker; it does not bound effects still
/// running at the executor after a transport timeout.
pub struct SubmissionWorker {
    transport: Arc<ExecutorTransport>,
    active: Arc<AtomicBool>,
}

impl SubmissionWorker {
    /// Uses the already-configured, peer-checked executor transport.
    pub fn new(transport: ExecutorTransport) -> Self {
        Self {
            transport: Arc::new(transport),
            active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts a worker without claiming executor admission or queuing retries.
    /// Dropping the returned ticket does not cancel the worker.
    pub fn start(
        &self,
        operation_id: &Id,
        idempotency_key: &Id,
        plan: &[u8],
        grant: &[u8],
        signature: &str,
    ) -> Result<SubmissionTicket, StartFailure> {
        let frame = encode_submission(operation_id, idempotency_key, plan, grant, signature)
            .map_err(|_| StartFailure::InvalidInput)?;
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| StartFailure::Busy)?;
        let permit = Permit(Arc::clone(&self.active));
        let transport = Arc::clone(&self.transport);
        let operation_id = operation_id.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("rustiron-submit".into())
            .spawn(move || {
                let _permit = permit;
                let result = transport.submit_encoded(&operation_id, &frame);
                // The requester may have disconnected. The operation is not cancelled.
                drop(sender.send(result));
            })
            .map_err(|_| StartFailure::Unavailable)?;
        Ok(SubmissionTicket { receiver })
    }
}

struct Permit(Arc<AtomicBool>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// A local wait handle, not evidence that the executor admitted an operation.
pub struct SubmissionTicket {
    receiver: mpsc::Receiver<Result<SubmissionReply, SubmitFailure>>,
}

impl SubmissionTicket {
    /// Waits for the recorded reply or transport outcome without cancelling work.
    /// Timeout or a disconnected worker does not establish whether anything was sent.
    pub fn wait_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Result<SubmissionReply, SubmitFailure>, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}
