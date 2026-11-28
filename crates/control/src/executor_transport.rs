//! Peer-checked transport to an executor; not exposed on the operator socket.

use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

use rustiron_contracts::{
    ApiError, ErrorCode, Id, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    execution::{
        StatusQuery, StatusResponse, SubmissionReply, decode_status_response,
        decode_submission_reply, encode_status_query, encode_submission,
    },
    local::{self, DEADLINE},
};

const SUBMISSION_REPLY_WAIT: Duration = Duration::from_secs(600);

/// A failed submission, classified by whether any request bytes may have left.
#[derive(Debug, Eq, PartialEq)]
pub enum SubmitFailure {
    /// The supplied data could not form a bounded submission.
    InvalidInput,
    /// The request was not sent because the local identity or connection failed.
    NotSent,
    /// Sending began or a reply was unusable; the effect requires reconciliation.
    OutcomeUnknown,
}

/// Immutable local executor endpoint, configured by the coordinator itself.
/// Production always requires a root-owned socket and a root kernel peer.
#[derive(Clone)]
pub struct ExecutorTransport {
    socket: PathBuf,
    owner_uid: u32,
    peer_uid: u32,
}

impl ExecutorTransport {
    /// Selects an absolute executor socket path; no request can override it.
    pub fn new(socket: PathBuf) -> Result<Self, ErrorCode> {
        if !socket.is_absolute() || socket.file_name().is_none() {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            socket,
            owner_uid: 0,
            peer_uid: 0,
        })
    }

    #[cfg(test)]
    fn fixture(socket: PathBuf, owner_uid: u32, peer_uid: u32) -> Self {
        Self {
            socket,
            owner_uid,
            peer_uid,
        }
    }

    fn connect(&self, deadline: Instant) -> Result<std::os::unix::net::UnixStream, ErrorCode> {
        check_socket(&self.socket, self.owner_uid)?;
        local::connect_peer(&self.socket, self.peer_uid, deadline)
    }

    /// Reads a correlated recorded outcome, without applying any operation.
    pub fn status(&self, query: &StatusQuery) -> Result<StatusResponse, ErrorCode> {
        self.status_until(query, Instant::now() + DEADLINE)
    }

    pub(crate) fn status_until(
        &self,
        query: &StatusQuery,
        deadline: Instant,
    ) -> Result<StatusResponse, ErrorCode> {
        local::operator_uid()?;
        let bytes = encode_status_query(query).map_err(|_| ErrorCode::InvalidRequest)?;
        let mut stream = self.connect(deadline)?;
        local::write_frame(
            &mut stream,
            &bytes,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            deadline,
        )
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
        let reply = local::read_frame(
            &mut stream,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            deadline,
        )
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
        decode_status_response(&reply, query).map_err(|_| ErrorCode::DependencyUnavailable)
    }

    pub(crate) fn evidence_until(
        &self,
        query: &rustiron_contracts::execution::EvidenceQuery,
        deadline: Instant,
    ) -> Result<Result<rustiron_contracts::execution::EvidenceValue, ApiError>, ErrorCode> {
        local::operator_uid()?;
        let bytes = rustiron_contracts::execution::encode_evidence_query(query)
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let mut stream = self.connect(deadline)?;
        local::write_frame(
            &mut stream,
            &bytes,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            deadline,
        )
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
        let reply = local::read_frame(
            &mut stream,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            deadline,
        )
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
        rustiron_contracts::execution::decode_evidence_response(&reply, query)
            .map_err(|_| ErrorCode::DependencyUnavailable)
    }

    /// One framed read exchange; the caller encodes and decodes.
    fn exchange(&self, bytes: &[u8], deadline: Instant) -> Result<Vec<u8>, ErrorCode> {
        local::operator_uid()?;
        let mut stream = self.connect(deadline)?;
        local::write_frame(
            &mut stream,
            bytes,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            deadline,
        )
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
        local::read_frame(
            &mut stream,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            deadline,
        )
        .map_err(|_| ErrorCode::DependencyUnavailable)
    }

    /// D-103 (W778): the executor journal's owned sites, read-only.
    pub(crate) fn site_records_until(
        &self,
        query: &rustiron_contracts::execution::SiteRecordsQuery,
        deadline: Instant,
    ) -> Result<Result<Vec<rustiron_contracts::execution::SiteRecord>, ApiError>, ErrorCode> {
        let bytes = rustiron_contracts::execution::encode_site_records_query(query)
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let reply = self.exchange(&bytes, deadline)?;
        rustiron_contracts::execution::decode_site_records_response(&reply, query)
            .map_err(|_| ErrorCode::DependencyUnavailable)
    }

    /// D-104 (W779): the executor's bounded host summary, read-only.
    pub(crate) fn host_summary_until(
        &self,
        query: &rustiron_contracts::summary::HostSummaryQuery,
        deadline: Instant,
    ) -> Result<Result<rustiron_contracts::summary::HostSummary, ApiError>, ErrorCode> {
        let bytes = rustiron_contracts::summary::encode_host_summary_query(query)
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let reply = self.exchange(&bytes, deadline)?;
        rustiron_contracts::summary::decode_host_summary_response(&reply, query)
            .map_err(|_| ErrorCode::DependencyUnavailable)
    }

    /// Forwards one already-signed grant and plan without signing or retrying.
    pub fn submit(
        &self,
        operation_id: &Id,
        idempotency_key: &Id,
        plan: &[u8],
        grant: &[u8],
        signature: &str,
    ) -> Result<SubmissionReply, SubmitFailure> {
        let bytes = encode_submission(operation_id, idempotency_key, plan, grant, signature)
            .map_err(|_| SubmitFailure::InvalidInput)?;
        self.submit_encoded(operation_id, &bytes)
    }

    pub(crate) fn submit_encoded(
        &self,
        operation_id: &Id,
        bytes: &[u8],
    ) -> Result<SubmissionReply, SubmitFailure> {
        local::operator_uid().map_err(|_| SubmitFailure::NotSent)?;
        let deadline = Instant::now() + DEADLINE;
        let mut stream = self.connect(deadline).map_err(|_| SubmitFailure::NotSent)?;
        local::write_frame(
            &mut stream,
            bytes,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            deadline,
        )
        .map_err(|_| SubmitFailure::OutcomeUnknown)?;
        let reply = local::read_frame(
            &mut stream,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            Instant::now() + SUBMISSION_REPLY_WAIT,
        )
        .map_err(|_| SubmitFailure::OutcomeUnknown)?;
        decode_submission_reply(&reply, operation_id).map_err(|_| SubmitFailure::OutcomeUnknown)
    }
}

fn check_socket(path: &Path, owner_uid: u32) -> Result<(), ErrorCode> {
    let parent = path.parent().ok_or(ErrorCode::InvalidRequest)?;
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut current = PathBuf::from("/");
    for component in parent.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(part) => current.push(part),
            _ => return Err(ErrorCode::InvalidRequest),
        }
        let metadata = fs::symlink_metadata(&current).map_err(local::io_code)?;
        let final_directory = current == parent;
        let trusted_owner = metadata.uid() == 0 || metadata.uid() == owner_uid;
        let writable = metadata.mode() & 0o022 != 0;
        let sticky_ancestor =
            !final_directory && metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || !trusted_owner
            || (writable && !sticky_ancestor)
            || (final_directory && metadata.uid() != owner_uid)
        {
            return Err(ErrorCode::UnauthorizedPeer);
        }
    }
    if parent == Path::new("/") {
        return Err(ErrorCode::UnauthorizedPeer);
    }
    let metadata = fs::symlink_metadata(path).map_err(local::io_code)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner_uid
        || metadata.nlink() != 1
        || !matches!(metadata.mode() & 0o7777, 0o600 | 0o660)
    {
        return Err(ErrorCode::UnauthorizedPeer);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Read,
        os::unix::{
            fs::{DirBuilderExt, PermissionsExt},
            net::UnixListener,
        },
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
        thread,
        time::Instant,
    };

    use super::{ExecutorTransport, SubmitFailure};
    use rustiron_contracts::{
        ErrorCode, Id, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
        execution::{OutcomeState, StatusQuery, decode_status_query, decode_submission},
        local,
    };

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        directory: PathBuf,
        socket: PathBuf,
        uid: u32,
    }
    impl Fixture {
        fn new() -> (Self, UnixListener) {
            let directory = std::env::temp_dir().join(format!(
                "ri-control-executor-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            let socket = directory.join("executor.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
            (
                Self {
                    directory,
                    socket,
                    uid: local::operator_uid().unwrap(),
                },
                listener,
            )
        }
        fn client(&self) -> ExecutorTransport {
            ExecutorTransport::fixture(self.socket.clone(), self.uid, self.uid)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }
    fn id(value: &str) -> Id {
        Id::try_from(value.to_owned()).unwrap()
    }
    fn query() -> StatusQuery {
        StatusQuery {
            request_id: id("query_1"),
            operation_id: id("operation_1"),
        }
    }

    fn apply_request() -> rustiron_contracts::apply::ApplyRequest {
        rustiron_contracts::apply::ApplyRequest {
            request_id: id("request_1"),
            operation_id: id("operation_1"),
            idempotency_key: id("retry_1"),
            plan: br#"{"nested": {"x":1}}"#.to_vec(),
            grant: br#"{"issuer": "fixture"}"#.to_vec(),
            signature: "synthetic_signature".to_owned(),
        }
    }

    #[test]
    fn coordinator_forwards_and_correlates_a_signed_submission() {
        use rustiron_contracts::apply::{
            ApplyOutcome, decode_apply_response, encode_apply_request,
        };
        let (fixture, listener) = Fixture::new();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let frame = local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            let request = decode_submission(&frame).unwrap();
            assert_eq!(request.plan, apply_request().plan);
            assert_eq!(request.grant, apply_request().grant);
            assert_eq!(request.signature, apply_request().signature);
            let reply = br#"{"schema_version":1,"operation_id":"operation_1","state":"succeeded","replay":false,"error":null}"#;
            local::write_frame(
                &mut stream,
                reply,
                MAX_RESPONSE_BYTES,
                ErrorCode::ResponseTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
        });
        let coordinator = crate::Coordinator::new(None).with_executor(fixture.client());
        let (mut client, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let handler = thread::spawn(move || coordinator.handle(peer));
        let request = apply_request();
        local::write_frame(
            &mut client,
            &encode_apply_request(&request).unwrap(),
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        let reply = local::read_frame(
            &mut client,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        let result =
            decode_apply_response(&reply, &request.request_id, &request.operation_id).unwrap();
        assert!(
            matches!(result.outcome, ApplyOutcome::ExecutorReply { reply } if reply.state == Some(OutcomeState::Succeeded))
        );
        assert!(handler.join().unwrap());
        server.join().unwrap();
    }

    #[test]
    fn disconnected_operator_does_not_cancel_the_submission() {
        use rustiron_contracts::apply::encode_apply_request;
        use std::sync::mpsc;
        use std::time::Duration;
        let (fixture, listener) = Fixture::new();
        let (accepted, seen) = mpsc::channel();
        let (release, proceed) = mpsc::channel();
        let executor = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let frame = local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            assert_eq!(
                decode_submission(&frame).unwrap().operation_id,
                id("operation_1")
            );
            accepted.send(()).unwrap();
            proceed.recv_timeout(Duration::from_secs(2)).unwrap();
            let reply = br#"{"schema_version":1,"operation_id":"operation_1","state":"succeeded","replay":false,"error":null}"#;
            local::write_frame(
                &mut stream,
                reply,
                MAX_RESPONSE_BYTES,
                ErrorCode::ResponseTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
        });
        let coordinator = crate::Coordinator::new(None).with_executor(fixture.client());
        let (mut client, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let handler = thread::spawn(move || coordinator.handle(peer));
        local::write_frame(
            &mut client,
            &encode_apply_request(&apply_request()).unwrap(),
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        drop(client);
        seen.recv_timeout(Duration::from_secs(2)).unwrap();
        release.send(()).unwrap();
        assert!(!handler.join().unwrap());
        executor.join().unwrap();
    }

    #[test]
    fn coordinator_timeout_is_unknown_and_worker_keeps_running() {
        use crate::submission_worker::SubmissionWorker;
        use rustiron_contracts::apply::ApplyOutcome;
        use std::{sync::mpsc, time::Duration};
        let (fixture, listener) = Fixture::new();
        let (accepted, seen) = mpsc::channel();
        let (release, proceed) = mpsc::channel();
        let executor = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            accepted.send(()).unwrap();
            proceed.recv_timeout(Duration::from_secs(2)).unwrap();
            let reply = br#"{"schema_version":1,"operation_id":"operation_1","state":"succeeded","replay":false,"error":null}"#;
            local::write_frame(
                &mut stream,
                reply,
                MAX_RESPONSE_BYTES,
                ErrorCode::ResponseTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
        });
        let worker = SubmissionWorker::new(fixture.client());
        let response = crate::apply(
            apply_request(),
            Some(&worker),
            Instant::now() + Duration::from_millis(100),
        );
        assert_eq!(response.outcome, ApplyOutcome::OutcomeUnknown);
        seen.recv_timeout(Duration::from_secs(2)).unwrap();
        release.send(()).unwrap();
        executor.join().unwrap();
    }

    #[test]
    fn coordinator_rejects_malformed_submission_before_contacting_executor() {
        let (fixture, listener) = Fixture::new();
        listener.set_nonblocking(true).unwrap();
        let coordinator = crate::Coordinator::new(None).with_executor(fixture.client());
        let (mut client, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let handler = thread::spawn(move || coordinator.handle(peer));
        let invalid = br#"{"schema_version":1,"request_id":"request_1","method":"plan_apply","params":{"operation_id":"operation_1","idempotency_key":"retry_1","plan":{},"grant":{},"signature":"s","path":"/etc"}}"#;
        local::write_frame(
            &mut client,
            invalid,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        let bytes = local::read_frame(
            &mut client,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        assert_eq!(
            rustiron_contracts::decode_response(&bytes)
                .unwrap()
                .result
                .unwrap_err()
                .code(),
            ErrorCode::InvalidRequest
        );
        assert!(handler.join().unwrap());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn coordinator_without_executor_reports_not_sent() {
        use rustiron_contracts::apply::{
            ApplyOutcome, NotSentReason, decode_apply_response, encode_apply_request,
        };
        let coordinator = crate::Coordinator::new(None);
        let (mut client, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let handler = thread::spawn(move || coordinator.handle(peer));
        let request = apply_request();
        local::write_frame(
            &mut client,
            &encode_apply_request(&request).unwrap(),
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        let bytes = local::read_frame(
            &mut client,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        assert_eq!(
            decode_apply_response(&bytes, &request.request_id, &request.operation_id)
                .unwrap()
                .outcome,
            ApplyOutcome::NotSent {
                reason: NotSentReason::Unavailable
            }
        );
        assert!(handler.join().unwrap());
    }

    #[test]
    fn concurrent_operator_submission_is_refused_before_sending() {
        use rustiron_contracts::apply::{
            ApplyOutcome, NotSentReason, decode_apply_response, encode_apply_request,
        };
        use std::{
            sync::{Arc, mpsc},
            time::Duration,
        };
        let (fixture, listener) = Fixture::new();
        let (accepted, seen) = mpsc::channel();
        let (release, proceed) = mpsc::channel();
        let executor = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            accepted.send(()).unwrap();
            proceed.recv_timeout(Duration::from_secs(2)).unwrap();
            let reply = br#"{"schema_version":1,"operation_id":"operation_1","state":"succeeded","replay":false,"error":null}"#;
            local::write_frame(
                &mut stream,
                reply,
                MAX_RESPONSE_BYTES,
                ErrorCode::ResponseTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            listener.set_nonblocking(true).unwrap();
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        });
        let coordinator = Arc::new(crate::Coordinator::new(None).with_executor(fixture.client()));
        let (mut first, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let owner = Arc::clone(&coordinator);
        let first_handler = thread::spawn(move || owner.handle(peer));
        let request = apply_request();
        let bytes = encode_apply_request(&request).unwrap();
        local::write_frame(
            &mut first,
            &bytes,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        seen.recv_timeout(Duration::from_secs(2)).unwrap();
        let (mut second, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let second_handler = thread::spawn(move || coordinator.handle(peer));
        local::write_frame(
            &mut second,
            &bytes,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        let response = local::read_frame(
            &mut second,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        assert_eq!(
            decode_apply_response(&response, &request.request_id, &request.operation_id)
                .unwrap()
                .outcome,
            ApplyOutcome::NotSent {
                reason: NotSentReason::Busy
            }
        );
        assert!(second_handler.join().unwrap());
        release.send(()).unwrap();
        local::read_frame(
            &mut first,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        assert!(first_handler.join().unwrap());
        executor.join().unwrap();
    }

    #[test]
    fn status_is_framed_and_correlated_with_the_executor_reply() {
        let (fixture, listener) = Fixture::new();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let bytes = local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            assert_eq!(decode_status_query(&bytes).unwrap(), query());
            let reply = br#"{"schema_version":1,"request_id":"query_1","status":"ok","data":{"kind":"operation_status","value":{"operation_id":"operation_1","state":"intent"}},"error":null}"#;
            local::write_frame(
                &mut stream,
                reply,
                MAX_RESPONSE_BYTES,
                ErrorCode::ResponseTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
        });
        assert_eq!(
            fixture
                .client()
                .status(&query())
                .unwrap()
                .result
                .unwrap()
                .state,
            OutcomeState::Intent
        );
        server.join().unwrap();
    }

    #[test]
    fn status_rejects_an_uncorrelated_reply() {
        let (fixture, listener) = Fixture::new();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            let reply = br#"{"schema_version":1,"request_id":"other_query","status":"ok","data":{"kind":"operation_status","value":{"operation_id":"operation_1","state":"intent"}},"error":null}"#;
            local::write_frame(
                &mut stream,
                reply,
                MAX_RESPONSE_BYTES,
                ErrorCode::ResponseTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
        });
        assert_eq!(
            fixture.client().status(&query()).unwrap_err(),
            ErrorCode::DependencyUnavailable
        );
        server.join().unwrap();
    }

    #[test]
    fn coordinator_forwards_an_authenticated_status_query() {
        use rustiron_contracts::{
            ReadCommand, ReadData, Request, decode_request, decode_response, encode_request,
        };

        let (fixture, listener) = Fixture::new();
        let executor = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let bytes = local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            assert_eq!(decode_status_query(&bytes).unwrap(), query());
            let reply = br#"{"schema_version":1,"request_id":"query_1","status":"ok","data":{"kind":"operation_status","value":{"operation_id":"operation_1","state":"intent"}},"error":null}"#;
            local::write_frame(
                &mut stream,
                reply,
                MAX_RESPONSE_BYTES,
                ErrorCode::ResponseTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
        });
        let coordinator = crate::Coordinator::new(None).with_executor(fixture.client());
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let handler = thread::spawn(move || coordinator.handle(server));
        let request = Request {
            request_id: query().request_id,
            command: ReadCommand::OperationStatus {
                operation_id: query().operation_id,
            },
        };
        let request_bytes = encode_request(&request).unwrap();
        assert_eq!(decode_request(&request_bytes).unwrap(), request);
        local::write_frame(
            &mut client,
            &request_bytes,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        let bytes = local::read_frame(
            &mut client,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        let response = decode_response(&bytes).unwrap();
        assert_eq!(response.request_id, Some(request.request_id));
        assert!(
            matches!(response.result, Ok(ReadData::OperationStatus(value)) if value.operation_id == query().operation_id && value.state == OutcomeState::Intent)
        );
        assert!(handler.join().unwrap());
        executor.join().unwrap();
    }

    #[test]
    fn a_stalled_status_peer_respects_the_caller_deadline() {
        let (fixture, listener) = Fixture::new();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            thread::sleep(std::time::Duration::from_millis(300));
        });
        let started = Instant::now();
        let result = fixture
            .client()
            .status_until(&query(), started + std::time::Duration::from_millis(100));
        assert_eq!(result.unwrap_err(), ErrorCode::DependencyUnavailable);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        server.join().unwrap();
    }

    #[test]
    fn a_closed_connection_after_submission_has_unknown_outcome() {
        let (fixture, listener) = Fixture::new();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let bytes = local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            let request = decode_submission(&bytes).unwrap();
            assert_eq!(request.plan, br#"{"plan":"fixture"}"#);
            assert_eq!(request.grant, br#"{"grant":"fixture"}"#);
            assert_eq!(request.signature, "synthetic_signature");
        });
        let result = fixture.client().submit(
            &id("operation_1"),
            &id("retry_1"),
            br#"{"plan":"fixture"}"#,
            br#"{"grant":"fixture"}"#,
            "synthetic_signature",
        );
        assert_eq!(result.unwrap_err(), SubmitFailure::OutcomeUnknown);
        server.join().unwrap();
    }

    #[test]
    fn submission_worker_is_bounded_and_outlives_its_ticket() {
        use crate::submission_worker::{StartFailure, SubmissionWorker};
        use std::sync::mpsc;
        use std::time::Duration;

        let (fixture, listener) = Fixture::new();
        let (accepted, seen) = mpsc::channel();
        let (release, proceed) = mpsc::channel();
        let server = thread::spawn(move || {
            for operation in ["operation_1", "operation_2"] {
                let (mut stream, _) = listener.accept().unwrap();
                let bytes = local::read_frame(
                    &mut stream,
                    MAX_REQUEST_BYTES,
                    ErrorCode::RequestTooLarge,
                    Instant::now() + local::DEADLINE,
                )
                .unwrap();
                assert_eq!(
                    decode_submission(&bytes).unwrap().operation_id,
                    id(operation)
                );
                if operation == "operation_1" {
                    accepted.send(()).unwrap();
                    proceed.recv_timeout(Duration::from_secs(2)).unwrap();
                }
                let reply = format!(
                    r#"{{"schema_version":1,"operation_id":"{operation}","state":"succeeded","replay":false,"error":null}}"#
                );
                local::write_frame(
                    &mut stream,
                    reply.as_bytes(),
                    MAX_RESPONSE_BYTES,
                    ErrorCode::ResponseTooLarge,
                    Instant::now() + local::DEADLINE,
                )
                .unwrap();
            }
        });
        let worker = SubmissionWorker::new(fixture.client());
        let start = |operation: &str| {
            worker.start(&id(operation), &id("retry_1"), b"{}", b"{}", "signature")
        };
        assert_eq!(
            worker
                .start(
                    &id("operation_1"),
                    &id("retry_1"),
                    b"bad-json",
                    b"{}",
                    "signature"
                )
                .err(),
            Some(StartFailure::InvalidInput)
        );
        let ticket = start("operation_1").unwrap();
        seen.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(ticket);
        assert_eq!(start("operation_2").err(), Some(StartFailure::Busy));
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let second = loop {
            match start("operation_2") {
                Ok(ticket) => break ticket,
                Err(StartFailure::Busy) if Instant::now() < deadline => thread::yield_now(),
                Err(error) => panic!("worker did not release its slot: {error:?}"),
            }
        };
        let reply = second
            .wait_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert_eq!(reply.state, Some(OutcomeState::Succeeded));
        server.join().unwrap();
    }

    #[test]
    fn a_worker_wait_timeout_does_not_hide_a_lost_executor_reply() {
        use crate::submission_worker::SubmissionWorker;
        use std::sync::mpsc;
        use std::time::Duration;

        let (fixture, listener) = Fixture::new();
        let (accepted, seen) = mpsc::channel();
        let (release, proceed) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            accepted.send(()).unwrap();
            proceed.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        let worker = SubmissionWorker::new(fixture.client());
        let ticket = worker
            .start(
                &id("operation_1"),
                &id("retry_1"),
                b"{}",
                b"{}",
                "signature",
            )
            .unwrap();
        seen.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            ticket.wait_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release.send(()).unwrap();
        assert_eq!(
            ticket
                .wait_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap_err(),
            SubmitFailure::OutcomeUnknown
        );
        server.join().unwrap();
    }

    #[test]
    fn a_correlated_submission_reply_is_returned() {
        let (fixture, listener) = Fixture::new();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let bytes = local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            let submission = decode_submission(&bytes).unwrap();
            assert_eq!(submission.plan, br#"{"plan":"fixture"}"#);
            assert_eq!(submission.grant, br#"{"grant":"fixture"}"#);
            assert_eq!(submission.signature, "synthetic_signature");
            let reply = br#"{"schema_version":1,"operation_id":"operation_1","state":"succeeded","replay":false,"error":null}"#;
            local::write_frame(
                &mut stream,
                reply,
                MAX_RESPONSE_BYTES,
                ErrorCode::ResponseTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
        });
        let reply = fixture
            .client()
            .submit(
                &id("operation_1"),
                &id("retry_1"),
                br#"{"plan":"fixture"}"#,
                br#"{"grant":"fixture"}"#,
                "synthetic_signature",
            )
            .unwrap();
        assert_eq!(reply.state, Some(OutcomeState::Succeeded));
        server.join().unwrap();
    }

    #[test]
    fn a_reply_for_another_operation_leaves_the_outcome_unknown() {
        let (fixture, listener) = Fixture::new();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
            let reply = br#"{"schema_version":1,"operation_id":"another_operation","state":"succeeded","replay":false,"error":null}"#;
            local::write_frame(
                &mut stream,
                reply,
                MAX_RESPONSE_BYTES,
                ErrorCode::ResponseTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
        });
        let result = fixture.client().submit(
            &id("operation_1"),
            &id("retry_1"),
            br#"{"plan":"fixture"}"#,
            br#"{"grant":"fixture"}"#,
            "synthetic_signature",
        );
        assert_eq!(result.unwrap_err(), SubmitFailure::OutcomeUnknown);
        server.join().unwrap();
    }

    #[test]
    fn invalid_input_and_untrusted_socket_fail_before_sending() {
        let (fixture, _listener) = Fixture::new();
        let client = fixture.client();
        assert_eq!(
            client
                .submit(
                    &id("operation_1"),
                    &id("retry_1"),
                    b"not-json",
                    b"{}",
                    "signature"
                )
                .unwrap_err(),
            SubmitFailure::InvalidInput
        );
        fs::set_permissions(&fixture.socket, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            client
                .submit(
                    &id("operation_1"),
                    &id("retry_1"),
                    b"{}",
                    b"{}",
                    "signature"
                )
                .unwrap_err(),
            SubmitFailure::NotSent
        );
    }

    #[test]
    fn a_wrong_executor_peer_receives_no_request() {
        let (fixture, listener) = Fixture::new();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
        });
        let client =
            ExecutorTransport::fixture(fixture.socket.clone(), fixture.uid, fixture.uid + 1);
        assert_eq!(
            client.status(&query()).unwrap_err(),
            ErrorCode::UnauthorizedPeer
        );
        server.join().unwrap();
    }

    #[test]
    fn a_writable_executor_directory_is_refused() {
        let (fixture, _listener) = Fixture::new();
        fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            fixture.client().status(&query()).unwrap_err(),
            ErrorCode::UnauthorizedPeer
        );
        fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn a_socket_symlink_is_refused() {
        let (fixture, _listener) = Fixture::new();
        let alias = fixture.directory.join("alias.sock");
        std::os::unix::fs::symlink(&fixture.socket, &alias).unwrap();
        let client = ExecutorTransport::fixture(alias, fixture.uid, fixture.uid);
        assert_eq!(
            client.status(&query()).unwrap_err(),
            ErrorCode::UnauthorizedPeer
        );
    }

    /// W326 (B05): the product v2 vectors, as the CLI sends them.
    const PRODUCT_VECTORS: &str =
        include_str!("../../contracts/tests/fixtures/product-backup-vectors.json");

    fn product_vector(name: &str) -> (Vec<u8>, Vec<u8>) {
        let vectors: serde_json::Value = serde_json::from_str(PRODUCT_VECTORS).unwrap();
        let vector = vectors
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == name)
            .unwrap();
        let bytes = |field: &str| vector[field].as_str().unwrap().as_bytes().to_vec();
        (bytes("plan_canonical"), bytes("grant_canonical"))
    }

    /// Serves one submission and then one status read, as the product
    /// executor answers them: the reply and the state are the recorded W319
    /// and W320 lab outcomes (`untouched`, `NOT_ADMITTED_FOR_EFFECT`).
    fn product_executor(
        listener: UnixListener,
        plan: Vec<u8>,
        grant: Vec<u8>,
        capture: bool,
    ) -> thread::JoinHandle<()> {
        use rustiron_contracts::approval::{ProductBackupPlan, ProductBackupTarget};
        thread::spawn(move || {
            let read = |stream: &mut std::os::unix::net::UnixStream| {
                local::read_frame(
                    stream,
                    MAX_REQUEST_BYTES,
                    ErrorCode::RequestTooLarge,
                    Instant::now() + local::DEADLINE,
                )
                .unwrap()
            };
            let write = |stream: &mut std::os::unix::net::UnixStream, bytes: &[u8]| {
                local::write_frame(
                    stream,
                    bytes,
                    MAX_RESPONSE_BYTES,
                    ErrorCode::ResponseTooLarge,
                    Instant::now() + local::DEADLINE,
                )
                .unwrap();
            };
            let (mut stream, _) = listener.accept().unwrap();
            let frame = read(&mut stream);
            let submission = decode_submission(&frame).unwrap();
            assert_eq!(submission.plan, plan, "exact signed plan bytes");
            assert_eq!(submission.grant, grant, "exact signed grant bytes");
            let target = ProductBackupPlan::decode(submission.plan).unwrap();
            assert_eq!(
                matches!(target.target(), ProductBackupTarget::BackupCapture { .. }),
                capture
            );
            write(
                &mut stream,
                br#"{"schema_version":1,"operation_id":"operation_1","state":"untouched","replay":false,"error":"NOT_ADMITTED_FOR_EFFECT"}"#,
            );
            let (mut stream, _) = listener.accept().unwrap();
            let query = decode_status_query(&read(&mut stream)).unwrap();
            assert_eq!(query.operation_id, id("operation_1"));
            let reply = serde_json::json!({
                "schema_version": 1, "request_id": query.request_id, "status": "ok",
                "data": {"kind": "operation_status", "value": {"operation_id": "operation_1", "state": "untouched"}},
                "error": null,
            });
            write(&mut stream, &serde_json::to_vec(&reply).unwrap());
        })
    }

    /// W326 (B05): a signed product v2 capture or probe passes through the
    /// coordinator socket unchanged, and the operator reads back the recorded
    /// reply and the recorded state.
    #[test]
    fn coordinator_forwards_product_v2_plans_and_reads_back_their_state() {
        use rustiron_contracts::{
            ReadCommand, ReadData, Request,
            apply::{ApplyOutcome, ApplyRequest, decode_apply_response, encode_apply_request},
            decode_response, encode_request,
        };
        for (name, capture) in [("capture", true), ("probe", false)] {
            let (fixture, listener) = Fixture::new();
            let (plan, grant) = product_vector(name);
            let executor = product_executor(listener, plan.clone(), grant.clone(), capture);
            let socket = fixture.directory.join("control.sock");
            let control = crate::bind(&socket).unwrap();
            let coordinator = crate::Coordinator::new(None).with_executor(fixture.client());
            let server = thread::spawn(move || {
                for _ in 0..2 {
                    let (stream, _) = control.accept().unwrap();
                    assert!(coordinator.handle(stream));
                }
            });
            let exchange = |bytes: &[u8]| {
                let deadline = Instant::now() + local::DEADLINE;
                let mut stream = local::connect(&socket, fixture.uid, deadline).unwrap();
                local::write_frame(
                    &mut stream,
                    bytes,
                    MAX_REQUEST_BYTES,
                    ErrorCode::RequestTooLarge,
                    deadline,
                )
                .unwrap();
                local::read_frame(
                    &mut stream,
                    MAX_RESPONSE_BYTES,
                    ErrorCode::ResponseTooLarge,
                    deadline,
                )
                .unwrap()
            };
            let request = ApplyRequest {
                request_id: id("request_1"),
                operation_id: id("operation_1"),
                idempotency_key: id("retry_1"),
                plan,
                grant,
                signature: "synthetic_signature".to_owned(),
            };
            let applied = decode_apply_response(
                &exchange(&encode_apply_request(&request).unwrap()),
                &request.request_id,
                &request.operation_id,
            )
            .unwrap();
            let ApplyOutcome::ExecutorReply { reply } = applied.outcome else {
                panic!(
                    "{name}: expected the executor reply, got {:?}",
                    applied.outcome
                );
            };
            assert_eq!(reply.state, Some(OutcomeState::Untouched), "{name}");
            assert_eq!(reply.error.as_deref(), Some("NOT_ADMITTED_FOR_EFFECT"));
            assert!(!reply.replay);
            assert_eq!(reply.exit_code(), 5, "{name}: a known refusal, not success");
            let status = Request {
                request_id: id("status_1"),
                command: ReadCommand::OperationStatus {
                    operation_id: id("operation_1"),
                },
            };
            let response = decode_response(&exchange(&encode_request(&status).unwrap())).unwrap();
            assert!(
                matches!(response.result, Ok(ReadData::OperationStatus(ref value)) if value.state == OutcomeState::Untouched),
                "{name}: {response:?}"
            );
            server.join().unwrap();
            executor.join().unwrap();
        }
    }
}
