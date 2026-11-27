use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

use crate::{Id, Text};

/// A stable public error code for the read-only protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Invalid schema or semantic parameters.
    InvalidRequest,
    /// The peer uses a schema this build does not support.
    UnsupportedVersion,
    /// Request bytes exceed the protocol limit.
    RequestTooLarge,
    /// Response bytes exceed the protocol limit.
    ResponseTooLarge,
    /// The local peer is not allowed to perform the request.
    UnauthorizedPeer,
    /// A referenced resource does not exist in the permitted inventory.
    NotFound,
    /// Pagination must be restarted deliberately.
    CursorExpired,
    /// A transport or required dependency is unavailable.
    DependencyUnavailable,
}

impl ErrorCode {
    /// Every code, for the error-code list check (W704). Keep it in step
    /// with the enum, as `ExecutorError::ALL` is.
    pub const ALL: [Self; 8] = [
        Self::InvalidRequest,
        Self::UnsupportedVersion,
        Self::RequestTooLarge,
        Self::ResponseTooLarge,
        Self::UnauthorizedPeer,
        Self::NotFound,
        Self::CursorExpired,
        Self::DependencyUnavailable,
    ];

    /// Stable CLI exit status; human messages are not a machine contract.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidRequest
            | Self::UnsupportedVersion
            | Self::RequestTooLarge
            | Self::ResponseTooLarge => 2,
            Self::UnauthorizedPeer => 3,
            Self::NotFound | Self::CursorExpired => 4,
            Self::DependencyUnavailable => 7,
        }
    }

    /// Default redacted, actionable message, independent of caller input.
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidRequest => {
                "Invalid request; check the documented schema and parameter limits."
            }
            Self::UnsupportedVersion => "Unsupported schema version; use schema version 1.",
            Self::RequestTooLarge => "Request exceeds the allowed byte limit; reduce its size.",
            Self::ResponseTooLarge => "Response exceeds the allowed byte limit; narrow the query.",
            Self::UnauthorizedPeer => {
                "Local peer is not authorized; check socket access and identity."
            }
            Self::NotFound => "Resource not found in the permitted inventory.",
            Self::CursorExpired => "Cursor is no longer valid; restart the list query.",
            Self::DependencyUnavailable => {
                "Dependency unavailable; inspect its status before retrying."
            }
        }
    }
}

/// A bounded wire error; it never includes parser errors or raw request bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApiError {
    code: ErrorCode,
    message: Text,
    retryable: bool,
    #[serde(deserialize_with = "Option::deserialize")]
    operation_id: Option<Id>,
    details: Vec<Text>,
}

impl ApiError {
    /// Builds a safe default error without reflecting rejected input.
    ///
    /// # Panics
    ///
    /// Never: every [`ErrorCode`] message fits [`Text`] (tested for each code).
    #[expect(
        clippy::expect_used,
        reason = "every ErrorCode message is a short static string within Text bounds"
    )]
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            message: Text::try_from(code.message().to_owned())
                .expect("static error messages are bounded"),
            retryable: false,
            operation_id: None,
            details: Vec::new(),
        }
    }

    /// Returns the stable machine code.
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns bounded human guidance, escaped by the human renderer.
    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    pub(crate) fn is_bounded_read_error(&self) -> bool {
        self.details.len() <= 8 && self.operation_id.is_none()
    }
}

/// A local protocol failure without potentially sensitive parser context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// Malformed, ambiguous, too deeply nested or structurally invalid JSON.
    InvalidMessage,
    /// An invalid opaque identifier.
    InvalidIdentifier,
    /// A text value exceeds its bounded transport size.
    InvalidText,
    /// Pagination limits are outside 1..=100.
    InvalidLimit,
    /// A timestamp is outside the exact JSON integer range.
    InvalidTimestamp,
    /// Unsupported numeric schema version.
    UnsupportedVersion,
    /// Request size exceeds the allowed transport payload.
    RequestTooLarge,
    /// Response size exceeds the allowed transport payload.
    ResponseTooLarge,
}

impl ProtocolError {
    /// Converts to a safe wire error, retaining no request/parser strings.
    pub fn api_error(self) -> ApiError {
        let code = match self {
            Self::UnsupportedVersion => ErrorCode::UnsupportedVersion,
            Self::RequestTooLarge => ErrorCode::RequestTooLarge,
            Self::ResponseTooLarge => ErrorCode::ResponseTooLarge,
            _ => ErrorCode::InvalidRequest,
        };
        ApiError::new(code)
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMessage => "invalid JSON message or schema",
            Self::InvalidIdentifier => "invalid opaque identifier",
            Self::InvalidText => "text exceeds its byte limit",
            Self::InvalidLimit => "page limit must be between 1 and 100",
            Self::InvalidTimestamp => "timestamp exceeds the exact JSON integer range",
            Self::UnsupportedVersion => "unsupported schema version",
            Self::RequestTooLarge => "request exceeds its byte limit",
            Self::ResponseTooLarge => "response exceeds its byte limit",
        })
    }
}

impl Error for ProtocolError {}

#[cfg(test)]
mod w672_tests {
    use super::*;

    /// The `expect` in [`ApiError::new`] holds for every code. The `match` is
    /// exhaustive, so a new code fails to compile until it is listed here.
    /// Add the new code to [`ErrorCode::ALL`] at the same time.
    #[test]
    fn every_error_code_builds_a_bounded_message() {
        for code in ErrorCode::ALL {
            match code {
                ErrorCode::InvalidRequest => {}
                ErrorCode::UnsupportedVersion => {}
                ErrorCode::RequestTooLarge => {}
                ErrorCode::ResponseTooLarge => {}
                ErrorCode::UnauthorizedPeer => {}
                ErrorCode::NotFound => {}
                ErrorCode::CursorExpired => {}
                ErrorCode::DependencyUnavailable => {}
            }
            assert_eq!(ApiError::new(code).code, code);
        }
    }

    /// W704: the error-code list has one row for each code and no other row.
    #[test]
    fn every_error_code_has_one_row_in_the_list() {
        const LIST: &str = include_str!("../../../docs/technical/ERROR-CODES.md");
        let heading = "## Read protocol (`ErrorCode`)";
        let start = LIST.find(heading).expect("section heading") + heading.len();
        let section = &LIST[start..];
        let section = &section[..section.find("\n## ").unwrap_or(section.len())];
        let mut listed: Vec<String> = section
            .lines()
            .filter_map(|line| line.strip_prefix("| `")?.split_once("` |"))
            .map(|(code, _)| format!("\"{code}\""))
            .collect();
        let mut codes: Vec<String> = ErrorCode::ALL
            .iter()
            .map(|code| serde_json::to_string(code).expect("code serializes"))
            .collect();
        listed.sort_unstable();
        codes.sort_unstable();
        assert_eq!(listed, codes);
    }
}
