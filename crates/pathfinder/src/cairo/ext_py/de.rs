//! The json deserializable types

use super::{CallFailure, SubprocessError};
use crate::{core::CallResultValue, rpc::types::reply::FeeEstimate};

/// The python loop currently responds with these four possibilities. An enum would be more
/// appropriate.
///
/// This is [`ChildResponse::refine`]'d into [`RefinedChildResponse`]
#[derive(serde::Deserialize, Debug)]
#[allow(unused)]
pub(crate) struct ChildResponse<'a> {
    /// Describes the outcome with three alternatives (good, known error, unknown error)
    status: Status,
    /// Head of the raw exception message limited to 197 first characters and an three dots for
    /// longer. Probably okay to give as a hint in the internal error message.
    #[serde(borrow)]
    exception: Option<std::borrow::Cow<'a, str>>,
    /// Enumeration of "known errors", present when `status` is [`Status::Error`].
    kind: Option<ErrorKind>,
    /// Timing information, possibly available.
    #[serde(default)]
    timings: Timings,
    /// The real output from the contract when `status` is [`Status::Ok`].
    #[serde(default)]
    output: Option<OutputValue>,
}

/// Deserializes either the call output value or the fee estimate.
#[derive(serde::Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum OutputValue {
    Call(Vec<CallResultValue>),
    Fee(FeeEstimate),
}

impl<'a> ChildResponse<'a> {
    pub(super) fn refine(mut self) -> Result<RefinedChildResponse<'a>, SubprocessError> {
        match (&self.status, &mut self.kind, &mut self.exception) {
            (Status::Ok, None, None) => Ok(RefinedChildResponse {
                status: RefinedStatus::Ok(self.output.ok_or(SubprocessError::InvalidResponse)?),
                timings: self.timings,
            }),
            (Status::Error, x @ Some(_), None) => Ok(RefinedChildResponse {
                status: RefinedStatus::Error(x.take().unwrap()),
                timings: self.timings,
            }),
            (Status::Failed, None, s @ &mut Some(_)) => Ok(RefinedChildResponse {
                status: RefinedStatus::Failed(s.take().unwrap()),
                timings: self.timings,
            }),
            // these should not happen, so turn them into similar as serde_json errors
            _ => Err(SubprocessError::InvalidResponse),
        }
    }
}

impl RefinedChildResponse<'_> {
    pub(super) fn into_messages(
        self,
    ) -> (Option<Timings>, Status, Result<OutputValue, CallFailure>) {
        match self {
            RefinedChildResponse {
                timings,
                status: RefinedStatus::Ok(x),
            } => (Some(timings), Status::Ok, Ok(x)),
            RefinedChildResponse {
                timings,
                status: RefinedStatus::Error(e),
            } => (Some(timings), Status::Error, Err(CallFailure::from(e))),
            RefinedChildResponse {
                timings,
                status: RefinedStatus::Failed(s),
            } => (
                Some(timings),
                Status::Failed,
                Err(CallFailure::ExecutionFailed(s.to_string())),
            ),
        }
    }
}

/// Different kinds of errors the python side recognizes.
#[derive(serde::Deserialize, Debug)]
pub enum ErrorKind {
    #[serde(rename = "NO_SUCH_BLOCK")]
    NoSuchBlock,
    #[serde(rename = "NO_SUCH_CONTRACT")]
    NoSuchContract,
    #[serde(rename = "INVALID_SCHEMA_VERSION")]
    InvalidSchemaVersion,
    #[serde(rename = "INVALID_INPUT")]
    InvalidCommand,
}

#[derive(serde::Deserialize, PartialEq, Debug)]
pub enum Status {
    /// No errors
    #[serde(rename = "ok")]
    Ok,
    /// Known error happened
    #[serde(rename = "error")]
    Error,
    /// Any of the cairo-lang errors happened
    #[serde(rename = "failed")]
    Failed,
}

/// Just something python internally recorded, so we'd know at least something.
/// No plans aside from logging for now for the data.
#[derive(serde::Deserialize, Debug, Default)]
#[allow(unused)]
pub(super) struct Timings {
    /// Time it took to parse, before opening the transaction.
    parsing: Option<f64>,
    /// Time it took to find the tree root, and execute.
    execution: Option<f64>,
}

/// The format we'd prefer to process instead of [`ChildResponse`].
pub(super) struct RefinedChildResponse<'a> {
    status: RefinedStatus<'a>,
    timings: Timings,
}

/// More sensible alternative to [`Status`].
pub(super) enum RefinedStatus<'a> {
    Ok(OutputValue),
    Error(ErrorKind),
    Failed(std::borrow::Cow<'a, str>),
}
