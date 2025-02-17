use blockifier::execution::stack_trace::{
    gen_tx_execution_error_trace,
    Cairo1RevertFrame,
    Cairo1RevertSummary,
    ErrorStack as BlockifierErrorStack,
    ErrorStackSegment,
};
use blockifier::transaction::errors::TransactionExecutionError;
use blockifier::transaction::objects::RevertError;
use pathfinder_common::{ClassHash, ContractAddress, EntryPoint};

use crate::IntoFelt;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ErrorStack(pub Vec<Frame>);

impl From<BlockifierErrorStack> for ErrorStack {
    fn from(value: BlockifierErrorStack) -> Self {
        Self(
            value
                .stack
                .into_iter()
                .flat_map(|v| Frames::from(v).0)
                .collect(),
        )
    }
}

impl From<TransactionExecutionError> for ErrorStack {
    fn from(value: TransactionExecutionError) -> Self {
        let error_stack = gen_tx_execution_error_trace(&value);
        error_stack.into()
    }
}

impl From<RevertError> for ErrorStack {
    fn from(value: RevertError) -> Self {
        match value {
            RevertError::Execution(error_stack) => error_stack.into(),
            RevertError::PostExecution(fee_check_error) => {
                Self(vec![Frame::StringFrame(fee_check_error.to_string())])
            }
        }
    }
}

impl From<Cairo1RevertSummary> for ErrorStack {
    fn from(value: Cairo1RevertSummary) -> Self {
        Self(Frames::from(value).0)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Frame {
    CallFrame(CallFrame),
    StringFrame(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CallFrame {
    pub storage_address: ContractAddress,
    pub class_hash: ClassHash,
    pub selector: Option<EntryPoint>,
}

impl From<Cairo1RevertFrame> for Frame {
    fn from(value: Cairo1RevertFrame) -> Self {
        Self::CallFrame(CallFrame {
            storage_address: ContractAddress(value.contract_address.0.into_felt()),
            // FIXME: what should we do here if the frame has no class hash?
            class_hash: ClassHash(value.class_hash.unwrap_or_default().0.into_felt()),
            selector: Some(EntryPoint(value.selector.0.into_felt())),
        })
    }
}

struct Frames(pub Vec<Frame>);

impl From<ErrorStackSegment> for Frames {
    fn from(value: ErrorStackSegment) -> Self {
        match value {
            ErrorStackSegment::EntryPoint(entry_point) => Self(vec![Frame::CallFrame(CallFrame {
                storage_address: ContractAddress(entry_point.storage_address.0.into_felt()),
                class_hash: ClassHash(entry_point.class_hash.0.into_felt()),
                selector: entry_point.selector.map(|s| EntryPoint(s.0.into_felt())),
            })]),
            ErrorStackSegment::Cairo1RevertSummary(revert_summary) => revert_summary.into(),
            ErrorStackSegment::Vm(vm_exception) => {
                Self(vec![Frame::StringFrame(String::from(&vm_exception))])
            }
            ErrorStackSegment::StringFrame(string_frame) => {
                Self(vec![Frame::StringFrame(string_frame)])
            }
        }
    }
}

impl From<Cairo1RevertSummary> for Frames {
    fn from(value: Cairo1RevertSummary) -> Self {
        let failure_reason =
            starknet_api::execution_utils::format_panic_data(&value.last_retdata.0);
        Self(
            value
                .stack
                .into_iter()
                .map(Into::into)
                .chain(std::iter::once(Frame::StringFrame(failure_reason)))
                .collect(),
        )
    }
}
