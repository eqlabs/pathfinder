use blockifier::execution::stack_trace::{
    gen_tx_execution_error_trace,
    ErrorStack as BlockifierErrorStack,
    ErrorStackSegment,
};
use blockifier::transaction::errors::TransactionExecutionError;
use blockifier::transaction::objects::RevertError;
use pathfinder_common::{ClassHash, ContractAddress, EntryPoint};

use crate::IntoFelt;

#[derive(Clone, Debug, Default)]
pub struct ErrorStack(pub Vec<Frame>);

impl From<BlockifierErrorStack> for ErrorStack {
    fn from(value: BlockifierErrorStack) -> Self {
        Self(value.stack.into_iter().map(Into::into).collect())
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

#[derive(Clone, Debug)]
pub enum Frame {
    CallFrame(CallFrame),
    StringFrame(String),
}

impl From<ErrorStackSegment> for Frame {
    fn from(value: ErrorStackSegment) -> Self {
        match value {
            ErrorStackSegment::EntryPoint(entry_point) => Frame::CallFrame(CallFrame {
                storage_address: ContractAddress(entry_point.storage_address.0.into_felt()),
                class_hash: ClassHash(entry_point.class_hash.0.into_felt()),
                selector: entry_point.selector.map(|s| EntryPoint(s.0.into_felt())),
            }),
            ErrorStackSegment::Cairo1RevertSummary(revert_summary) => {
                Frame::StringFrame(format!("{:?}", revert_summary))
            }
            ErrorStackSegment::Vm(vm_exception) => Frame::StringFrame(String::from(&vm_exception)),
            ErrorStackSegment::StringFrame(string_frame) => Frame::StringFrame(string_frame),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CallFrame {
    pub storage_address: ContractAddress,
    pub class_hash: ClassHash,
    pub selector: Option<EntryPoint>,
}
