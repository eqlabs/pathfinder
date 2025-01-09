use blockifier::execution::stack_trace::{
    gen_transaction_execution_error_trace,
    ErrorStack as BlockifierErrorStack,
};
use blockifier::transaction::errors::TransactionExecutionError;
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
        let error_stack = gen_transaction_execution_error_trace(&value);
        error_stack.into()
    }
}

#[derive(Clone, Debug)]
pub enum Frame {
    CallFrame(CallFrame),
    StringFrame(String),
}

impl From<blockifier::execution::stack_trace::Frame> for Frame {
    fn from(value: blockifier::execution::stack_trace::Frame) -> Self {
        match value {
            blockifier::execution::stack_trace::Frame::EntryPoint(entry_point) => {
                Frame::CallFrame(CallFrame {
                    storage_address: ContractAddress(entry_point.storage_address.0.into_felt()),
                    class_hash: ClassHash(entry_point.class_hash.0.into_felt()),
                    selector: entry_point.selector.map(|s| EntryPoint(s.0.into_felt())),
                })
            }
            blockifier::execution::stack_trace::Frame::Vm(vm_exception) => {
                Frame::StringFrame(String::from(&vm_exception))
            }
            blockifier::execution::stack_trace::Frame::StringFrame(string_frame) => {
                Frame::StringFrame(string_frame)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct CallFrame {
    pub storage_address: ContractAddress,
    pub class_hash: ClassHash,
    pub selector: Option<EntryPoint>,
}
