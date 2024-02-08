use p2p_proto::receipt::{
    DeclareTransactionReceipt, DeployAccountTransactionReceipt, DeployTransactionReceipt,
    InvokeTransactionReceipt, L1HandlerTransactionReceipt,
};
use pathfinder_common::{
    receipt::{BuiltinCounters, ExecutionResources, ExecutionStatus, L2ToL1Message},
    ContractAddress, EthereumAddress, Fee, L2ToL1MessagePayloadElem, TransactionHash,
};

/// Represents a simplified [`pathfinder_common::receipt::Receipt`] (events and transaction index excluded).
#[derive(Clone, Default, Debug, PartialEq)]
pub struct Receipt {
    pub actual_fee: Option<Fee>,
    pub execution_resources: Option<ExecutionResources>,
    pub l2_to_l1_messages: Vec<L2ToL1Message>,
    pub execution_status: ExecutionStatus,
    pub transaction_hash: TransactionHash,
}

impl From<pathfinder_common::receipt::Receipt> for Receipt {
    fn from(x: pathfinder_common::receipt::Receipt) -> Self {
        Self {
            transaction_hash: x.transaction_hash,
            actual_fee: x.actual_fee,
            execution_resources: x.execution_resources,
            l2_to_l1_messages: x.l2_to_l1_messages,
            execution_status: x.execution_status,
        }
    }
}

impl TryFrom<p2p_proto::receipt::Receipt> for Receipt {
    type Error = anyhow::Error;

    fn try_from(proto: p2p_proto::receipt::Receipt) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        use p2p_proto::receipt::Receipt::{Declare, Deploy, DeployAccount, Invoke, L1Handler};

        match proto {
            Invoke(InvokeTransactionReceipt { common })
            | Declare(DeclareTransactionReceipt { common })
            | L1Handler(L1HandlerTransactionReceipt { common, .. })
            | Deploy(DeployTransactionReceipt { common, .. })
            | DeployAccount(DeployAccountTransactionReceipt { common, .. }) => Ok(Self {
                transaction_hash: TransactionHash(common.transaction_hash.0),
                actual_fee: Some(Fee(common.actual_fee)),
                execution_resources: Some(ExecutionResources {
                    builtin_instance_counter: BuiltinCounters {
                        output_builtin: common.execution_resources.builtins.output.into(),
                        pedersen_builtin: common.execution_resources.builtins.pedersen.into(),
                        range_check_builtin: common.execution_resources.builtins.range_check.into(),
                        ecdsa_builtin: common.execution_resources.builtins.ecdsa.into(),
                        bitwise_builtin: common.execution_resources.builtins.bitwise.into(),
                        ec_op_builtin: common.execution_resources.builtins.ec_op.into(),
                        keccak_builtin: common.execution_resources.builtins.keccak.into(),
                        poseidon_builtin: common.execution_resources.builtins.poseidon.into(),
                        segment_arena_builtin: 0,
                    },
                    n_steps: common.execution_resources.steps.into(),
                    n_memory_holes: common.execution_resources.memory_holes.into(),
                }),
                l2_to_l1_messages: common
                    .messages_sent
                    .into_iter()
                    .map(|x| L2ToL1Message {
                        from_address: ContractAddress(x.from_address),
                        payload: x
                            .payload
                            .into_iter()
                            .map(L2ToL1MessagePayloadElem)
                            .collect(),
                        to_address: EthereumAddress(x.to_address.0),
                    })
                    .collect(),
                execution_status: if common.revert_reason.is_empty() {
                    ExecutionStatus::Succeeded
                } else {
                    ExecutionStatus::Reverted {
                        reason: common.revert_reason,
                    }
                },
            }),
        }
    }
}
