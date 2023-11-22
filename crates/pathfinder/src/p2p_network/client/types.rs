use p2p_proto::receipt::{
    DeclareTransactionReceipt, DeployAccountTransactionReceipt, DeployTransactionReceipt,
    InvokeTransactionReceipt, L1HandlerTransactionReceipt,
};
use pathfinder_common::{
    ContractAddress, EntryPoint, EthereumAddress, Fee, L1ToL2MessageNonce,
    L1ToL2MessagePayloadElem, L2ToL1MessagePayloadElem, TransactionHash,
};
use starknet_gateway_types::reply::transaction as gw;

/// Represents a simplified receipt (events and execution status excluded).
///
/// This type is not in the `p2p` to avoid `p2p` dependence on `starknet_gateway_types`.
#[derive(Clone, Debug, PartialEq)]
pub struct Receipt {
    pub transaction_hash: TransactionHash,
    pub actual_fee: Fee,
    pub execution_resources: gw::ExecutionResources,
    pub l1_to_l2_consumed_message: Option<gw::L1ToL2Message>,
    pub l2_to_l1_messages: Vec<gw::L2ToL1Message>,
    // Empty means not reverted
    pub revert_error: String,
}

impl From<starknet_gateway_types::reply::transaction::Receipt> for Receipt {
    fn from(r: starknet_gateway_types::reply::transaction::Receipt) -> Self {
        Self {
            transaction_hash: TransactionHash(r.transaction_hash.0),
            actual_fee: r.actual_fee.unwrap_or_default(),
            execution_resources: r.execution_resources.unwrap_or_default(),
            l1_to_l2_consumed_message: r.l1_to_l2_consumed_message,
            l2_to_l1_messages: r.l2_to_l1_messages,
            revert_error: r.revert_error.unwrap_or_default(),
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
                actual_fee: Fee(common.actual_fee),
                execution_resources: gw::ExecutionResources {
                    builtin_instance_counter: gw::BuiltinCounters {
                        output_builtin: common.execution_resources.builtins.output.into(),
                        pedersen_builtin: common.execution_resources.builtins.pedersen.into(),
                        range_check_builtin: common.execution_resources.builtins.range_check.into(),
                        ecdsa_builtin: common.execution_resources.builtins.ecdsa.into(),
                        bitwise_builtin: common.execution_resources.builtins.bitwise.into(),
                        ec_op_builtin: common.execution_resources.builtins.ec_op.into(),
                        keccak_builtin: common.execution_resources.builtins.keccak.into(),
                        poseidon_builtin: common.execution_resources.builtins.poseidon.into(),
                        segment_arena_builtin: common
                            .execution_resources
                            .builtins
                            .segment_arena
                            .into(),
                    },
                    n_steps: common.execution_resources.steps.into(),
                    n_memory_holes: common.execution_resources.memory_holes.into(),
                },
                l1_to_l2_consumed_message: match common.consumed_message {
                    Some(x) => Some(gw::L1ToL2Message {
                        from_address: EthereumAddress(x.from_address.0),
                        payload: x
                            .payload
                            .into_iter()
                            .map(L1ToL2MessagePayloadElem)
                            .collect(),
                        selector: EntryPoint(x.entry_point_selector),
                        to_address: ContractAddress::new(x.to_address).ok_or_else(|| {
                            anyhow::anyhow!("Invalid contract address > u32::MAX")
                        })?,
                        nonce: Some(L1ToL2MessageNonce(x.nonce)),
                    }),
                    None => None,
                },
                l2_to_l1_messages: common
                    .messages_sent
                    .into_iter()
                    .map(|x| gw::L2ToL1Message {
                        from_address: ContractAddress(x.from_address),
                        payload: x
                            .payload
                            .into_iter()
                            .map(L2ToL1MessagePayloadElem)
                            .collect(),
                        to_address: EthereumAddress(x.to_address.0),
                    })
                    .collect(),
                revert_error: common.revert_reason,
            }),
        }
    }
}
