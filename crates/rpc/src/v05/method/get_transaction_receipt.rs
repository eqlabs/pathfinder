use crate::context::RpcContext;
use anyhow::Context;
use pathfinder_common::TransactionHash;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GetTransactionReceiptInput {
    transaction_hash: TransactionHash,
}

crate::error::generate_rpc_error_subset!(GetTransactionReceiptError: TxnHashNotFoundV04);

pub async fn get_transaction_receipt(
    context: RpcContext,
    input: GetTransactionReceiptInput,
) -> Result<types::MaybePendingTransactionReceipt, GetTransactionReceiptError> {
    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let db_tx = db.transaction().context("Creating database transaction")?;

        // Check pending transactions.
        let pending = context
            .pending_data
            .get(&db_tx)
            .context("Querying pending data")?;

        if let Some((transaction, receipt)) = pending
            .block
            .transactions
            .iter()
            .zip(pending.block.transaction_receipts.iter())
            .find_map(|(t, r)| (t.hash() == input.transaction_hash).then(|| (t.clone(), r.clone())))
        {
            let pending = types::PendingTransactionReceipt::from(receipt, &transaction);
            return Ok(types::MaybePendingTransactionReceipt::Pending(pending));
        }

        let (transaction, receipt, block_hash) = db_tx
            .transaction_with_receipt(input.transaction_hash)
            .context("Reading transaction receipt from database")?
            .ok_or(GetTransactionReceiptError::TxnHashNotFoundV04)?;

        let block_number = db_tx
            .block_id(block_hash.into())
            .context("Querying block number")?
            .context("Block number info missing")?
            .0;

        let l1_accepted = db_tx
            .block_is_l1_accepted(block_number.into())
            .context("Querying block status")?;

        let finality_status = if l1_accepted {
            types::FinalityStatus::AcceptedOnL1
        } else {
            types::FinalityStatus::AcceptedOnL2
        };

        Ok(types::MaybePendingTransactionReceipt::Normal(
            types::TransactionReceipt::with_block_data(
                receipt,
                finality_status,
                block_hash,
                block_number,
                transaction,
            ),
        ))
    });

    jh.await.context("Database read panic or shutting down")?
}

mod types {
    use crate::felt::{RpcFelt, RpcFelt251};
    use crate::v02::types::reply::BlockStatus;
    use pathfinder_common::{
        BlockHash, BlockNumber, ContractAddress, EthereumAddress, EventData, EventKey, Fee,
        L2ToL1MessagePayloadElem, TransactionHash,
    };
    use pathfinder_serde::{u64_as_hex_str, EthereumAddressAsHexStr, H256AsNoLeadingZerosHexStr};
    use primitive_types::H256;
    use serde::Serialize;
    use serde_with::serde_as;
    use starknet_gateway_types::reply::transaction::{
        BuiltinCounters, ExecutionResources, L2ToL1Message,
    };

    /// L2 transaction receipt as returned by the RPC API.
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(untagged)]
    pub enum MaybePendingTransactionReceipt {
        Normal(TransactionReceipt),
        Pending(PendingTransactionReceipt),
    }

    /// Non-pending L2 transaction receipt as returned by the RPC API.
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(tag = "type")]
    pub enum TransactionReceipt {
        #[serde(rename = "INVOKE")]
        Invoke(InvokeTransactionReceipt),
        #[serde(rename = "DECLARE")]
        Declare(DeclareTransactionReceipt),
        #[serde(rename = "L1_HANDLER")]
        L1Handler(L1HandlerTransactionReceipt),
        // FIXME regenesis: remove Deploy receipt type after regenesis
        // We are keeping this type of receipt until regenesis
        // only to support older pre-0.11.0 blocks
        #[serde(rename = "DEPLOY")]
        Deploy(DeployTransactionReceipt),
        #[serde(rename = "DEPLOY_ACCOUNT")]
        DeployAccount(DeployAccountTransactionReceipt),
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct InvokeTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonTransactionReceiptProperties,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct CommonTransactionReceiptProperties {
        #[serde_as(as = "RpcFelt")]
        pub transaction_hash: TransactionHash,
        pub actual_fee: Fee,
        #[serde_as(as = "RpcFelt")]
        pub block_hash: BlockHash,
        pub block_number: BlockNumber,
        pub messages_sent: Vec<MessageToL1>,
        pub events: Vec<Event>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub revert_reason: Option<String>,
        pub execution_resources: ExecutionResourcesProperties,
        pub execution_status: ExecutionStatus,
        pub finality_status: FinalityStatus,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct CommonPendingTransactionReceiptProperties {
        pub transaction_hash: TransactionHash,
        pub actual_fee: Fee,
        pub messages_sent: Vec<MessageToL1>,
        pub events: Vec<Event>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub revert_reason: Option<String>,
        pub execution_status: ExecutionStatus,
        pub execution_resources: ExecutionResourcesProperties,
        pub finality_status: FinalityStatus,
    }

    /// Similar to [`ExecutionResources`], with irrelevant properties stripped.
    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct ExecutionResourcesProperties {
        // All these properties are actually strings in the spec, hence the serde attributes.
        #[serde(with = "u64_as_hex_str")]
        pub steps: u64,
        #[serde(with = "u64_as_hex_str")]
        pub memory_holes: u64,
        #[serde(with = "u64_as_hex_str")]
        pub range_check_builtin_applications: u64,
        #[serde(with = "u64_as_hex_str")]
        pub pedersen_builtin_applications: u64,
        #[serde(with = "u64_as_hex_str")]
        pub poseidon_builtin_applications: u64,
        #[serde(with = "u64_as_hex_str")]
        pub ec_op_builtin_applications: u64,
        #[serde(with = "u64_as_hex_str")]
        pub ecdsa_builtin_applications: u64,
        #[serde(with = "u64_as_hex_str")]
        pub bitwise_builtin_applications: u64,
        #[serde(with = "u64_as_hex_str")]
        pub keccak_builtin_applications: u64,
    }

    impl From<ExecutionResources> for ExecutionResourcesProperties {
        fn from(value: ExecutionResources) -> Self {
            let ExecutionResources {
                builtin_instance_counter:
                    BuiltinCounters {
                        // Absent from the OpenRPC spec
                        output_builtin: _,
                        pedersen_builtin,
                        range_check_builtin,
                        ecdsa_builtin,
                        bitwise_builtin,
                        ec_op_builtin,
                        keccak_builtin,
                        poseidon_builtin,
                        // Absent from the OpenRPC spec
                        segment_arena_builtin: _,
                    },
                n_steps,
                n_memory_holes,
            } = value;

            Self {
                steps: n_steps,
                memory_holes: n_memory_holes,
                range_check_builtin_applications: range_check_builtin,
                pedersen_builtin_applications: pedersen_builtin,
                poseidon_builtin_applications: poseidon_builtin,
                ec_op_builtin_applications: ec_op_builtin,
                ecdsa_builtin_applications: ecdsa_builtin,
                bitwise_builtin_applications: bitwise_builtin,
                keccak_builtin_applications: keccak_builtin,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub enum ExecutionStatus {
        Succeeded,
        Reverted,
    }

    impl From<starknet_gateway_types::reply::transaction::ExecutionStatus> for ExecutionStatus {
        fn from(value: starknet_gateway_types::reply::transaction::ExecutionStatus) -> Self {
            match value {
                starknet_gateway_types::reply::transaction::ExecutionStatus::Succeeded => {
                    Self::Succeeded
                }
                starknet_gateway_types::reply::transaction::ExecutionStatus::Reverted => {
                    Self::Reverted
                }
            }
        }
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub enum FinalityStatus {
        AcceptedOnL2,
        AcceptedOnL1,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct L1HandlerTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonTransactionReceiptProperties,
        #[serde_as(as = "H256AsNoLeadingZerosHexStr")]
        pub message_hash: H256,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeployTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonTransactionReceiptProperties,
        #[serde_as(as = "RpcFelt251")]
        pub contract_address: ContractAddress,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeployAccountTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonTransactionReceiptProperties,
        #[serde_as(as = "RpcFelt251")]
        pub contract_address: ContractAddress,
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeclareTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonTransactionReceiptProperties,
    }

    impl TransactionReceipt {
        pub fn with_block_data(
            receipt: starknet_gateway_types::reply::transaction::Receipt,
            finality_status: FinalityStatus,
            block_hash: BlockHash,
            block_number: BlockNumber,
            transaction: starknet_gateway_types::reply::transaction::Transaction,
        ) -> Self {
            let common = CommonTransactionReceiptProperties {
                transaction_hash: receipt.transaction_hash,
                actual_fee: receipt
                    .actual_fee
                    .unwrap_or_else(|| Fee(Default::default())),
                block_hash,
                block_number,
                messages_sent: receipt
                    .l2_to_l1_messages
                    .into_iter()
                    .map(MessageToL1::from)
                    .collect(),
                events: receipt.events.into_iter().map(Event::from).collect(),
                revert_reason: receipt.revert_error,
                execution_resources: ExecutionResourcesProperties::from(
                    receipt.execution_resources.unwrap_or_default(),
                ),
                execution_status: receipt.execution_status.into(),
                finality_status,
            };

            use starknet_gateway_types::reply::transaction::Transaction::*;
            match transaction {
                Declare(_) => Self::Declare(DeclareTransactionReceipt { common }),
                Deploy(tx) => Self::Deploy(DeployTransactionReceipt {
                    common,
                    contract_address: tx.contract_address,
                }),
                DeployAccount(tx) => Self::DeployAccount(DeployAccountTransactionReceipt {
                    common,
                    contract_address: tx.contract_address,
                }),
                Invoke(_) => Self::Invoke(InvokeTransactionReceipt { common }),
                L1Handler(tx) => Self::L1Handler(L1HandlerTransactionReceipt {
                    common,
                    message_hash: tx.calculate_message_hash(),
                }),
            }
        }
    }

    /// Non-pending L2 transaction receipt as returned by the RPC API.
    ///
    /// Pending receipts don't have status, status_data, block_hash, block_number fields
    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(tag = "type")]
    pub enum PendingTransactionReceipt {
        #[serde(rename = "INVOKE")]
        Invoke(PendingInvokeTransactionReceipt),
        #[serde(rename = "DECLARE")]
        Declare(PendingDeclareTransactionReceipt),
        #[serde(rename = "DEPLOY")]
        Deploy(PendingDeployTransactionReceipt),
        #[serde(rename = "DEPLOY_ACCOUNT")]
        DeployAccount(PendingDeployAccountTransactionReceipt),
        #[serde(rename = "L1_HANDLER")]
        L1Handler(PendingL1HandlerTransactionReceipt),
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct PendingInvokeTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonPendingTransactionReceiptProperties,
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct PendingDeclareTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonPendingTransactionReceiptProperties,
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct PendingDeployTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonPendingTransactionReceiptProperties,

        pub contract_address: ContractAddress,
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct PendingDeployAccountTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonPendingTransactionReceiptProperties,

        pub contract_address: ContractAddress,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct PendingL1HandlerTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonPendingTransactionReceiptProperties,
        #[serde_as(as = "H256AsNoLeadingZerosHexStr")]
        pub message_hash: H256,
    }

    impl PendingTransactionReceipt {
        pub fn from(
            receipt: starknet_gateway_types::reply::transaction::Receipt,
            transaction: &starknet_gateway_types::reply::transaction::Transaction,
        ) -> Self {
            let common = CommonPendingTransactionReceiptProperties {
                transaction_hash: receipt.transaction_hash,
                actual_fee: receipt
                    .actual_fee
                    .unwrap_or_else(|| Fee(Default::default())),
                messages_sent: receipt
                    .l2_to_l1_messages
                    .into_iter()
                    .map(MessageToL1::from)
                    .collect(),
                events: receipt.events.into_iter().map(Event::from).collect(),
                revert_reason: receipt.revert_error,
                execution_status: receipt.execution_status.into(),
                execution_resources: ExecutionResourcesProperties::from(
                    receipt.execution_resources.unwrap_or_default(),
                ),
                finality_status: FinalityStatus::AcceptedOnL2,
            };

            use starknet_gateway_types::reply::transaction::Transaction::*;
            match transaction {
                Declare(_) => Self::Declare(PendingDeclareTransactionReceipt { common }),
                Deploy(tx) => Self::Deploy(PendingDeployTransactionReceipt {
                    common,
                    contract_address: tx.contract_address,
                }),
                DeployAccount(tx) => Self::DeployAccount(PendingDeployAccountTransactionReceipt {
                    common,
                    contract_address: tx.contract_address,
                }),
                Invoke(_) => Self::Invoke(PendingInvokeTransactionReceipt { common }),
                L1Handler(tx) => Self::L1Handler(PendingL1HandlerTransactionReceipt {
                    common,
                    message_hash: tx.calculate_message_hash(),
                }),
            }
        }
    }

    /// Message sent from L2 to L1.
    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct MessageToL1 {
        pub from_address: ContractAddress,
        #[serde_as(as = "EthereumAddressAsHexStr")]
        pub to_address: EthereumAddress,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub payload: Vec<L2ToL1MessagePayloadElem>,
    }

    impl MessageToL1 {
        fn from(msg: L2ToL1Message) -> Self {
            Self {
                from_address: msg.from_address,
                to_address: msg.to_address,
                payload: msg.payload,
            }
        }
    }

    /// Event emitted as a part of a transaction.
    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct Event {
        #[serde_as(as = "RpcFelt251")]
        pub from_address: ContractAddress,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub keys: Vec<EventKey>,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub data: Vec<EventData>,
    }

    impl From<pathfinder_common::event::Event> for Event {
        fn from(e: pathfinder_common::event::Event) -> Self {
            Self {
                from_address: e.from_address,
                keys: e.keys,
                data: e.data,
            }
        }
    }

    /// Represents transaction status.
    #[derive(Copy, Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub enum TransactionStatus {
        #[serde(rename = "ACCEPTED_ON_L2")]
        AcceptedOnL2,
        #[serde(rename = "ACCEPTED_ON_L1")]
        AcceptedOnL1,
        #[serde(rename = "REJECTED")]
        Rejected,
    }

    impl From<BlockStatus> for TransactionStatus {
        fn from(status: BlockStatus) -> Self {
            match status {
                BlockStatus::Pending => TransactionStatus::AcceptedOnL2,
                BlockStatus::AcceptedOnL2 => TransactionStatus::AcceptedOnL2,
                BlockStatus::AcceptedOnL1 => TransactionStatus::AcceptedOnL1,
                BlockStatus::Rejected => TransactionStatus::Rejected,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // TODO: add serialization tests for each receipt variant..

    use super::*;
    use crate::v05::method::get_transaction_receipt::types::ExecutionResourcesProperties;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockNumber, EthereumAddress, Fee};
    use primitive_types::H160;
    use starknet_gateway_types::reply::transaction::{BuiltinCounters, ExecutionResources};

    mod parsing {
        use super::*;
        use serde_json::json;

        #[test]
        fn positional_args() {
            let positional = json!(["0xdeadbeef"]);

            let input = serde_json::from_value::<GetTransactionReceiptInput>(positional).unwrap();
            assert_eq!(
                input,
                GetTransactionReceiptInput {
                    transaction_hash: transaction_hash!("0xdeadbeef")
                }
            )
        }

        #[test]
        fn named_args() {
            let named_args = json!({
                "transaction_hash": "0xdeadbeef"
            });

            let input = serde_json::from_value::<GetTransactionReceiptInput>(named_args).unwrap();
            assert_eq!(
                input,
                GetTransactionReceiptInput {
                    transaction_hash: transaction_hash!("0xdeadbeef")
                }
            )
        }
    }

    mod errors {
        use super::*;

        #[tokio::test]
        async fn hash_not_found() {
            let context = RpcContext::for_tests();
            let input = GetTransactionReceiptInput {
                transaction_hash: transaction_hash_bytes!(b"non_existent"),
            };

            let result = get_transaction_receipt(context, input).await;

            assert_matches::assert_matches!(
                result,
                Err(GetTransactionReceiptError::TxnHashNotFoundV04)
            );
        }
    }

    #[tokio::test]
    async fn success() {
        let context = RpcContext::for_tests();
        let input = GetTransactionReceiptInput {
            transaction_hash: transaction_hash_bytes!(b"txn 0"),
        };

        let result = get_transaction_receipt(context, input).await.unwrap();
        use types::*;
        assert_eq!(
            result,
            MaybePendingTransactionReceipt::Normal(TransactionReceipt::Invoke(
                InvokeTransactionReceipt {
                    common: CommonTransactionReceiptProperties {
                        transaction_hash: transaction_hash_bytes!(b"txn 0"),
                        actual_fee: Fee::ZERO,
                        block_hash: block_hash_bytes!(b"genesis"),
                        block_number: BlockNumber::new_or_panic(0),
                        messages_sent: vec![],
                        events: vec![Event {
                            data: vec![event_data_bytes!(b"event 0 data")],
                            from_address: contract_address_bytes!(b"event 0 from addr"),
                            keys: vec![event_key_bytes!(b"event 0 key")],
                        }],
                        execution_status: ExecutionStatus::Succeeded,
                        finality_status: FinalityStatus::AcceptedOnL1,
                        revert_reason: None,
                        execution_resources: ExecutionResources::default().into(),
                    }
                }
            ))
        )
    }

    #[tokio::test]
    async fn success_v03() {
        let context = RpcContext::for_tests();
        let input = GetTransactionReceiptInput {
            transaction_hash: transaction_hash_bytes!(b"txn 6"),
        };

        let result = get_transaction_receipt(context, input).await.unwrap();
        use types::*;
        assert_eq!(
            result,
            MaybePendingTransactionReceipt::Normal(TransactionReceipt::Invoke(
                InvokeTransactionReceipt {
                    common: CommonTransactionReceiptProperties {
                        transaction_hash: transaction_hash_bytes!(b"txn 6"),
                        actual_fee: Fee::ZERO,
                        block_hash: block_hash_bytes!(b"latest"),
                        block_number: BlockNumber::new_or_panic(2),
                        messages_sent: vec![MessageToL1 {
                            from_address: contract_address!("0xcafebabe"),
                            to_address: EthereumAddress(H160::zero()),
                            payload: vec![
                                l2_to_l1_message_payload_elem!("0x1"),
                                l2_to_l1_message_payload_elem!("0x2"),
                                l2_to_l1_message_payload_elem!("0x3"),
                            ],
                        }],
                        events: vec![],
                        execution_status: ExecutionStatus::Succeeded,
                        finality_status: FinalityStatus::AcceptedOnL2,
                        revert_reason: None,
                        execution_resources: ExecutionResources::default().into(),
                    }
                }
            ))
        )
    }

    #[test]
    fn execution_resources_properties_into() {
        let original = ExecutionResources {
            builtin_instance_counter: BuiltinCounters {
                output_builtin: 0,
                pedersen_builtin: 1,
                range_check_builtin: 2,
                ecdsa_builtin: 3,
                bitwise_builtin: 4,
                ec_op_builtin: 5,
                keccak_builtin: 6,
                poseidon_builtin: 7,
                segment_arena_builtin: 8,
            },
            n_steps: 9,
            n_memory_holes: 10,
        };

        let into = ExecutionResourcesProperties::from(original);

        assert_eq!(into.steps, original.n_steps);
        assert_eq!(into.memory_holes, original.n_memory_holes);
        assert_eq!(
            into.range_check_builtin_applications,
            original.builtin_instance_counter.range_check_builtin
        );
        assert_eq!(
            into.pedersen_builtin_applications,
            original.builtin_instance_counter.pedersen_builtin
        );
        assert_eq!(
            into.poseidon_builtin_applications,
            original.builtin_instance_counter.poseidon_builtin
        );
        assert_eq!(
            into.ec_op_builtin_applications,
            original.builtin_instance_counter.ec_op_builtin
        );
        assert_eq!(
            into.ecdsa_builtin_applications,
            original.builtin_instance_counter.ecdsa_builtin
        );
        assert_eq!(
            into.bitwise_builtin_applications,
            original.builtin_instance_counter.bitwise_builtin
        );
        assert_eq!(
            into.keccak_builtin_applications,
            original.builtin_instance_counter.keccak_builtin
        );
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;
        let transaction_hash = transaction_hash_bytes!(b"pending tx hash 0");
        let input = GetTransactionReceiptInput { transaction_hash };

        let result = get_transaction_receipt(context, input).await.unwrap();
        use types::*;
        assert_eq!(
            result,
            MaybePendingTransactionReceipt::Pending(PendingTransactionReceipt::Invoke(
                PendingInvokeTransactionReceipt {
                    common: CommonPendingTransactionReceiptProperties {
                        transaction_hash,
                        actual_fee: Fee::ZERO,
                        messages_sent: vec![],
                        events: vec![
                            Event {
                                data: vec![],
                                from_address: contract_address!("0xabcddddddd"),
                                keys: vec![event_key_bytes!(b"pending key")],
                            },
                            Event {
                                data: vec![],
                                from_address: contract_address!("0xabcddddddd"),
                                keys: vec![event_key_bytes!(b"pending key")],
                            },
                            Event {
                                data: vec![],
                                from_address: contract_address!("0xabcaaaaaaa"),
                                keys: vec![event_key_bytes!(b"pending key 2")],
                            },
                        ],
                        revert_reason: None,
                        execution_status: ExecutionStatus::Succeeded,
                        execution_resources: ExecutionResources::default().into(),
                        finality_status: FinalityStatus::AcceptedOnL2
                    }
                }
            ))
        );
    }

    #[tokio::test]
    async fn reverted() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = GetTransactionReceiptInput {
            transaction_hash: transaction_hash_bytes!(b"txn reverted"),
        };
        // Should be a reverted invoke receipt.
        let receipt = get_transaction_receipt(context.clone(), input)
            .await
            .unwrap();

        let receipt = match receipt {
            types::MaybePendingTransactionReceipt::Normal(types::TransactionReceipt::Invoke(x)) => {
                x
            }
            _ => panic!(),
        };

        assert_eq!(
            receipt.common.execution_status,
            types::ExecutionStatus::Reverted
        );

        let input = GetTransactionReceiptInput {
            transaction_hash: transaction_hash_bytes!(b"pending reverted"),
        };

        // Should be a reverted pending invoke receipt.
        let receipt = get_transaction_receipt(context, input).await.unwrap();

        let receipt = match receipt {
            types::MaybePendingTransactionReceipt::Pending(
                types::PendingTransactionReceipt::Invoke(x),
            ) => x,
            _ => panic!(),
        };

        assert_eq!(
            receipt.common.execution_status,
            types::ExecutionStatus::Reverted
        );
    }

    #[tokio::test]
    async fn json_output() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = GetTransactionReceiptInput {
            transaction_hash: transaction_hash_bytes!(b"txn reverted"),
        };

        let receipt = get_transaction_receipt(context.clone(), input)
            .await
            .unwrap();

        let receipt = serde_json::to_value(receipt).unwrap();

        let expected = serde_json::json!({
            "transaction_hash": transaction_hash_bytes!(b"txn reverted"),
            "actual_fee": "0x0",
            "execution_resources": {
                "bitwise_builtin_applications": "0x0",
                "ec_op_builtin_applications": "0x0",
                "ecdsa_builtin_applications": "0x0",
                "keccak_builtin_applications": "0x0",
                "memory_holes": "0x0",
                "steps": "0x0",
                "pedersen_builtin_applications": "0x0",
                "poseidon_builtin_applications": "0x0",
                "range_check_builtin_applications": "0x0",
            },
            "execution_status": "REVERTED",
            "finality_status": "ACCEPTED_ON_L2",
            "block_hash": block_hash_bytes!(b"latest"),
            "block_number": 2,
            "messages_sent": [],
            "revert_reason": "Reverted because",
            "events": [],
            "type": "INVOKE",
        });

        assert_eq!(receipt, expected);
    }
}
