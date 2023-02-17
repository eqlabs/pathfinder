use crate::v02::common::get_block_status;
use crate::v02::RpcContext;
use anyhow::Context;
use pathfinder_common::StarknetTransactionHash;
use pathfinder_storage::{StarknetBlocksTable, StarknetTransactionsTable};

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetTransactionReceiptInput {
    transaction_hash: StarknetTransactionHash,
}

crate::error::generate_rpc_error_subset!(GetTransactionReceiptError: TxnHashNotFound);

pub async fn get_transaction_receipt(
    context: RpcContext,
    input: GetTransactionReceiptInput,
) -> Result<types::MaybePendingTransactionReceipt, GetTransactionReceiptError> {
    // First check pending data as this is in-mem and should be faster.
    if let Some(pending) = &context.pending_data {
        let receipt_transaction = pending.block().await.and_then(|block| {
            block
                .transaction_receipts
                .iter()
                .zip(block.transactions.iter())
                .find_map(|(receipt, tx)| {
                    (receipt.transaction_hash == input.transaction_hash)
                        .then(|| (receipt.clone(), tx.clone()))
                })
        });

        if let Some((receipt, transaction)) = receipt_transaction {
            return Ok(types::MaybePendingTransactionReceipt::Pending(
                types::PendingTransactionReceipt::from(receipt, &transaction),
            ));
        };
    }

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let db_tx = db.transaction().context("Creating database transaction")?;

        match StarknetTransactionsTable::get_transaction_with_receipt(
            &db_tx,
            input.transaction_hash,
        )
        .context("Reading transaction receipt from database")?
        {
            Some((transaction, receipt, block_hash)) => {
                // We require the block status here as well..
                let block_number = StarknetBlocksTable::get_number(&db_tx, block_hash)
                    .context("Reading block from database")?
                    .context("Block missing from database")?;
                let block_status = get_block_status(&db_tx, block_number)?;

                Ok(types::MaybePendingTransactionReceipt::Normal(
                    types::TransactionReceipt::with_block_data(
                        receipt,
                        block_status,
                        block_hash,
                        block_number,
                        transaction,
                    ),
                ))
            }
            None => Err(GetTransactionReceiptError::TxnHashNotFound),
        }
    });

    jh.await.context("Database read panic or shutting down")?
}

mod types {
    use crate::felt::{RpcFelt, RpcFelt251};
    use crate::v02::types::reply::BlockStatus;
    use pathfinder_common::{
        ContractAddress, EthereumAddress, EventData, EventKey, Fee, L1ToL2MessagePayloadElem,
        L2ToL1MessagePayloadElem, StarknetBlockHash, StarknetBlockNumber, StarknetTransactionHash,
    };
    use pathfinder_serde::{EthereumAddressAsHexStr, FeeAsHexStr};
    use serde::Serialize;
    use serde_with::serde_as;
    use starknet_gateway_types::reply::transaction::{L1ToL2Message, L2ToL1Message};

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
        pub transaction_hash: StarknetTransactionHash,
        #[serde_as(as = "FeeAsHexStr")]
        pub actual_fee: Fee,
        pub status: TransactionStatus,
        #[serde_as(as = "RpcFelt")]
        pub block_hash: StarknetBlockHash,
        pub block_number: StarknetBlockNumber,
        pub messages_sent: Vec<MessageToL1>,
        pub events: Vec<Event>,
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct L1HandlerTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonTransactionReceiptProperties,
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
            status: BlockStatus,
            block_hash: StarknetBlockHash,
            block_number: StarknetBlockNumber,
            transaction: starknet_gateway_types::reply::transaction::Transaction,
        ) -> Self {
            let common = CommonTransactionReceiptProperties {
                transaction_hash: receipt.transaction_hash,
                actual_fee: receipt
                    .actual_fee
                    .unwrap_or_else(|| Fee(Default::default())),
                status: status.into(),
                block_hash,
                block_number,
                messages_sent: receipt
                    .l2_to_l1_messages
                    .into_iter()
                    .map(MessageToL1::from)
                    .collect(),
                events: receipt.events.into_iter().map(Event::from).collect(),
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
                L1Handler(_) => Self::L1Handler(L1HandlerTransactionReceipt { common }),
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
    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct CommonPendingTransactionReceiptProperties {
        pub transaction_hash: StarknetTransactionHash,
        #[serde_as(as = "FeeAsHexStr")]
        pub actual_fee: Fee,
        pub messages_sent: Vec<MessageToL1>,
        pub events: Vec<Event>,
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

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct PendingL1HandlerTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonPendingTransactionReceiptProperties,
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
                L1Handler(_) => Self::L1Handler(PendingL1HandlerTransactionReceipt { common }),
            }
        }
    }

    /// Message sent from L2 to L1.
    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct MessageToL1 {
        #[serde_as(as = "EthereumAddressAsHexStr")]
        pub to_address: EthereumAddress,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub payload: Vec<L2ToL1MessagePayloadElem>,
    }

    impl From<L2ToL1Message> for MessageToL1 {
        fn from(msg: L2ToL1Message) -> Self {
            Self {
                to_address: msg.to_address,
                payload: msg.payload,
            }
        }
    }

    /// Message sent from L1 to L2.
    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct MessageToL2 {
        #[serde_as(as = "EthereumAddressAsHexStr")]
        pub from_address: EthereumAddress,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub payload: Vec<L1ToL2MessagePayloadElem>,
    }

    impl From<L1ToL2Message> for MessageToL2 {
        fn from(msg: L1ToL2Message) -> Self {
            Self {
                from_address: msg.from_address,
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

    impl From<starknet_gateway_types::reply::transaction::Event> for Event {
        fn from(e: starknet_gateway_types::reply::transaction::Event) -> Self {
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
        #[serde(rename = "PENDING")]
        Pending,
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
                BlockStatus::Pending => TransactionStatus::Pending,
                BlockStatus::AcceptedOnL2 => TransactionStatus::AcceptedOnL2,
                BlockStatus::AcceptedOnL1 => TransactionStatus::AcceptedOnL1,
                BlockStatus::Rejected => TransactionStatus::Rejected,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use pathfinder_common::{
            felt, EthereumAddress, EventData, EventKey, L2ToL1MessagePayloadElem,
        };

        #[test]
        fn receipt() {
            impl CommonTransactionReceiptProperties {
                pub fn test_data() -> Self {
                    Self {
                        transaction_hash: StarknetTransactionHash(felt!("0xdeadbeef")),
                        actual_fee: Fee(ethers::types::H128::from_low_u64_be(0x1)),
                        status: TransactionStatus::AcceptedOnL1,
                        block_hash: StarknetBlockHash(felt!("0xaaa")),
                        block_number: StarknetBlockNumber::new_or_panic(3),
                        messages_sent: vec![MessageToL1 {
                            to_address: EthereumAddress(ethers::types::H160::from_low_u64_be(0x55)),
                            payload: vec![L2ToL1MessagePayloadElem(felt!("0x6"))],
                        }],
                        events: vec![Event {
                            from_address: ContractAddress::new_or_panic(felt!("0xe6")),
                            keys: vec![EventKey(felt!("0xe7"))],
                            data: vec![EventData(felt!("0xe8"))],
                        }],
                    }
                }
            }

            impl CommonPendingTransactionReceiptProperties {
                pub fn test_data() -> Self {
                    Self {
                        transaction_hash: StarknetTransactionHash(felt!("0xfeedfeed")),
                        actual_fee: Fee(ethers::types::H128::from_low_u64_be(0x2)),
                        messages_sent: vec![MessageToL1 {
                            to_address: EthereumAddress(ethers::types::H160::from_low_u64_be(0x5)),
                            payload: vec![L2ToL1MessagePayloadElem(felt!("0x6"))],
                        }],
                        events: vec![Event {
                            from_address: ContractAddress::new_or_panic(felt!("0xa6")),
                            keys: vec![EventKey(felt!("0xa7"))],
                            data: vec![EventData(felt!("0xa8"))],
                        }],
                    }
                }
            }

            use MaybePendingTransactionReceipt::*;
            let data = vec![
                // All fields populated
                Normal(TransactionReceipt::Invoke(InvokeTransactionReceipt {
                    common: CommonTransactionReceiptProperties::test_data(),
                })),
                // All optional are None
                Normal(TransactionReceipt::Invoke(InvokeTransactionReceipt {
                    common: CommonTransactionReceiptProperties {
                        messages_sent: vec![],
                        events: vec![],
                        ..CommonTransactionReceiptProperties::test_data()
                    },
                })),
                // Somewhat redundant, but want to exhaust the variants
                Normal(TransactionReceipt::Declare(DeclareTransactionReceipt {
                    common: CommonTransactionReceiptProperties {
                        transaction_hash: StarknetTransactionHash(felt!("0xdeaf01")),
                        ..CommonTransactionReceiptProperties::test_data()
                    },
                })),
                Normal(TransactionReceipt::L1Handler(L1HandlerTransactionReceipt {
                    common: CommonTransactionReceiptProperties {
                        transaction_hash: StarknetTransactionHash(felt!("0xdeaf02")),
                        ..CommonTransactionReceiptProperties::test_data()
                    },
                })),
                Normal(TransactionReceipt::Deploy(DeployTransactionReceipt {
                    common: CommonTransactionReceiptProperties {
                        transaction_hash: StarknetTransactionHash(felt!("0xdeaf03")),
                        ..CommonTransactionReceiptProperties::test_data()
                    },
                    contract_address: ContractAddress::new_or_panic(felt!("0xcc")),
                })),
                Pending(PendingTransactionReceipt::Invoke(
                    PendingInvokeTransactionReceipt {
                        common: CommonPendingTransactionReceiptProperties {
                            transaction_hash: StarknetTransactionHash(felt!("0xdeaf11")),
                            ..CommonPendingTransactionReceiptProperties::test_data()
                        },
                    },
                )),
                Pending(PendingTransactionReceipt::Declare(
                    PendingDeclareTransactionReceipt {
                        common: CommonPendingTransactionReceiptProperties {
                            transaction_hash: StarknetTransactionHash(felt!("0xdeaf12")),
                            ..CommonPendingTransactionReceiptProperties::test_data()
                        },
                    },
                )),
                Pending(PendingTransactionReceipt::L1Handler(
                    PendingL1HandlerTransactionReceipt {
                        common: CommonPendingTransactionReceiptProperties {
                            transaction_hash: StarknetTransactionHash(felt!("0xdeaf13")),
                            ..CommonPendingTransactionReceiptProperties::test_data()
                        },
                    },
                )),
                Pending(PendingTransactionReceipt::Deploy(
                    PendingDeployTransactionReceipt {
                        common: CommonPendingTransactionReceiptProperties {
                            transaction_hash: StarknetTransactionHash(felt!("0xdeaf14")),
                            ..CommonPendingTransactionReceiptProperties::test_data()
                        },
                        contract_address: ContractAddress::new_or_panic(felt!("0xdd")),
                    },
                )),
            ];

            let fixture =
                include_str!("../../../fixtures/0.44.0/receipt.json").replace([' ', '\n'], "");

            assert_eq!(serde_json::to_string(&data).unwrap(), fixture);
            assert_eq!(
                serde_json::from_str::<Vec<MaybePendingTransactionReceipt>>(&fixture).unwrap(),
                data
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::{
        felt, felt_bytes, ContractAddress, EventData, EventKey, Fee, StarknetBlockHash,
        StarknetBlockNumber, StarknetTransactionHash,
    };

    mod parsing {
        use super::*;

        use jsonrpsee::types::Params;

        #[test]
        fn positional_args() {
            let positional = r#"[
                "0xdeadbeef"
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<GetTransactionReceiptInput>().unwrap();
            assert_eq!(
                input,
                GetTransactionReceiptInput {
                    transaction_hash: StarknetTransactionHash(felt!("0xdeadbeef"))
                }
            )
        }

        #[test]
        fn named_args() {
            let named_args = r#"{
                "transaction_hash": "0xdeadbeef"
            }"#;
            let named_args = Params::new(Some(named_args));

            let input = named_args.parse::<GetTransactionReceiptInput>().unwrap();
            assert_eq!(
                input,
                GetTransactionReceiptInput {
                    transaction_hash: StarknetTransactionHash(felt!("0xdeadbeef"))
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
                transaction_hash: StarknetTransactionHash(felt_bytes!(b"non_existent")),
            };

            let result = get_transaction_receipt(context, input).await;

            assert_matches::assert_matches!(
                result,
                Err(GetTransactionReceiptError::TxnHashNotFound)
            );
        }
    }

    #[tokio::test]
    async fn success() {
        let context = RpcContext::for_tests();
        let input = GetTransactionReceiptInput {
            transaction_hash: StarknetTransactionHash(felt_bytes!(b"txn 0")),
        };

        let result = get_transaction_receipt(context, input).await.unwrap();
        use types::*;
        assert_eq!(
            result,
            MaybePendingTransactionReceipt::Normal(TransactionReceipt::Invoke(
                InvokeTransactionReceipt {
                    common: CommonTransactionReceiptProperties {
                        transaction_hash: StarknetTransactionHash(felt_bytes!(b"txn 0")),
                        actual_fee: Fee(ethers::types::H128::zero()),
                        status: TransactionStatus::AcceptedOnL2,
                        block_hash: StarknetBlockHash(felt_bytes!(b"genesis")),
                        block_number: StarknetBlockNumber::new_or_panic(0),
                        messages_sent: vec![],
                        events: vec![Event {
                            data: vec![EventData(felt_bytes!(b"event 0 data"))],
                            from_address: ContractAddress::new_or_panic(felt_bytes!(
                                b"event 0 from addr"
                            )),
                            keys: vec![EventKey(felt_bytes!(b"event 0 key"))],
                        }],
                    }
                }
            ))
        )
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;
        let transaction_hash = StarknetTransactionHash(felt_bytes!(b"pending tx hash 0"));
        let input = GetTransactionReceiptInput { transaction_hash };

        let result = get_transaction_receipt(context, input).await.unwrap();
        use types::*;
        assert_eq!(
            result,
            MaybePendingTransactionReceipt::Pending(PendingTransactionReceipt::Invoke(
                PendingInvokeTransactionReceipt {
                    common: CommonPendingTransactionReceiptProperties {
                        transaction_hash,
                        actual_fee: Fee(ethers::types::H128::zero()),
                        messages_sent: vec![],
                        events: vec![
                            Event {
                                data: vec![],
                                from_address: ContractAddress::new_or_panic(felt!("0xabcddddddd")),
                                keys: vec![EventKey(felt_bytes!(b"pending key"))],
                            },
                            Event {
                                data: vec![],
                                from_address: ContractAddress::new_or_panic(felt!("0xabcddddddd")),
                                keys: vec![EventKey(felt_bytes!(b"pending key"))],
                            },
                            Event {
                                data: vec![],
                                from_address: ContractAddress::new_or_panic(felt!("0xabcaaaaaaa")),
                                keys: vec![EventKey(felt_bytes!(b"pending key 2"))],
                            },
                        ],
                    }
                }
            ))
        );
    }
}
