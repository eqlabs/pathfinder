use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::BlockId;
use starknet_gateway_types::reply::PendingBlock;

use crate::context::RpcContext;

pub enum Output {
    Full {
        header: Box<pathfinder_common::BlockHeader>,
        body: Vec<(
            pathfinder_common::transaction::Transaction,
            pathfinder_common::receipt::Receipt,
            Vec<pathfinder_common::event::Event>,
        )>,
        is_l1_accepted: bool,
    },
    Pending(Arc<PendingBlock>),
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub block_id: BlockId,
}

crate::error::generate_rpc_error_subset!(Error: BlockNotFound);

pub async fn get_block_with_receipts(context: RpcContext, input: Input) -> Result<Output, Error> {
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Creating database connection")?;

        let db = db.transaction().context("Creating database transaction")?;

        let block_id = match input.block_id {
            BlockId::Pending => {
                let pending = context
                    .pending_data
                    .get(&db)
                    .context("Querying pending data")?;

                return Ok(Output::Pending(pending.block));
            }
            other => other.try_into().expect("Only pending cast should fail"),
        };

        let header = db
            .block_header(block_id)
            .context("Fetching block header")?
            .ok_or(Error::BlockNotFound)?;

        let body = db
            .transaction_data_for_block(block_id)
            .context("Fetching transaction data")?
            .context("Transaction data missing")?;

        let is_l1_accepted = db
            .block_is_l1_accepted(block_id)
            .context("Fetching block finality")?;

        Ok(Output::Full {
            header: header.into(),
            body,
            is_l1_accepted,
        })
    })
    .await
    .context("Joining blocking task")?
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        match self {
            Output::Full {
                header,
                body,
                is_l1_accepted,
            } => {
                let finality = if *is_l1_accepted {
                    crate::dto::TxnFinalityStatus::AcceptedOnL1
                } else {
                    crate::dto::TxnFinalityStatus::AcceptedOnL2
                };
                serializer.serialize_field(
                    "status",
                    &if *is_l1_accepted {
                        "ACCEPTED_ON_L1"
                    } else {
                        "ACCEPTED_ON_L2"
                    },
                )?;
                serializer.flatten(&crate::dto::BlockHeader(header))?;
                serializer.serialize_iter(
                    "transactions",
                    body.len(),
                    &mut body
                        .iter()
                        .map(|(transaction, receipt, events)| TransactionWithReceipt {
                            transaction,
                            receipt,
                            events,
                            finality,
                        }),
                )?;
            }
            Output::Pending(block) => {
                serializer.flatten(&crate::dto::PendingBlockHeader(block))?;
                serializer.serialize_iter(
                    "transactions",
                    block.transactions.len(),
                    &mut block
                        .transactions
                        .iter()
                        .zip(block.transaction_receipts.iter())
                        .map(|(transaction, (receipt, events))| TransactionWithReceipt {
                            transaction,
                            receipt,
                            events,
                            finality: crate::dto::TxnFinalityStatus::AcceptedOnL2,
                        }),
                )?;
            }
        }
        serializer.end()
    }
}

struct TransactionWithReceipt<'a> {
    pub transaction: &'a pathfinder_common::transaction::Transaction,
    pub receipt: &'a pathfinder_common::receipt::Receipt,
    pub events: &'a [pathfinder_common::event::Event],
    pub finality: crate::dto::TxnFinalityStatus,
}

impl crate::dto::serialize::SerializeForVersion for TransactionWithReceipt<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("transaction", &crate::dto::Transaction(self.transaction))?;
        serializer.serialize_field(
            "receipt",
            &crate::dto::TxnReceipt {
                receipt: self.receipt,
                transaction: self.transaction,
                events: self.events,
                finality: self.finality,
            },
        )?;
        serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions_sorted::assert_eq;

    use super::*;
    use crate::dto::serialize::{SerializeForVersion, Serializer};
    use crate::RpcVersion;

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = Input {
            block_id: BlockId::Pending,
        };

        let output = get_block_with_receipts(context.clone(), input)
            .await
            .unwrap()
            .serialize(Serializer {
                version: RpcVersion::V07,
            })
            .unwrap();

        let expected = serde_json::json!({
            "l1_da_mode": "CALLDATA",
            "l1_data_gas_price": {
                "price_in_fri": "0x7374726b206461746761737072696365",
                "price_in_wei": "0x6461746761737072696365",
            },
            "l1_gas_price": {
                "price_in_fri": "0x7374726b20676173207072696365",
                "price_in_wei": "0x676173207072696365",
            },
            "parent_hash": "0x6c6174657374",
            "sequencer_address": "0x70656e64696e672073657175656e6365722061646472657373",
            "starknet_version": "0.11.0",
            "timestamp": 1234567,
            "transactions": [
                {
                    "receipt": {
                        "actual_fee": {
                            "amount": "0x0",
                            "unit": "WEI",
                        },
                        "events": [
                            {
                                "data": [],
                                "from_address": "0xabcddddddd",
                                "keys": [
                                    "0x70656e64696e67206b6579",
                                ],
                            },
                            {
                                "data": [],
                                "from_address": "0xabcddddddd",
                                "keys": [
                                    "0x70656e64696e67206b6579",
                                    "0x7365636f6e642070656e64696e67206b6579",
                                ],
                            },
                            {
                                "data": [],
                                "from_address": "0xabcaaaaaaa",
                                "keys": [
                                    "0x70656e64696e67206b65792032",
                                ],
                            },
                        ],
                        "execution_resources": {
                            "data_availability": {
                                "l1_data_gas": 0,
                                "l1_gas": 0
                            },
                            "steps": 0
                        },
                        "execution_status": "SUCCEEDED",
                        "finality_status": "ACCEPTED_ON_L2",
                        "messages_sent": [],
                        "transaction_hash": "0x70656e64696e6720747820686173682030",
                        "type": "INVOKE",
                    },
                    "transaction": {
                        "calldata": [],
                        "contract_address": "0x70656e64696e6720636f6e747261637420616464722030",
                        "entry_point_selector": "0x656e74727920706f696e742030",
                        "max_fee": "0x0",
                        "signature": [],
                        "transaction_hash": "0x70656e64696e6720747820686173682030",
                        "type": "INVOKE",
                        "version": "0x0",
                    },
                },
                {
                    "receipt": {
                        "actual_fee": {
                            "amount": "0x0",
                            "unit": "WEI",
                        },
                        "contract_address": "0x1122355",
                        "events": [],
                        "execution_resources": {
                            "data_availability": {
                                "l1_data_gas": 0,
                                "l1_gas": 0
                            },
                            "steps": 0
                        },
                        "execution_status": "SUCCEEDED",
                        "finality_status": "ACCEPTED_ON_L2",
                        "messages_sent": [],
                        "transaction_hash": "0x70656e64696e6720747820686173682031",
                        "type": "DEPLOY",
                    },
                    "transaction": {
                        "class_hash": "0x70656e64696e6720636c61737320686173682031",
                        "constructor_calldata": [],
                        "contract_address_salt": "0x73616c7479",
                        "transaction_hash": "0x70656e64696e6720747820686173682031",
                        "type": "DEPLOY",
                        "version": "0x0",
                    },
                },
                {
                    "receipt": {
                        "actual_fee": {
                            "amount": "0x0",
                            "unit": "WEI",
                        },
                        "events": [],
                        "execution_resources": {
                            "data_availability": {
                                "l1_data_gas": 0,
                                "l1_gas": 0
                            },
                            "steps": 0
                        },
                        "execution_status": "REVERTED",
                        "finality_status": "ACCEPTED_ON_L2",
                        "messages_sent": [],
                        "revert_reason": "Reverted!",
                        "transaction_hash": "0x70656e64696e67207265766572746564",
                        "type": "INVOKE",
                    },
                    "transaction": {
                        "calldata": [],
                        "contract_address": "0x70656e64696e6720636f6e747261637420616464722030",
                        "entry_point_selector": "0x656e74727920706f696e742030",
                        "max_fee": "0x0",
                        "signature": [],
                        "transaction_hash": "0x70656e64696e67207265766572746564",
                        "type": "INVOKE",
                        "version": "0x0",
                    },
                },
            ],
        });

        assert_eq!(output, expected);
    }

    #[tokio::test]
    async fn latest() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = Input {
            block_id: BlockId::Latest,
        };

        let output = get_block_with_receipts(context.clone(), input)
            .await
            .unwrap()
            .serialize(Serializer {
                version: RpcVersion::V07,
            })
            .unwrap();

        let expected = serde_json::json!({
            "block_hash": "0x6c6174657374",
            "block_number": 2,
            "l1_da_mode": "CALLDATA",
            "l1_data_gas_price": {
                "price_in_fri": "0x0",
                "price_in_wei": "0x0",
            },
            "l1_gas_price": {
                "price_in_fri": "0x0",
                "price_in_wei": "0x2",
            },
            "new_root": "0x57b695c82af81429fdc8966088b0196105dfb5aa22b54cbc86fc95dc3b3ece1",
            "parent_hash": "0x626c6f636b2031",
            "sequencer_address": "0x2",
            "starknet_version": "",
            "status": "ACCEPTED_ON_L2",
            "timestamp": 2,
            "transactions": [
                {
                    "receipt": {
                        "actual_fee": {
                            "amount": "0x0",
                            "unit": "WEI",
                        },
                        "events": [],
                        "execution_resources": {
                            "data_availability": {
                                "l1_data_gas": 0,
                                "l1_gas": 0,
                            },
                            "memory_holes": 5,
                            "pedersen_builtin_applications": 32,
                            "steps": 10,
                        },
                        "execution_status": "SUCCEEDED",
                        "finality_status": "ACCEPTED_ON_L2",
                        "messages_sent": [],
                        "transaction_hash": "0x74786e2033",
                        "type": "INVOKE",
                    },
                    "transaction": {
                        "calldata": [],
                        "contract_address": "0x636f6e74726163742031",
                        "entry_point_selector": "0x0",
                        "max_fee": "0x0",
                        "signature": [],
                        "transaction_hash": "0x74786e2033",
                        "type": "INVOKE",
                        "version": "0x0",
                    },
                },
                {
                    "receipt": {
                        "actual_fee": {
                            "amount": "0x0",
                            "unit": "WEI",
                        },
                        "events": [],
                        "execution_resources": {
                            "data_availability": {
                                "l1_data_gas": 0,
                                "l1_gas": 0,
                            },
                            "memory_holes": 5,
                            "pedersen_builtin_applications": 32,
                            "steps": 10,
                        },
                        "execution_status": "SUCCEEDED",
                        "finality_status": "ACCEPTED_ON_L2",
                        "messages_sent": [],
                        "transaction_hash": "0x74786e2034",
                        "type": "INVOKE",
                    },
                    "transaction": {
                        "calldata": [],
                        "contract_address": "0x0",
                        "entry_point_selector": "0x0",
                        "max_fee": "0x0",
                        "signature": [],
                        "transaction_hash": "0x74786e2034",
                        "type": "INVOKE",
                        "version": "0x0",
                    },
                },
                {
                    "receipt": {
                        "actual_fee": {
                            "amount": "0x0",
                            "unit": "WEI",
                        },
                        "events": [],
                        "execution_resources": {
                            "data_availability": {
                                "l1_data_gas": 0,
                                "l1_gas": 0,
                            },
                            "memory_holes": 5,
                            "pedersen_builtin_applications": 32,
                            "steps": 10,
                        },
                        "execution_status": "SUCCEEDED",
                        "finality_status": "ACCEPTED_ON_L2",
                        "messages_sent": [],
                        "transaction_hash": "0x74786e2035",
                        "type": "INVOKE",
                    },
                    "transaction": {
                        "calldata": [],
                        "contract_address": "0x636f6e74726163742031",
                        "entry_point_selector": "0x0",
                        "max_fee": "0x0",
                        "signature": [],
                        "transaction_hash": "0x74786e2035",
                        "type": "INVOKE",
                        "version": "0x0",
                    },
                },
                {
                    "receipt": {
                        "actual_fee": {
                            "amount": "0x0",
                            "unit": "WEI",
                        },
                        "events": [],
                        "execution_resources": {
                            "data_availability": {
                                "l1_data_gas": 0,
                                "l1_gas": 0,
                            },
                            "memory_holes": 5,
                            "pedersen_builtin_applications": 32,
                            "steps": 10,
                        },
                        "execution_status": "SUCCEEDED",
                        "finality_status": "ACCEPTED_ON_L2",
                        "messages_sent": [
                            {
                                "from_address": "0xcafebabe",
                                "payload": [
                                    "0x1",
                                    "0x2",
                                    "0x3",
                                ],
                                "to_address": "0x0",
                            },
                        ],
                        "transaction_hash": "0x74786e2036",
                        "type": "INVOKE",
                    },
                    "transaction": {
                        "calldata": [],
                        "contract_address": "0x636f6e74726163742031",
                        "entry_point_selector": "0x0",
                        "max_fee": "0x0",
                        "signature": [],
                        "transaction_hash": "0x74786e2036",
                        "type": "INVOKE",
                        "version": "0x0",
                    },
                },
                {
                    "receipt": {
                        "actual_fee": {
                            "amount": "0x0",
                            "unit": "WEI",
                        },
                        "events": [],
                        "execution_resources": {
                            "data_availability": {
                                "l1_data_gas": 0,
                                "l1_gas": 0,
                            },
                            "memory_holes": 5,
                            "pedersen_builtin_applications": 32,
                            "steps": 10,
                        },
                        "execution_status": "REVERTED",
                        "finality_status": "ACCEPTED_ON_L2",
                        "messages_sent": [],
                        "revert_reason": "Reverted because",
                        "transaction_hash": "0x74786e207265766572746564",
                        "type": "INVOKE",
                    },
                    "transaction": {
                        "calldata": [],
                        "contract_address": "0x636f6e74726163742031",
                        "entry_point_selector": "0x0",
                        "max_fee": "0x0",
                        "signature": [],
                        "transaction_hash": "0x74786e207265766572746564",
                        "type": "INVOKE",
                        "version": "0x0",
                    },
                },
            ],
        });
        assert_eq!(output, expected);
    }
}
