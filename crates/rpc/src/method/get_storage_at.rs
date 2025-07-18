use anyhow::Context;
use pathfinder_common::{ContractAddress, StorageAddress, StorageValue};

use crate::context::RpcContext;
use crate::types::BlockId;
use crate::RpcVersion;

#[derive(Debug, PartialEq, Eq)]
pub struct Input {
    pub contract_address: ContractAddress,
    pub key: StorageAddress,
    pub block_id: BlockId,
}

impl crate::dto::DeserializeForVersion for Input {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                contract_address: value.deserialize("contract_address").map(ContractAddress)?,
                key: value.deserialize("key").map(StorageAddress)?,
                block_id: value.deserialize("block_id")?,
            })
        })
    }
}

#[derive(Debug)]
pub struct Output(StorageValue);

crate::error::generate_rpc_error_subset!(Error: ContractNotFound, BlockNotFound);

/// Get the value of the storage at the given address and key.
pub async fn get_storage_at(
    context: RpcContext,
    input: Input,
    rpc_version: RpcVersion,
) -> Result<Output, Error> {
    let span = tracing::Span::current();
    let jh = util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        if input.block_id.is_pending() {
            if let Some(value) = context
                .pending_data
                .get(&tx, rpc_version)
                .context("Querying pending data")?
                .state_update()
                .storage_value(input.contract_address, input.key)
            {
                return Ok(Output(value));
            }
        }

        let block_id = input
            .block_id
            .to_common_coerced(&tx)
            .map_err(|_| Error::BlockNotFound)?;
        if !tx.block_exists(block_id)? {
            return Err(Error::BlockNotFound);
        }

        let value = tx
            .storage_value(block_id, input.contract_address, input.key)
            .context("Querying storage value")?;

        match value {
            Some(value) => Ok(Output(value)),
            None => {
                if tx.contract_exists(input.contract_address, block_id)? {
                    Ok(Output(StorageValue::ZERO))
                } else {
                    Err(Error::ContractNotFound)
                }
            }
        }
    });

    jh.await.context("Database read panic or shutting down")?
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::BlockNumber;
    use serde_json::json;

    use super::*;
    use crate::dto::DeserializeForVersion;
    use crate::RpcVersion;

    /// # Important
    ///
    /// `BlockId` parsing is tested in
    /// [`get_block`][crate::rpc::method::get_block::tests::parsing]
    /// and is not repeated here.
    #[rstest::rstest]
    #[case::positional(json!(["1", "2", "latest"]))]
    #[case::named(json!({"contract_address": "0x1", "key": "0x2", "block_id": "latest"}))]
    fn parsing(#[case] input: serde_json::Value) {
        let expected = Input {
            contract_address: contract_address!("0x1"),
            key: storage_address!("0x2"),
            block_id: BlockId::Latest,
        };

        let input = Input::deserialize(crate::dto::Value::new(input, RpcVersion::V07)).unwrap();

        assert_eq!(input, expected);
    }

    const RPC_VERSION: RpcVersion = RpcVersion::V09;

    #[tokio::test]
    async fn pending() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let contract_address = contract_address_bytes!(b"pending contract 1 address");
        let key = storage_address_bytes!(b"pending storage key 0");
        let block_id = BlockId::Pending;

        let result = get_storage_at(
            ctx,
            Input {
                contract_address,
                key,
                block_id,
            },
            RPC_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(result.0, storage_value_bytes!(b"pending storage value 0"));
    }

    #[tokio::test]
    async fn pending_falls_back_to_latest() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let contract_address = contract_address_bytes!(b"contract 1");
        let key = storage_address_bytes!(b"storage addr 0");
        let block_id = BlockId::Pending;

        let result = get_storage_at(
            ctx,
            Input {
                contract_address,
                key,
                block_id,
            },
            RPC_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(result.0, storage_value_bytes!(b"storage value 2"));
    }

    #[tokio::test]
    async fn pending_deployed_defaults_to_zero() {
        let ctx = RpcContext::for_tests_with_pending().await;
        // Contract is deployed in pending block, but has no storage values set.
        let contract_address = contract_address_bytes!(b"pending contract 0 address");
        let key = storage_address_bytes!(b"non-existent");
        let block_id = BlockId::Pending;

        let result = get_storage_at(
            ctx,
            Input {
                contract_address,
                key,
                block_id,
            },
            RPC_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(result.0, StorageValue::ZERO);
    }

    #[tokio::test]
    async fn latest() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let contract_address = contract_address_bytes!(b"contract 1");
        let key = storage_address_bytes!(b"storage addr 0");
        let block_id = BlockId::Latest;

        let result = get_storage_at(
            ctx,
            Input {
                contract_address,
                key,
                block_id,
            },
            RPC_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(result.0, storage_value_bytes!(b"storage value 2"));
    }

    #[tokio::test]
    async fn l1_accepted() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let contract_address = contract_address_bytes!(b"contract 1");
        let key = storage_address_bytes!(b"storage addr 0");
        let block_id = BlockId::L1Accepted;

        let result = get_storage_at(
            ctx,
            Input {
                contract_address,
                key,
                block_id,
            },
            RPC_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(result.0, storage_value_bytes!(b"storage value 1"));
    }

    #[tokio::test]
    async fn defaults_to_zero() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let contract_address = contract_address_bytes!(b"contract 1");
        let key = storage_address_bytes!(b"non-existent");
        let block_id = BlockId::Latest;

        let result = get_storage_at(
            ctx,
            Input {
                contract_address,
                key,
                block_id,
            },
            RPC_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(result.0, StorageValue::ZERO);
    }

    #[tokio::test]
    async fn by_hash() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let contract_address = contract_address_bytes!(b"contract 1");
        let key = storage_address_bytes!(b"storage addr 0");
        let block_id = BlockId::Hash(block_hash_bytes!(b"block 1"));

        let result = get_storage_at(
            ctx,
            Input {
                contract_address,
                key,
                block_id,
            },
            RPC_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(result.0, storage_value_bytes!(b"storage value 1"));
    }

    #[tokio::test]
    async fn by_number() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let contract_address = contract_address_bytes!(b"contract 1");
        let key = storage_address_bytes!(b"storage addr 0");
        let block_id = BlockId::Number(BlockNumber::GENESIS + 1);

        let result = get_storage_at(
            ctx,
            Input {
                contract_address,
                key,
                block_id,
            },
            RPC_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(result.0, storage_value_bytes!(b"storage value 1"));
    }

    #[tokio::test]
    async fn unknown_contract() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let contract_address = contract_address_bytes!(b"non-existent");
        let key = storage_address_bytes!(b"storage addr 0");
        let block_id = BlockId::Latest;

        let result = get_storage_at(
            ctx,
            Input {
                contract_address,
                key,
                block_id,
            },
            RPC_VERSION,
        )
        .await;

        assert_matches!(result, Err(Error::ContractNotFound));
    }

    #[tokio::test]
    async fn contract_is_unknown_before_deployment() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let contract_address = contract_address_bytes!(b"contract 1");
        let key = storage_address_bytes!(b"storage addr 0");
        let block_id = BlockId::Hash(block_hash_bytes!(b"genesis"));

        let result = get_storage_at(
            ctx,
            Input {
                contract_address,
                key,
                block_id,
            },
            RPC_VERSION,
        )
        .await;

        assert_matches!(result, Err(Error::ContractNotFound));
    }

    #[tokio::test]
    async fn block_not_found_by_number() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let contract_address = contract_address_bytes!(b"contract 1");
        let key = storage_address_bytes!(b"storage addr 0");
        let block_id = BlockId::Number(BlockNumber::MAX);

        let result = get_storage_at(
            ctx,
            Input {
                contract_address,
                key,
                block_id,
            },
            RPC_VERSION,
        )
        .await;

        assert_matches!(result, Err(Error::BlockNotFound));
    }

    #[tokio::test]
    async fn block_not_found_by_hash() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let contract_address = contract_address_bytes!(b"contract 1");
        let key = storage_address_bytes!(b"storage addr 0");
        let block_id = BlockId::Hash(block_hash_bytes!(b"unknown"));

        let result = get_storage_at(
            ctx,
            Input {
                contract_address,
                key,
                block_id,
            },
            RPC_VERSION,
        )
        .await;

        assert_matches!(result, Err(Error::BlockNotFound));
    }
}
