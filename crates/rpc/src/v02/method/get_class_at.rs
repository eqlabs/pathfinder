use anyhow::Context;
use pathfinder_common::{BlockId, ContractAddress};

use crate::context::RpcContext;
use crate::v02::types::ContractClass;

crate::error::generate_rpc_error_subset!(GetClassAtError: BlockNotFound, ContractNotFound);

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GetClassAtInput {
    block_id: BlockId,
    contract_address: ContractAddress,
}

impl crate::dto::DeserializeForVersion for GetClassAtInput {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_serde()
    }
}

pub async fn get_class_at(
    context: RpcContext,
    input: GetClassAtInput,
) -> Result<ContractClass, GetClassAtError> {
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        let pending_class_hash = if input.block_id == BlockId::Pending {
            context
                .pending_data
                .get(&tx)
                .context("Querying pending data")?
                .state_update
                .contract_class(input.contract_address)
        } else {
            None
        };

        // Map block id to the storage variant.
        let block_id = match input.block_id {
            BlockId::Pending => pathfinder_storage::BlockId::Latest,
            other => other.try_into().expect("Only pending cast should fail"),
        };

        if !tx.block_exists(block_id)? {
            return Err(GetClassAtError::BlockNotFound);
        }

        let class_hash = match pending_class_hash {
            Some(class_hash) => class_hash,
            None => tx
                .contract_class_hash(block_id, input.contract_address)
                .context("Querying contract's class hash")?
                .ok_or(GetClassAtError::ContractNotFound)?,
        };

        let definition = tx
            .class_definition(class_hash)
            .context("Fetching class definition")?
            .context("Class definition missing from database")?;

        let class = ContractClass::from_definition_bytes(&definition)
            .context("Parsing class definition")?;

        Ok(class)
    });

    jh.await.context("Reading class from database")?
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;

    use super::*;

    mod parsing {
        use serde_json::json;

        use super::*;

        #[test]
        fn positional_args() {
            let positional = json!([
                { "block_hash": "0xabcde" },
                "0x12345"
            ]);

            let input = serde_json::from_value::<GetClassAtInput>(positional).unwrap();
            let expected = GetClassAtInput {
                block_id: block_hash!("0xabcde").into(),
                contract_address: contract_address!("0x12345"),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            let named = json!({
                "block_id": { "block_hash": "0xabcde" },
                "contract_address": "0x12345"
            });

            let input = serde_json::from_value::<GetClassAtInput>(named).unwrap();
            let expected = GetClassAtInput {
                block_id: block_hash!("0xabcde").into(),
                contract_address: contract_address!("0x12345"),
            };
            assert_eq!(input, expected);
        }
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests();

        // Cairo class v0.x
        let valid_v0 = contract_address_bytes!(b"contract 0");
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Pending,
                contract_address: valid_v0,
            },
        )
        .await
        .unwrap();

        // Cairo class v1.x
        let valid_v1 = contract_address_bytes!(b"contract 2 (sierra)");
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Pending,
                contract_address: valid_v1,
            },
        )
        .await
        .unwrap();

        let invalid = contract_address_bytes!(b"invalid");
        let error = super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Pending,
                contract_address: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassAtError::ContractNotFound);
    }

    #[tokio::test]
    async fn latest() {
        let context = RpcContext::for_tests();

        // Cairo class v0.x
        let valid_v0 = contract_address_bytes!(b"contract 0");
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Latest,
                contract_address: valid_v0,
            },
        )
        .await
        .unwrap();

        // Cairo class v1.x
        let valid_v1 = contract_address_bytes!(b"contract 2 (sierra)");
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Latest,
                contract_address: valid_v1,
            },
        )
        .await
        .unwrap();

        let invalid = contract_address_bytes!(b"invalid");
        let error = super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Latest,
                contract_address: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassAtError::ContractNotFound);
    }

    #[tokio::test]
    async fn number() {
        use pathfinder_common::BlockNumber;

        let context = RpcContext::for_tests();

        // Cairo v0.x class
        // This contract is declared in block 1.
        let valid_v0 = contract_address_bytes!(b"contract 1");
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
                contract_address: valid_v0,
            },
        )
        .await
        .unwrap();

        // Cairo v1.x class (sierra)
        // This contract is declared in block 2.
        let valid_v1 = contract_address_bytes!(b"contract 2 (sierra)");
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Number(BlockNumber::new_or_panic(2)),
                contract_address: valid_v1,
            },
        )
        .await
        .unwrap();

        let error = super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Number(BlockNumber::GENESIS),
                contract_address: valid_v0,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassAtError::ContractNotFound);

        let invalid = contract_address_bytes!(b"invalid");
        let error = super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Number(BlockNumber::new_or_panic(2)),
                contract_address: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassAtError::ContractNotFound);

        // Class exists, but block number does not.
        let error = super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Number(BlockNumber::MAX),
                contract_address: valid_v0,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassAtError::BlockNotFound);
    }

    #[tokio::test]
    async fn hash() {
        let context = RpcContext::for_tests();

        // Cairo v0.x class
        // This class is declared in block 1.
        let valid_v0 = contract_address_bytes!(b"contract 1");
        let block1_hash = block_hash_bytes!(b"block 1");
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Hash(block1_hash),
                contract_address: valid_v0,
            },
        )
        .await
        .unwrap();

        // Cairo v1.x class (sierra)
        // This class is declared in block 2.
        let valid_v1 = contract_address_bytes!(b"contract 2 (sierra)");
        let block2_hash = block_hash_bytes!(b"latest");
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Hash(block2_hash),
                contract_address: valid_v1,
            },
        )
        .await
        .unwrap();

        let block0_hash = block_hash_bytes!(b"genesis");
        let error = super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Hash(block0_hash),
                contract_address: valid_v0,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassAtError::ContractNotFound);

        let invalid = contract_address_bytes!(b"invalid");
        let latest_hash = block_hash_bytes!(b"latest");
        let error = super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Hash(latest_hash),
                contract_address: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassAtError::ContractNotFound);

        // Class exists, but block hash does not.
        let invalid_block = block_hash_bytes!(b"invalid");
        let error = super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Hash(invalid_block),
                contract_address: valid_v0,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassAtError::BlockNotFound);
    }
}
