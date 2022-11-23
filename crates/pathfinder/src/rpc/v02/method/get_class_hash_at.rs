use crate::rpc::v02::RpcContext;
use crate::state::state_tree::GlobalStateTree;
use crate::storage::{StarknetBlocksBlockId, StarknetBlocksTable};
use anyhow::Context;
use pathfinder_core::{BlockId, ClassHash, ContractAddress, ContractStateHash};

crate::rpc::error::generate_rpc_error_subset!(GetClassHashAtError: BlockNotFound, ContractNotFound);

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetClassHashAtInput {
    block_id: BlockId,
    contract_address: ContractAddress,
}

pub async fn get_class_hash_at(
    context: RpcContext,
    input: GetClassHashAtInput,
) -> Result<ClassHash, GetClassHashAtError> {
    let block_id = match input.block_id {
        BlockId::Hash(hash) => hash.into(),
        BlockId::Number(number) => number.into(),
        BlockId::Latest => StarknetBlocksBlockId::Latest,
        BlockId::Pending => {
            match get_pending_class_hash(context.pending_data, input.contract_address).await {
                Some(class_hash) => return Ok(class_hash),
                None => StarknetBlocksBlockId::Latest,
            }
        }
    };

    let span = tracing::Span::current();
    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        // Read the class hash via the state tree. This involves:
        //  1. Reading the state_hash for this contract from the global tree
        //  2. Fetching the class hash from the `contract_states` table
        //
        // (2) can also be achieved by fetching it directly from the `contracts` table,
        // but it felt more "correct" to continue using the global state mechanism.
        let global_root = StarknetBlocksTable::get_root(&tx, block_id)
            .context("Reading global root from database")?
            .ok_or(GetClassHashAtError::BlockNotFound)?;

        let tree = GlobalStateTree::load(&tx, global_root).context("Loading global state tree")?;
        let state_hash = tree
            .get(input.contract_address)
            .context("Fetching contract leaf in global tree")?
            .ok_or(GetClassHashAtError::ContractNotFound)?;

        read_class_hash(&tx, state_hash)
            .context("Reading class hash from state table")?
            // Class hash should not be None at this stage since we have a valid block and non-zero contract state_hash.
            .ok_or_else(|| {
                tracing::error!(%state_hash, "Class hash is missing in `contract_states` table");
                anyhow::anyhow!("State table missing row for state_hash={}", state_hash).into()
            })
    });

    jh.await.context("Database read panic or shutting down")?
}

/// Returns the [ClassHash] of the given [ContractAddress] if any is defined in the pending data.
async fn get_pending_class_hash(
    pending: Option<crate::state::PendingData>,
    address: ContractAddress,
) -> Option<ClassHash> {
    pending?.state_update().await.and_then(|state_update| {
        state_update
            .state_diff
            .deployed_contracts
            .iter()
            .find_map(|contract| (contract.address == address).then_some(contract.class_hash))
    })
}

/// Returns the [ClassHash] for the given [ContractStateHash] from the database.
fn read_class_hash(
    tx: &rusqlite::Transaction<'_>,
    state_hash: ContractStateHash,
) -> anyhow::Result<Option<ClassHash>> {
    use rusqlite::OptionalExtension;

    tx.query_row(
        "SELECT hash FROM contract_states WHERE state_hash=?",
        [state_hash],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{starkhash, starkhash_bytes};
    use assert_matches::assert_matches;

    mod parsing {
        use super::*;
        use jsonrpsee::types::Params;
        use pathfinder_core::StarknetBlockHash;

        #[test]
        fn positional_args() {
            let positional = r#"[
                { "block_hash": "0xabcde" },
                "0x12345"
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<GetClassHashAtInput>().unwrap();
            let expected = GetClassHashAtInput {
                block_id: StarknetBlockHash(starkhash!("0abcde")).into(),
                contract_address: ContractAddress::new_or_panic(starkhash!("012345")),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            let named = r#"{
                "block_id": { "block_hash": "0xabcde" },
                "contract_address": "0x12345"
            }"#;
            let named = Params::new(Some(named));

            let input = named.parse::<GetClassHashAtInput>().unwrap();
            let expected = GetClassHashAtInput {
                block_id: StarknetBlockHash(starkhash!("0abcde")).into(),
                contract_address: ContractAddress::new_or_panic(starkhash!("012345")),
            };
            assert_eq!(input, expected);
        }
    }

    mod errors {
        use super::*;

        #[tokio::test]
        async fn contract_not_found() {
            let context = RpcContext::for_tests();

            let input = GetClassHashAtInput {
                block_id: BlockId::Latest,
                contract_address: ContractAddress::new_or_panic(starkhash_bytes!(b"invalid")),
            };
            let result = get_class_hash_at(context, input).await;
            assert_matches!(result, Err(GetClassHashAtError::ContractNotFound));
        }

        #[tokio::test]
        async fn block_not_found() {
            use pathfinder_core::StarknetBlockHash;

            let context = RpcContext::for_tests();

            let input = GetClassHashAtInput {
                block_id: BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"invalid"))),
                // This contract does exist and is added in block 0.
                contract_address: ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0")),
            };
            let result = get_class_hash_at(context, input).await;
            assert_matches!(result, Err(GetClassHashAtError::BlockNotFound));
        }
    }

    #[tokio::test]
    async fn latest() {
        let context = RpcContext::for_tests();
        let expected = ClassHash(starkhash_bytes!(b"class 0 hash"));

        let input = GetClassHashAtInput {
            block_id: BlockId::Latest,
            contract_address: ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0")),
        };
        let result = get_class_hash_at(context, input).await.unwrap();
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn at_block() {
        use pathfinder_core::StarknetBlockNumber;
        let context = RpcContext::for_tests();

        // This contract is deployed in block 1.
        let address = ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));

        let input = GetClassHashAtInput {
            block_id: StarknetBlockNumber::new_or_panic(0).into(),
            contract_address: address,
        };
        let result = get_class_hash_at(context.clone(), input).await;
        assert_matches!(result, Err(GetClassHashAtError::ContractNotFound));

        let expected = ClassHash(starkhash_bytes!(b"class 1 hash"));
        let input = GetClassHashAtInput {
            block_id: StarknetBlockNumber::new_or_panic(1).into(),
            contract_address: address,
        };
        let result = get_class_hash_at(context.clone(), input).await.unwrap();
        assert_eq!(result, expected);

        let input = GetClassHashAtInput {
            block_id: StarknetBlockNumber::new_or_panic(2).into(),
            contract_address: address,
        };
        let result = get_class_hash_at(context, input).await.unwrap();
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn pending_defaults_to_latest() {
        let context = RpcContext::for_tests();
        let expected = ClassHash(starkhash_bytes!(b"class 0 hash"));

        let input = GetClassHashAtInput {
            block_id: BlockId::Pending,
            contract_address: ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0")),
        };
        let result = get_class_hash_at(context, input).await.unwrap();
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;

        // This should still work even though it was deployed in an actual block.
        let expected = ClassHash(starkhash_bytes!(b"class 0 hash"));
        let input = GetClassHashAtInput {
            block_id: BlockId::Pending,
            contract_address: ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0")),
        };
        let result = get_class_hash_at(context.clone(), input).await.unwrap();
        assert_eq!(result, expected);

        // This is an actual pending deployed contract.
        let expected = ClassHash(starkhash_bytes!(b"pending contract 0 hash"));
        let input = GetClassHashAtInput {
            block_id: BlockId::Pending,
            contract_address: ContractAddress::new_or_panic(starkhash_bytes!(
                b"pending contract 0 address"
            )),
        };
        let result = get_class_hash_at(context.clone(), input).await.unwrap();
        assert_eq!(result, expected);

        // This one remains missing.
        let input = GetClassHashAtInput {
            block_id: BlockId::Latest,
            contract_address: ContractAddress::new_or_panic(starkhash_bytes!(b"invalid")),
        };
        let result = get_class_hash_at(context, input).await;
        assert_matches!(result, Err(GetClassHashAtError::ContractNotFound));
    }
}
