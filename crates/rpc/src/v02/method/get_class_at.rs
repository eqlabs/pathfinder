use crate::state::state_tree::GlobalStateTree;
use crate::v02::types::ContractClass;
use crate::v02::RpcContext;
use anyhow::Context;
use pathfinder_common::{BlockId, ClassHash, ContractAddress};
use pathfinder_storage::{StarknetBlocksBlockId, StarknetBlocksTable};
use rusqlite::OptionalExtension;
use starknet_gateway_types::pending::PendingData;

crate::error::generate_rpc_error_subset!(GetClassAtError: BlockNotFound, ContractNotFound);

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetClassAtInput {
    block_id: BlockId,
    contract_address: ContractAddress,
}

pub async fn get_class_at(
    context: RpcContext,
    input: GetClassAtInput,
) -> Result<ContractClass, GetClassAtError> {
    let span = tracing::Span::current();
    let block = match input.block_id {
        BlockId::Number(number) => number.into(),
        BlockId::Hash(hash) => hash.into(),
        BlockId::Latest => StarknetBlocksBlockId::Latest,
        BlockId::Pending => {
            match get_pending_class_hash(context.pending_data, input.contract_address).await {
                Some(class) => {
                    let jh = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                        let _g = span.enter();
                        let mut db = context
                            .storage
                            .connection()
                            .context("Opening database connection")?;

                        let tx = db.transaction().context("Creating database transaction")?;

                        let definition = get_definition(&tx, class)?;
                        let class = ContractClass::from_definition_bytes(&definition)
                            .context("Parsing class definition")?;

                        Ok(class)
                    });

                    let class = jh
                        .await
                        .context("Reading class definition from database")??;
                    return Ok(class);
                }
                None => StarknetBlocksBlockId::Latest,
            }
        }
    };

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;
        let definition = get_definition_at(&tx, block, input.contract_address)?;
        let class = ContractClass::from_definition_bytes(&definition)
            .context("Parsing class definition")?;
        Ok(class)
    });

    jh.await.context("Reading class from database")?
}

/// Fetches the class's definition without checking any block requirements.
///
/// This is useful if you have previously already verified that the class should exist.
fn get_definition(tx: &rusqlite::Transaction<'_>, class: ClassHash) -> anyhow::Result<Vec<u8>> {
    let definition = tx
        .query_row(
            "SELECT definition FROM contract_code WHERE hash=?",
            [class],
            |row| {
                let data = row.get_ref_unwrap(0).as_blob()?.to_vec();
                Ok(data)
            },
        )
        .optional()
        .context("Reading definition from database")?
        .context("Class definition is missing")?;

    Ok(definition)
}

fn get_definition_at(
    tx: &rusqlite::Transaction<'_>,
    block: StarknetBlocksBlockId,
    contract: ContractAddress,
) -> Result<Vec<u8>, GetClassAtError> {
    let global_root = StarknetBlocksTable::get_root(tx, block)
        .context("Reading global root from database")?
        .ok_or(GetClassAtError::BlockNotFound)?;

    let tree = GlobalStateTree::load(tx, global_root).context("Loading global state tree")?;
    let state_hash = tree
        .get(contract)
        .context("Fetching contract leaf in global tree")?
        .ok_or(GetClassAtError::ContractNotFound)?;

    let definition = tx
        .query_row(
            "SELECT definition FROM contract_code code JOIN contract_states states ON (code.hash = states.hash) WHERE states.state_hash=?",
            [state_hash],
            |row| {
                let data = row.get_ref_unwrap(0).as_blob()?.to_vec();
                Ok(data)
            }
        )
        .optional()
        .context("Reading definition from database")?
        .context("Class definition is missing")?;

    let definition = zstd::decode_all(&*definition)
        .context("Decompressing contract definition")
        .map_err(|e| {
            GetClassAtError::Internal(anyhow::anyhow!(
                "Decompressing class definition failed: {}",
                e
            ))
        })?;

    Ok(definition)
}

/// Returns the [ClassHash] of the given [ContractAddress] if any is defined in the pending data.
async fn get_pending_class_hash(
    pending: Option<PendingData>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use pathfinder_common::{starkhash, starkhash_bytes};

    mod parsing {
        use super::*;
        use jsonrpsee::types::Params;
        use pathfinder_common::StarknetBlockHash;

        #[test]
        fn positional_args() {
            let positional = r#"[
                { "block_hash": "0xabcde" },
                "0x12345"
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<GetClassAtInput>().unwrap();
            let expected = GetClassAtInput {
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

            let input = named.parse::<GetClassAtInput>().unwrap();
            let expected = GetClassAtInput {
                block_id: StarknetBlockHash(starkhash!("0abcde")).into(),
                contract_address: ContractAddress::new_or_panic(starkhash!("012345")),
            };
            assert_eq!(input, expected);
        }
    }

    #[test]
    fn get_definition() {
        let context = RpcContext::for_tests();
        let mut conn = context.storage.connection().unwrap();
        let tx = conn.transaction().unwrap();

        let valid = ClassHash(starkhash_bytes!(b"class 0 hash"));
        super::get_definition(&tx, valid).unwrap();
    }

    #[test]
    fn latest() {
        let context = RpcContext::for_tests();
        let mut conn = context.storage.connection().unwrap();
        let tx = conn.transaction().unwrap();

        let valid = ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0"));
        super::get_definition_at(&tx, StarknetBlocksBlockId::Latest, valid).unwrap();

        let invalid = ContractAddress::new_or_panic(starkhash_bytes!(b"invalid"));
        let error =
            super::get_definition_at(&tx, StarknetBlocksBlockId::Latest, invalid).unwrap_err();
        assert_matches!(error, GetClassAtError::ContractNotFound);
    }

    #[test]
    fn number() {
        use pathfinder_common::StarknetBlockNumber;

        let context = RpcContext::for_tests();
        let mut conn = context.storage.connection().unwrap();
        let tx = conn.transaction().unwrap();

        // This contract is declared in block 1.
        let valid = ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));
        super::get_definition_at(&tx, StarknetBlockNumber::new_or_panic(1).into(), valid).unwrap();
        let error =
            super::get_definition_at(&tx, StarknetBlockNumber::GENESIS.into(), valid).unwrap_err();
        assert_matches!(error, GetClassAtError::ContractNotFound);

        let invalid = ContractAddress::new_or_panic(starkhash_bytes!(b"invalid"));
        let error =
            super::get_definition_at(&tx, StarknetBlockNumber::new_or_panic(2).into(), invalid)
                .unwrap_err();
        assert_matches!(error, GetClassAtError::ContractNotFound);

        // Class exists, but block number does not.
        let error =
            super::get_definition_at(&tx, StarknetBlockNumber::MAX.into(), valid).unwrap_err();
        assert_matches!(error, GetClassAtError::BlockNotFound);
    }

    #[test]
    fn hash() {
        use pathfinder_common::StarknetBlockHash;

        let context = RpcContext::for_tests();
        let mut conn = context.storage.connection().unwrap();
        let tx = conn.transaction().unwrap();

        // This class is declared in block 1.
        let valid = ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));
        let block1_hash = StarknetBlockHash(starkhash_bytes!(b"block 1"));
        super::get_definition_at(&tx, block1_hash.into(), valid).unwrap();

        let block0_hash = StarknetBlockHash(starkhash_bytes!(b"genesis"));
        let error = super::get_definition_at(&tx, block0_hash.into(), valid).unwrap_err();
        assert_matches!(error, GetClassAtError::ContractNotFound);

        let invalid = ContractAddress::new_or_panic(starkhash_bytes!(b"invalid"));
        let latest_hash = StarknetBlockHash(starkhash_bytes!(b"latest"));
        let error = super::get_definition_at(&tx, latest_hash.into(), invalid).unwrap_err();
        assert_matches!(error, GetClassAtError::ContractNotFound);

        // Class exists, but block hash does not.
        let invalid_block = StarknetBlockHash(starkhash_bytes!(b"invalid"));
        let error = super::get_definition_at(&tx, invalid_block.into(), valid).unwrap_err();
        assert_matches!(error, GetClassAtError::BlockNotFound);
    }
}
