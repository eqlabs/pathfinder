use crate::v02::types::ContractClass;
use crate::v02::RpcContext;
use anyhow::Context;
use pathfinder_common::{BlockId, ClassHash};
use rusqlite::OptionalExtension;
use starknet_gateway_types::pending::PendingData;

crate::error::generate_rpc_error_subset!(GetClassError: BlockNotFound, ClassHashNotFound);

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetClassInput {
    block_id: BlockId,
    class_hash: ClassHash,
}

pub async fn get_class(
    context: RpcContext,
    input: GetClassInput,
) -> Result<ContractClass, GetClassError> {
    let block = match input.block_id {
        BlockId::Pending => {
            if is_pending_class(&context.pending_data, input.class_hash).await {
                BlockId::Pending
            } else {
                BlockId::Latest
            }
        }
        other => other,
    };

    let span = tracing::Span::current();
    let jh = tokio::task::spawn_blocking(move || -> Result<ContractClass, GetClassError> {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Creating database transaction")?;

        let definition = match block {
            BlockId::Pending => read_pending(&tx, input.class_hash),
            BlockId::Number(number) => read_at_number(&tx, input.class_hash, number),
            BlockId::Hash(hash) => read_at_hash(&tx, input.class_hash, hash),
            BlockId::Latest => read_latest(&tx, input.class_hash),
        }?;

        let definition =
            zstd::decode_all(&*definition).context("Decompressing class definition")?;
        let class = ContractClass::from_definition_bytes(&definition)
            .context("Parsing class definition")?;

        Ok(class)
    });

    jh.await.context("Reading class from database")?
}

/// Returns the class definition data.
///
/// This is useful only if you are already certain this class was declared.
fn read_pending(
    tx: &rusqlite::Transaction<'_>,
    class: ClassHash,
) -> Result<Vec<u8>, GetClassError> {
    tx.query_row(
        "SELECT definition FROM class_definitions WHERE hash=?",
        rusqlite::params! { class },
        |row| {
            let def = row.get_ref_unwrap(0).as_blob()?.to_owned();
            Ok(def)
        },
    )
    .optional()
    .context("Reading class definition from database")?
    .ok_or(GetClassError::ClassHashNotFound)
}

/// Returns the class definition data iff it was declared on a canonical block.
fn read_latest(tx: &rusqlite::Transaction<'_>, class: ClassHash) -> Result<Vec<u8>, GetClassError> {
    // This works because declared_on is only set if the class was declared in a canonical block.
    tx.query_row(
        "SELECT definition FROM class_definitions WHERE hash=? AND declared_on IS NOT NULL",
        rusqlite::params! { class },
        |row| {
            let def = row.get_ref_unwrap(0).as_blob()?.to_owned();
            Ok(def)
        },
    )
    .optional()
    .context("Reading class definition from database")?
    .ok_or(GetClassError::ClassHashNotFound)
}

/// Returns the class definition data iff it was declared on or before the given block hash.
/// The block hash provided must also form part of the canonical chain.
fn read_at_hash(
    tx: &rusqlite::Transaction<'_>,
    class: ClassHash,
    block: pathfinder_common::StarknetBlockHash,
) -> Result<Vec<u8>, GetClassError> {
    let number = tx
        .query_row(
            "SELECT number FROM canonical_blocks WHERE hash=?",
            rusqlite::params! { block },
            |row| {
                let number = row.get_ref_unwrap(0).as_i64()?;
                Ok(number)
            },
        )
        .optional()
        .context("Reading block number from database")?
        .ok_or(GetClassError::BlockNotFound)?;

    tx.query_row(
        r"SELECT definition FROM class_definitions code JOIN canonical_blocks blocks ON (code.declared_on = blocks.hash)
        WHERE code.hash=? AND blocks.number <= ?",
        rusqlite::params! { class, number },
        |row| {
            let def = row.get_ref_unwrap(0).as_blob()?.to_owned();
            Ok(def)
        },
    )
    .optional()
    .context("Reading class definition from database")?
    .ok_or(GetClassError::ClassHashNotFound)
}

/// Returns the class definition data iff it was declared on or before the given block number.
fn read_at_number(
    tx: &rusqlite::Transaction<'_>,
    class: ClassHash,
    block: pathfinder_common::StarknetBlockNumber,
) -> Result<Vec<u8>, GetClassError> {
    // Check that the block number exists. This has to happen first as the <= check
    // in the class selection query will work even if the block number exceeds what
    // is available in canonical_blocks.
    let latest = tx
        .query_row("SELECT MAX(number) FROM canonical_blocks", [], |row| {
            let num = row.get_ref_unwrap(0).as_i64()?;
            Ok(num)
        })
        .context("Reading latest block number")?;
    if block.get() > latest as u64 {
        return Err(GetClassError::BlockNotFound);
    }

    tx.query_row(
        r"SELECT definition FROM class_definitions code JOIN canonical_blocks blocks ON (code.declared_on = blocks.hash)
        WHERE code.hash=? AND blocks.number <= ?",
        rusqlite::params! { class, block },
        |row| {
            let def = row.get_ref_unwrap(0).as_blob()?.to_owned();
            Ok(def)
        },
    )
    .optional()
    .context("Reading class definition from database")?
    .ok_or(GetClassError::ClassHashNotFound)
}

/// Returns true if the class is declared or deployed in the pending state.
async fn is_pending_class(pending: &Option<PendingData>, hash: ClassHash) -> bool {
    let state_diff = match pending {
        Some(pending) => match pending.state_update().await {
            Some(pending) => pending,
            None => return false,
        },
        None => return false,
    };

    let declared = state_diff.state_diff.old_declared_contracts.iter().cloned();
    let deployed = state_diff
        .state_diff
        .deployed_contracts
        .iter()
        .map(|contract| contract.class_hash);

    deployed.chain(declared).any(|item| item == hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use pathfinder_common::felt_bytes;

    mod parsing {
        use super::*;
        use jsonrpsee::types::Params;
        use pathfinder_common::felt;
        use pathfinder_common::StarknetBlockHash;

        #[test]
        fn positional_args() {
            let positional = r#"[
                { "block_hash": "0xabcde" },
                "0x12345"
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<GetClassInput>().unwrap();
            let expected = GetClassInput {
                block_id: StarknetBlockHash(felt!("0xabcde")).into(),
                class_hash: ClassHash(felt!("0x12345")),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            let named = r#"{
                "block_id": { "block_hash": "0xabcde" },
                "class_hash": "0x12345"
            }"#;
            let named = Params::new(Some(named));

            let input = named.parse::<GetClassInput>().unwrap();
            let expected = GetClassInput {
                block_id: StarknetBlockHash(felt!("0xabcde")).into(),
                class_hash: ClassHash(felt!("0x12345")),
            };
            assert_eq!(input, expected);
        }
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests();

        // Cairo v0.x class
        let valid_v0 = ClassHash(felt_bytes!(b"class 0 hash"));
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Pending,
                class_hash: valid_v0,
            },
        )
        .await
        .unwrap();
        // Cairo v1.x class (Sierra)
        let valid_v1 = ClassHash(felt_bytes!(b"class 2 hash (sierra)"));
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Pending,
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap();

        let invalid = ClassHash(felt_bytes!(b"invalid"));
        let error = super::get_class(
            context,
            GetClassInput {
                block_id: BlockId::Pending,
                class_hash: invalid,
            },
        )
        .await
        .unwrap_err();

        assert_matches!(error, GetClassError::ClassHashNotFound);
    }

    #[tokio::test]
    async fn latest() {
        let context = RpcContext::for_tests();

        // Cairo v0.x class
        let valid_v0 = ClassHash(felt_bytes!(b"class 0 hash"));
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Latest,
                class_hash: valid_v0,
            },
        )
        .await
        .unwrap();

        // Cairo v1.x class (Sierra)
        let valid_v1 = ClassHash(felt_bytes!(b"class 2 hash (sierra)"));
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Latest,
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap();

        let invalid = ClassHash(felt_bytes!(b"invalid"));
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Latest,
                class_hash: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // This class is defined, but is not declared in any canonical block.
        let invalid = ClassHash(felt_bytes!(b"class 1 hash"));
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Latest,
                class_hash: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);
    }

    #[tokio::test]
    async fn at_number() {
        use pathfinder_common::StarknetBlockNumber;

        let context = RpcContext::for_tests();

        // Cairo v0.x class
        // This class is declared in block 1.
        let valid_v0 = ClassHash(felt_bytes!(b"class 0 hash"));
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Number(StarknetBlockNumber::new_or_panic(1)),
                class_hash: valid_v0,
            },
        )
        .await
        .unwrap();

        // Cairo v1.x class (Sierra)
        // This class is declared in block 2.
        let valid_v1 = ClassHash(felt_bytes!(b"class 2 hash (sierra)"));
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Number(StarknetBlockNumber::new_or_panic(2)),
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap();

        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Number(StarknetBlockNumber::GENESIS),
                class_hash: valid_v0,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        let invalid = ClassHash(felt_bytes!(b"invalid"));
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Number(StarknetBlockNumber::new_or_panic(2)),
                class_hash: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // This class is defined, but is not declared in any canonical block.
        let invalid = ClassHash(felt_bytes!(b"class 1 hash"));
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Number(StarknetBlockNumber::new_or_panic(2)),
                class_hash: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // Class exists, but block number does not.
        let valid = ClassHash(felt_bytes!(b"class 0 hash"));
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Number(StarknetBlockNumber::MAX),
                class_hash: valid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::BlockNotFound);
    }

    #[tokio::test]
    async fn read_at_hash() {
        use pathfinder_common::StarknetBlockHash;

        let context = RpcContext::for_tests();

        // Cairo v0.x class
        // This class is declared in block 1.
        let valid_v0 = ClassHash(felt_bytes!(b"class 0 hash"));
        let block1_hash = StarknetBlockHash(felt_bytes!(b"block 1"));
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Hash(block1_hash),
                class_hash: valid_v0,
            },
        )
        .await
        .unwrap();

        // Cairo v1.x class
        // This class is declared in block 2.
        let valid_v1 = ClassHash(felt_bytes!(b"class 2 hash (sierra)"));
        let block2_hash = StarknetBlockHash(felt_bytes!(b"latest"));
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Hash(block2_hash),
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap();

        let block0_hash = StarknetBlockHash(felt_bytes!(b"genesis"));
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Hash(block0_hash),
                class_hash: valid_v0,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        let invalid = ClassHash(felt_bytes!(b"invalid"));
        let latest_hash = StarknetBlockHash(felt_bytes!(b"latest"));
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Hash(latest_hash),
                class_hash: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // This class is defined, but is not declared in any canonical block.
        let invalid = ClassHash(felt_bytes!(b"class 1 hash"));
        let latest_hash = StarknetBlockHash(felt_bytes!(b"latest"));
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Hash(latest_hash),
                class_hash: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // Class exists, but block hash does not.
        let valid = ClassHash(felt_bytes!(b"class 0 hash"));
        let invalid_block = StarknetBlockHash(felt_bytes!(b"invalid"));
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Hash(invalid_block),
                class_hash: valid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::BlockNotFound);
    }
}
