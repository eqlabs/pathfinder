use crate::core::{BlockId, ClassHash};
use crate::rpc::v02::types::ContractClass;
use crate::rpc::v02::RpcContext;

use anyhow::Context;
use rusqlite::OptionalExtension;

crate::rpc::error::generate_rpc_error_subset!(GetClassError: BlockNotFound, ClassHashNotFound);

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
        "SELECT definition FROM contract_code WHERE hash=?",
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
        "SELECT definition FROM contract_code WHERE hash=? AND declared_on IS NOT NULL",
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
    block: crate::core::StarknetBlockHash,
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
        r"SELECT definition FROM contract_code code JOIN canonical_blocks blocks ON (code.declared_on = blocks.hash) 
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
    block: crate::core::StarknetBlockNumber,
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
        r"SELECT definition FROM contract_code code JOIN canonical_blocks blocks ON (code.declared_on = blocks.hash) 
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
async fn is_pending_class(pending: &Option<crate::state::PendingData>, hash: ClassHash) -> bool {
    let state_diff = match pending {
        Some(pending) => match pending.state_update().await {
            Some(pending) => pending,
            None => return false,
        },
        None => return false,
    };

    let declared = state_diff.state_diff.declared_contracts.iter().cloned();
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
    use crate::starkhash_bytes;
    use assert_matches::assert_matches;

    mod parsing {
        use crate::core::StarknetBlockHash;
        use crate::starkhash;

        use super::*;

        use jsonrpsee::types::Params;

        #[test]
        fn positional_args() {
            let positional = r#"[
                { "block_hash": "0xabcde" },
                "0x12345"
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<GetClassInput>().unwrap();
            let expected = GetClassInput {
                block_id: StarknetBlockHash(starkhash!("0abcde")).into(),
                class_hash: ClassHash(starkhash!("012345")),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            let positional = r#"{
                "block_id": { "block_hash": "0xabcde" },
                "class_hash": "0x12345"
            }"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<GetClassInput>().unwrap();
            let expected = GetClassInput {
                block_id: StarknetBlockHash(starkhash!("0abcde")).into(),
                class_hash: ClassHash(starkhash!("012345")),
            };
            assert_eq!(input, expected);
        }
    }

    #[test]
    fn read_pending() {
        let context = RpcContext::for_tests();
        let mut conn = context.storage.connection().unwrap();
        let tx = conn.transaction().unwrap();

        let valid = ClassHash(starkhash_bytes!(b"class 0 hash"));
        super::read_pending(&tx, valid).unwrap();

        let invalid = ClassHash(starkhash_bytes!(b"invalid"));
        let error = super::read_pending(&tx, invalid).unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);
    }

    #[test]
    fn read_latest() {
        let context = RpcContext::for_tests();
        let mut conn = context.storage.connection().unwrap();
        let tx = conn.transaction().unwrap();

        let valid = ClassHash(starkhash_bytes!(b"class 0 hash"));
        super::read_latest(&tx, valid).unwrap();

        let invalid = ClassHash(starkhash_bytes!(b"invalid"));
        let error = super::read_latest(&tx, invalid).unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // This class is defined, but is not declared in any canonical block.
        let invalid = ClassHash(starkhash_bytes!(b"class 1 hash"));
        let error = super::read_latest(&tx, invalid).unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);
    }

    #[test]
    fn read_at_number() {
        use crate::core::StarknetBlockNumber;

        let context = RpcContext::for_tests();
        let mut conn = context.storage.connection().unwrap();
        let tx = conn.transaction().unwrap();

        // This class is declared in block 1.
        let valid = ClassHash(starkhash_bytes!(b"class 0 hash"));
        super::read_at_number(&tx, valid, StarknetBlockNumber::new_or_panic(1)).unwrap();

        let error = super::read_at_number(&tx, valid, StarknetBlockNumber::GENESIS).unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        let invalid = ClassHash(starkhash_bytes!(b"invalid"));
        let error =
            super::read_at_number(&tx, invalid, StarknetBlockNumber::new_or_panic(2)).unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // This class is defined, but is not declared in any canonical block.
        let invalid = ClassHash(starkhash_bytes!(b"class 1 hash"));
        let error =
            super::read_at_number(&tx, invalid, StarknetBlockNumber::new_or_panic(2)).unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // Class exists, but block number does not.
        let valid = ClassHash(starkhash_bytes!(b"class 0 hash"));
        let error = super::read_at_number(&tx, valid, StarknetBlockNumber::MAX).unwrap_err();
        assert_matches!(error, GetClassError::BlockNotFound);
    }

    #[test]
    fn read_at_hash() {
        use crate::core::StarknetBlockHash;

        let context = RpcContext::for_tests();
        let mut conn = context.storage.connection().unwrap();
        let tx = conn.transaction().unwrap();

        // This class is declared in block 1.
        let valid = ClassHash(starkhash_bytes!(b"class 0 hash"));
        let block1_hash = StarknetBlockHash(starkhash_bytes!(b"block 1"));
        super::read_at_hash(&tx, valid, block1_hash).unwrap();

        let block0_hash = StarknetBlockHash(starkhash_bytes!(b"genesis"));
        let error = super::read_at_hash(&tx, valid, block0_hash).unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        let invalid = ClassHash(starkhash_bytes!(b"invalid"));
        let latest_hash = StarknetBlockHash(starkhash_bytes!(b"latest"));
        let error = super::read_at_hash(&tx, invalid, latest_hash).unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // This class is defined, but is not declared in any canonical block.
        let invalid = ClassHash(starkhash_bytes!(b"class 1 hash"));
        let latest_hash = StarknetBlockHash(starkhash_bytes!(b"latest"));
        let error = super::read_at_hash(&tx, invalid, latest_hash).unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // Class exists, but block hash does not.
        let valid = ClassHash(starkhash_bytes!(b"class 0 hash"));
        let invalid_block = StarknetBlockHash(starkhash_bytes!(b"invalid"));
        let error = super::read_at_hash(&tx, valid, invalid_block).unwrap_err();
        assert_matches!(error, GetClassError::BlockNotFound);
    }
}
