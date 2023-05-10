use crate::context::RpcContext;
use crate::v02::types::ContractClass;
use anyhow::Context;
use pathfinder_common::{BlockId, ClassHash, ContractAddress};
use pathfinder_storage::StarknetBlocksBlockId;
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
    let block_id = match input.block_id {
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

                        let definition = database::definition_unchecked(&tx, class)?;
                        let definition = zstd::decode_all(&*definition)
                            .context("Decompressing class definition")?;
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

        if !crate::utils::block_exists(&tx, block_id)? {
            return Err(GetClassAtError::BlockNotFound);
        }

        let compressed_definition = match block_id {
            StarknetBlocksBlockId::Number(number) => {
                database::definition_at_block_number(&tx, input.contract_address, number)
            }
            StarknetBlocksBlockId::Hash(hash) => {
                database::definition_at_block_hash(&tx, input.contract_address, hash)
            }
            StarknetBlocksBlockId::Latest => {
                database::definition_at_latest_block(&tx, input.contract_address)
            }
        }?
        .ok_or(GetClassAtError::ContractNotFound)?;

        let definition =
            zstd::decode_all(&*compressed_definition).context("Decompressing class definition")?;

        let class = ContractClass::from_definition_bytes(&definition)
            .context("Parsing class definition")?;

        Ok(class)
    });

    jh.await.context("Reading class from database")?
}

mod database {
    use pathfinder_common::{StarknetBlockHash, StarknetBlockNumber};

    use super::*;

    pub fn definition_at_latest_block(
        tx: &rusqlite::Transaction<'_>,
        contract: ContractAddress,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        tx.query_row(
            r"SELECT definition FROM class_definitions 
                JOIN contract_updates ON (class_definitions.hash = contract_updates.class_hash)
                WHERE contract_updates.contract_address = ?
                ORDER BY contract_updates.block_number DESC LIMIT 1",
            [contract],
            |row| row.get(0),
        )
        .optional()
        .context("Fetching class definition at latest block")
    }

    pub fn definition_at_block_number(
        tx: &rusqlite::Transaction<'_>,
        contract: ContractAddress,
        block_number: StarknetBlockNumber,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        tx.query_row(
            r"SELECT definition FROM class_definitions 
                JOIN contract_updates ON (class_definitions.hash = contract_updates.class_hash)
                WHERE contract_updates.contract_address = ?
                    AND contract_updates.block_number <= ?
                ORDER BY contract_updates.block_number DESC LIMIT 1",
            rusqlite::params![contract, block_number],
            |row| row.get(0),
        )
        .optional()
        .context("Fetching class definition at block number")
    }

    pub fn definition_at_block_hash(
        tx: &rusqlite::Transaction<'_>,
        contract: ContractAddress,
        block_hash: StarknetBlockHash,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        tx.query_row(
            r"SELECT definition FROM class_definitions 
                JOIN contract_updates ON (class_definitions.hash = contract_updates.class_hash)
                WHERE contract_updates.contract_address = ?
                    AND contract_updates.block_number <= (SELECT number FROM canonical_blocks WHERE hash = ?)
                ORDER BY contract_updates.block_number DESC LIMIT 1",
            rusqlite::params![contract, block_hash],
            |row| row.get(0),
        )
        .optional()
        .context("Fetching class definition at block hash")
    }

    /// Fetches the class's definition without checking any block requirements.
    ///
    /// This is useful if you have previously already verified that the class should exist,
    /// for example if the class declaration is part of the pending block.
    pub fn definition_unchecked(
        tx: &rusqlite::Transaction<'_>,
        class_hash: ClassHash,
    ) -> anyhow::Result<Vec<u8>> {
        tx.query_row(
            "SELECT definition FROM class_definitions WHERE hash=?",
            [class_hash],
            |row| row.get(0),
        )
        .optional()
        .context("Reading definition from database")?
        .context("Class definition is missing")
    }
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
    use pathfinder_common::{felt, felt_bytes};

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
                block_id: StarknetBlockHash(felt!("0xabcde")).into(),
                contract_address: ContractAddress::new_or_panic(felt!("0x12345")),
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
                block_id: StarknetBlockHash(felt!("0xabcde")).into(),
                contract_address: ContractAddress::new_or_panic(felt!("0x12345")),
            };
            assert_eq!(input, expected);
        }
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests();

        // Cairo class v0.x
        let valid_v0 = ContractAddress::new_or_panic(felt_bytes!(b"contract 0"));
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
        let valid_v1 = ContractAddress::new_or_panic(felt_bytes!(b"contract 2 (sierra)"));
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Pending,
                contract_address: valid_v1,
            },
        )
        .await
        .unwrap();

        let invalid = ContractAddress::new_or_panic(felt_bytes!(b"invalid"));
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
        let valid_v0 = ContractAddress::new_or_panic(felt_bytes!(b"contract 0"));
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
        let valid_v1 = ContractAddress::new_or_panic(felt_bytes!(b"contract 2 (sierra)"));
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Latest,
                contract_address: valid_v1,
            },
        )
        .await
        .unwrap();

        let invalid = ContractAddress::new_or_panic(felt_bytes!(b"invalid"));
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
        use pathfinder_common::StarknetBlockNumber;

        let context = RpcContext::for_tests();

        // Cairo v0.x class
        // This contract is declared in block 1.
        let valid_v0 = ContractAddress::new_or_panic(felt_bytes!(b"contract 1"));
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Number(StarknetBlockNumber::new_or_panic(1)),
                contract_address: valid_v0,
            },
        )
        .await
        .unwrap();

        // Cairo v1.x class (sierra)
        // This contract is declared in block 2.
        let valid_v1 = ContractAddress::new_or_panic(felt_bytes!(b"contract 2 (sierra)"));
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Number(StarknetBlockNumber::new_or_panic(2)),
                contract_address: valid_v1,
            },
        )
        .await
        .unwrap();

        let error = super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Number(StarknetBlockNumber::GENESIS),
                contract_address: valid_v0,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassAtError::ContractNotFound);

        let invalid = ContractAddress::new_or_panic(felt_bytes!(b"invalid"));
        let error = super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Number(StarknetBlockNumber::new_or_panic(2)),
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
                block_id: BlockId::Number(StarknetBlockNumber::MAX),
                contract_address: valid_v0,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassAtError::BlockNotFound);
    }

    #[tokio::test]
    async fn hash() {
        use pathfinder_common::StarknetBlockHash;

        let context = RpcContext::for_tests();

        // Cairo v0.x class
        // This class is declared in block 1.
        let valid_v0 = ContractAddress::new_or_panic(felt_bytes!(b"contract 1"));
        let block1_hash = StarknetBlockHash(felt_bytes!(b"block 1"));
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
        let valid_v1 = ContractAddress::new_or_panic(felt_bytes!(b"contract 2 (sierra)"));
        let block2_hash = StarknetBlockHash(felt_bytes!(b"latest"));
        super::get_class_at(
            context.clone(),
            GetClassAtInput {
                block_id: BlockId::Hash(block2_hash),
                contract_address: valid_v1,
            },
        )
        .await
        .unwrap();

        let block0_hash = StarknetBlockHash(felt_bytes!(b"genesis"));
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

        let invalid = ContractAddress::new_or_panic(felt_bytes!(b"invalid"));
        let latest_hash = StarknetBlockHash(felt_bytes!(b"latest"));
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
        let invalid_block = StarknetBlockHash(felt_bytes!(b"invalid"));
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
