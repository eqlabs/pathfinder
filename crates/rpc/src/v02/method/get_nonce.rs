use crate::felt::RpcFelt;
use crate::v02::RpcContext;
use anyhow::Context;
use pathfinder_common::{BlockId, ContractAddress, ContractNonce};
use starknet_gateway_types::pending::PendingData;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetNonceInput {
    block_id: BlockId,
    contract_address: ContractAddress,
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug, PartialEq)]
pub struct GetNonceOutput(#[serde_as(as = "RpcFelt")] ContractNonce);

crate::error::generate_rpc_error_subset!(GetNonceError: BlockNotFound, ContractNotFound);

pub async fn get_nonce(
    context: RpcContext,
    input: GetNonceInput,
) -> Result<GetNonceOutput, GetNonceError> {
    use pathfinder_merkle_tree::state_tree::StorageCommitmentTree;
    use pathfinder_storage::{ContractsStateTable, StarknetBlocksBlockId, StarknetBlocksTable};

    // We can potentially read the nonce from pending without having to reach out to the database.
    let block_id = match input.block_id {
        BlockId::Pending => {
            match get_pending_nonce(&context.pending_data, input.contract_address).await {
                Some(nonce) => return Ok(GetNonceOutput(nonce)),
                None => StarknetBlocksBlockId::Latest,
            }
        }
        BlockId::Latest => StarknetBlocksBlockId::Latest,
        BlockId::Hash(hash) => hash.into(),
        BlockId::Number(number) => number.into(),
    };

    let storage = context.storage.clone();
    let span = tracing::Span::current();
    let jh = tokio::task::spawn_blocking(move || -> Result<_, GetNonceError> {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Creating database transaction")?;

        let storage_commitment = StarknetBlocksTable::get_storage_commitment(&tx, block_id)
            .context("Fetching storage commitment")?
            .ok_or(GetNonceError::BlockNotFound)?;

        let storage_commitment_tree = StorageCommitmentTree::load(&tx, storage_commitment)
            .context("Loading storage commitment tree")?;

        let state_hash = storage_commitment_tree
            .get(input.contract_address)
            .context("Get contract state hash from storage commitment tree")?
            .ok_or(GetNonceError::ContractNotFound)?;

        let nonce = ContractsStateTable::get_nonce(&tx, state_hash)
            .context("Reading contract nonce")?
            // Since the contract does exist, the nonce should not be missing.
            .context("Contract nonce is missing from database")?;

        Ok(GetNonceOutput(nonce))
    });
    jh.await.context("Database read panic or shutting down")?
}

/// Returns the contract's pending nonce.
async fn get_pending_nonce(
    pending: &Option<PendingData>,
    contract_address: ContractAddress,
) -> Option<ContractNonce> {
    match pending {
        Some(pending) => pending
            .state_update()
            .await
            .and_then(|update| update.state_diff.nonces.get(&contract_address).copied()),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{get_nonce, GetNonceError, GetNonceInput};
    use crate::v02::RpcContext;
    use pathfinder_common::{felt, felt_bytes};
    use pathfinder_common::{
        BlockId, ContractAddress, ContractNonce, GasPrice, SequencerAddress, StarknetBlockHash,
        StarknetBlockNumber, StarknetBlockTimestamp, StateCommitment,
    };

    mod parsing {
        use super::*;

        #[test]
        fn positional_args() {
            use jsonrpsee::types::Params;

            let positional = r#"[
                { "block_hash": "0xabcde" },
                "0x12345"
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<GetNonceInput>().unwrap();
            let expected = GetNonceInput {
                block_id: StarknetBlockHash(felt!("0xabcde")).into(),
                contract_address: ContractAddress::new_or_panic(felt!("0x12345")),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            use jsonrpsee::types::Params;

            let named = r#"{
                "block_id": { "block_hash": "0xabcde" },
                "contract_address": "0x12345"
            }"#;
            let named = Params::new(Some(named));

            let input = named.parse::<GetNonceInput>().unwrap();
            let expected = GetNonceInput {
                block_id: StarknetBlockHash(felt!("0xabcde")).into(),
                contract_address: ContractAddress::new_or_panic(felt!("0x12345")),
            };
            assert_eq!(input, expected);
        }
    }

    mod errors {
        use super::*;

        #[tokio::test]
        async fn contract_not_found() {
            let context = RpcContext::for_tests();

            let input = GetNonceInput {
                block_id: BlockId::Latest,
                contract_address: ContractAddress::new_or_panic(felt_bytes!(b"invalid")),
            };

            let result = get_nonce(context, input).await;

            assert_matches::assert_matches!(result, Err(GetNonceError::ContractNotFound));
        }

        #[tokio::test]
        async fn block_not_found() {
            use pathfinder_common::StarknetBlockHash;

            let context = RpcContext::for_tests();

            let input = GetNonceInput {
                block_id: BlockId::Hash(StarknetBlockHash(felt_bytes!(b"invalid"))),
                // This contract does exist and is added in block 0.
                contract_address: ContractAddress::new_or_panic(felt_bytes!(b"contract 0")),
            };

            let result = get_nonce(context, input).await;

            assert_matches::assert_matches!(result, Err(GetNonceError::BlockNotFound));
        }
    }

    #[tokio::test]
    async fn latest() {
        let context = RpcContext::for_tests();

        // This contract is created in `setup_storage` and has a nonce set to 0x1.
        let input = GetNonceInput {
            block_id: BlockId::Latest,
            contract_address: ContractAddress::new_or_panic(felt_bytes!(b"contract 0")),
        };
        let nonce = get_nonce(context, input).await.unwrap();
        assert_eq!(nonce.0, ContractNonce(felt!("0x1")));
    }

    #[tokio::test]
    async fn at_block() {
        let context = RpcContext::for_tests();

        // This contract is created in `setup_storage` at block 1,
        // but only gets nonce=0x10 explicitly set in block 2.
        let input = GetNonceInput {
            block_id: StarknetBlockNumber::new_or_panic(2).into(),
            contract_address: ContractAddress::new_or_panic(felt_bytes!(b"contract 1")),
        };
        let nonce = get_nonce(context, input).await.unwrap();
        assert_eq!(nonce.0, ContractNonce(felt!("0x10")));
    }

    #[tokio::test]
    async fn pending_defaults_to_latest() {
        let context = RpcContext::for_tests();

        // This contract is created in `setup_storage` and has a nonce set to 0x1, and is not
        // overwritten in pending (since this test does not specify any pending data).
        let input = GetNonceInput {
            block_id: BlockId::Pending,
            contract_address: ContractAddress::new_or_panic(felt_bytes!(b"contract 0")),
        };
        let nonce = get_nonce(context, input).await.unwrap();
        assert_eq!(nonce.0, ContractNonce(felt!("0x1")));
    }

    #[tokio::test]
    async fn defaults_to_zero() {
        let context = RpcContext::for_tests();

        // This contract is created in `setup_storage` at block 1,
        // but only gets a nonce explicitly set in block 2.
        let input = GetNonceInput {
            block_id: StarknetBlockNumber::new_or_panic(1).into(),
            contract_address: ContractAddress::new_or_panic(felt_bytes!(b"contract 1")),
        };
        let nonce = get_nonce(context, input).await.unwrap();
        assert_eq!(nonce.0, ContractNonce::ZERO);
    }

    #[tokio::test]
    async fn pending() {
        use super::get_pending_nonce;
        use std::sync::Arc;

        // The data this test actually cares about
        let valid_1 = ContractAddress::new_or_panic(felt_bytes!(b"i am valid"));
        let valid_2 = ContractAddress::new_or_panic(felt_bytes!(b"valid as well"));
        let nonce_1 = ContractNonce(felt_bytes!(b"the nonce"));
        let nonce_2 = ContractNonce(felt_bytes!(b"other nonce"));
        let invalid = ContractAddress::new_or_panic(felt_bytes!(b"not valid"));

        // We don't care about this data, but it is required for setting up pending data.
        let block = starknet_gateway_types::reply::PendingBlock {
            gas_price: GasPrice(0),
            parent_hash: StarknetBlockHash(felt_bytes!(b"dont care")),
            sequencer_address: SequencerAddress(felt_bytes!(b"dont care")),
            status: starknet_gateway_types::reply::Status::Pending,
            timestamp: StarknetBlockTimestamp::new_or_panic(1234),
            transaction_receipts: Vec::new(),
            transactions: Vec::new(),
            starknet_version: None,
        };
        let block = Arc::new(block);

        // We only care about the nonce data, but the rest is required for setting up pending data.
        let state_update = starknet_gateway_types::reply::PendingStateUpdate {
            old_root: StateCommitment(felt_bytes!(b"dont care")),
            state_diff: starknet_gateway_types::reply::state_update::StateDiff {
                storage_diffs: std::collections::HashMap::new(),
                deployed_contracts: Vec::new(),
                old_declared_contracts: Vec::new(),
                declared_classes: Vec::new(),
                nonces: [(valid_1, nonce_1), (valid_2, nonce_2)]
                    .into_iter()
                    .collect(),
                replaced_classes: Vec::new(),
            },
        };
        let state_update = Arc::new(state_update);

        let pending_data = starknet_gateway_types::pending::PendingData::default();
        pending_data.set(block, state_update).await;
        let pending_data = Some(pending_data);

        let result = get_pending_nonce(&pending_data, valid_1).await;
        assert_eq!(result, Some(nonce_1));

        let result = get_pending_nonce(&pending_data, valid_2).await;
        assert_eq!(result, Some(nonce_2));

        let result = get_pending_nonce(&pending_data, invalid).await;
        assert_eq!(result, None);

        let result = get_pending_nonce(&None, valid_1).await;
        assert_eq!(result, None);
    }
}
