use anyhow::Context;

pub struct GetNonce;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetNonceInput {
    block_id: crate::core::BlockId,
    contract_address: crate::core::ContractAddress,
}

crate::rpc_error_subset!(GetNonceError: BlockNotFound, ContractNotFound);

#[async_trait::async_trait]
impl super::RpcMethod for GetNonce {
    const NAME: &'static str = "starknet_getNonce";

    type Input = GetNonceInput;

    type Output = crate::core::ContractNonce;

    type Error = GetNonceError;

    async fn execute(
        context: std::sync::Arc<super::api::RpcApi>,
        input: Self::Input,
    ) -> Result<Self::Output, Self::Error> {
        use crate::state::state_tree::GlobalStateTree;
        use crate::storage::{StarknetBlocksBlockId, StarknetBlocksTable};

        // We can potentially read the nonce from pending without having to reach out to the database.
        use crate::core::BlockId;
        let block_id = match input.block_id {
            BlockId::Pending => {
                if let Some(pending) = context.pending_data.clone() {
                    if let Some(pending_state_update) = pending.state_update().await {
                        if let Some(nonce) = pending_state_update
                            .state_diff
                            .nonces
                            .get(&input.contract_address)
                        {
                            return Ok(*nonce);
                        }
                    }
                };

                StarknetBlocksBlockId::Latest
            }
            BlockId::Latest => StarknetBlocksBlockId::Latest,
            BlockId::Hash(hash) => hash.into(),
            BlockId::Number(number) => number.into(),
        };

        let storage = context.storage.clone();
        let span = tracing::Span::current();
        let jh = tokio::task::spawn_blocking(move || -> Result<Self::Output, Self::Error> {
            let _g = span.enter();
            let mut db = storage
                .connection()
                .context("Opening database connection")?;
            let tx = db.transaction().context("Creating database transaction")?;

            let global_root = StarknetBlocksTable::get_root(&tx, block_id)
                .context("Fetching global root")?
                .ok_or(Self::Error::BlockNotFound)?;

            let global_state_tree =
                GlobalStateTree::load(&tx, global_root).context("Loading global state tree")?;

            let state_hash = global_state_tree
                .get(input.contract_address)
                .context("Get contract state hash from global state tree")?;

            // There is a dedicated error code for a non-existent contract in the RPC API spec, so use it.
            if state_hash.0 == stark_hash::StarkHash::ZERO {
                return Err(Self::Error::ContractNotFound);
            }

            let nonce = crate::storage::ContractsStateTable::get_nonce(&tx, state_hash)
                .context("Reading contract nonce")?
                // Since the contract does exist, the nonce should not be missing.
                .context("Contract nonce is missing from database")?;

            Ok(nonce)
        });
        let result = jh.await.context("Database read panic or shutting down")?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::{
        core::{BlockId, ContractAddress},
        rpc::RpcMethod,
        state::SyncState,
    };
    use crate::{
        core::{Chain, StarknetBlockHash},
        rpc::api::RpcApi,
        starkhash,
    };
    use crate::{rpc::tests::setup_storage, starkhash_bytes};

    type SequencerClient = crate::sequencer::Client;

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

            let input = positional
                .parse::<<GetNonce as RpcMethod>::Input>()
                .unwrap();
            let expected = GetNonceInput {
                block_id: StarknetBlockHash(starkhash!("0abcde")).into(),
                contract_address: ContractAddress::new_or_panic(starkhash!("012345")),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            use jsonrpsee::types::Params;

            let positional = r#"{
                "block_id": { "block_hash": "0xabcde" },
                "contract_address": "0x12345"
            }"#;
            let positional = Params::new(Some(positional));

            let input = positional
                .parse::<<GetNonce as RpcMethod>::Input>()
                .unwrap();
            let expected = GetNonceInput {
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
            let storage = setup_storage();
            let sequencer = SequencerClient::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state.clone());
            let context = Arc::new(api);

            let input = GetNonceInput {
                block_id: BlockId::Latest,
                contract_address: ContractAddress::new_or_panic(starkhash_bytes!(b"invalid")),
            };

            let result = GetNonce::execute(context, input).await;

            assert_matches::assert_matches!(result, Err(GetNonceError::ContractNotFound));
        }

        #[tokio::test]
        async fn block_not_found() {
            use crate::core::StarknetBlockHash;

            let storage = setup_storage();
            let sequencer = SequencerClient::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state.clone());
            let context = Arc::new(api);

            let input = GetNonceInput {
                block_id: BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"invalid"))),
                // This contract does exist and is added in block 0.
                contract_address: ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0")),
            };

            let result = GetNonce::execute(context, input).await;

            assert_matches::assert_matches!(result, Err(GetNonceError::BlockNotFound));
        }
    }
}
