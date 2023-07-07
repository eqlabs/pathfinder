use crate::context::RpcContext;
use crate::felt::RpcFelt;
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
    // We can potentially read the nonce from pending without having to reach out to the database.
    let block_id = match input.block_id {
        BlockId::Pending => {
            match get_pending_nonce(&context.pending_data, input.contract_address).await {
                Some(nonce) => return Ok(GetNonceOutput(nonce)),
                None => pathfinder_storage::BlockId::Latest,
            }
        }
        other => other.try_into().expect("Only pending cast should fail"),
    };

    let contract_address = input.contract_address;

    let storage = context.storage.clone();
    let span = tracing::Span::current();
    let jh = tokio::task::spawn_blocking(move || -> Result<_, GetNonceError> {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Creating database transaction")?;

        // Check that block exists. This should occur first as the block number
        // isn't checked explicitly (i.e. nonce fetch just uses <= number).
        let block_exists = tx.block_exists(block_id).context("Checking block exists")?;
        if !block_exists {
            return Err(GetNonceError::BlockNotFound);
        }

        let nonce = tx
            .contract_nonce(contract_address, block_id)
            .context("Querying contract nonce from database")?;

        if let Some(nonce) = nonce {
            return Ok(GetNonceOutput(nonce));
        };

        // Check whether contract exists or not.
        let contract_exists = tx
            .contract_exists(contract_address, block_id)
            .context("Checking contract exists")?;

        if contract_exists {
            Ok(GetNonceOutput(ContractNonce::ZERO))
        } else {
            Err(GetNonceError::ContractNotFound)
        }
    });
    jh.await.context("Database read panic or shutting down")?
}

// 020CFA74EE3564B4CD5435CDACE0F9C4D43B939620E4A0BB5076105DF0A626C6

/// Returns the contract's pending nonce.
async fn get_pending_nonce(
    pending: &Option<PendingData>,
    contract_address: ContractAddress,
) -> Option<ContractNonce> {
    match pending {
        Some(pending) => pending.state_update().await.and_then(|update| {
            update
                .contract_updates
                .get(&contract_address)
                .and_then(|x| x.nonce)
        }),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{get_nonce, GetNonceError, GetNonceInput};
    use crate::context::RpcContext;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::StarknetVersion;
    use pathfinder_common::{BlockId, BlockNumber, BlockTimestamp, ContractNonce, GasPrice};

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
                block_id: block_hash!("0xabcde").into(),
                contract_address: contract_address!("0x12345"),
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
                block_id: block_hash!("0xabcde").into(),
                contract_address: contract_address!("0x12345"),
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
                contract_address: contract_address_bytes!(b"invalid"),
            };

            let result = get_nonce(context, input).await;

            assert_matches::assert_matches!(result, Err(GetNonceError::ContractNotFound));
        }

        #[tokio::test]
        async fn block_not_found() {
            let context = RpcContext::for_tests();

            let input = GetNonceInput {
                block_id: BlockId::Hash(block_hash_bytes!(b"invalid")),
                // This contract does exist and is added in block 0.
                contract_address: contract_address_bytes!(b"contract 0"),
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
            contract_address: contract_address_bytes!(b"contract 0"),
        };
        let nonce = get_nonce(context, input).await.unwrap();
        assert_eq!(nonce.0, contract_nonce!("0x1"));
    }

    #[tokio::test]
    async fn at_block() {
        let context = RpcContext::for_tests();

        // This contract is created in `setup_storage` at block 1,
        // but only gets nonce=0x10 explicitly set in block 2.
        let input = GetNonceInput {
            block_id: BlockNumber::new_or_panic(2).into(),
            contract_address: contract_address_bytes!(b"contract 1"),
        };
        let nonce = get_nonce(context, input).await.unwrap();
        assert_eq!(nonce.0, contract_nonce!("0x10"));
    }

    #[tokio::test]
    async fn pending_defaults_to_latest() {
        let context = RpcContext::for_tests();

        // This contract is created in `setup_storage` and has a nonce set to 0x1, and is not
        // overwritten in pending (since this test does not specify any pending data).
        let input = GetNonceInput {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"contract 0"),
        };
        let nonce = get_nonce(context, input).await.unwrap();
        assert_eq!(nonce.0, contract_nonce!("0x1"));
    }

    #[tokio::test]
    async fn defaults_to_zero() {
        let context = RpcContext::for_tests();

        // This contract is created in `setup_storage` at block 1,
        // but only gets a nonce explicitly set in block 2.
        let input = GetNonceInput {
            block_id: BlockNumber::new_or_panic(1).into(),
            contract_address: contract_address_bytes!(b"contract 1"),
        };
        let nonce = get_nonce(context, input).await.unwrap();

        assert_eq!(nonce.0, ContractNonce::ZERO);
    }

    #[tokio::test]
    async fn pending() {
        use super::get_pending_nonce;
        use std::sync::Arc;

        // The data this test actually cares about
        let valid_1 = contract_address_bytes!(b"i am valid");
        let valid_2 = contract_address_bytes!(b"valid as well");
        let nonce_1 = contract_nonce_bytes!(b"the nonce");
        let nonce_2 = contract_nonce_bytes!(b"other nonce");
        let invalid = contract_address_bytes!(b"not valid");

        // We don't care about this data, but it is required for setting up pending data.
        let block = starknet_gateway_types::reply::PendingBlock {
            gas_price: GasPrice(0),
            parent_hash: block_hash_bytes!(b"dont care"),
            sequencer_address: sequencer_address_bytes!(b"dont care"),
            status: starknet_gateway_types::reply::Status::Pending,
            timestamp: BlockTimestamp::new_or_panic(1234),
            transaction_receipts: Vec::new(),
            transactions: Vec::new(),
            starknet_version: StarknetVersion::default(),
        };
        let block = Arc::new(block);

        let state_update = pathfinder_common::StateUpdate::default()
            .with_contract_nonce(valid_1, nonce_1)
            .with_contract_nonce(valid_2, nonce_2);
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
