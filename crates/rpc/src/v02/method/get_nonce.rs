use crate::context::RpcContext;
use crate::felt::RpcFelt;
use anyhow::Context;
use pathfinder_common::{BlockId, ContractAddress, ContractNonce};

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
    let contract_address = input.contract_address;

    let span = tracing::Span::current();
    let jh = tokio::task::spawn_blocking(move || -> Result<_, GetNonceError> {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Creating database transaction")?;

        let block_id = match input.block_id {
            BlockId::Pending => {
                let pending_state_update = context
                    .pending_state_update(&tx)
                    .context("Querying pending state update")?;

                if let Some(pending_state_update) = pending_state_update {
                    let nonce = pending_state_update
                        .contract_updates
                        .get(&input.contract_address)
                        .and_then(|x| x.nonce);

                    if let Some(nonce) = nonce {
                        return Ok(GetNonceOutput(nonce));
                    }
                }

                pathfinder_storage::BlockId::Latest
            }
            other => other.try_into().expect("Only pending cast should fail"),
        };

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

#[cfg(test)]
mod tests {
    use super::{get_nonce, GetNonceError, GetNonceInput};
    use crate::context::RpcContext;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockId, BlockNumber, ContractNonce};

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
        let context = RpcContext::for_tests_with_pending().await;

        let input = GetNonceInput {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"pending contract 0 address"),
        };
        let nonce = get_nonce(context.clone(), input).await.unwrap();

        assert_eq!(nonce.0, contract_nonce!("0x123"));

        let input = GetNonceInput {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"invalid"),
        };
        let not_found = get_nonce(context, input).await.unwrap_err();
        assert_matches::assert_matches!(not_found, GetNonceError::ContractNotFound);
    }
}
