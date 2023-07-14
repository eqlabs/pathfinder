use crate::context::RpcContext;
use crate::felt::RpcFelt;
use anyhow::Context;
use pathfinder_common::{BlockId, ClassHash, ContractAddress};

crate::error::generate_rpc_error_subset!(GetClassHashAtError: BlockNotFound, ContractNotFound);

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetClassHashAtInput {
    block_id: BlockId,
    contract_address: ContractAddress,
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug)]
pub struct GetClassHashOutput(#[serde_as(as = "RpcFelt")] ClassHash);

pub async fn get_class_hash_at(
    context: RpcContext,
    input: GetClassHashAtInput,
) -> Result<GetClassHashOutput, GetClassHashAtError> {
    let span = tracing::Span::current();
    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        let block_id = match input.block_id {
            BlockId::Pending => {
                let pending_class = context
                    .pending_state_update(&tx)
                    .context("Querying pending state update")?
                    .and_then(|u| {
                        u.contract_updates
                            .get(&input.contract_address)
                            .and_then(|c| c.class.as_ref().map(|x| x.class_hash()))
                    });

                if let Some(class_hash) = pending_class {
                    return Ok(GetClassHashOutput(class_hash));
                }

                pathfinder_storage::BlockId::Latest
            }
            other => other.try_into().expect("Only pending cast should fail"),
        };

        // Check for block existence.
        if !tx.block_exists(block_id)? {
            return Err(GetClassHashAtError::BlockNotFound);
        }

        tx.contract_class_hash(block_id, input.contract_address)
            .context("Fetching class hash from database")?
            .ok_or(GetClassHashAtError::ContractNotFound)
            .map(GetClassHashOutput)
    });

    jh.await.context("Database read panic or shutting down")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    use pathfinder_common::macro_prelude::*;

    mod parsing {
        use super::*;
        use jsonrpsee::types::Params;

        #[test]
        fn positional_args() {
            let positional = r#"[
                { "block_hash": "0xabcde" },
                "0x12345"
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<GetClassHashAtInput>().unwrap();
            let expected = GetClassHashAtInput {
                block_id: block_hash!("0xabcde").into(),
                contract_address: contract_address!("0x12345"),
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

            let input = GetClassHashAtInput {
                block_id: BlockId::Latest,
                contract_address: contract_address_bytes!(b"invalid"),
            };
            let result = get_class_hash_at(context, input).await;
            assert_matches!(result, Err(GetClassHashAtError::ContractNotFound));
        }

        #[tokio::test]
        async fn block_not_found() {
            let context = RpcContext::for_tests();

            let input = GetClassHashAtInput {
                block_id: BlockId::Hash(block_hash_bytes!(b"invalid")),
                // This contract does exist and is added in block 0.
                contract_address: contract_address_bytes!(b"contract 0"),
            };
            let result = get_class_hash_at(context, input).await;
            assert_matches!(result, Err(GetClassHashAtError::BlockNotFound));
        }
    }

    #[tokio::test]
    async fn latest() {
        let context = RpcContext::for_tests();
        let expected = class_hash_bytes!(b"class 0 hash");

        let input = GetClassHashAtInput {
            block_id: BlockId::Latest,
            contract_address: contract_address_bytes!(b"contract 0"),
        };
        let result = get_class_hash_at(context, input).await.unwrap();
        assert_eq!(result.0, expected);
    }

    #[tokio::test]
    async fn at_block() {
        use pathfinder_common::BlockNumber;
        let context = RpcContext::for_tests();

        // This contract is deployed in block 1.
        let address = contract_address_bytes!(b"contract 1");

        let input = GetClassHashAtInput {
            block_id: BlockNumber::new_or_panic(0).into(),
            contract_address: address,
        };
        let result = get_class_hash_at(context.clone(), input).await;
        assert_matches!(result, Err(GetClassHashAtError::ContractNotFound));

        let expected = class_hash_bytes!(b"class 1 hash");
        let input = GetClassHashAtInput {
            block_id: BlockNumber::new_or_panic(1).into(),
            contract_address: address,
        };
        let result = get_class_hash_at(context.clone(), input).await.unwrap();
        assert_eq!(result.0, expected);

        let input = GetClassHashAtInput {
            block_id: BlockNumber::new_or_panic(2).into(),
            contract_address: address,
        };
        let result = get_class_hash_at(context, input).await.unwrap();
        assert_eq!(result.0, expected);
    }

    #[tokio::test]
    async fn pending_defaults_to_latest() {
        let context = RpcContext::for_tests();
        let expected = class_hash_bytes!(b"class 0 hash");

        let input = GetClassHashAtInput {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"contract 0"),
        };
        let result = get_class_hash_at(context, input).await.unwrap();
        assert_eq!(result.0, expected);
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;

        // This should still work even though it was deployed in an actual block.
        let expected = class_hash_bytes!(b"class 0 hash");
        let input = GetClassHashAtInput {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"contract 0"),
        };
        let result = get_class_hash_at(context.clone(), input).await.unwrap();
        assert_eq!(result.0, expected);

        // This is an actual pending deployed contract.
        let expected = class_hash_bytes!(b"pending class 0 hash");
        let input = GetClassHashAtInput {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"pending contract 0 address"),
        };
        let result = get_class_hash_at(context.clone(), input).await.unwrap();
        assert_eq!(result.0, expected);

        // Replaced class in pending should also work.
        let expected = class_hash_bytes!(b"pending class 2 hash (replaced)");
        let input = GetClassHashAtInput {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"pending contract 2 (replaced)"),
        };
        let result = get_class_hash_at(context.clone(), input).await.unwrap();
        assert_eq!(result.0, expected);

        // This one remains missing.
        let input = GetClassHashAtInput {
            block_id: BlockId::Latest,
            contract_address: contract_address_bytes!(b"invalid"),
        };
        let result = get_class_hash_at(context, input).await;
        assert_matches!(result, Err(GetClassHashAtError::ContractNotFound));
    }
}
