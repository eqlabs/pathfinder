use crate::context::RpcContext;
use crate::v02::types::ContractClass;
use anyhow::Context;
use pathfinder_common::{BlockId, ClassHash};
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
    let (block_id, is_pending) = match input.block_id {
        BlockId::Pending => {
            let latest = pathfinder_storage::BlockId::Latest;
            let is_pending = is_pending_class(&context.pending_data, input.class_hash).await;
            (latest, is_pending)
        }
        other => (
            other.try_into().expect("Only pending cast should fail"),
            false,
        ),
    };

    let span = tracing::Span::current();
    let jh = tokio::task::spawn_blocking(move || -> Result<ContractClass, GetClassError> {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Creating database transaction")?;

        // Check that block exists
        let block_exists = tx.block_exists(block_id)?;
        if !block_exists {
            return Err(GetClassError::BlockNotFound);
        }

        // If the class is declared in the pending block, then we shouldn't check the class's
        // declaration point.
        let definition = if is_pending {
            tx.class_definition(input.class_hash)
        } else {
            tx.class_definition_at(block_id, input.class_hash)
        }
        .context("Fetching class definition")?;

        let Some(definition) = definition else {
            return Err(GetClassError::ClassHashNotFound);
        };

        let class = ContractClass::from_definition_bytes(&definition)
            .context("Parsing class definition")?;

        Ok(class)
    });

    jh.await.context("Reading class from database")?
}

/// Returns true if the class is declared in the pending state.
async fn is_pending_class(pending: &Option<PendingData>, hash: ClassHash) -> bool {
    let state_diff = match pending {
        Some(pending) => match pending.state_update().await {
            Some(pending) => pending,
            None => return false,
        },
        None => return false,
    };

    let cairo = state_diff.declared_cairo_classes.iter().cloned();
    let sierra = state_diff
        .declared_sierra_classes
        .keys()
        .map(|sierra| ClassHash(sierra.0));

    cairo.chain(sierra).any(|item| item == hash)
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

            let input = positional.parse::<GetClassInput>().unwrap();
            let expected = GetClassInput {
                block_id: block_hash!("0xabcde").into(),
                class_hash: class_hash!("0x12345"),
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
                block_id: block_hash!("0xabcde").into(),
                class_hash: class_hash!("0x12345"),
            };
            assert_eq!(input, expected);
        }
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests();

        // Cairo v0.x class
        let valid_v0 = class_hash_bytes!(b"class 0 hash");
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
        let valid_v1 = class_hash_bytes!(b"class 2 hash (sierra)");
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Pending,
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap();

        let invalid = class_hash_bytes!(b"invalid");
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
        let valid_v0 = class_hash_bytes!(b"class 0 hash");
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
        let valid_v1 = class_hash_bytes!(b"class 2 hash (sierra)");
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Latest,
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap();

        let invalid = class_hash_bytes!(b"invalid");
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

        // This class is defined, but is not declared in any canonical block, such
        // as what may occur for a pending class declaration.
        let undeclared = class_hash_bytes!(b"class pending hash");
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Latest,
                class_hash: undeclared,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);
    }

    #[tokio::test]
    async fn at_number() {
        use pathfinder_common::BlockNumber;

        let context = RpcContext::for_tests();

        // Cairo v0.x class
        // This class is declared in block 0.
        let valid_v0 = class_hash_bytes!(b"class 0 hash");
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
                class_hash: valid_v0,
            },
        )
        .await
        .unwrap();

        // Cairo v1.x class (Sierra)
        // This class is declared in block 2.
        let valid_v1 = class_hash_bytes!(b"class 2 hash (sierra)");
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Number(BlockNumber::new_or_panic(2)),
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap();

        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Number(BlockNumber::GENESIS),
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        let invalid = class_hash_bytes!(b"invalid");
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Number(BlockNumber::new_or_panic(2)),
                class_hash: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // This class is defined, but is not declared in any canonical block, such
        // as what may occur for a pending class declaration.
        let undeclared = class_hash_bytes!(b"class pending hash");
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Number(BlockNumber::new_or_panic(2)),
                class_hash: undeclared,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // Class exists, but block number does not.
        let valid = class_hash_bytes!(b"class 0 hash");
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Number(BlockNumber::MAX),
                class_hash: valid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::BlockNotFound);
    }

    #[tokio::test]
    async fn read_at_hash() {
        let context = RpcContext::for_tests();

        // Cairo v0.x class
        // This class is declared in block 1.
        let valid_v0 = class_hash_bytes!(b"class 0 hash");
        let block1_hash = block_hash_bytes!(b"block 1");
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
        let valid_v1 = class_hash_bytes!(b"class 2 hash (sierra)");
        let block2_hash = block_hash_bytes!(b"latest");
        super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Hash(block2_hash),
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap();

        let block0_hash = block_hash_bytes!(b"genesis");
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Hash(block0_hash),
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        let invalid = class_hash_bytes!(b"invalid");
        let latest_hash = block_hash_bytes!(b"latest");
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
        let undeclared = class_hash_bytes!(b"class pending hash");
        let latest_hash = block_hash_bytes!(b"latest");
        let error = super::get_class(
            context.clone(),
            GetClassInput {
                block_id: BlockId::Hash(latest_hash),
                class_hash: undeclared,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, GetClassError::ClassHashNotFound);

        // Class exists, but block hash does not.
        let valid = class_hash_bytes!(b"class 0 hash");
        let invalid_block = block_hash_bytes!(b"invalid");
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
