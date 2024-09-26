use anyhow::Context;
use pathfinder_common::{BlockId, ClassHash};

use crate::context::RpcContext;
use crate::dto;
use crate::dto::serialize::SerializeForVersion;
use crate::v02::types::{CairoContractClass, ContractClass, SierraContractClass};

crate::error::generate_rpc_error_subset!(Error: BlockNotFound, ClassHashNotFound);

#[derive(Debug, PartialEq, Eq)]
pub struct Input {
    block_id: BlockId,
    class_hash: ClassHash,
}

impl crate::dto::DeserializeForVersion for Input {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                block_id: value.deserialize("block_id")?,
                class_hash: ClassHash(value.deserialize("class_hash")?),
            })
        })
    }
}

#[derive(Debug)]
pub enum Output {
    DeprecatedClass(CairoContractClass),
    Class(SierraContractClass),
}

impl From<ContractClass> for Output {
    fn from(value: ContractClass) -> Self {
        match value {
            ContractClass::Cairo(x) => Self::DeprecatedClass(x),
            ContractClass::Sierra(x) => Self::Class(x),
        }
    }
}

pub async fn get_class(context: RpcContext, input: Input) -> Result<Output, Error> {
    let span = tracing::Span::current();
    let jh = tokio::task::spawn_blocking(move || -> Result<Output, Error> {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Creating database transaction")?;

        let is_pending = if input.block_id.is_pending() {
            context
                .pending_data
                .get(&tx)
                .context("Querying pending data")?
                .state_update
                .class_is_declared(input.class_hash)
        } else {
            false
        };

        // Map block id to the storage variant.
        let block_id = match input.block_id {
            BlockId::Pending => pathfinder_storage::BlockId::Latest,
            other => other.try_into().expect("Only pending cast should fail"),
        };

        // Check that block exists
        let block_exists = tx.block_exists(block_id)?;
        if !block_exists {
            return Err(Error::BlockNotFound);
        }

        // If the class is declared in the pending block, then we shouldn't check the
        // class's declaration point.
        let definition = if is_pending {
            tx.class_definition(input.class_hash)
        } else {
            tx.class_definition_at(block_id, input.class_hash)
        }
        .context("Fetching class definition")?;

        let Some(definition) = definition else {
            return Err(Error::ClassHashNotFound);
        };

        let class = ContractClass::from_definition_bytes(&definition)
            .context("Parsing class definition")?
            .into();

        Ok(class)
    });

    jh.await.context("Reading class from database")?
}

impl SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: dto::serialize::Serializer,
    ) -> Result<dto::serialize::Ok, dto::serialize::Error> {
        match self {
            Output::DeprecatedClass(cairo) => {
                dto::DeprecatedContractClass(cairo).serialize(serializer)
            }
            Output::Class(sierra) => dto::ContractClass(sierra).serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;

    use super::*;

    mod parsing {
        use dto::DeserializeForVersion;
        use serde_json::json;

        use super::*;
        use crate::RpcVersion;

        #[test]
        fn positional_args() {
            let positional = json!([
                { "block_hash": "0xabcde" },
                "0x12345"
            ]);

            let input =
                Input::deserialize(crate::dto::Value::new(positional, RpcVersion::V07)).unwrap();
            let expected = Input {
                block_id: block_hash!("0xabcde").into(),
                class_hash: class_hash!("0x12345"),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            let named = json!({
                "block_id": { "block_hash": "0xabcde" },
                "class_hash": "0x12345"
            });

            let input = Input::deserialize(crate::dto::Value::new(named, RpcVersion::V07)).unwrap();
            let expected = Input {
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
            Input {
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
            Input {
                block_id: BlockId::Pending,
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap();

        let invalid = class_hash_bytes!(b"invalid");
        let error = super::get_class(
            context,
            Input {
                block_id: BlockId::Pending,
                class_hash: invalid,
            },
        )
        .await
        .unwrap_err();

        assert_matches!(error, Error::ClassHashNotFound);
    }

    #[tokio::test]
    async fn latest() {
        let context = RpcContext::for_tests();

        // Cairo v0.x class
        let valid_v0 = class_hash_bytes!(b"class 0 hash");
        super::get_class(
            context.clone(),
            Input {
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
            Input {
                block_id: BlockId::Latest,
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap();

        let invalid = class_hash_bytes!(b"invalid");
        let error = super::get_class(
            context.clone(),
            Input {
                block_id: BlockId::Latest,
                class_hash: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, Error::ClassHashNotFound);

        // This class is defined, but is not declared in any canonical block, such
        // as what may occur for a pending class declaration.
        let undeclared = class_hash_bytes!(b"class pending hash");
        let error = super::get_class(
            context.clone(),
            Input {
                block_id: BlockId::Latest,
                class_hash: undeclared,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, Error::ClassHashNotFound);
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
            Input {
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
            Input {
                block_id: BlockId::Number(BlockNumber::new_or_panic(2)),
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap();

        let error = super::get_class(
            context.clone(),
            Input {
                block_id: BlockId::Number(BlockNumber::GENESIS),
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, Error::ClassHashNotFound);

        let invalid = class_hash_bytes!(b"invalid");
        let error = super::get_class(
            context.clone(),
            Input {
                block_id: BlockId::Number(BlockNumber::new_or_panic(2)),
                class_hash: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, Error::ClassHashNotFound);

        // This class is defined, but is not declared in any canonical block, such
        // as what may occur for a pending class declaration.
        let undeclared = class_hash_bytes!(b"class pending hash");
        let error = super::get_class(
            context.clone(),
            Input {
                block_id: BlockId::Number(BlockNumber::new_or_panic(2)),
                class_hash: undeclared,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, Error::ClassHashNotFound);

        // Class exists, but block number does not.
        let valid = class_hash_bytes!(b"class 0 hash");
        let error = super::get_class(
            context.clone(),
            Input {
                block_id: BlockId::Number(BlockNumber::MAX),
                class_hash: valid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, Error::BlockNotFound);
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
            Input {
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
            Input {
                block_id: BlockId::Hash(block2_hash),
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap();

        let block0_hash = block_hash_bytes!(b"genesis");
        let error = super::get_class(
            context.clone(),
            Input {
                block_id: BlockId::Hash(block0_hash),
                class_hash: valid_v1,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, Error::ClassHashNotFound);

        let invalid = class_hash_bytes!(b"invalid");
        let latest_hash = block_hash_bytes!(b"latest");
        let error = super::get_class(
            context.clone(),
            Input {
                block_id: BlockId::Hash(latest_hash),
                class_hash: invalid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, Error::ClassHashNotFound);

        // This class is defined, but is not declared in any canonical block.
        let undeclared = class_hash_bytes!(b"class pending hash");
        let latest_hash = block_hash_bytes!(b"latest");
        let error = super::get_class(
            context.clone(),
            Input {
                block_id: BlockId::Hash(latest_hash),
                class_hash: undeclared,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, Error::ClassHashNotFound);

        // Class exists, but block hash does not.
        let valid = class_hash_bytes!(b"class 0 hash");
        let invalid_block = block_hash_bytes!(b"invalid");
        let error = super::get_class(
            context.clone(),
            Input {
                block_id: BlockId::Hash(invalid_block),
                class_hash: valid,
            },
        )
        .await
        .unwrap_err();
        assert_matches!(error, Error::BlockNotFound);
    }
}
