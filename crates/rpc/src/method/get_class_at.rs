use anyhow::Context;
use pathfinder_common::{BlockId, ContractAddress};

use crate::context::RpcContext;
use crate::dto;
use crate::dto::SerializeForVersion;
use crate::types::{CairoContractClass, ContractClass, SierraContractClass};

crate::error::generate_rpc_error_subset!(Error: BlockNotFound, ContractNotFound);

#[derive(Debug, PartialEq, Eq)]
pub struct Input {
    block_id: pathfinder_common::BlockId,
    contract_address: pathfinder_common::ContractAddress,
}

impl crate::dto::DeserializeForVersion for Input {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                block_id: value.deserialize("block_id")?,
                contract_address: ContractAddress(value.deserialize("contract_address")?),
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

impl SerializeForVersion for Output {
    fn serialize(&self, serializer: dto::Serializer) -> Result<dto::Ok, dto::Error> {
        match self {
            Output::DeprecatedClass(cairo) => cairo.serialize(serializer),
            Output::Class(sierra) => sierra.serialize(serializer),
        }
    }
}

/// Get a contract class.
pub async fn get_class_at(context: RpcContext, input: Input) -> Result<Output, Error> {
    let span = tracing::Span::current();
    let jh = util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        let pending_class_hash = if input.block_id == BlockId::Pending {
            context
                .pending_data
                .get(&tx)
                .context("Querying pending data")?
                .state_update
                .contract_class(input.contract_address)
        } else {
            None
        };

        // Map block id to the storage variant.
        let block_id = match input.block_id {
            BlockId::Pending => pathfinder_storage::BlockId::Latest,
            other => other.try_into().expect("Only pending cast should fail"),
        };

        if !tx.block_exists(block_id)? {
            return Err(Error::BlockNotFound);
        }

        let class_hash = match pending_class_hash {
            Some(class_hash) => class_hash,
            None => tx
                .contract_class_hash(block_id, input.contract_address)
                .context("Querying contract's class hash")?
                .ok_or(Error::ContractNotFound)?,
        };

        let definition = tx
            .class_definition(class_hash)
            .context("Fetching class definition")?
            .context("Class definition missing from database")?;

        let class = ContractClass::from_definition_bytes(&definition)
            .context("Parsing class definition")?;

        Ok(class)
    });

    let class = jh.await.context("Reading class from database")??;
    Ok(Output::from(class))
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;

    use super::*;
    use crate::dto::{SerializeForVersion, Serializer};
    use crate::RpcVersion;

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
                contract_address: contract_address!("0x12345"),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            let named = json!({
                "block_id": { "block_hash": "0xabcde" },
                "contract_address": "0x12345"
            });

            let input = Input::deserialize(crate::dto::Value::new(named, RpcVersion::V07)).unwrap();
            let expected = Input {
                block_id: block_hash!("0xabcde").into(),
                contract_address: contract_address!("0x12345"),
            };
            assert_eq!(input, expected);
        }
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[tokio::test]
    async fn cairo_0(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests();
        let input = Input {
            block_id: BlockId::Latest,
            contract_address: contract_address_bytes!(b"contract 1"),
        };

        let output = get_class_at(context, input)
            .await
            .unwrap()
            .serialize(Serializer { version })
            .unwrap();

        crate::assert_json_matches_fixture!(output, version, "class_at/cairo0.json");
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[tokio::test]
    async fn cairo_1(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests();
        let input = Input {
            block_id: BlockId::Latest,
            contract_address: contract_address_bytes!(b"contract 2 (sierra)"),
        };

        let output = get_class_at(context, input)
            .await
            .unwrap()
            .serialize(Serializer { version })
            .unwrap();

        crate::assert_json_matches_fixture!(output, version, "class_at/sierra.json");
    }

    #[tokio::test]
    async fn contract_not_found() {
        let context = RpcContext::for_tests();
        let input = Input {
            block_id: BlockId::Latest,
            contract_address: contract_address_bytes!(b"invalid"),
        };

        let error = get_class_at(context, input).await.unwrap_err();
        assert_matches!(error, Error::ContractNotFound);
    }

    #[tokio::test]
    async fn block_not_found() {
        let context = RpcContext::for_tests();
        let input = Input {
            block_id: BlockId::Hash(block_hash_bytes!(b"invalid")),
            contract_address: contract_address_bytes!(b"contract 1"),
        };

        let error = get_class_at(context, input).await.unwrap_err();
        assert_matches!(error, Error::BlockNotFound);
    }
}
