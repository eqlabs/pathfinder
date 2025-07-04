use anyhow::Context;
use pathfinder_common::{BlockId, ClassHash, ContractAddress};

use crate::context::RpcContext;
use crate::RpcVersion;

crate::error::generate_rpc_error_subset!(Error: BlockNotFound, ContractNotFound);

#[derive(Debug, PartialEq, Eq)]
pub struct Input {
    block_id: BlockId,
    contract_address: ContractAddress,
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
pub struct Output(ClassHash);

pub async fn get_class_hash_at(
    context: RpcContext,
    input: Input,
    rpc_version: RpcVersion,
) -> Result<Output, Error> {
    let span = tracing::Span::current();
    util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        if input.block_id == BlockId::Pending {
            let pending = context
                .pending_data
                .get(&tx, rpc_version)
                .context("Querying pending data")?
                .state_update()
                .contract_class(input.contract_address);

            if let Some(pending) = pending {
                return Ok(Output(pending));
            }
        }

        let block_id = input.block_id.to_finalized_coerced();
        if !tx.block_exists(block_id)? {
            return Err(Error::BlockNotFound);
        }

        // Check for block existence.
        if !tx.block_exists(block_id)? {
            return Err(Error::BlockNotFound);
        }

        tx.contract_class_hash(block_id, input.contract_address)
            .context("Fetching class hash from database")?
            .ok_or(Error::ContractNotFound)
            .map(Output)
    })
    .await
    .context("Joining blocking task")?
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;

    use super::*;
    use crate::RpcVersion;

    mod parsing {
        use serde_json::json;

        use super::*;
        use crate::dto::DeserializeForVersion;
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

    const RPC_VERSION: RpcVersion = RpcVersion::V09;

    mod errors {
        use super::*;

        #[tokio::test]
        async fn contract_not_found() {
            let context = RpcContext::for_tests();

            let input = Input {
                block_id: BlockId::Latest,
                contract_address: contract_address_bytes!(b"invalid"),
            };
            let result = get_class_hash_at(context, input, RPC_VERSION).await;
            assert_matches!(result, Err(Error::ContractNotFound));
        }

        #[tokio::test]
        async fn block_not_found() {
            let context = RpcContext::for_tests();

            let input = Input {
                block_id: BlockId::Hash(block_hash_bytes!(b"invalid")),
                // This contract does exist and is added in block 0.
                contract_address: contract_address_bytes!(b"contract 0"),
            };
            let result = get_class_hash_at(context, input, RPC_VERSION).await;
            assert_matches!(result, Err(Error::BlockNotFound));
        }
    }

    #[tokio::test]
    async fn latest() {
        let context = RpcContext::for_tests();
        let expected = class_hash_bytes!(b"class 0 hash");

        let input = Input {
            block_id: BlockId::Latest,
            contract_address: contract_address_bytes!(b"contract 0"),
        };
        let result = get_class_hash_at(context, input, RPC_VERSION)
            .await
            .unwrap();
        assert_eq!(result.0, expected);
    }

    #[tokio::test]
    async fn at_block() {
        use pathfinder_common::BlockNumber;
        let context = RpcContext::for_tests();

        // This contract is deployed in block 1.
        let address = contract_address_bytes!(b"contract 1");

        let input = Input {
            block_id: BlockNumber::new_or_panic(0).into(),
            contract_address: address,
        };
        let result = get_class_hash_at(context.clone(), input, RPC_VERSION).await;
        assert_matches!(result, Err(Error::ContractNotFound));

        let expected = class_hash_bytes!(b"class 1 hash");
        let input = Input {
            block_id: BlockNumber::new_or_panic(1).into(),
            contract_address: address,
        };
        let result = get_class_hash_at(context.clone(), input, RPC_VERSION)
            .await
            .unwrap();
        assert_eq!(result.0, expected);

        let input = Input {
            block_id: BlockNumber::new_or_panic(2).into(),
            contract_address: address,
        };
        let result = get_class_hash_at(context, input, RPC_VERSION)
            .await
            .unwrap();
        assert_eq!(result.0, expected);
    }

    #[tokio::test]
    async fn pending_defaults_to_latest() {
        let context = RpcContext::for_tests();
        let expected = class_hash_bytes!(b"class 0 hash");

        let input = Input {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"contract 0"),
        };
        let result = get_class_hash_at(context, input, RPC_VERSION)
            .await
            .unwrap();
        assert_eq!(result.0, expected);
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;

        // This should still work even though it was deployed in an actual block.
        let expected = class_hash_bytes!(b"class 0 hash");
        let input = Input {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"contract 0"),
        };
        let result = get_class_hash_at(context.clone(), input, RPC_VERSION)
            .await
            .unwrap();
        assert_eq!(result.0, expected);

        // This is an actual pending deployed contract.
        let expected = class_hash_bytes!(b"pending class 0 hash");
        let input = Input {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"pending contract 0 address"),
        };
        let result = get_class_hash_at(context.clone(), input, RPC_VERSION)
            .await
            .unwrap();
        assert_eq!(result.0, expected);

        // Replaced class in pending should also work.
        let expected = class_hash_bytes!(b"pending class 2 hash (replaced)");
        let input = Input {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"pending contract 2 (replaced)"),
        };
        let result = get_class_hash_at(context.clone(), input, RPC_VERSION)
            .await
            .unwrap();
        assert_eq!(result.0, expected);

        // This one remains missing.
        let input = Input {
            block_id: BlockId::Latest,
            contract_address: contract_address_bytes!(b"invalid"),
        };
        let result = get_class_hash_at(context, input, RPC_VERSION).await;
        assert_matches!(result, Err(Error::ContractNotFound));
    }
    use crate::dto::{SerializeForVersion, Serializer};

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[case::v09(RpcVersion::V09)]
    #[tokio::test]
    async fn json_rpc_latest(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests();
        let input = Input {
            block_id: BlockId::Latest,
            contract_address: contract_address_bytes!(b"contract 0"),
        };

        let output = get_class_hash_at(context, input, RPC_VERSION)
            .await
            .unwrap()
            .serialize(Serializer { version })
            .unwrap();

        crate::assert_json_matches_fixture!(output, version, "class_hash/latest.json");
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[case::v09(RpcVersion::V09)]
    #[tokio::test]
    async fn json_rpc_pending(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests_with_pending().await;
        let input = Input {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"pending contract 0 address"),
        };

        let output = get_class_hash_at(context, input, RPC_VERSION)
            .await
            .unwrap()
            .serialize(Serializer { version })
            .unwrap();

        crate::assert_json_matches_fixture!(output, version, "class_hash/pending.json");
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[case::v09(RpcVersion::V09)]
    #[tokio::test]
    async fn json_rpc_at_block(#[case] version: RpcVersion) {
        use pathfinder_common::BlockNumber;

        let context = RpcContext::for_tests();
        let input = Input {
            block_id: BlockNumber::new_or_panic(1).into(),
            contract_address: contract_address_bytes!(b"contract 1"),
        };

        let output = get_class_hash_at(context, input, RPC_VERSION)
            .await
            .unwrap()
            .serialize(Serializer { version })
            .unwrap();

        crate::assert_json_matches_fixture!(output, version, "class_hash/at_block.json");
    }

    #[tokio::test]
    async fn error_contract_not_found() {
        let context = RpcContext::for_tests();
        let input = Input {
            block_id: BlockId::Latest,
            contract_address: contract_address_bytes!(b"invalid"),
        };

        let error = get_class_hash_at(context, input, RPC_VERSION)
            .await
            .unwrap_err();
        assert_matches!(error, Error::ContractNotFound);
    }
}
