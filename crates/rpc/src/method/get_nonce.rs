use anyhow::Context;
use pathfinder_common::{BlockId, ContractAddress, ContractNonce};

use crate::context::RpcContext;

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
                contract_address: value.deserialize("contract_address").map(ContractAddress)?,
            })
        })
    }
}

#[derive(Debug)]
pub struct Output(ContractNonce);

crate::error::generate_rpc_error_subset!(Error: BlockNotFound, ContractNotFound);

pub async fn get_nonce(context: RpcContext, input: Input) -> Result<Output, Error> {
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || -> Result<_, Error> {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Creating database transaction")?;

        if input.block_id.is_pending() {
            if let Some(nonce) = context
                .pending_data
                .get(&tx)
                .context("Querying pending data")?
                .state_update
                .contract_nonce(input.contract_address)
            {
                return Ok(Output(nonce));
            }
        }

        let block_id = match input.block_id {
            BlockId::Pending => pathfinder_storage::BlockId::Latest,
            other => other.try_into().expect("Only pending cast should fail"),
        };

        // Check that block exists. This should occur first as the block number
        // isn't checked explicitly (i.e. nonce fetch just uses <= number).
        let block_exists = tx.block_exists(block_id).context("Checking block exists")?;
        if !block_exists {
            return Err(Error::BlockNotFound);
        }

        let nonce = tx
            .contract_nonce(input.contract_address, block_id)
            .context("Querying contract nonce from database")?;

        if let Some(nonce) = nonce {
            return Ok(Output(nonce));
        };

        // Early starknet contracts had no nonces, so its possible for a contract to
        // exist without having the nonce explicitly set to zero on deployment.
        let contract_exists = tx
            .contract_exists(input.contract_address, block_id)
            .context("Checking contract exists")?;

        if contract_exists {
            Ok(Output(ContractNonce::ZERO))
        } else {
            Err(Error::ContractNotFound)
        }
    })
    .await
    .context("Joining blocking task")?
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        serializer.serialize(&crate::dto::Felt(&self.0 .0))
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockId, BlockNumber, ContractNonce};

    use super::{get_nonce, Error, Input};
    use crate::context::RpcContext;

    #[tokio::test]
    async fn contract_not_found() {
        let context = RpcContext::for_tests();

        let input = Input {
            block_id: BlockId::Latest,
            contract_address: contract_address_bytes!(b"invalid"),
        };

        let result = get_nonce(context, input).await;

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

        let result = get_nonce(context, input).await;

        assert_matches!(result, Err(Error::BlockNotFound));
    }

    #[tokio::test]
    async fn latest() {
        let context = RpcContext::for_tests();

        // This contract is created in `setup_storage` and has a nonce set to 0x1.
        let input = Input {
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
        let input = Input {
            block_id: BlockNumber::new_or_panic(2).into(),
            contract_address: contract_address_bytes!(b"contract 1"),
        };
        let nonce = get_nonce(context, input).await.unwrap();
        assert_eq!(nonce.0, contract_nonce!("0x10"));
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;

        // This contract is created in `setup_storage` and has a nonce set in the
        // pending block.
        let input = Input {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"contract 1"),
        };
        let nonce = get_nonce(context, input).await.unwrap();
        assert_eq!(nonce.0, contract_nonce_bytes!(b"pending nonce"));
    }

    #[tokio::test]
    async fn pending_defaults_to_latest() {
        let context = RpcContext::for_tests();

        // This contract is created in `setup_storage` and has a nonce set to 0x1, and
        // is not overwritten in pending (since this test does not specify any
        // pending data).
        let input = Input {
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
        let input = Input {
            block_id: BlockNumber::new_or_panic(1).into(),
            contract_address: contract_address_bytes!(b"contract 1"),
        };
        let nonce = get_nonce(context, input).await.unwrap();

        assert_eq!(nonce.0, ContractNonce::ZERO);
    }

    #[tokio::test]
    async fn contract_deployed_in_pending_defaults_to_zero() {
        let context = RpcContext::for_tests_with_pending().await;

        // This contract is deployed in the pending block but does not have a nonce
        // update.
        let input = Input {
            block_id: BlockId::Pending,
            contract_address: contract_address_bytes!(b"pending contract 0 address"),
        };
        let nonce = get_nonce(context, input).await.unwrap();
        assert_eq!(nonce.0, ContractNonce::ZERO);
    }
}
