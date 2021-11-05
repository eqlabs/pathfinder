use web3::{
    contract::tokens::Tokenizable,
    ethabi::Token,
    types::{H160, H256, U256},
};

use anyhow::{Context, Result};

use crate::ethereum::starknet::{ContractUpdate, DeployedContract, StorageUpdate};

/// Extension trait which adds parsing of Ethereum [Tokens](Token) into
/// common types required by StarkNet Mempages and Facts.
///
/// This is implemented for [Iterator<Item = Token>] for ease of use.
pub trait MempageParsingExt {
    fn get_next_token(&mut self) -> Result<Token>;

    fn parse_u256(&mut self) -> Result<U256> {
        self.get_next_token()?
            .into_uint()
            .context("token could not be cast to U256")
    }

    fn parse_address(&mut self) -> Result<H160> {
        self.get_next_token()?
            .into_address()
            .context("token could not be cast to address")
    }

    fn parse_hash(&mut self) -> Result<H256> {
        let token = self.get_next_token()?;
        H256::from_token(token).context("token could not be cast to hash")
    }

    fn parse_deployed_contract(&mut self) -> Result<DeployedContract> {
        let address = self.parse_address().context("contract address")?;
        let hash = self.parse_hash().context("contract hash")?;
        let call_data_length = self.parse_u256().context("call data length")?.as_usize();

        let mut call_data = Vec::with_capacity(call_data_length);
        for i in 0..call_data_length {
            let data = self
                .parse_u256()
                .with_context(|| format!("call data {} of {}", i, call_data_length))?;
            call_data.push(data);
        }

        Ok(DeployedContract {
            address,
            hash,
            call_data,
        })
    }

    fn parse_contract_update(&mut self) -> Result<ContractUpdate> {
        let address = self.parse_address().context("contract address")?;
        let num_storage_updates = self
            .parse_u256()
            .context("number of storage updates")?
            .as_usize();

        let mut storage_updates = Vec::with_capacity(num_storage_updates);
        for i in 0..num_storage_updates {
            let update = self
                .parse_storage_update()
                .with_context(|| format!("storage update {} of {}", i, num_storage_updates))?;
            storage_updates.push(update);
        }

        Ok(ContractUpdate {
            address,
            storage_updates,
        })
    }

    fn parse_storage_update(&mut self) -> Result<StorageUpdate> {
        let address = self.parse_address().context("storage address")?;
        let value = self.parse_u256().context("storage value")?;

        Ok(StorageUpdate { address, value })
    }
}

impl<I> MempageParsingExt for I
where
    I: Iterator<Item = Token>,
{
    fn get_next_token(&mut self) -> Result<Token> {
        self.next().context("token missing")
    }
}
