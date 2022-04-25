use std::vec::IntoIter;

use anyhow::{Context, Result};
use pedersen_hash::StarkHash;
use web3::types::U256;

use crate::{
    core::{ContractAddress, ContractHash, StorageAddress, StorageValue},
    ethereum::state_update::{ContractUpdate, DeployedContract, StateUpdate, StorageUpdate},
};

/// Utility to parse StarkNet memory pages into a [StateUpdate].
///
/// The broad structure of a [StateUpdate] is as follows:
///     1. New contracts deployed,
///     2. Contract variable updates
///
/// Expanding on (1):
///     a. Length of deployment data (in elements, not number of contracts)
///     b. The deployment data must then be interpretted as follows (until data is done):
///         1. contract's address
///         2. contract's hash
///         3. number of constructor arguments (N)
///         4. N x constructor arguments
///
/// Expanding on (2):
///     a. The number of contracts with updated variables.
///     b. For each contract i:
///         1. The contract's address
///         1. The number of variable updates for contract i.
///         2. For each variable update j:
///             a. Variable's address
///             b. Variable's new value
pub struct StateUpdateParser(pub IntoIter<U256>);

impl StateUpdateParser {
    pub fn parse(mempage_data: Vec<U256>) -> Result<StateUpdate> {
        let mut parser = Self(mempage_data.into_iter());

        let deployed_contracts = parser.parse_contract_deployments()?;
        let contract_updates = parser.parse_contract_updates()?;

        Ok(StateUpdate {
            deployed_contracts,
            contract_updates,
        })
    }

    fn parse_contract_deployments(&mut self) -> Result<Vec<DeployedContract>> {
        let deployment_data_len = self
            .0
            .next()
            .context("Contract deployment length missing")?;
        let deployment_data_len =
            parse_usize(deployment_data_len).context("Parsing contract deployment length")?;

        let mut deployment_data = self.0.by_ref().take(deployment_data_len);
        let mut data_consumed = 0;

        let mut deployed_contracts = Vec::new();
        while let Some(address) = deployment_data.next() {
            let address = parse_starkhash(address).context("Parsing contract address")?;
            let address = ContractAddress(address);

            let hash = deployment_data
                .next()
                .context("Deployed contract hash missing")?;
            let hash = parse_starkhash(hash).context("Parsing contract hash")?;
            let hash = ContractHash(hash);

            let num_constructor_args = deployment_data
                .next()
                .context("Constructor arg count missing")?;
            let num_constructor_args =
                parse_usize(num_constructor_args).context("Parsing constructor arg count")?;

            let constructor_args = deployment_data
                .by_ref()
                .take(num_constructor_args)
                .map(|arg| parse_starkhash(arg).context("Parsing constructor arg"))
                .collect::<Result<Vec<_>>>()?;
            anyhow::ensure!(
                constructor_args.len() == num_constructor_args,
                "Missing constructor args"
            );

            deployed_contracts.push(DeployedContract {
                address,
                hash,
                call_data: constructor_args,
            });

            data_consumed += 3 + num_constructor_args;
        }

        anyhow::ensure!(
            data_consumed == deployment_data_len,
            "contract deployment data length mismatch"
        );

        Ok(deployed_contracts)
    }

    fn parse_contract_updates(&mut self) -> Result<Vec<ContractUpdate>> {
        let num_contracts = self
            .0
            .next()
            .context("Missing number of contract updates")?;
        let num_contracts =
            parse_usize(num_contracts).context("Parsing number of contract updates")?;

        (0..num_contracts)
            .map(|i| {
                self.parse_contract_update()
                    .with_context(|| format!("contract {} of {}", i, num_contracts))
            })
            .collect()
    }

    fn parse_contract_update(&mut self) -> Result<ContractUpdate> {
        let address = self.0.next().context("Missing contract address")?;
        let address = parse_starkhash(address).context("Parsing contract address")?;
        let address = ContractAddress(address);

        let num_updates = self.0.next().context("Missing number of storage updates")?;
        let num_updates = parse_usize(num_updates).context("Parsing Number of storage updates")?;

        let storage_updates = (0..num_updates)
            .map(|i| {
                self.parse_storage_update()
                    .with_context(|| format!("storage update {} of {}", i, num_updates))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(ContractUpdate {
            address,
            storage_updates,
        })
    }

    fn parse_storage_update(&mut self) -> Result<StorageUpdate> {
        let address = self.0.next().context("Missing storage address")?;
        let address = parse_starkhash(address).context("Parsing storage address")?;
        let address = StorageAddress(address);
        let value = self.0.next().context("Missing storage value")?;
        let value = parse_starkhash(value).context("Parsing storage value")?;
        let value = StorageValue(value);

        Ok(StorageUpdate { address, value })
    }
}

/// A safe parsing into [usize].
fn parse_usize(value: U256) -> Result<usize> {
    anyhow::ensure!(value <= U256::from(usize::MAX), "value exceeds usize::MAX");
    // This is safe due to the previous ensure.
    Ok(value.as_usize())
}

/// A safe parsing into [StarkHash]
fn parse_starkhash(value: U256) -> Result<StarkHash> {
    let mut buf = [0u8; 32];
    value.to_big_endian(&mut buf);
    let starkhash = StarkHash::from_be_bytes(buf)?;
    Ok(starkhash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u256_from_starkhash(hash: StarkHash) -> U256 {
        let bytes = hash.to_be_bytes();
        U256::from_big_endian(&bytes[..])
    }

    impl From<StorageUpdate> for Vec<U256> {
        fn from(val: StorageUpdate) -> Self {
            let address = u256_from_starkhash(val.address.0);
            let value = u256_from_starkhash(val.value.0);
            vec![address, value]
        }
    }

    impl From<ContractUpdate> for Vec<U256> {
        fn from(val: ContractUpdate) -> Self {
            let mut data = vec![
                u256_from_starkhash(val.address.0),
                U256::from(val.storage_updates.len()),
            ];
            data.extend(
                val.storage_updates
                    .into_iter()
                    .flat_map(|u| Into::<Vec<U256>>::into(u).into_iter()),
            );
            data
        }
    }

    // Newtype so we can impl Into<Vec<U256>>
    #[derive(Debug, PartialEq, Clone)]
    struct ContractUpdates(Vec<ContractUpdate>);

    impl From<ContractUpdates> for Vec<U256> {
        fn from(val: ContractUpdates) -> Self {
            let mut data = vec![U256::from(val.0.len())];
            data.extend(
                val.0
                    .into_iter()
                    .flat_map(|u| Into::<Vec<U256>>::into(u).into_iter()),
            );
            data
        }
    }

    impl From<DeployedContract> for Vec<U256> {
        fn from(val: DeployedContract) -> Self {
            let mut data = vec![
                u256_from_starkhash(val.address.0),
                u256_from_starkhash(val.hash.0),
                U256::from(val.call_data.len()),
            ];
            data.extend(val.call_data.into_iter().map(u256_from_starkhash));
            data
        }
    }

    // Newtype so we can impl Into<Vec<U256>>
    #[derive(Debug, PartialEq, Clone)]
    struct DeploymentUpdates(Vec<DeployedContract>);

    impl From<DeploymentUpdates> for Vec<U256> {
        fn from(val: DeploymentUpdates) -> Self {
            let mut data = val
                .0
                .into_iter()
                .flat_map(|u| Into::<Vec<U256>>::into(u).into_iter())
                .collect::<Vec<_>>();

            data.insert(0, U256::from(data.len()));
            data
        }
    }

    impl From<StateUpdate> for Vec<U256> {
        fn from(val: StateUpdate) -> Self {
            let deployed: Vec<U256> = DeploymentUpdates(val.deployed_contracts).into();
            let updates: Vec<U256> = ContractUpdates(val.contract_updates).into();

            deployed.into_iter().chain(updates.into_iter()).collect()
        }
    }

    fn contract_update() -> ContractUpdate {
        ContractUpdate {
            address: ContractAddress(StarkHash::from_hex_str("123456").unwrap()),
            storage_updates: vec![
                StorageUpdate {
                    address: StorageAddress(StarkHash::from_hex_str("1").unwrap()),
                    value: StorageValue(StarkHash::from_hex_str("301").unwrap()),
                },
                StorageUpdate {
                    address: StorageAddress(StarkHash::from_hex_str("2").unwrap()),
                    value: StorageValue(StarkHash::from_hex_str("305").unwrap()),
                },
            ],
        }
    }

    fn deployed_contract() -> DeployedContract {
        DeployedContract {
            address: ContractAddress(StarkHash::from_hex_str("45691").unwrap()),
            hash: ContractHash(StarkHash::from_hex_str("22513").unwrap()),
            call_data: vec![
                StarkHash::from_hex_str("1").unwrap(),
                StarkHash::from_hex_str("2").unwrap(),
                StarkHash::from_hex_str("1230").unwrap(),
            ],
        }
    }

    mod parse_usize {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test]
        fn ok() {
            let value = 35812usize;
            let data = U256::from(value);
            let result = parse_usize(data).unwrap();

            assert_eq!(result, value);
        }

        #[test]
        fn max() {
            let value = usize::MAX;
            let data = U256::from(value);
            let result = parse_usize(data).unwrap();

            assert_eq!(result, value);
        }

        #[test]
        fn overflow() {
            let value = usize::MAX;
            let data = U256::from(value) + U256::from(1);
            parse_usize(data).unwrap_err();
        }
    }

    mod parse_storage_update {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test]
        fn ok() {
            let update = StorageUpdate {
                address: StorageAddress(StarkHash::from_hex_str("200").unwrap()),
                value: StorageValue(StarkHash::from_hex_str("300").unwrap()),
            };
            let data: Vec<U256> = update.clone().into();

            let mut parser = StateUpdateParser(data.into_iter());
            let result = parser.parse_storage_update().unwrap();
            assert_eq!(result, update);
        }

        #[test]
        fn missing_data() {
            let update = StorageUpdate {
                address: StorageAddress(StarkHash::from_hex_str("200").unwrap()),
                value: StorageValue(StarkHash::from_hex_str("300").unwrap()),
            };
            let mut data: Vec<U256> = update.into();
            data.pop();

            let mut parser = StateUpdateParser(data.into_iter());
            parser.parse_storage_update().unwrap_err();
        }
    }

    mod parse_contract_update {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test]
        fn ok() {
            let update = contract_update();
            let data: Vec<U256> = update.clone().into();

            let mut parser = StateUpdateParser(data.into_iter());
            let result = parser.parse_contract_update().unwrap();
            assert_eq!(result, update);
        }

        #[test]
        fn no_storage_updates() {
            let update = ContractUpdate {
                address: ContractAddress(StarkHash::from_hex_str("123456").unwrap()),
                storage_updates: Vec::new(),
            };

            let data: Vec<U256> = update.clone().into();

            let mut parser = StateUpdateParser(data.into_iter());
            let result = parser.parse_contract_update().unwrap();
            assert_eq!(result, update);
        }

        #[test]
        fn missing_storage_update() {
            // Corrupt the update length field, increasing it by 1.
            let update = contract_update();
            let mut data: Vec<U256> = update.into();
            data[1] += U256::from(1);

            let mut parser = StateUpdateParser(data.into_iter());
            parser.parse_contract_update().unwrap_err();
        }
    }

    mod parse_contract_updates {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test]
        fn ok() {
            let updates = ContractUpdates(vec![contract_update(), contract_update()]);
            let data: Vec<U256> = updates.clone().into();

            let mut parser = StateUpdateParser(data.into_iter());
            let result = parser.parse_contract_updates().unwrap();
            assert_eq!(result, updates.0);
        }

        #[test]
        fn no_contract_updates() {
            let updates = ContractUpdates(Vec::new());
            let data: Vec<U256> = updates.clone().into();

            let mut parser = StateUpdateParser(data.into_iter());
            let result = parser.parse_contract_updates().unwrap();
            assert_eq!(result, updates.0);
        }

        #[test]
        fn missing_contract_update() {
            let updates = ContractUpdates(vec![contract_update(), contract_update()]);
            // Corrupt the update length field, increasing it by 1.
            let mut data: Vec<U256> = updates.into();
            data[0] += U256::from(1);

            let mut parser = StateUpdateParser(data.into_iter());
            parser.parse_contract_updates().unwrap_err();
        }
    }

    mod parse_contract_deployments {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test]
        fn ok() {
            let deployment = DeploymentUpdates(vec![deployed_contract(), deployed_contract()]);
            let data: Vec<U256> = deployment.clone().into();

            let mut parser = StateUpdateParser(data.into_iter());
            let result = parser.parse_contract_deployments().unwrap();
            assert_eq!(result, deployment.0);
        }

        #[test]
        fn no_updates() {
            let deployment = DeploymentUpdates(Vec::new());
            let data: Vec<U256> = deployment.clone().into();

            let mut parser = StateUpdateParser(data.into_iter());
            let result = parser.parse_contract_deployments().unwrap();
            assert_eq!(result, deployment.0);
        }

        #[test]
        fn missing_data() {
            let deployment = DeploymentUpdates(vec![deployed_contract(), deployed_contract()]);
            let mut data: Vec<U256> = deployment.into();
            // Corrupt the length field, increasing it by 1.
            data[0] += U256::from(1);

            let mut parser = StateUpdateParser(data.into_iter());
            parser.parse_contract_deployments().unwrap_err();
        }
    }

    mod fact {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test]
        fn ok() {
            let fact = StateUpdate {
                deployed_contracts: vec![deployed_contract(), deployed_contract()],
                contract_updates: vec![contract_update(), contract_update()],
            };

            let data: Vec<U256> = fact.clone().into();

            let result = StateUpdateParser::parse(data).unwrap();
            assert_eq!(result, fact);
        }

        #[test]
        fn no_deployed_contracts() {
            let fact = StateUpdate {
                deployed_contracts: Vec::new(),
                contract_updates: vec![contract_update(), contract_update()],
            };

            let data: Vec<U256> = fact.clone().into();

            let result = StateUpdateParser::parse(data).unwrap();
            assert_eq!(result, fact);
        }

        #[test]
        fn no_updated_contracts() {
            let fact = StateUpdate {
                deployed_contracts: vec![deployed_contract(), deployed_contract()],
                contract_updates: Vec::new(),
            };

            let data: Vec<U256> = fact.clone().into();

            let result = StateUpdateParser::parse(data).unwrap();
            assert_eq!(result, fact);
        }

        #[test]
        fn no_updates() {
            let fact = StateUpdate {
                deployed_contracts: Vec::new(),
                contract_updates: Vec::new(),
            };

            let data: Vec<U256> = fact.clone().into();

            let result = StateUpdateParser::parse(data).unwrap();
            assert_eq!(result, fact);
        }
    }
}
