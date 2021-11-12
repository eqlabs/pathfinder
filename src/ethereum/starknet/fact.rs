use anyhow::{Context, Result};
use web3::types::U256;

/// Describes the deployment of a new StarkNet contract.
#[derive(Debug, Clone, PartialEq)]
pub struct DeployedContract {
    pub address: U256,
    pub hash: U256,
    pub call_data: Vec<U256>,
}

/// A StarkNet contract's storage updates.
#[derive(Debug, Clone, PartialEq)]
pub struct ContractUpdate {
    pub address: U256,
    pub storage_updates: Vec<StorageUpdate>,
}

/// A StarkNet contract's storage update.
#[derive(Debug, Clone, PartialEq)]
pub struct StorageUpdate {
    pub address: U256,
    pub value: U256,
}

/// The set of state updates of a StarkNet [Fact].
///
/// Contains new [DeployedContracts](DeployedContract) as well as [ContractUpdates](ContractUpdate).
#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    pub deployed_contracts: Vec<DeployedContract>,
    pub contract_updates: Vec<ContractUpdate>,
}

impl Fact {
    /// Parses a set of flattened StarkNet memory pages into a [Fact].
    ///
    /// Note that this should exclude the first memory page as this does
    /// not relate to a [Fact's](Fact) data directly.
    pub fn parse_mempages<I>(mempages: I) -> Result<Fact>
    where
        I: Iterator<Item = U256>,
    {
        FactParser(mempages).parse_fact()
    }
}

/// Utility to parse StarkNet memory pages into a [Fact].
///
/// The broad structure of a [Fact] is as follows:
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
struct FactParser<I>(I)
where
    I: Iterator<Item = U256>;

impl<I> FactParser<I>
where
    I: Iterator<Item = U256>,
{
    fn parse_fact(mut self) -> Result<Fact> {
        let deployed_contracts = self.parse_contract_deployments()?;
        let contract_updates = self.parse_contract_updates()?;

        Ok(Fact {
            deployed_contracts,
            contract_updates,
        })
    }

    fn parse_contract_deployments(&mut self) -> Result<Vec<DeployedContract>> {
        let deployment_data_len = self.parse_usize().context("contract deployment length")?;

        let mut deployment_data = self.0.by_ref().take(deployment_data_len);
        let mut data_consumed = 0;

        let mut deployed_contracts = Vec::new();
        while let Some(address) = deployment_data.next() {
            let hash = deployment_data
                .next()
                .context("deployed contract hash missing")?;

            let num_constructor_args = deployment_data
                .next()
                .context("constructor arg count missing")?;
            anyhow::ensure!(
                num_constructor_args <= U256::from(usize::MAX),
                "constructor arg count exceeds usize::MAX"
            );
            // Safe due to previous ensure.
            let num_constructor_args = num_constructor_args.as_usize();

            let constructor_args = deployment_data
                .by_ref()
                .take(num_constructor_args)
                .collect::<Vec<_>>();
            anyhow::ensure!(
                constructor_args.len() == num_constructor_args,
                "deployed contract constructor missing constructor args"
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
        let num_contracts = self.parse_usize().context("number of contract updates")?;

        (0..num_contracts)
            .map(|i| {
                self.parse_contract_update()
                    .with_context(|| format!("contract {} of {}", i, num_contracts))
            })
            .collect()
    }

    fn parse_contract_update(&mut self) -> Result<ContractUpdate> {
        let address = self.0.next().context("contract address missing")?;

        let num_updates = self.parse_usize().context("number of storage updates")?;

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
        let address = self.0.next().context("missing storage address")?;
        let value = self.0.next().context("missing storage value")?;

        Ok(StorageUpdate { address, value })
    }

    /// A safe parsing into [usize].
    fn parse_usize(&mut self) -> Result<usize> {
        let size = self.0.next().context("value missing")?;

        anyhow::ensure!(size <= U256::from(usize::MAX), "value exceeds usize::MAX");
        // This is safe due to the previous ensure.
        Ok(size.as_usize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::from_over_into)]
    impl Into<Vec<U256>> for StorageUpdate {
        fn into(self) -> Vec<U256> {
            vec![self.address, self.value]
        }
    }

    #[allow(clippy::from_over_into)]
    impl Into<Vec<U256>> for ContractUpdate {
        fn into(self) -> Vec<U256> {
            let mut data = vec![self.address, U256::from(self.storage_updates.len())];
            data.extend(
                self.storage_updates
                    .into_iter()
                    .flat_map(|u| Into::<Vec<U256>>::into(u).into_iter()),
            );
            data
        }
    }

    // Newtype so we can impl Into<Vec<U256>>
    #[derive(Debug, PartialEq, Clone)]
    struct ContractUpdates(Vec<ContractUpdate>);

    #[allow(clippy::from_over_into)]
    impl Into<Vec<U256>> for ContractUpdates {
        fn into(self) -> Vec<U256> {
            let mut data = vec![U256::from(self.0.len())];
            data.extend(
                self.0
                    .into_iter()
                    .flat_map(|u| Into::<Vec<U256>>::into(u).into_iter()),
            );
            data
        }
    }

    #[allow(clippy::from_over_into)]
    impl Into<Vec<U256>> for DeployedContract {
        fn into(self) -> Vec<U256> {
            let mut data = vec![self.address, self.hash, U256::from(self.call_data.len())];
            data.extend(self.call_data.into_iter());
            data
        }
    }

    // Newtype so we can impl Into<Vec<U256>>
    #[derive(Debug, PartialEq, Clone)]
    struct DeploymentUpdates(Vec<DeployedContract>);

    #[allow(clippy::from_over_into)]
    impl Into<Vec<U256>> for DeploymentUpdates {
        fn into(self) -> Vec<U256> {
            let mut data = self
                .0
                .into_iter()
                .flat_map(|u| Into::<Vec<U256>>::into(u).into_iter())
                .collect::<Vec<_>>();

            data.insert(0, U256::from(data.len()));
            data
        }
    }

    #[allow(clippy::from_over_into)]
    impl Into<Vec<U256>> for Fact {
        fn into(self) -> Vec<U256> {
            let deployed: Vec<U256> = DeploymentUpdates(self.deployed_contracts).into();
            let updates: Vec<U256> = ContractUpdates(self.contract_updates).into();

            deployed.into_iter().chain(updates.into_iter()).collect()
        }
    }

    fn contract_update() -> ContractUpdate {
        ContractUpdate {
            address: U256::from(123456),
            storage_updates: vec![
                StorageUpdate {
                    address: U256::from(1),
                    value: U256::from(301),
                },
                StorageUpdate {
                    address: U256::from(2),
                    value: U256::from(305),
                },
            ],
        }
    }

    fn deployed_contract() -> DeployedContract {
        DeployedContract {
            address: U256::from(45691),
            hash: U256::from(22513),
            call_data: vec![U256::from(1), U256::from(2), U256::from(1230)],
        }
    }

    #[cfg(test)]
    mod parse_usize {
        use super::*;

        #[test]
        fn ok() {
            let value = 35812usize;
            let data = vec![U256::from(value)].into_iter();
            let mut parser = FactParser(data);
            let result = parser.parse_usize().unwrap();

            assert_eq!(result, value);
        }

        #[test]
        fn max() {
            let value = usize::MAX;
            let data = vec![U256::from(value)].into_iter();
            let mut parser = FactParser(data);
            let result = parser.parse_usize().unwrap();

            assert_eq!(result, value);
        }

        #[test]
        fn overflow() {
            let value = usize::MAX;
            let data = vec![U256::from(value) + U256::from(1)].into_iter();
            let mut parser = FactParser(data);
            parser.parse_usize().unwrap_err();
        }

        #[test]
        fn missing() {
            let data = Vec::new().into_iter();
            let mut parser = FactParser(data);
            parser.parse_usize().unwrap_err();
        }
    }

    #[cfg(test)]
    mod parse_storage_update {
        use super::*;

        #[test]
        fn ok() {
            let update = StorageUpdate {
                address: U256::from(200),
                value: U256::from(300),
            };
            let data: Vec<U256> = update.clone().into();

            let mut parser = FactParser(data.into_iter());
            let result = parser.parse_storage_update().unwrap();
            assert_eq!(result, update);
        }

        #[test]
        fn missing_data() {
            let update = StorageUpdate {
                address: U256::from(200),
                value: U256::from(300),
            };
            let data: Vec<U256> = update.into();

            let mut parser = FactParser(data.into_iter().skip(1));
            parser.parse_storage_update().unwrap_err();
        }
    }

    #[cfg(test)]
    mod parse_contract_update {
        use super::*;

        #[test]
        fn ok() {
            let update = contract_update();
            let data: Vec<U256> = update.clone().into();

            let mut parser = FactParser(data.into_iter());
            let result = parser.parse_contract_update().unwrap();
            assert_eq!(result, update);
        }

        #[test]
        fn no_storage_updates() {
            let update = ContractUpdate {
                address: U256::from(123456),
                storage_updates: Vec::new(),
            };

            let data: Vec<U256> = update.clone().into();

            let mut parser = FactParser(data.into_iter());
            let result = parser.parse_contract_update().unwrap();
            assert_eq!(result, update);
        }

        #[test]
        fn missing_storage_update() {
            // Corrupt the update length field, increasing it by 1.
            let update = contract_update();
            let mut data: Vec<U256> = update.into();
            data[1] += U256::from(1);

            let mut parser = FactParser(data.into_iter());
            parser.parse_contract_update().unwrap_err();
        }
    }

    #[cfg(test)]
    mod parse_contract_updates {
        use super::*;

        #[test]
        fn ok() {
            let updates = ContractUpdates(vec![contract_update(), contract_update()]);
            let data: Vec<U256> = updates.clone().into();

            let mut parser = FactParser(data.into_iter());
            let result = parser.parse_contract_updates().unwrap();
            assert_eq!(result, updates.0);
        }

        #[test]
        fn no_contract_updates() {
            let updates = ContractUpdates(Vec::new());
            let data: Vec<U256> = updates.clone().into();

            let mut parser = FactParser(data.into_iter());
            let result = parser.parse_contract_updates().unwrap();
            assert_eq!(result, updates.0);
        }

        #[test]
        fn missing_contract_update() {
            let updates = ContractUpdates(vec![contract_update(), contract_update()]);
            // Corrupt the update length field, increasing it by 1.
            let mut data: Vec<U256> = updates.into();
            data[0] += U256::from(1);

            let mut parser = FactParser(data.into_iter());
            parser.parse_contract_updates().unwrap_err();
        }
    }

    #[cfg(test)]
    mod parse_contract_deployments {
        use super::*;

        #[test]
        fn ok() {
            let deployment = DeploymentUpdates(vec![deployed_contract(), deployed_contract()]);
            let data: Vec<U256> = deployment.clone().into();

            let mut parser = FactParser(data.into_iter());
            let result = parser.parse_contract_deployments().unwrap();
            assert_eq!(result, deployment.0);
        }

        #[test]
        fn no_updates() {
            let deployment = DeploymentUpdates(Vec::new());
            let data: Vec<U256> = deployment.clone().into();

            let mut parser = FactParser(data.into_iter());
            let result = parser.parse_contract_deployments().unwrap();
            assert_eq!(result, deployment.0);
        }

        #[test]
        fn missing_data() {
            let deployment = DeploymentUpdates(vec![deployed_contract(), deployed_contract()]);
            let mut data: Vec<U256> = deployment.into();
            // Corrupt the length field, increasing it by 1.
            data[0] += U256::from(1);

            let mut parser = FactParser(data.into_iter());
            parser.parse_contract_deployments().unwrap_err();
        }
    }

    #[cfg(test)]
    mod fact {
        use super::*;

        #[test]
        fn ok() {
            let fact = Fact {
                deployed_contracts: vec![deployed_contract(), deployed_contract()],
                contract_updates: vec![contract_update(), contract_update()],
            };

            let data: Vec<U256> = fact.clone().into();

            let parser = FactParser(data.into_iter());
            let result = parser.parse_fact().unwrap();
            assert_eq!(result, fact);
        }

        #[test]
        fn no_deployed_contracts() {
            let fact = Fact {
                deployed_contracts: Vec::new(),
                contract_updates: vec![contract_update(), contract_update()],
            };

            let data: Vec<U256> = fact.clone().into();

            let parser = FactParser(data.into_iter());
            let result = parser.parse_fact().unwrap();
            assert_eq!(result, fact);
        }

        #[test]
        fn no_updated_contracts() {
            let fact = Fact {
                deployed_contracts: vec![deployed_contract(), deployed_contract()],
                contract_updates: Vec::new(),
            };

            let data: Vec<U256> = fact.clone().into();

            let parser = FactParser(data.into_iter());
            let result = parser.parse_fact().unwrap();
            assert_eq!(result, fact);
        }

        #[test]
        fn no_updates() {
            let fact = Fact {
                deployed_contracts: Vec::new(),
                contract_updates: Vec::new(),
            };

            let data: Vec<U256> = fact.clone().into();

            let parser = FactParser(data.into_iter());
            let result = parser.parse_fact().unwrap();
            assert_eq!(result, fact);
        }
    }
}
