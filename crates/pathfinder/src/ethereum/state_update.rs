mod parse;
mod retrieve;
pub mod state_root;

use pedersen::StarkHash;
use retrieve::*;

use crate::{
    core::{ContractAddress, ContractHash, StorageAddress, StorageValue},
    ethereum::{
        api::Web3EthApi,
        log::{GetLogsError, StateUpdateLog},
        state_update::{parse::StateUpdateParser, retrieve::retrieve_transition_fact},
        Chain,
    },
};

/// Describes the deployment of a new StarkNet contract.
#[derive(Debug, Clone, PartialEq)]
pub struct DeployedContract {
    pub address: ContractAddress,
    pub hash: ContractHash,
    pub call_data: Vec<StarkHash>,
}

/// A StarkNet contract's storage updates.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContractUpdate {
    pub address: ContractAddress,
    pub storage_updates: Vec<StorageUpdate>,
}

/// A StarkNet contract's storage update.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StorageUpdate {
    pub address: StorageAddress,
    pub value: StorageValue,
}

/// The set of state updates of a StarkNet [StateUpdate].
///
/// Contains new [DeployedContracts](DeployedContract) as well as [ContractUpdates](ContractUpdate).
#[derive(Debug, Clone, PartialEq)]
pub struct StateUpdate {
    pub deployed_contracts: Vec<DeployedContract>,
    pub contract_updates: Vec<ContractUpdate>,
}

#[derive(Debug, thiserror::Error)]
pub enum RetrieveStateUpdateError {
    #[error("Not found: State transition fact")]
    StateTransitionFactNotFound,
    #[error("Not found: Memory page hashes")]
    MemoryPageHashesNotFound,
    #[error("Not found: Memory page log")]
    MemoryPageLogNotFound,
    #[error("Not found: Memory page transaction")]
    MemoryPageTransactionNotFound,
    #[error("Reorg event detected")]
    Reorg,
    #[error(transparent)]
    GetLogs(#[from] GetLogsError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl StateUpdate {
    /// Retrieves the [StateUpdate] associated with the given [StateUpdateLog] from L1.
    pub async fn retrieve(
        transport: &impl Web3EthApi,
        state_update: StateUpdateLog,
        chain: Chain,
    ) -> Result<Self, RetrieveStateUpdateError> {
        let transition_fact = retrieve_transition_fact(transport, state_update, chain).await?;

        let mempage_hashes = retrieve_mempage_hashes(transport, transition_fact, chain).await?;

        let mempage_logs = retrieve_memory_page_logs(transport, mempage_hashes, chain).await?;

        let mempage_data = retrieve_mempage_transaction_data(transport, mempage_logs).await?;

        // flatten memory page data (skip first page)
        let mempage_data = mempage_data
            .into_iter()
            .skip(1)
            .flatten()
            .collect::<Vec<_>>();

        // parse memory page data
        let update = StateUpdateParser::parse(mempage_data)?;
        Ok(update)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pedersen::StarkHash;
    use pretty_assertions::assert_eq;
    use web3::types::H256;

    use crate::core::{
        EthereumBlockHash, EthereumBlockNumber, EthereumLogIndex, EthereumTransactionHash,
        EthereumTransactionIndex, GlobalRoot, StarknetBlockNumber,
    };
    use crate::ethereum::{test_transport, BlockOrigin, EthOrigin, TransactionOrigin};

    use super::*;

    #[tokio::test]
    async fn reality_check() {
        let update_log = StateUpdateLog {
            origin: EthOrigin {
                block: BlockOrigin {
                    hash: EthereumBlockHash(
                        H256::from_str(
                            "0x4de2eead55dfd20058fbbe77fb579cffb96985b26d86e24f1af361cf139b3a0d",
                        )
                        .unwrap(),
                    ),
                    number: EthereumBlockNumber(5973783),
                },
                transaction: TransactionOrigin {
                    hash: EthereumTransactionHash(
                        H256::from_str(
                            "0xae7d1c87bc3a7ed34d129b5b037a0848f020bac1fa20082686399c88b538a6e2",
                        )
                        .unwrap(),
                    ),
                    index: EthereumTransactionIndex(4),
                },
                log_index: EthereumLogIndex(23),
            },
            global_root: GlobalRoot(
                StarkHash::from_hex_str(
                    "1256D7337B57DD78AAA67563760FBDB561D7F51F335771E6D8D6CE60E4C1387",
                )
                .unwrap(),
            ),
            block_number: StarknetBlockNumber(16407),
        };

        let chain = crate::ethereum::Chain::Goerli;
        let transport = test_transport(chain);
        let update = StateUpdate::retrieve(&transport, update_log, chain)
            .await
            .unwrap();

        let expected = StateUpdate {
            deployed_contracts: vec![DeployedContract {
                address: ContractAddress(StarkHash::from_hex_str("6CF1C6DCA6DE4CE15DB3EB7AEE1C6191537C82E2F2DE22FE4426199EE50E9A").unwrap()),
                hash: ContractHash(StarkHash::from_hex_str("484DE75F165C844F9D8C5B07A7D1A650A476815DC7A061126FD41BB998C043D").unwrap()),
                call_data: vec![StarkHash::from_hex_str("5D7C088BB051DB0A4C5A9C435A2009E2A82EE896080DDF4E6E953770F313EAF").unwrap()],
            }],
            contract_updates: vec![
                ContractUpdate {
                address: ContractAddress(StarkHash::from_hex_str("6CF1C6DCA6DE4CE15DB3EB7AEE1C6191537C82E2F2DE22FE4426199EE50E9A").unwrap()),
                storage_updates: vec![
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("21683F821A0574472445355BE6D2B769119E8515F8376A1D7878523DFDECF7B").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("6CF1C6DCA6DE4CE15DB3EB7AEE1C6191537C82E2F2DE22FE4426199EE50E9A").unwrap()),
                    },
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("3B28019CCFDBD30FFC65951D94BB85C9E2B8434111A000B5AFD533CE65F57A4").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("5D7C088BB051DB0A4C5A9C435A2009E2A82EE896080DDF4E6E953770F313EAF").unwrap()),
                    },
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("3C0BA99F1A18BCDC81FCBCB6B4F15A9A6725F937075AED6FAC107FFCB147068").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("1").unwrap()),
                    },
                ],
            },
            ContractUpdate {
                address: ContractAddress(StarkHash::from_hex_str("FDB9F231A6C257D492DB4D091703ABA277E97B583AB9E3115B5A571FC22E4D").unwrap()),
                storage_updates: vec![
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("154D7895A89D2A9EA002F6455F0BE1F409302F4E3A53B06B86C8A83E12D343E").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("6673A13BB9C8D4FD9ADFDF4AA0478BAFB4F6EE191D7BF31E3085136B803B0FC").unwrap()),
                    },
                ],
            },
            ContractUpdate {
                address: ContractAddress(StarkHash::from_hex_str("29366B381BA18C53E9DB8A4476E0599C71CB63F001950D094CE23EDCD2CD81C").unwrap()),
                storage_updates: vec![
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("367FBE030560FA33F15D19C5A53436B3345771F3769607B168E9BAFB540E665").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("8AC7230489E80000").unwrap()),
                    },
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("367FBE030560FA33F15D19C5A53436B3345771F3769607B168E9BAFB540E666").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("0").unwrap()),
                    },
                ],
            },
            ContractUpdate {
                address: ContractAddress(StarkHash::from_hex_str("2FC0D82D539509C5642B64F59299B7E9FD23C114BD2640BDC979602667F8C1F").unwrap()),
                storage_updates: vec![
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("D34C3A8EDE05D741C7C11C8A517FEB3FEFCC425ED633E4D93758446BA289BA").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("7E5").unwrap()),
                    },
                ],
            },
            ContractUpdate {
                address: ContractAddress(StarkHash::from_hex_str("4F664133F8C8C9A34B7D0B85AC09571BC92FBDC23CD7F82B0E8CEA3E3837B4C").unwrap()),
                storage_updates: vec![
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("D34C3A8EDE05D741C7C11C8A517FEB3FEFCC425ED633E4D93758446BA289BA").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("7C7").unwrap()),
                    },
                ],
            },
            ContractUpdate {
                address: ContractAddress(StarkHash::from_hex_str("69A7CFDF88197230CA4CE9377E1D8AAE7AD5E36E25DD35C7F3C73DAAD16940E").unwrap()),
                storage_updates: vec![
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("1CCC09C8A19948E048DE7ADD6929589945E25F22059C7345AAF7837188D8D05").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("5A95504FA8DFC374D4072459027F6A50EAC084BB9F233DAE048C50FB8EECB8A").unwrap()),
                    },
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("31E7534F8DDB1628D6E07DB5C743E33403B9A0B57508A93F4C49582040A2F71").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("0").unwrap()),
                    },
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("37501DF619C4FC4E96F6C0243F55E3ABE7D1ACA7DB9AF8F3740BA3696B3FDAC").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("1").unwrap()),
                    },
                ],
            },
            ContractUpdate {
                address: ContractAddress(StarkHash::from_hex_str("7075572D159FA30E93C6A917F75B5D664A99A7CEC4AF40FA7E6EF8094B7A3EE").unwrap()),
                storage_updates: vec![
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("5").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("456").unwrap()),
                    },
                ],
            },
            ContractUpdate {
                address: ContractAddress(StarkHash::from_hex_str("7C1069DD27607ABF370C745B9781183FDD7E8082AC39C4E57D858913EE7D022").unwrap()),
                storage_updates: vec![
                    StorageUpdate {
                        address: StorageAddress(StarkHash::from_hex_str("5").unwrap()),
                        value: StorageValue(StarkHash::from_hex_str("66").unwrap()),
                    },
                ],
            },
                ],
        };

        assert_eq!(update, expected);
    }
}
