mod parse;
mod retrieve;
mod state_root;

use retrieve::*;

use web3::{types::U256, Transport, Web3};

use crate::ethereum::{
    log::StateUpdateLog,
    state_update::{parse::StateUpdateParser, retrieve::retrieve_transition_fact},
};

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

/// The set of state updates of a StarkNet [StateUpdate].
///
/// Contains new [DeployedContracts](DeployedContract) as well as [ContractUpdates](ContractUpdate).
#[derive(Debug, Clone, PartialEq)]
pub struct StateUpdate {
    pub deployed_contracts: Vec<DeployedContract>,
    pub contract_updates: Vec<ContractUpdate>,
}

#[derive(Debug)]
pub enum RetrieveStateUpdateError {
    StateTransitionFactNotFound,
    MemoryPageHashesNotFound,
    MemoryPageLogNotFound,
    MemoryPageTransactionNotFound,
    Reorg,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for RetrieveStateUpdateError {
    fn from(err: anyhow::Error) -> Self {
        RetrieveStateUpdateError::Other(err)
    }
}

impl StateUpdate {
    /// Retrieves the [StateUpdate] associated with the given [StateUpdateLog] from L1.
    pub async fn retrieve<T: Transport>(
        transport: &Web3<T>,
        state_update: StateUpdateLog,
    ) -> Result<Self, RetrieveStateUpdateError> {
        let transition_fact = retrieve_transition_fact(transport, state_update).await?;

        let mempage_hashes = retrieve_mempage_hashes(transport, transition_fact).await?;

        let mempage_logs = retrieve_memory_page_logs(transport, mempage_hashes).await?;

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

    use pretty_assertions::assert_eq;
    use web3::types::H256;

    use crate::ethereum::{
        test::create_test_websocket_transport, BlockOrigin, EthOrigin, TransactionOrigin,
    };

    use super::*;

    #[tokio::test]
    async fn reality_check() {
        let update_log = StateUpdateLog {
            origin: EthOrigin {
                block: BlockOrigin {
                    hash: H256::from_str(
                        "0x4de2eead55dfd20058fbbe77fb579cffb96985b26d86e24f1af361cf139b3a0d",
                    )
                    .unwrap(),
                    number: 5973783,
                },
                transaction: TransactionOrigin {
                    hash: H256::from_str(
                        "0xae7d1c87bc3a7ed34d129b5b037a0848f020bac1fa20082686399c88b538a6e2",
                    )
                    .unwrap(),
                    index: 4,
                },
                log_index: U256::from(23),
            },
            global_root: U256::from_dec_str(
                "518441586592570845566219848761263100073689884954357429195191348826336924551",
            )
            .unwrap(),
            block_number: U256::from(16407),
        };

        let transport = create_test_websocket_transport().await;
        let update = StateUpdate::retrieve(&transport, update_log).await.unwrap();

        let expected = StateUpdate {
            deployed_contracts: vec![DeployedContract {
                address: U256::from_dec_str(
                    "192488165172431958337374653286540488197496085928528474156682062131548720794",
                )
                .unwrap(),
                hash: U256::from_dec_str(
                    "2044010574308692949556595542798601982234418418155425337239169936905147778109",
                )
                .unwrap(),
                call_data: vec![U256::from_dec_str(
                    "2642765183390518226191464338033793552381526284343500407573756018492213116591",
                )
                .unwrap()],
            }],
            contract_updates: vec![
                ContractUpdate {
                address: U256::from_dec_str("192488165172431958337374653286540488197496085928528474156682062131548720794").unwrap(),
                storage_updates: vec![
                    StorageUpdate {
                        address: U256::from_dec_str("944407150971126289822123988889809430356945584469838657342381477018902384507").unwrap(),
                        value: U256::from_dec_str("192488165172431958337374653286540488197496085928528474156682062131548720794").unwrap(),
                    },
                    StorageUpdate {
                        address: U256::from_dec_str("1672321442399497129215646424919402195095307045612040218489019266998007191460").unwrap(),
                        value: U256::from_dec_str("2642765183390518226191464338033793552381526284343500407573756018492213116591").unwrap(),
                    },
                    StorageUpdate {
                        address: U256::from_dec_str("1697461057326310581967816530165551571743938660869987744467005324703617544296").unwrap(),
                        value: U256::from_dec_str("1").unwrap(),
                    },
                ],
            },
            ContractUpdate {
                address: U256::from_dec_str("448295659999083968328940375285038656322099894268333081962140244605900303949").unwrap(),
                storage_updates: vec![
                    StorageUpdate {
                        address: U256::from_dec_str("602215580536707347725838306637776804408199085594156310665557293021069653054").unwrap(),
                        value: U256::from_dec_str("2896263172456672743997340121599341750222389451987581831383456686827572015356").unwrap(),
                    },
                ],
            },
            ContractUpdate {
                address: U256::from_dec_str("1165061033308622722462994167118484809586375016882777118347772110833430878236").unwrap(),
                storage_updates: vec![
                    StorageUpdate {
                        address: U256::from_dec_str("1540662175873464101179255226853115482807345027999462461827073633037049718373").unwrap(),
                        value: U256::from_dec_str("10000000000000000000").unwrap(),
                    },
                    StorageUpdate {
                        address: U256::from_dec_str("1540662175873464101179255226853115482807345027999462461827073633037049718374").unwrap(),
                        value: U256::from_dec_str("0").unwrap(),
                    },
                ],
            },
            ContractUpdate {
                address: U256::from_dec_str("1349964407441356736445072259996730168659555931570900222313776602622042541087").unwrap(),
                storage_updates: vec![
                    StorageUpdate {
                        address: U256::from_dec_str("373330842113182176873498781695511789062490522341957425172839703021474711994").unwrap(),
                        value: U256::from_dec_str("2021").unwrap(),
                    },
                ],
            },
            ContractUpdate {
                address: U256::from_dec_str("2244586465834706804729538181057356971546152457586787167114978055045865765708").unwrap(),
                storage_updates: vec![
                    StorageUpdate {
                        address: U256::from_dec_str("373330842113182176873498781695511789062490522341957425172839703021474711994").unwrap(),
                        value: U256::from_dec_str("1991").unwrap(),
                    },
                ],
            },
            ContractUpdate {
                address: U256::from_dec_str("2986834203059737059446342291161493286636848077470151713641910585406717858830").unwrap(),
                storage_updates: vec![
                    StorageUpdate {
                        address: U256::from_dec_str("814079005391940027390129862062157285361348684878695833898695909074510122245").unwrap(),
                        value: U256::from_dec_str("2560748179529625008397514353415812350378239053783288928353583273304539450250").unwrap(),
                    },
                    StorageUpdate {
                        address: U256::from_dec_str("1410752890141599390055702225444248987277077018130707938554244692172889272177").unwrap(),
                        value: U256::from_dec_str("0").unwrap(),
                    },
                    StorageUpdate {
                        address: U256::from_dec_str("1563672576422918850564506150092036819309968525068313502302455251173901598124").unwrap(),
                        value: U256::from_dec_str("1").unwrap(),
                    },
                ],
            },
            ContractUpdate {
                address: U256::from_dec_str("3179147613456994138674947757137017509117110013980711456682683972427617641454").unwrap(),
                storage_updates: vec![
                    StorageUpdate {
                        address: U256::from_dec_str("5").unwrap(),
                        value: U256::from_dec_str("1110").unwrap(),
                    },
                ],
            },
            ContractUpdate {
                address: U256::from_dec_str("3507237088938936343013853947406435564768985008074076680138339097283612102690").unwrap(),
                storage_updates: vec![
                    StorageUpdate {
                        address: U256::from_dec_str("5").unwrap(),
                        value: U256::from_dec_str("102").unwrap(),
                    },
                ],
            },
                ],
        };

        assert_eq!(update, expected);
    }
}
