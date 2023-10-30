//! Conversions between DTOs and common types.
//!
//! Also includes some "bridging" types which should eventually be removed
use pathfinder_common::{
    event::Event,
    state_update::SystemContractUpdate,
    transaction::{
        DeclareTransactionV0V1, DeclareTransactionV2, DeployAccountTransaction, DeployTransaction,
        EntryPointType, InvokeTransactionV0, InvokeTransactionV1, L1HandlerTransaction,
        TransactionVariant,
    },
    BlockHash, BlockNumber, BlockTimestamp, CallParam, CasmHash, ClassHash, ConstructorParam,
    ContractAddress, ContractAddressSalt, ContractNonce, EntryPoint, EventData, EventKey, Fee,
    GasPrice, SequencerAddress, SierraHash, StarknetVersion, StateCommitment, StorageAddress,
    StorageValue, TransactionNonce, TransactionSignatureElem, TransactionVersion,
};
use std::{collections::HashMap, time::SystemTime};

/// We don't want to introduce circular dependencies between crates
/// and we need to work around for the orphan rule - implement conversion fns for types ourside our crate.
pub trait TryFromDto<T> {
    fn try_from_dto(dto: T) -> anyhow::Result<Self>
    where
        Self: Sized;
}

/// Block header but without most of the commitments
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockHeader {
    pub hash: BlockHash,
    pub parent_hash: BlockHash,
    pub number: BlockNumber,
    pub timestamp: BlockTimestamp,
    pub gas_price: GasPrice,
    pub sequencer_address: SequencerAddress,
    pub starknet_version: StarknetVersion,
    pub state_commitment: StateCommitment,
}

/// Simple state update meant for the temporary p2p client hidden behind
/// the gateway client api, ie.:
/// - does not contain any commitments
/// - does not specify if the class was declared or replaced
///
/// TODO: remove this once proper p2p friendly sync is implemented
#[derive(Debug, Clone, PartialEq)]
pub struct StateUpdate {
    pub contract_updates: HashMap<ContractAddress, ContractUpdate>,
    pub system_contract_updates: HashMap<ContractAddress, SystemContractUpdate>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StateUpdateWithDefs {
    pub block_hash: BlockHash,
    pub state_update: StateUpdate,
    pub classes: Vec<Class>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContractUpdate {
    pub storage: HashMap<StorageAddress, StorageValue>,
    /// The class associated with this update as the result of either a deploy or class replacement transaction.
    /// We don't explicitly know if it's one or the other
    pub class: Option<ClassHash>,
    pub nonce: Option<ContractNonce>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Class {
    Cairo {
        hash: ClassHash,
        definition: Vec<u8>,
    },
    Sierra {
        sierra_hash: SierraHash,
        definition: Vec<u8>,
        casm_hash: CasmHash,
    },
}

impl Class {
    pub fn definition_mut(&mut self) -> &mut Vec<u8> {
        match self {
            Class::Cairo { definition, .. } => definition,
            Class::Sierra { definition, .. } => definition,
        }
    }
}

impl From<p2p_proto::state::Class> for Class {
    fn from(class: p2p_proto::state::Class) -> Self {
        match class.casm_hash {
            Some(casm_hash) => Class::Sierra {
                sierra_hash: SierraHash(class.compiled_hash.0),
                definition: class.definition,
                casm_hash: CasmHash(casm_hash.0),
            },
            None => Class::Cairo {
                hash: ClassHash(class.compiled_hash.0),
                definition: class.definition,
            },
        }
    }
}

impl From<pathfinder_common::BlockHeader> for BlockHeader {
    fn from(value: pathfinder_common::BlockHeader) -> Self {
        Self {
            hash: value.hash,
            parent_hash: value.parent_hash,
            number: value.number,
            timestamp: value.timestamp,
            gas_price: value.gas_price,
            sequencer_address: value.sequencer_address,
            starknet_version: value.starknet_version,
            state_commitment: value.state_commitment,
        }
    }
}

impl TryFrom<p2p_proto::block::BlockHeader> for BlockHeader {
    type Error = anyhow::Error;

    fn try_from(dto: p2p_proto::block::BlockHeader) -> anyhow::Result<Self> {
        Ok(Self {
            hash: BlockHash(dto.hash.0),
            parent_hash: BlockHash(dto.parent_hash.0),
            number: BlockNumber::new(dto.number)
                .ok_or(anyhow::anyhow!("Invalid block number > i64::MAX"))?,
            timestamp: BlockTimestamp::new(
                dto.time.duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
            )
            .ok_or(anyhow::anyhow!("Invalid block timestamp"))?,
            sequencer_address: SequencerAddress(dto.sequencer_address.0),
            // TODO imo missing in the spec
            gas_price: GasPrice::from_be_slice(dto.gas_price.as_slice())?,
            // TODO not sure if should be in the spec
            starknet_version: StarknetVersion::from(dto.starknet_version),
            // TODO remove this field when signature verification is done
            // allows to verify block hash and state commitment when present
            state_commitment: StateCommitment(dto.state_commitment.unwrap_or_default().0),
        })
    }
}

impl From<pathfinder_common::StateUpdate> for StateUpdate {
    fn from(s: pathfinder_common::StateUpdate) -> Self {
        Self {
            contract_updates: s
                .contract_updates
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            system_contract_updates: s.system_contract_updates,
        }
    }
}

impl From<pathfinder_common::state_update::ContractUpdate> for ContractUpdate {
    fn from(c: pathfinder_common::state_update::ContractUpdate) -> Self {
        Self {
            storage: c.storage,
            class: c.class.map(|x| x.class_hash()),
            nonce: c.nonce,
        }
    }
}

impl From<p2p_proto::state::StateDiff> for StateUpdate {
    fn from(proto: p2p_proto::state::StateDiff) -> Self {
        const SYSTEM_CONTRACT: ContractAddress = ContractAddress::ONE;
        let mut system_contract_update = SystemContractUpdate {
            storage: Default::default(),
        };
        let mut contract_updates = HashMap::new();
        proto.contract_diffs.into_iter().for_each(|diff| {
            if diff.address.0 == SYSTEM_CONTRACT.0 {
                diff.values.into_iter().for_each(|x| {
                    system_contract_update
                        .storage
                        .insert(StorageAddress(x.key), StorageValue(x.value));
                });
            } else {
                contract_updates.insert(
                    ContractAddress(diff.address.0),
                    ContractUpdate {
                        storage: diff
                            .values
                            .into_iter()
                            .map(|x| (StorageAddress(x.key), StorageValue(x.value)))
                            .collect(),
                        class: diff.class_hash.map(ClassHash),
                        nonce: diff.nonce.map(ContractNonce),
                    },
                );
            }
        });

        let system_contract_updates = if system_contract_update.storage.is_empty() {
            Default::default()
        } else {
            [(SYSTEM_CONTRACT, system_contract_update)].into()
        };

        Self {
            contract_updates,
            system_contract_updates,
        }
    }
}

impl TryFromDto<p2p_proto::transaction::Transaction> for TransactionVariant {
    fn try_from_dto(dto: p2p_proto::transaction::Transaction) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        use p2p_proto::transaction::Transaction::*;

        Ok(match dto {
            DeclareV0(x) => TransactionVariant::DeclareV0(DeclareTransactionV0V1 {
                class_hash: ClassHash(x.class_hash.0),
                max_fee: Fee(x.max_fee),
                nonce: TransactionNonce(x.nonce),
                sender_address: ContractAddress(x.sender.0),
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
            }),
            DeclareV1(x) => TransactionVariant::DeclareV1(DeclareTransactionV0V1 {
                class_hash: ClassHash(x.class_hash.0),
                max_fee: Fee(x.max_fee),
                nonce: TransactionNonce(x.nonce),
                sender_address: ContractAddress(x.sender.0),
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
            }),
            DeclareV2(x) => TransactionVariant::DeclareV2(DeclareTransactionV2 {
                class_hash: ClassHash(x.class_hash.0),
                max_fee: Fee(x.max_fee),
                nonce: TransactionNonce(x.nonce),
                sender_address: ContractAddress(x.sender.0),
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
                compiled_class_hash: CasmHash(x.compiled_class_hash),
            }),
            DeclareV3(_) => unimplemented!(),
            Deploy(x) => TransactionVariant::Deploy(DeployTransaction {
                contract_address: ContractAddress(x.address.0),
                contract_address_salt: ContractAddressSalt(x.address_salt),
                class_hash: ClassHash(x.class_hash.0),
                constructor_calldata: x.calldata.into_iter().map(ConstructorParam).collect(),
                version: match x.version {
                    0 => TransactionVersion::ZERO,
                    1 => TransactionVersion::ONE,
                    _ => anyhow::bail!("Invalid deploy transaction version"),
                },
            }),
            DeployAccountV1(x) => TransactionVariant::DeployAccount(DeployAccountTransaction {
                contract_address: ContractAddress(x.address.0),
                max_fee: Fee(x.max_fee),
                version: TransactionVersion::ONE,
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
                nonce: TransactionNonce(x.nonce),
                contract_address_salt: ContractAddressSalt(x.address_salt),
                constructor_calldata: x.calldata.into_iter().map(CallParam).collect(),
                class_hash: ClassHash(x.class_hash.0),
            }),
            DeployAccountV3(_) => unimplemented!(),
            InvokeV0(x) => TransactionVariant::InvokeV0(InvokeTransactionV0 {
                calldata: x.calldata.into_iter().map(CallParam).collect(),
                sender_address: ContractAddress(x.address.0),
                entry_point_selector: EntryPoint(x.entry_point_selector),
                entry_point_type: x.entry_point_type.map(|x| {
                    use p2p_proto::transaction::EntryPointType::{External, L1Handler};
                    match x {
                        External => EntryPointType::External,
                        L1Handler => EntryPointType::L1Handler,
                    }
                }),
                max_fee: Fee(x.max_fee),
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
            }),
            InvokeV1(x) => TransactionVariant::InvokeV1(InvokeTransactionV1 {
                calldata: x.calldata.into_iter().map(CallParam).collect(),
                sender_address: ContractAddress(x.sender.0),
                max_fee: Fee(x.max_fee),
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
                nonce: TransactionNonce(x.nonce),
            }),
            InvokeV3(_) => unimplemented!(),
            L1HandlerV1(x) => TransactionVariant::L1Handler(L1HandlerTransaction {
                contract_address: ContractAddress(x.address.0),
                entry_point_selector: EntryPoint(x.entry_point_selector),
                nonce: TransactionNonce(x.nonce),
                calldata: x.calldata.into_iter().map(CallParam).collect(),
                // TODO there's a bug in the spec, all available L1 handler transactions up to now (Sep '23)
                // carry version 0
                // e.g.
                // @block 10k
                // https://alpha-mainnet.starknet.io/feeder_gateway/get_transaction?transactionHash=0x02e42cd5f71a2b09547083f82e267ac2f37ba71e09fa868ffce90d141531c3ba
                // @block ~261k
                // https://alpha-mainnet.starknet.io/feeder_gateway/get_transaction?transactionHash=0x02e42cd5f71a2b09547083f82e267ac2f37ba71e09fa868ffce90d141531c3ba
                version: TransactionVersion::ZERO,
            }),
        })
    }
}

impl TryFromDto<p2p_proto::event::Event> for Event {
    fn try_from_dto(proto: p2p_proto::event::Event) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            from_address: ContractAddress(proto.from_address),
            keys: proto.keys.into_iter().map(EventKey).collect(),
            data: proto.data.into_iter().map(EventData).collect(),
        })
    }
}
