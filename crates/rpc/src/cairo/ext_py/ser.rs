//! The json serializable types

use pathfinder_common::{
    BlockHash, BlockId, BlockNumber, CallParam, Chain, ClassHash, ContractAddress, EntryPoint,
    EthereumAddress, StateUpdate, StorageAddress, StorageValue,
};
use starknet_gateway_types::request::{BlockHashOrTag, BlockNumberOrTag, Tag};
use std::{collections::HashMap, fmt::Display};

use super::TransactionAndClassHashHint;

/// The command we send to the Python loop.
#[serde_with::serde_as]
#[derive(serde::Serialize, Debug)]
#[serde(tag = "verb", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum ChildCommand<'a> {
    Call {
        #[serde(flatten)]
        common: CommonProperties<'a>,

        contract_address: &'a ContractAddress,
        calldata: &'a [CallParam],
        entry_point_selector: Option<&'a EntryPoint>,
    },
    EstimateFee {
        #[serde(flatten)]
        common: CommonProperties<'a>,

        // zero means use the gas price from the block.
        #[serde_as(as = "&pathfinder_serde::U256AsHexStr")]
        gas_price: &'a primitive_types::U256,
        transactions: &'a [TransactionAndClassHashHint],
    },
    EstimateMsgFee {
        #[serde(flatten)]
        common: CommonProperties<'a>,

        // zero means use the gas price from the block.
        #[serde_as(as = "&pathfinder_serde::U256AsHexStr")]
        gas_price: &'a primitive_types::U256,

        sender_address: EthereumAddress,
        contract_address: &'a ContractAddress,
        calldata: &'a [CallParam],
        entry_point_selector: Option<&'a EntryPoint>,
    },
    SimulateTx {
        #[serde(flatten)]
        common: CommonProperties<'a>,

        // zero means use the gas price from the block.
        #[serde_as(as = "&pathfinder_serde::U256AsHexStr")]
        gas_price: &'a primitive_types::U256,
        transactions: &'a [TransactionAndClassHashHint],
        skip_validate: &'a bool,
    },
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug)]
pub(crate) struct CommonProperties<'a> {
    pub at_block: &'a BlockHashNumberOrLatest,
    pub chain: UsedChain,

    // Pending state
    pub pending_updates: StorageUpdates<'a>,
    pub pending_deployed: DeployedContracts<'a>,
    pub pending_nonces: Nonces<'a>,
    pub pending_timestamp: u64,
}

/// Private version of [`pathfinder_common::Chain`] for serialization.
#[derive(serde::Serialize, Debug, Clone, Copy)]
pub(crate) enum UsedChain {
    #[serde(rename = "MAINNET")]
    Mainnet,
    #[serde(rename = "TESTNET")]
    Testnet,
    #[serde(rename = "TESTNET2")]
    Testnet2,
}

impl From<Chain> for UsedChain {
    fn from(c: Chain) -> Self {
        match c {
            pathfinder_common::Chain::Mainnet => UsedChain::Mainnet,
            pathfinder_common::Chain::Testnet => UsedChain::Testnet,
            pathfinder_common::Chain::Testnet2 => UsedChain::Testnet2,
            pathfinder_common::Chain::Integration => UsedChain::Testnet,
            pathfinder_common::Chain::Custom => UsedChain::Testnet,
        }
    }
}

/// Custom type for setting the serialization in stone, or at least same as python code.
///
/// In call.py this is `def maybe_pending_updates`.
#[derive(Debug)]
pub struct StorageUpdates<'a>(Option<&'a StateUpdate>);

impl<'a> From<Option<&'a StateUpdate>> for StorageUpdates<'a> {
    fn from(u: Option<&'a StateUpdate>) -> Self {
        Self(u)
    }
}

impl<'a> serde::Serialize for StorageUpdates<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        struct StorageUpdates<'a>(&'a HashMap<StorageAddress, StorageValue>);

        impl<'a> serde::Serialize for StorageUpdates<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeSeq;

                #[derive(serde::Serialize)]
                struct Element<'a> {
                    key: &'a StorageAddress,
                    value: &'a StorageValue,
                }

                let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                for (key, value) in self.0 {
                    seq.serialize_element(&Element { key, value })?;
                }
                seq.end()
            }
        }

        let system_updates = self
            .0
            .iter()
            .flat_map(|x| x.system_contract_updates.iter())
            .map(|(addr, update)| (addr, &update.storage));
        let storage_updates = self
            .0
            .iter()
            .flat_map(|x| x.contract_updates.iter())
            .map(|(addr, update)| (addr, &update.storage));
        let updates = system_updates.chain(storage_updates);
        let count = updates.clone().count();
        let mut map = serializer.serialize_map(Some(count))?;
        for (address, update) in updates {
            map.serialize_entry(address, &StorageUpdates(update))?;
        }
        map.end()
    }
}

/// Custom type for setting the serialization in stone, or at least same as python code.
///
/// In call.py this is read by `def maybe_pending_deployed`.
#[derive(Debug)]
pub struct DeployedContracts<'a>(Option<&'a StateUpdate>);

impl<'a> From<Option<&'a StateUpdate>> for DeployedContracts<'a> {
    fn from(u: Option<&'a StateUpdate>) -> Self {
        Self(u)
    }
}

impl<'a> serde::Serialize for DeployedContracts<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        #[derive(serde::Serialize)]
        struct DeployedContract {
            address: ContractAddress,
            contract_hash: ClassHash,
        }

        let contracts = self
            .0
            .iter()
            .flat_map(|x| x.contract_updates.iter())
            // Note that this includes both deployed and replaced classes.
            .filter_map(|(addr, update)| update.class.as_ref().map(|c| (*addr, c.class_hash())));

        let count = contracts.clone().count();

        let mut seq = serializer.serialize_seq(Some(count))?;

        for (address, class) in contracts {
            let contract = DeployedContract {
                address,
                contract_hash: class,
            };

            seq.serialize_element(&contract)?;
        }

        seq.end()
    }
}

/// On python side these are handled by `def maybe_pending_nonces`
#[derive(Debug)]
pub struct Nonces<'a>(Option<&'a StateUpdate>);

impl<'a> From<Option<&'a StateUpdate>> for Nonces<'a> {
    fn from(u: Option<&'a StateUpdate>) -> Self {
        Self(u)
    }
}

impl<'a> serde::Serialize for Nonces<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let nonces = self
            .0
            .iter()
            .flat_map(|x| x.contract_updates.iter())
            .filter_map(|(addr, update)| update.nonce.as_ref().map(|n| (addr, n)));

        let count = nonces.clone().count();

        let mut map = serializer.serialize_map(Some(count))?;

        for (addr, nonce) in nonces {
            map.serialize_entry(addr, nonce)?;
        }

        map.end()
    }
}

/// Custom "when" without the Pending tag, which has no meaning crossing process boundaries.
#[derive(Copy, Clone, Debug)]
pub enum BlockHashNumberOrLatest {
    Hash(BlockHash),
    Number(BlockNumber),
    Latest,
}

impl Display for BlockHashNumberOrLatest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockHashNumberOrLatest::Hash(h) => f.write_fmt(format_args!("Hash({h})")),
            BlockHashNumberOrLatest::Number(n) => f.write_fmt(format_args!("Number({n})")),
            BlockHashNumberOrLatest::Latest => f.write_str("latest"),
        }
    }
}

impl serde::Serialize for BlockHashNumberOrLatest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use BlockHashNumberOrLatest::*;
        match self {
            Hash(h) => h.serialize(serializer),
            // We serialize block number as string, since the Python-side dataclass expects
            // `at_block` to be a string (and does proper conversion on that)
            Number(n) => n.get().to_string().serialize(serializer),
            // I failed to get this working with the derive(serde::Serialize)
            Latest => "latest".serialize(serializer),
        }
    }
}

impl From<BlockHash> for BlockHashNumberOrLatest {
    fn from(h: BlockHash) -> Self {
        BlockHashNumberOrLatest::Hash(h)
    }
}

impl From<BlockNumber> for BlockHashNumberOrLatest {
    fn from(n: BlockNumber) -> Self {
        BlockHashNumberOrLatest::Number(n)
    }
}

/// The type representing [`starknet_gateway_types::request::Tag::Pending`] value, which cannot be accepted as
/// [`BlockHashNumberOrLatest`].
#[derive(Debug)]
pub struct Pending;

impl TryFrom<Tag> for BlockHashNumberOrLatest {
    type Error = Pending;

    fn try_from(value: Tag) -> Result<Self, Self::Error> {
        match value {
            Tag::Latest => Ok(BlockHashNumberOrLatest::Latest),
            Tag::Pending => Err(Pending),
        }
    }
}

impl TryFrom<BlockHashOrTag> for BlockHashNumberOrLatest {
    type Error = Pending;

    fn try_from(value: BlockHashOrTag) -> Result<Self, Self::Error> {
        match value {
            BlockHashOrTag::Hash(h) => Ok(h.into()),
            BlockHashOrTag::Tag(x) => x.try_into(),
        }
    }
}

impl TryFrom<BlockNumberOrTag> for BlockHashNumberOrLatest {
    type Error = Pending;

    fn try_from(value: BlockNumberOrTag) -> Result<Self, Self::Error> {
        match value {
            BlockNumberOrTag::Number(n) => Ok(n.into()),
            BlockNumberOrTag::Tag(x) => x.try_into(),
        }
    }
}

impl TryFrom<BlockId> for BlockHashNumberOrLatest {
    type Error = Pending;

    fn try_from(value: BlockId) -> Result<Self, Self::Error> {
        match value {
            BlockId::Number(n) => Ok(n.into()),
            BlockId::Hash(h) => Ok(h.into()),
            BlockId::Latest => Ok(BlockHashNumberOrLatest::Latest),
            BlockId::Pending => Err(Pending),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cairo::ext_py::ser::Nonces;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::ContractAddress;

    mod storage_updates {
        use super::*;

        #[test]
        fn none() {
            let result = serde_json::to_string(&StorageUpdates(None)).unwrap();
            assert_eq!(result, "{}");
        }

        #[test]
        fn with_updates() {
            let expected = r#"{
                "0x7c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451":[{"key":"0x5","value":"0xabc"}],
                "0x1":[{"key":"0x123","value":"0xdef"}]
            }"#;
            // Use Value so we don't run into ordering issues.
            let expected: serde_json::Value = serde_json::from_str(expected).unwrap();

            let update = StateUpdate::default()
                .with_storage_update(
                    contract_address!(
                        "07c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451"
                    ),
                    storage_address!("0x5"),
                    storage_value!("0xabc"),
                )
                .with_system_storage_update(
                    ContractAddress::ONE,
                    storage_address!("0x123"),
                    storage_value!("0xdef"),
                );
            let s = serde_json::to_value(StorageUpdates(Some(&update))).unwrap();
            assert_eq!(expected, s);
        }
    }

    mod deployed_contracts {
        use super::*;

        #[test]
        fn none() {
            let result = serde_json::to_string(&DeployedContracts(None)).unwrap();
            assert_eq!(result, "[]");
        }

        #[test]
        fn with_deployed_contract() {
            let expected = r#"[{"address":"0x7c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451","contract_hash":"0x10455c752b86932ce552f2b0fe81a880746649b9aee7e0d842bf3f52378f9f8"}]"#;

            let result = serde_json::to_string(&DeployedContracts(Some(
                &StateUpdate::default().with_deployed_contract(
                    contract_address!(
                        "07c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451"
                    ),
                    class_hash!("010455c752b86932ce552f2b0fe81a880746649b9aee7e0d842bf3f52378f9f8"),
                ),
            )))
            .unwrap();
            assert_eq!(result, expected);
        }
    }

    mod block_hash_num_latest {
        use super::*;

        #[test]
        fn hash() {
            let result =
                serde_json::to_string::<BlockHashNumberOrLatest>(&block_hash!("0x1234").into())
                    .unwrap();
            assert_eq!(result, r#""0x1234""#);
        }

        #[test]
        fn number() {
            let result = serde_json::to_string::<BlockHashNumberOrLatest>(
                &BlockNumber::new_or_panic(1234).into(),
            )
            .unwrap();
            assert_eq!(result, r#""1234""#);
        }

        #[test]
        fn latest() {
            let result = serde_json::to_string(&BlockHashNumberOrLatest::Latest).unwrap();
            assert_eq!(result, r#""latest""#);
        }
    }

    mod nonces {
        use super::*;

        #[test]
        fn none() {
            let result = serde_json::to_string(&Nonces(None)).unwrap();
            assert_eq!(result, "{}");
        }

        #[test]
        fn with_nonce_update() {
            let result = serde_json::to_string(&Nonces(Some(
                &StateUpdate::default()
                    .with_contract_nonce(contract_address!("0x123"), contract_nonce!("0x1")),
            )))
            .unwrap();
            assert_eq!(result, r#"{"0x123":"0x1"}"#);
        }
    }
}
