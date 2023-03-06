//! The json serializable types

use pathfinder_common::{
    BlockId, CallParam, Chain, ContractAddress, ContractNonce, EntryPoint, StarknetBlockHash,
    StarknetBlockNumber,
};
use starknet_gateway_types::{
    reply::{
        state_update::{DeployedContract, StorageDiff},
        PendingStateUpdate,
    },
    request::{add_transaction::AddTransaction, BlockHashOrTag, BlockNumberOrTag, Tag},
};
use std::collections::HashMap;

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
        #[serde_as(as = "&pathfinder_serde::H256AsHexStr")]
        gas_price: &'a ethers::types::H256,
        transaction: &'a AddTransaction,
    },
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug)]
pub(crate) struct CommonProperties<'a> {
    pub at_block: &'a BlockHashNumberOrLatest,
    pub chain: UsedChain,

    // Pending state
    pub pending_updates: ContractUpdatesWrapper<'a>,
    pub pending_deployed: DeployedContractsWrapper<'a>,
    pub pending_nonces: NoncesWrapper<'a>,
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
pub struct ContractUpdatesWrapper<'a>(Option<&'a HashMap<ContractAddress, Vec<StorageDiff>>>);

impl<'a> From<Option<&'a PendingStateUpdate>> for ContractUpdatesWrapper<'a> {
    fn from(u: Option<&'a PendingStateUpdate>) -> Self {
        let map = u.map(|x| &x.state_diff.storage_diffs);
        ContractUpdatesWrapper(map)
    }
}

impl<'a> serde::Serialize for ContractUpdatesWrapper<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        if let Some(diff) = self.0 {
            let mut map = serializer.serialize_map(Some(diff.len()))?;
            for (address, diffs) in diff {
                map.serialize_entry(address, &DiffsWrapper(diffs))?;
            }
            map.end()
        } else {
            let map = serializer.serialize_map(Some(0))?;
            map.end()
        }
    }
}

struct DiffsWrapper<'a>(&'a [StorageDiff]);

impl<'a> serde::Serialize for DiffsWrapper<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for one in self.0 {
            seq.serialize_element(&DiffElement(one))?;
        }
        seq.end()
    }
}

struct DiffElement<'a>(&'a StorageDiff);

impl<'a> serde::Serialize for DiffElement<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("key", &self.0.key.get())?;
        map.serialize_entry("value", &self.0.value.0)?;
        map.end()
    }
}

/// Custom type for setting the serialization in stone, or at least same as python code.
///
/// In call.py this is read by `def maybe_pending_deployed`.
#[derive(Debug)]
pub struct DeployedContractsWrapper<'a>(Option<&'a [DeployedContract]>);

impl<'a> From<Option<&'a PendingStateUpdate>> for DeployedContractsWrapper<'a> {
    fn from(u: Option<&'a PendingStateUpdate>) -> Self {
        let cs = u.map(|u| u.state_diff.deployed_contracts.as_slice());
        DeployedContractsWrapper(cs)
    }
}

impl<'a> serde::Serialize for DeployedContractsWrapper<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        if let Some(cs) = self.0 {
            let mut seq = serializer.serialize_seq(Some(cs.len()))?;
            for contract in cs {
                seq.serialize_element(&DeployedContractElement(contract))?;
            }
            seq.end()
        } else {
            let seq = serializer.serialize_seq(Some(0))?;
            seq.end()
        }
    }
}

struct DeployedContractElement<'a>(&'a DeployedContract);

impl<'a> serde::Serialize for DeployedContractElement<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(2))?;
        // there is no need from python side to use this huge construction,
        // could be just addr => hash
        map.serialize_entry("address", &self.0.address)?;
        map.serialize_entry("contract_hash", &self.0.class_hash)?;
        map.end()
    }
}

/// On python side these are handled by `def maybe_pending_nonces`
#[derive(Debug)]
pub struct NoncesWrapper<'a>(Option<&'a HashMap<ContractAddress, ContractNonce>>);

impl<'a> From<Option<&'a PendingStateUpdate>> for NoncesWrapper<'a> {
    fn from(u: Option<&'a PendingStateUpdate>) -> Self {
        let ns = u.map(|u| &u.state_diff.nonces);
        NoncesWrapper(ns)
    }
}

impl<'a> serde::Serialize for NoncesWrapper<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(self.0.map(|x| x.len()).unwrap_or(0)))?;
        self.0
            .iter()
            .flat_map(|x| x.iter())
            .try_for_each(|(addr, nonce)| map.serialize_entry(addr, nonce))?;

        map.end()
    }
}

/// Custom "when" without the Pending tag, which has no meaning crossing process boundaries.
#[derive(Debug)]
pub enum BlockHashNumberOrLatest {
    Hash(StarknetBlockHash),
    Number(StarknetBlockNumber),
    Latest,
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

impl From<StarknetBlockHash> for BlockHashNumberOrLatest {
    fn from(h: StarknetBlockHash) -> Self {
        BlockHashNumberOrLatest::Hash(h)
    }
}

impl From<StarknetBlockNumber> for BlockHashNumberOrLatest {
    fn from(n: StarknetBlockNumber) -> Self {
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
    use crate::cairo::ext_py::ser::NoncesWrapper;
    use pathfinder_common::{
        felt, {ContractAddress, ContractNonce},
    };
    use std::collections::HashMap;

    #[test]
    fn serialize_some_updates() {
        use super::{ContractUpdatesWrapper, StorageDiff};
        use pathfinder_common::{StorageAddress, StorageValue};
        use std::collections::HashMap;

        let expected = r#"{"0x7c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451":[{"key":"0x5","value":"0x0"}]}"#;
        let map = {
            let mut map = HashMap::new();
            map.insert(
                ContractAddress::new_or_panic(felt!(
                    "07c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451"
                )),
                vec![StorageDiff {
                    key: StorageAddress::new_or_panic(felt!("0x5")),
                    value: StorageValue(felt!("0x0")),
                }],
            );
            map
        };
        let s = serde_json::to_string(&ContractUpdatesWrapper(Some(&map))).unwrap();
        assert_eq!(expected, s);
    }

    /// It is important this outcome is different from the empty list or dict, because the None and
    /// non-None values now carry a difference at the python side.
    ///
    /// See python test `test_call.py::test_call_on_reorgged_pending_block`.
    #[test]
    fn serialize_none_updates() {
        use super::ContractUpdatesWrapper;

        let expected = "{}";
        let s = serde_json::to_string(&ContractUpdatesWrapper(None)).unwrap();
        assert_eq!(expected, s);
    }

    #[test]
    fn serialize_some_deployed_contracts() {
        use super::{DeployedContract, DeployedContractsWrapper};
        use pathfinder_common::ClassHash;

        let expected = r#"[{"address":"0x7c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451","contract_hash":"0x10455c752b86932ce552f2b0fe81a880746649b9aee7e0d842bf3f52378f9f8"}]"#;
        let contracts = vec![DeployedContract {
            address: ContractAddress::new_or_panic(felt!(
                "07c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451"
            )),
            class_hash: ClassHash(felt!(
                "010455c752b86932ce552f2b0fe81a880746649b9aee7e0d842bf3f52378f9f8"
            )),
        }];
        let s = serde_json::to_string(&DeployedContractsWrapper(Some(&contracts))).unwrap();
        assert_eq!(expected, s);

        // this again could be null or []; it doesn't really have any meaning over at python side,
        // nor is it coupled to the updated contracts value in any way
        let s = serde_json::to_string(&DeployedContractsWrapper(Some(&[]))).unwrap();
        assert_eq!("[]", s);
    }

    /// It is important that this is not `[]` or `{}`, see [`serialize_none_updates`].
    #[test]
    fn serialize_none_deployed_contracts() {
        use super::DeployedContractsWrapper;

        let expected = r#"[]"#;
        let s = serde_json::to_string(&DeployedContractsWrapper(None)).unwrap();
        assert_eq!(expected, s);
    }

    #[test]
    fn serialize_block_hash_num_latest() {
        use super::BlockHashNumberOrLatest;
        use pathfinder_common::{StarknetBlockHash, StarknetBlockNumber};
        use stark_hash::Felt;

        let data = &[
            (StarknetBlockHash(Felt::ZERO).into(), "\"0x0\""),
            (StarknetBlockNumber::GENESIS.into(), "\"0\""),
            (BlockHashNumberOrLatest::Latest, "\"latest\""),
        ];

        for (input, output) in data {
            assert_eq!(output, &serde_json::to_string(input).unwrap())
        }
    }

    #[test]
    fn serialize_pending_nonces() {
        let data = [
            // this could just as well be none or just left out
            (None, "{}"),
            (Some(Default::default()), "{}"),
            (
                {
                    let mut map = HashMap::new();
                    map.insert(
                        ContractAddress::new(felt!("0x123")).unwrap(),
                        ContractNonce(felt!("0x1")),
                    );
                    // cannot have multiple in this test because ordering
                    Some(map)
                },
                "{\"0x123\":\"0x1\"}",
            ),
        ];

        for (maybe_map, expected) in data {
            assert_eq!(
                expected,
                &serde_json::to_string(&NoncesWrapper(maybe_map.as_ref())).unwrap()
            );
        }
    }
}
