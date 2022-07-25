//! The json serializable types

use crate::core::{CallParam, ContractAddress, EntryPoint};
use crate::rpc::types::BlockHashOrTag;
use crate::sequencer::reply::state_update::{Contract, StorageDiff};
use std::collections::HashMap;

/// The command we send to the python loop.
#[serde_with::serde_as]
#[derive(serde::Serialize, Debug)]
pub(crate) struct ChildCommand<'a> {
    pub command: Verb,
    pub contract_address: &'a ContractAddress,
    pub calldata: &'a [CallParam],
    pub entry_point_selector: &'a EntryPoint,
    pub at_block: &'a BlockHashNumberOrLatest,
    #[serde_as(as = "Option<&crate::rpc::serde::H256AsHexStr>")]
    pub gas_price: Option<&'a web3::types::H256>,
    pub signature: &'a [crate::core::CallSignatureElem],
    pub max_fee: &'a crate::core::Fee,
    #[serde_as(as = "crate::rpc::serde::TransactionVersionAsHexStr")]
    pub version: &'a crate::core::TransactionVersion,
    pub chain: UsedChain,
    pub pending_updates: ContractUpdatesWrapper<'a>,
    pub pending_deployed: DeployedContractsWrapper<'a>,
}

#[derive(serde::Serialize, Debug)]
pub(crate) enum Verb {
    #[serde(rename = "call")]
    Call,
    #[serde(rename = "estimate_fee")]
    EstimateFee,
}

/// Private version of [`crate::core::Chain`] for serialization.
#[derive(serde::Serialize, Debug, Clone, Copy)]
pub(crate) enum UsedChain {
    #[serde(rename = "MAINNET")]
    Mainnet,
    #[serde(rename = "GOERLI")]
    Goerli,
}

impl From<crate::core::Chain> for UsedChain {
    fn from(c: crate::core::Chain) -> Self {
        match c {
            crate::core::Chain::Mainnet => UsedChain::Mainnet,
            crate::core::Chain::Goerli => UsedChain::Goerli,
        }
    }
}

/// Custom type for setting the serialization in stone, or at least same as python code.
#[derive(Debug)]
pub struct ContractUpdatesWrapper<'a>(Option<&'a HashMap<ContractAddress, Vec<StorageDiff>>>);

impl<'a> From<Option<&'a crate::sequencer::reply::StateUpdate>> for ContractUpdatesWrapper<'a> {
    fn from(u: Option<&'a crate::sequencer::reply::StateUpdate>) -> Self {
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
            serializer.serialize_none()
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
        map.serialize_entry("key", &self.0.key.0)?;
        map.serialize_entry("value", &self.0.value.0)?;
        map.end()
    }
}

/// Custom type for setting the serialization in stone, or at least same as python code.
#[derive(Debug)]
pub struct DeployedContractsWrapper<'a>(Option<&'a [Contract]>);

impl<'a> From<Option<&'a crate::sequencer::reply::StateUpdate>> for DeployedContractsWrapper<'a> {
    fn from(u: Option<&'a crate::sequencer::reply::StateUpdate>) -> Self {
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
            serializer.serialize_none()
        }
    }
}

struct DeployedContractElement<'a>(&'a crate::sequencer::reply::state_update::Contract);

impl<'a> serde::Serialize for DeployedContractElement<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("address", &self.0.address)?;
        map.serialize_entry("contract_hash", &self.0.contract_hash)?;
        map.end()
    }
}

/// Custom "when" without the Pending tag, which has no meaning crossing process boundaries.
#[derive(Debug)]
pub enum BlockHashNumberOrLatest {
    Hash(crate::core::StarknetBlockHash),
    Number(crate::core::StarknetBlockNumber),
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
            Number(n) => n.serialize(serializer),
            // I failed to get this working with the derive(serde::Serialize)
            Latest => "latest".serialize(serializer),
        }
    }
}

impl From<crate::core::StarknetBlockHash> for BlockHashNumberOrLatest {
    fn from(h: crate::core::StarknetBlockHash) -> Self {
        BlockHashNumberOrLatest::Hash(h)
    }
}

impl From<crate::core::StarknetBlockNumber> for BlockHashNumberOrLatest {
    fn from(n: crate::core::StarknetBlockNumber) -> Self {
        BlockHashNumberOrLatest::Number(n)
    }
}

/// The type representing [`crate::rpc::types::Tag::Pending`] value, which cannot be accepted as
/// [`BlockHashNumberOrLatest`].
#[derive(Debug)]
pub struct Pending;

impl TryFrom<crate::rpc::types::Tag> for BlockHashNumberOrLatest {
    type Error = Pending;

    fn try_from(value: crate::rpc::types::Tag) -> Result<Self, Self::Error> {
        use crate::rpc::types::Tag;
        match value {
            Tag::Latest => Ok(BlockHashNumberOrLatest::Latest),
            Tag::Pending => Err(Pending),
        }
    }
}

impl TryFrom<crate::rpc::types::BlockHashOrTag> for BlockHashNumberOrLatest {
    type Error = Pending;

    fn try_from(value: crate::rpc::types::BlockHashOrTag) -> Result<Self, Self::Error> {
        match value {
            BlockHashOrTag::Hash(h) => Ok(h.into()),
            BlockHashOrTag::Tag(x) => x.try_into(),
        }
    }
}

impl TryFrom<crate::rpc::types::BlockNumberOrTag> for BlockHashNumberOrLatest {
    type Error = Pending;

    fn try_from(value: crate::rpc::types::BlockNumberOrTag) -> Result<Self, Self::Error> {
        match value {
            crate::rpc::types::BlockNumberOrTag::Number(n) => Ok(n.into()),
            crate::rpc::types::BlockNumberOrTag::Tag(x) => x.try_into(),
        }
    }
}

impl TryFrom<crate::core::BlockId> for BlockHashNumberOrLatest {
    type Error = Pending;

    fn try_from(value: crate::core::BlockId) -> Result<Self, Self::Error> {
        match value {
            crate::core::BlockId::Number(n) => Ok(n.into()),
            crate::core::BlockId::Hash(h) => Ok(h.into()),
            crate::core::BlockId::Latest => Ok(BlockHashNumberOrLatest::Latest),
            crate::core::BlockId::Pending => Err(Pending),
        }
    }
}

#[cfg(test)]
mod tests {
    use stark_hash::StarkHash;

    #[test]
    fn serialize_some_updates() {
        use super::ContractUpdatesWrapper;
        use crate::core::{ContractAddress, StorageAddress, StorageValue};
        use crate::sequencer::reply::state_update::StorageDiff;
        use std::collections::HashMap;

        let expected = r#"{"0x7c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451":[{"key":"0x5","value":"0x0"}]}"#;
        let map = {
            let mut map = HashMap::new();
            map.insert(
                ContractAddress(
                    StarkHash::from_hex_str(
                        "0x7c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451",
                    )
                    .unwrap(),
                ),
                vec![StorageDiff {
                    key: StorageAddress(StarkHash::from_hex_str("0x5").unwrap()),
                    value: StorageValue(StarkHash::from_hex_str("0x0").unwrap()),
                }],
            );
            map
        };
        let s = serde_json::to_string(&ContractUpdatesWrapper(Some(&map))).unwrap();
        assert_eq!(expected, s);
    }

    #[test]
    fn serialize_none_updates() {
        use super::ContractUpdatesWrapper;

        // this could be an empty object just as well
        let expected = "null";
        let s = serde_json::to_string(&ContractUpdatesWrapper(None)).unwrap();
        assert_eq!(expected, s);
    }

    #[test]
    fn serialize_some_deployed_contracts() {
        use super::DeployedContractsWrapper;
        use crate::core::{ClassHash, ContractAddress};
        use crate::sequencer::reply::state_update::Contract;

        let expected = r#"[{"address":"0x7c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451","contract_hash":"0x10455c752b86932ce552f2b0fe81a880746649b9aee7e0d842bf3f52378f9f8"}]"#;
        let contracts = vec![Contract {
            address: ContractAddress(
                StarkHash::from_hex_str(
                    "0x7c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451",
                )
                .unwrap(),
            ),
            contract_hash: ClassHash(
                StarkHash::from_hex_str(
                    "0x010455c752b86932ce552f2b0fe81a880746649b9aee7e0d842bf3f52378f9f8",
                )
                .unwrap(),
            ),
        }];
        let s = serde_json::to_string(&DeployedContractsWrapper(Some(&contracts))).unwrap();
        assert_eq!(expected, s);

        // this again could be null or []; it doesn't really have any meaning over at python side,
        // nor is it coupled to the updated contracts value in any way
        let s = serde_json::to_string(&DeployedContractsWrapper(Some(&[]))).unwrap();
        assert_eq!("[]", s);
    }

    #[test]
    fn serialize_none_deployed_contracts() {
        use super::DeployedContractsWrapper;

        // in python's view, this is an optional, whichever [] or null would work
        let expected = r#"null"#;
        let s = serde_json::to_string(&DeployedContractsWrapper(None)).unwrap();
        assert_eq!(expected, s);
    }

    #[test]
    fn serialize_block_hash_num_latest() {
        use super::BlockHashNumberOrLatest;
        use crate::core::{StarknetBlockHash, StarknetBlockNumber};

        let data = &[
            (StarknetBlockHash(StarkHash::ZERO).into(), "\"0x0\""),
            (StarknetBlockNumber(0).into(), "0"),
            (BlockHashNumberOrLatest::Latest, "\"latest\""),
        ];

        for (input, output) in data {
            assert_eq!(output, &serde_json::to_string(input).unwrap())
        }
    }
}
