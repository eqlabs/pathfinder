use pathfinder_common::{BlockHash, BlockNumber};
use pathfinder_serde::block_number_as_hex_str;
use serde_with::serde_as;

use crate::dto::U64Hex;

/// Describes Starknet's syncing status RPC reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Syncing {
    False,
    Status(Status),
}

impl std::fmt::Display for Syncing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Syncing::False => f.write_str("false"),
            Syncing::Status(status) => {
                write!(f, "{status}")
            }
        }
    }
}

impl crate::dto::serialize::SerializeForVersion for Syncing {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        match self {
            Syncing::False => serializer.serialize_bool(false),
            Syncing::Status(status) => status.serialize(serializer),
        }
    }
}

impl crate::dto::DeserializeForVersion for Syncing {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        // First try to deserialize as a boolean
        if value.clone().deserialize_serde::<bool>().is_ok() {
            return Ok(Syncing::False);
        }

        // If not a boolean, try to deserialize as a Status
        let status = Status::deserialize(value)?;
        Ok(Syncing::Status(status))
    }
}

/// Represents Starknet node syncing status.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub starting: NumberedBlock,
    pub current: NumberedBlock,
    pub highest: NumberedBlock,
}

serde_with::with_prefix!(prefix_starting "starting_");
serde_with::with_prefix!(prefix_current "current_");
serde_with::with_prefix!(prefix_highest "highest_");

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "starting: {:?}, current: {:?}, highest: {:?}",
            self.starting, self.current, self.highest,
        )
    }
}

impl crate::dto::serialize::SerializeForVersion for Status {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("starting_block_hash", &self.starting.hash)?;
        serializer.serialize_field(
            "starting_block_num",
            &block_number_as_hex_str(&self.starting.number),
        )?;
        serializer.serialize_field("current_block_hash", &self.current.hash)?;
        serializer.serialize_field(
            "current_block_num",
            &block_number_as_hex_str(&self.current.number),
        )?;
        serializer.serialize_field("highest_block_hash", &self.highest.hash)?;
        serializer.serialize_field(
            "highest_block_num",
            &block_number_as_hex_str(&self.highest.number),
        )?;
        serializer.end()
    }
}

impl crate::dto::DeserializeForVersion for Status {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                starting: NumberedBlock {
                    hash: value.deserialize("starting_block_hash").map(BlockHash)?,
                    number: value
                        .deserialize::<U64Hex>("starting_block_num")
                        .map(|num| BlockNumber::new_or_panic(num.0))?,
                },
                current: NumberedBlock {
                    hash: value.deserialize("current_block_hash").map(BlockHash)?,
                    number: value
                        .deserialize::<U64Hex>("current_block_num")
                        .map(|num| BlockNumber::new_or_panic(num.0))?,
                },
                highest: NumberedBlock {
                    hash: value.deserialize("highest_block_hash").map(BlockHash)?,
                    number: value
                        .deserialize::<U64Hex>("highest_block_num")
                        .map(|num| BlockNumber::new_or_panic(num.0))?,
                },
            })
        })
    }
}

/// Block hash and a number, for `starknet_syncing` response only.
#[serde_as]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct NumberedBlock {
    #[cfg_attr(test, serde(rename = "block_hash"))]
    pub hash: BlockHash,
    #[cfg_attr(test, serde_as(as = "StarknetBlockNumberAsHexStr"))]
    #[cfg_attr(test, serde(rename = "block_num"))]
    pub number: BlockNumber,
}

impl std::fmt::Debug for NumberedBlock {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "({}, {})", self.hash.0, self.number.get())
    }
}

impl From<(BlockHash, BlockNumber)> for NumberedBlock {
    fn from((hash, number): (BlockHash, BlockNumber)) -> Self {
        NumberedBlock { hash, number }
    }
}

/// Helper to make it a bit less painful to write examples.
#[cfg(test)]
impl<'a> From<(&'a str, u64)> for NumberedBlock {
    fn from((h, n): (&'a str, u64)) -> Self {
        use pathfinder_crypto::Felt;
        NumberedBlock {
            hash: BlockHash(Felt::from_hex_str(h).unwrap()),
            number: BlockNumber::new_or_panic(n),
        }
    }
}
