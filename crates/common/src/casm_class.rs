use num_bigint::BigUint;
use num_traits::Num;
use pathfinder_crypto::Felt;
use serde::{Deserialize, Serialize};

use crate::EntryPoint;

/// A contract in the Starknet network.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct CasmContractClass {
    pub bytecode: Vec<Felt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytecode_segment_lengths: Option<NestedIntList>,
    pub compiler_version: String,
    pub hints: serde_json::Value,
    pub entry_points_by_type: CasmContractEntryPoints,
    pub prime: BigUintAsHex,
}

/// The entry points (functions) of a contract.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct CasmContractEntryPoints {
    #[serde(rename = "EXTERNAL")]
    pub external: Vec<CasmContractEntryPoint>,
    #[serde(rename = "L1_HANDLER")]
    pub l1_handler: Vec<CasmContractEntryPoint>,
    #[serde(rename = "CONSTRUCTOR")]
    pub constructor: Vec<CasmContractEntryPoint>,
}

/// An entry point (function) of a contract.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct CasmContractEntryPoint {
    /// A field element that encodes the signature of the called function.
    pub selector: EntryPoint,
    /// The offset of the instruction that should be called within the contract
    /// bytecode.
    pub offset: usize,
    // List of builtins.
    pub builtins: Vec<String>,
}

/// A field element that encodes the signature of the called function.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub struct BigUintAsHex {
    /// A field element that encodes the signature of the called function.
    #[serde(
        serialize_with = "serialize_big_uint",
        deserialize_with = "deserialize_big_uint"
    )]
    pub value: BigUint,
}

pub fn serialize_big_uint<S>(num: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("{num:#x}"))
}

pub fn deserialize_big_uint<'a, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: serde::Deserializer<'a>,
{
    let s = &<String as serde::Deserialize>::deserialize(deserializer)?;
    match s.strip_prefix("0x") {
        Some(num_no_prefix) => BigUint::from_str_radix(num_no_prefix, 16)
            .map_err(|error| serde::de::Error::custom(format!("{error}"))),
        None => Err(serde::de::Error::custom(format!(
            "{s} does not start with `0x` is missing."
        ))),
    }
}

/// NestedIntList is either a list of NestedIntList or an integer.
/// E.g., `[0, [1, 2], [3, [4]]]`.
///
/// Used to represents the lengths of the segments in a contract, which are in a
/// form of a tree.
///
/// For example, the contract may be segmented by functions, where each function
/// is segmented by its branches. It is also possible to have the inner
/// segmentation only for some of the functions, while others are kept as
/// non-segmented leaves in the tree.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum NestedIntList {
    Leaf(usize),
    Node(Vec<NestedIntList>),
}

impl TryFrom<&str> for CasmContractClass {
    type Error = serde_json::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        serde_json::from_str(value)
    }
}
