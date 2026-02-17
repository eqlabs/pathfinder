use std::borrow::Cow;
use std::fmt;

use fake::{Dummy, Fake, Faker};
use pathfinder_crypto::Felt;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_with::serde_as;

use crate::{ByteCodeOffset, EntryPoint};

pub const CLASS_DEFINITION_MAX_ALLOWED_SIZE: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize, Dummy)]
pub enum ClassDefinition<'a> {
    Sierra(Sierra<'a>),
    Cairo(Cairo<'a>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sierra<'a> {
    /// Contract ABI.
    pub abi: Cow<'a, str>,

    /// Main program definition.
    pub sierra_program: Vec<Felt>,

    // Version
    pub contract_class_version: Cow<'a, str>,

    /// The contract entry points
    pub entry_points_by_type: SierraEntryPoints,
}

impl<T> Dummy<T> for Sierra<'_> {
    fn dummy_with_rng<R: Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            abi: "[]".into(),
            sierra_program: Faker.fake_with_rng(rng),
            contract_class_version: "0.1.0".into(),
            entry_points_by_type: Faker.fake_with_rng(rng),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cairo<'a> {
    /// Contract ABI, which has no schema definition.
    pub abi: Cow<'a, RawValue>,

    /// Main program definition. __We assume that this is valid JSON.__
    pub program: Cow<'a, RawValue>,

    /// The contract entry points.
    pub entry_points_by_type: CairoEntryPoints,
}

impl<T> Dummy<T> for Cairo<'_> {
    fn dummy_with_rng<R: Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            abi: Cow::Owned(
                RawValue::from_string("[]".into()).unwrap(),
            ),
            program: Cow::Owned(
                RawValue::from_string(
                    r#"
                    {
                        "attributes": [],
                        "builtins": [],
                        "data": [],
                        "debug_info": null,
                        "hints": {},
                        "identifiers": {},
                        "main_scope": "__main__",
                        "prime": "0x800000000000011000000000000000000000000000000000000000000000001",
                        "reference_manager": {}
                    }
                    "#.into()
                )
                .unwrap(),
            ),
            entry_points_by_type: Faker.fake_with_rng(rng),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Dummy)]
#[serde(deny_unknown_fields)]
pub struct SierraEntryPoints {
    #[serde(rename = "EXTERNAL")]
    pub external: Vec<SelectorAndFunctionIndex>,
    #[serde(rename = "L1_HANDLER")]
    pub l1_handler: Vec<SelectorAndFunctionIndex>,
    #[serde(rename = "CONSTRUCTOR")]
    pub constructor: Vec<SelectorAndFunctionIndex>,
}

#[derive(Debug, Deserialize, Serialize, Dummy)]
#[serde(deny_unknown_fields)]
pub struct CairoEntryPoints {
    #[serde(rename = "EXTERNAL")]
    pub external: Vec<SelectorAndOffset>,
    #[serde(rename = "L1_HANDLER")]
    pub l1_handler: Vec<SelectorAndOffset>,
    #[serde(rename = "CONSTRUCTOR")]
    pub constructor: Vec<SelectorAndOffset>,
}

#[derive(Copy, Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Hash, Eq)]
#[serde(deny_unknown_fields)]
pub enum EntryPointType {
    #[serde(rename = "EXTERNAL")]
    External,
    #[serde(rename = "L1_HANDLER")]
    L1Handler,
    #[serde(rename = "CONSTRUCTOR")]
    Constructor,
}

impl fmt::Display for EntryPointType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use EntryPointType::*;
        f.pad(match self {
            External => "EXTERNAL",
            L1Handler => "L1_HANDLER",
            Constructor => "CONSTRUCTOR",
        })
    }
}

#[serde_as]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SelectorAndOffset {
    pub selector: EntryPoint,
    #[serde_as(as = "OffsetSerde")]
    pub offset: ByteCodeOffset,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub enum OffsetSerde {
    HexStr(Felt),
    Decimal(u64),
}

impl serde_with::SerializeAs<ByteCodeOffset> for OffsetSerde {
    fn serialize_as<S>(source: &ByteCodeOffset, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::Serialize;

        Felt::serialize(&source.0, serializer)
    }
}

impl<'de> serde_with::DeserializeAs<'de, ByteCodeOffset> for OffsetSerde {
    fn deserialize_as<D>(deserializer: D) -> Result<ByteCodeOffset, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::Deserialize;

        let offset = OffsetSerde::deserialize(deserializer)?;
        let offset = match offset {
            OffsetSerde::HexStr(felt) => felt,
            OffsetSerde::Decimal(decimal) => Felt::from_u64(decimal),
        };
        Ok(ByteCodeOffset(offset))
    }
}

impl<T> Dummy<T> for SelectorAndOffset {
    fn dummy_with_rng<R: rand::prelude::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            selector: Faker.fake_with_rng(rng),
            offset: ByteCodeOffset(Felt::from_u64(rng.gen())),
        }
    }
}

/// Descriptor of an entry point in a Sierra class.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, Dummy)]
#[serde(deny_unknown_fields)]
pub struct SelectorAndFunctionIndex {
    pub selector: EntryPoint,
    pub function_idx: u64,
}
