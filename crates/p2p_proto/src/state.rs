use std::fmt::Debug;

use crate::common::Address;
use crate::{ToProtobuf, TryFromProtobuf};
use fake::Dummy;
use pathfinder_crypto::Felt;

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::state::ContractStoredValue")]
pub struct ContractStoredValue {
    pub key: Felt,
    pub value: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::state::state_diff::ContractDiff")]
pub struct ContractDiff {
    pub address: Address,
    #[optional]
    pub nonce: Option<Felt>,
    #[optional]
    pub class_hash: Option<Felt>,
    pub values: Vec<ContractStoredValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::state::StateDiff")]
pub struct StateDiff {
    pub domain: u32,
    pub contract_diffs: Vec<ContractDiff>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, serde::Serialize)]
#[protobuf(name = "crate::proto::state::EntryPoint")]
pub struct EntryPoint {
    pub selector: Felt,
    pub offset: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::state::Cairo0Class")]
pub struct Cairo0Class {
    pub abi: Vec<u8>,
    pub externals: Vec<EntryPoint>,
    pub l1_handlers: Vec<EntryPoint>,
    pub constructors: Vec<EntryPoint>,
    pub program: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, serde::Serialize)]
#[protobuf(name = "crate::proto::state::SierraEntryPoint")]
pub struct SierraEntryPoint {
    pub index: u64,
    pub selector: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, serde::Serialize)]
#[protobuf(name = "crate::proto::state::Cairo1EntryPoints")]
pub struct Cairo1EntryPoints {
    #[serde(rename = "EXTERNAL")]
    pub externals: Vec<SierraEntryPoint>,
    #[serde(rename = "L1_HANDLER")]
    pub l1_handlers: Vec<SierraEntryPoint>,
    #[serde(rename = "CONSTRUCTOR")]
    pub constructors: Vec<SierraEntryPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, serde::Serialize)]
#[protobuf(name = "crate::proto::state::Cairo1Class")]
pub struct Cairo1Class {
    #[serde(serialize_with = "json::bytes_as_str")]
    pub abi: Vec<u8>,
    #[serde(rename = "entry_points_by_type")]
    pub entry_points: Cairo1EntryPoints,
    #[serde(rename = "sierra_program")]
    pub program: Vec<Felt>,
    pub contract_class_version: String,
    #[serde(skip)]
    pub compiled: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum Class {
    Cairo0(Cairo0Class),
    Cairo1(Cairo1Class),
}

impl Class {
    pub fn to_json(self) -> anyhow::Result<Vec<u8>> {
        Ok(match self {
            Self::Cairo0(c) => serde_json::to_vec(&json::Cairo0Class::try_from(c)?)?,
            Self::Cairo1(c) => serde_json::to_vec(&c)?,
        })
    }
}

mod json {
    use super::EntryPoint;
    use serde::Serialize;

    pub fn bytes_as_str<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = std::str::from_utf8(bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&s)
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct Cairo0Class {
        #[serde(serialize_with = "bytes_as_str")]
        pub abi: Vec<u8>,
        pub entry_points_by_type: Cairo0ClassEntryPoints,
        pub program: Box<serde_json::value::RawValue>,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct Cairo0ClassEntryPoints {
        #[serde(rename = "EXTERNAL")]
        pub externals: Vec<EntryPoint>,
        #[serde(rename = "L1_HANDLER")]
        pub l1_handlers: Vec<EntryPoint>,
        #[serde(rename = "CONSTRUCTOR")]
        pub constructors: Vec<EntryPoint>,
    }

    impl TryFrom<super::Cairo0Class> for Cairo0Class {
        type Error = anyhow::Error;

        fn try_from(c: super::Cairo0Class) -> Result<Self, Self::Error> {
            Ok(Self {
                abi: c.abi,
                entry_points_by_type: Cairo0ClassEntryPoints {
                    externals: c.externals,
                    l1_handlers: c.l1_handlers,
                    constructors: c.constructors,
                },
                program: serde_json::value::RawValue::from_string(String::from_utf8(c.program)?)?,
            })
        }
    }

    #[cfg(test)]
    #[test]
    fn serialization() {
        use super::{Cairo1Class, Cairo1EntryPoints, Class};
        const COMMON_EXPECTED: &str = r#"{"abi":"{\"this_is\":\"the_abi\"}","entry_points_by_type":{"EXTERNAL":[],"L1_HANDLER":[],"CONSTRUCTOR":[]},"#;

        let c0 = Class::Cairo0(super::Cairo0Class {
            abi: b"{\"this_is\":\"the_abi\"}".to_vec(),
            externals: vec![],
            l1_handlers: vec![],
            constructors: vec![],
            program: b"{\"this_is\":\"the_program\"}".to_vec(),
        });
        pretty_assertions_sorted::assert_eq!(
            std::str::from_utf8(&c0.to_json().unwrap()).unwrap(),
            [COMMON_EXPECTED, r#""program":{"this_is":"the_program"}}"#].concat()
        );

        let c1 = Class::Cairo1(Cairo1Class {
            abi: b"{\"this_is\":\"the_abi\"}".to_vec(),
            entry_points: Cairo1EntryPoints {
                externals: vec![],
                l1_handlers: vec![],
                constructors: vec![],
            },
            program: vec![1u64.into()],
            contract_class_version: "1.2.3".to_string(),
            compiled: vec![0xFF],
        });
        pretty_assertions_sorted::assert_eq!(
            std::str::from_utf8(&c1.to_json().unwrap()).unwrap(),
            [
                COMMON_EXPECTED,
                r#""sierra_program":["0x1"],"contract_class_version":"1.2.3"}"#
            ]
            .concat()
        );
    }
}

impl ToProtobuf<crate::proto::state::Class> for Class {
    fn to_protobuf(self) -> crate::proto::state::Class {
        use crate::proto::state::{
            class::Class::{Cairo0, Cairo1},
            Class,
        };
        Class {
            class: Some(match self {
                Self::Cairo0(c) => Cairo0(c.to_protobuf()),
                Self::Cairo1(c) => Cairo1(c.to_protobuf()),
            }),
        }
    }
}

impl TryFromProtobuf<crate::proto::state::Class> for Class {
    fn try_from_protobuf(
        input: crate::proto::state::Class,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use crate::proto::state::class::Class::{Cairo0, Cairo1};
        match input.class {
            Some(Cairo0(c)) => Ok(Self::Cairo0(Cairo0Class::try_from_protobuf(c, field_name)?)),
            Some(Cairo1(c)) => Ok(Self::Cairo1(Cairo1Class::try_from_protobuf(c, field_name)?)),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: class field missing", field_name),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::state::Classes")]
pub struct Classes {
    pub domain: u32,
    pub classes: Vec<Class>,
}
