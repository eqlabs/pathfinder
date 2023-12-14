use std::fmt::Debug;

use crate::common::Address;
use crate::{ToProtobuf, TryFromProtobuf};
use fake::{Dummy, Fake, Faker};
use pathfinder_crypto::Felt;
use serde::{Deserialize, Serialize};

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

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    ToProtobuf,
    TryFromProtobuf,
    Dummy,
    Deserialize,
    Serialize,
    PartialOrd,
    Ord,
)]
#[protobuf(name = "crate::proto::state::EntryPoint")]
pub struct EntryPoint {
    pub selector: Felt,
    pub offset: Felt,
}

#[derive(/*Debug, */ Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, PartialOrd, Ord)]
#[protobuf(name = "crate::proto::state::Cairo0Class")]
pub struct Cairo0Class {
    pub abi: Vec<u8>,
    pub externals: Vec<EntryPoint>,
    pub l1_handlers: Vec<EntryPoint>,
    pub constructors: Vec<EntryPoint>,
    pub program: Vec<u8>,
}

impl Debug for Cairo0Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cairo0Class")
            .field(
                "abi",
                &std::str::from_utf8(&self.abi)
                    .unwrap_or(&format!("invalid utf8: {:#x?}", &self.abi)),
            )
            .field("externals", &self.externals)
            .field("l1_handlers", &self.l1_handlers)
            .field("constructors", &self.constructors)
            .field(
                "program",
                &std::str::from_utf8(&self.program)
                    .unwrap_or(&format!("invalid utf8: {:#x?}", &self.program)),
            )
            .finish()
    }
}

impl<T> Dummy<T> for Cairo0Class {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            abi: Faker.fake_with_rng::<String, _>(rng).into_bytes(),
            externals: Faker.fake_with_rng(rng),
            l1_handlers: Faker.fake_with_rng(rng),
            constructors: Faker.fake_with_rng(rng),
            // program: serde_json::to_vec(&Faker.fake_with_rng::<serde_json::Value, _>(rng)).unwrap(),
            program: r#"{"a":"program"}"#.into(),
        }
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    ToProtobuf,
    TryFromProtobuf,
    Dummy,
    Deserialize,
    Serialize,
    PartialOrd,
    Ord,
)]
#[protobuf(name = "crate::proto::state::SierraEntryPoint")]
pub struct SierraEntryPoint {
    pub index: u64,
    pub selector: Felt,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    ToProtobuf,
    TryFromProtobuf,
    Dummy,
    Deserialize,
    Serialize,
    PartialOrd,
    Ord,
)]
#[protobuf(name = "crate::proto::state::Cairo1EntryPoints")]
pub struct Cairo1EntryPoints {
    #[serde(rename = "EXTERNAL")]
    pub externals: Vec<SierraEntryPoint>,
    #[serde(rename = "L1_HANDLER")]
    pub l1_handlers: Vec<SierraEntryPoint>,
    #[serde(rename = "CONSTRUCTOR")]
    pub constructors: Vec<SierraEntryPoint>,
}

#[derive(
    /*Debug, */ Clone,
    PartialEq,
    Eq,
    ToProtobuf,
    TryFromProtobuf,
    Deserialize,
    Serialize,
    PartialOrd,
    Ord,
)]
#[protobuf(name = "crate::proto::state::Cairo1Class")]
pub struct Cairo1Class {
    #[serde(serialize_with = "json::serialize::bytes_as_str")]
    pub abi: Vec<u8>,
    #[serde(rename = "entry_points_by_type")]
    pub entry_points: Cairo1EntryPoints,
    #[serde(rename = "sierra_program")]
    pub program: Vec<Felt>,
    pub contract_class_version: String,
    #[serde(skip_deserializing)]
    pub compiled: Vec<u8>,
}

impl Debug for Cairo1Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cairo1Class")
            .field(
                "abi",
                &std::str::from_utf8(&self.abi)
                    .unwrap_or(&format!("invalid utf8: {:#x?}", &self.abi)),
            )
            .field("entry_points", &self.entry_points)
            .field("program", &self.program)
            .field("contract_class_version", &self.contract_class_version)
            .field("compiled", &format!("invalid utf8: {:#x?}", &self.compiled))
            .finish()
    }
}

impl<T> Dummy<T> for Cairo1Class {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            abi: Faker.fake_with_rng::<String, _>(rng).into_bytes(),
            entry_points: Faker.fake_with_rng(rng),
            program: Faker.fake_with_rng(rng),
            contract_class_version: "0.1.0".into(),
            compiled: Faker.fake_with_rng(rng),
        }
    }
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

impl<'a> From<json::deserialize::Cairo0Class<'a>> for Class {
    fn from(c: json::deserialize::Cairo0Class<'a>) -> Self {
        Self::Cairo0(Cairo0Class {
            abi: c.abi.as_bytes().to_vec(),
            externals: c.entry_points_by_type.externals,
            l1_handlers: c.entry_points_by_type.l1_handlers,
            constructors: c.entry_points_by_type.constructors,
            program: c.program.get().as_bytes().to_vec(),
        })
    }
}

impl From<Cairo1Class> for Class {
    fn from(c: Cairo1Class) -> Self {
        Self::Cairo1(c)
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

pub mod json {
    use super::EntryPoint;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize)]
    pub struct Cairo0Class {
        #[serde(serialize_with = "serialize::bytes_as_str")]
        pub abi: Vec<u8>,
        pub entry_points_by_type: Cairo0ClassEntryPoints,
        pub program: Box<serde_json::value::RawValue>,
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
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

    pub mod serialize {
        pub fn bytes_as_str<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let s = std::str::from_utf8(bytes).map_err(serde::ser::Error::custom)?;
            serializer.serialize_str(&s)
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

    pub mod deserialize {
        use serde::Deserialize;
        use serde_json::value::RawValue;

        #[derive(Debug, Clone, Deserialize)]
        pub struct Cairo0Class<'a> {
            #[serde(borrow)]
            pub abi: &'a str,
            pub entry_points_by_type: super::Cairo0ClassEntryPoints,
            pub program: &'a RawValue,
        }
    }
}
