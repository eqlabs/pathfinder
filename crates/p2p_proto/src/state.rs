use std::fmt::Debug;

use crate::common::Address;
use crate::{ToProtobuf, TryFromProtobuf};
use fake::{Dummy, Fake, Faker};
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

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, PartialOrd, Ord)]
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
            program: serde_json::to_vec(&serde_json::Value::Object(Faker.fake_with_rng(rng)))
                .unwrap(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, PartialOrd, Ord)]
#[protobuf(name = "crate::proto::state::SierraEntryPoint")]
pub struct SierraEntryPoint {
    pub index: u64,
    pub selector: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, PartialOrd, Ord)]
#[protobuf(name = "crate::proto::state::Cairo1EntryPoints")]
pub struct Cairo1EntryPoints {
    pub externals: Vec<SierraEntryPoint>,
    pub l1_handlers: Vec<SierraEntryPoint>,
    pub constructors: Vec<SierraEntryPoint>,
}

#[derive(Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, PartialOrd, Ord)]
#[protobuf(name = "crate::proto::state::Cairo1Class")]
pub struct Cairo1Class {
    pub abi: Vec<u8>,
    pub entry_points: Cairo1EntryPoints,
    pub program: Vec<Felt>,
    pub contract_class_version: String,
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
            .field(
                "compiled",
                &std::str::from_utf8(&self.abi)
                    .unwrap_or(&format!("invalid utf8: {:#x?}", &self.compiled)),
            )
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
