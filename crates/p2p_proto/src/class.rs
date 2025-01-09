use std::fmt::Debug;

use fake::{Dummy, Fake, Faker};
use pathfinder_crypto::Felt;
use tagged::Tagged;
use tagged_debug_derive::TaggedDebug;

use crate::common::{Hash, Iteration};
use crate::{proto, proto_field, ToProtobuf, TryFromProtobuf};

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, PartialOrd, Ord)]
#[protobuf(name = "crate::proto::class::EntryPoint")]
pub struct EntryPoint {
    pub selector: Felt,
    pub offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, ToProtobuf, TryFromProtobuf, PartialOrd, Ord)]
#[protobuf(name = "crate::proto::class::Cairo0Class")]
pub struct Cairo0Class {
    pub abi: String,
    pub externals: Vec<EntryPoint>,
    pub l1_handlers: Vec<EntryPoint>,
    pub constructors: Vec<EntryPoint>,
    pub program: String,
}

impl<T> Dummy<T> for Cairo0Class {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            abi: Faker.fake_with_rng(rng),
            externals: Faker.fake_with_rng(rng),
            l1_handlers: Faker.fake_with_rng(rng),
            constructors: Faker.fake_with_rng(rng),
            program: serde_json::to_string(&serde_json::Value::Object(Faker.fake_with_rng(rng)))
                .unwrap(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, PartialOrd, Ord)]
#[protobuf(name = "crate::proto::class::SierraEntryPoint")]
pub struct SierraEntryPoint {
    pub index: u64,
    pub selector: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, PartialOrd, Ord)]
#[protobuf(name = "crate::proto::class::Cairo1EntryPoints")]
pub struct Cairo1EntryPoints {
    pub externals: Vec<SierraEntryPoint>,
    pub l1_handlers: Vec<SierraEntryPoint>,
    pub constructors: Vec<SierraEntryPoint>,
}

#[derive(Clone, Debug, PartialEq, Eq, ToProtobuf, TryFromProtobuf, PartialOrd, Ord)]
#[protobuf(name = "crate::proto::class::Cairo1Class")]
pub struct Cairo1Class {
    pub abi: String,
    pub entry_points: Cairo1EntryPoints,
    pub program: Vec<Felt>,
    pub contract_class_version: String,
}

impl<T> Dummy<T> for Cairo1Class {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            abi: Faker.fake_with_rng(rng),
            entry_points: Faker.fake_with_rng(rng),
            program: Faker.fake_with_rng(rng),
            contract_class_version: "0.1.0".into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Dummy, TaggedDebug)]
pub enum Class {
    Cairo0 {
        class: Cairo0Class,
        domain: u32,
        class_hash: Hash,
    },
    Cairo1 {
        class: Cairo1Class,
        domain: u32,
        class_hash: Hash,
    },
}

impl ToProtobuf<proto::class::Class> for Class {
    fn to_protobuf(self) -> proto::class::Class {
        use proto::class::class::Class::{Cairo0, Cairo1};
        use proto::class::Class;
        match self {
            Self::Cairo0 {
                class,
                domain,
                class_hash,
            } => Class {
                class: Some(Cairo0(class.to_protobuf())),
                domain,
                class_hash: Some(class_hash.to_protobuf()),
            },
            Self::Cairo1 {
                class,
                domain,
                class_hash,
            } => Class {
                class: Some(Cairo1(class.to_protobuf())),
                domain,
                class_hash: Some(class_hash.to_protobuf()),
            },
        }
    }
}

impl TryFromProtobuf<proto::class::Class> for Class {
    fn try_from_protobuf(
        input: proto::class::Class,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::class::class::Class::{Cairo0, Cairo1};
        let class_hash = Hash::try_from_protobuf(input.class_hash, field_name)?;
        Ok(match proto_field(input.class, field_name)? {
            Cairo0(c) => Self::Cairo0 {
                class: Cairo0Class::try_from_protobuf(c, field_name)?,
                domain: input.domain,
                class_hash,
            },
            Cairo1(c) => Self::Cairo1 {
                class: Cairo1Class::try_from_protobuf(c, field_name)?,
                domain: input.domain,
                class_hash,
            },
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::class::ClassesRequest")]
pub struct ClassesRequest {
    pub iteration: Iteration,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Default, Clone, PartialEq, Eq, Dummy)]
pub enum ClassesResponse {
    Class(Class),
    #[default]
    Fin,
}

impl ToProtobuf<proto::class::ClassesResponse> for ClassesResponse {
    fn to_protobuf(self) -> proto::class::ClassesResponse {
        use proto::class::classes_response::ClassMessage::{Class, Fin};
        use proto::class::ClassesResponse;
        match self {
            Self::Class(class) => ClassesResponse {
                class_message: Some(Class(class.to_protobuf())),
            },
            Self::Fin => ClassesResponse {
                class_message: Some(Fin(proto::common::Fin {})),
            },
        }
    }
}

impl TryFromProtobuf<proto::class::ClassesResponse> for ClassesResponse {
    fn try_from_protobuf(
        input: proto::class::ClassesResponse,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::class::classes_response::ClassMessage::{Class, Fin};
        match proto_field(input.class_message, field_name)? {
            Class(c) => Ok(Self::Class(TryFromProtobuf::try_from_protobuf(
                c, field_name,
            )?)),
            Fin(_) => Ok(Self::Fin),
        }
    }
}
