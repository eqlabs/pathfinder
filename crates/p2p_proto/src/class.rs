use std::fmt::Debug;

use crate::common::Iteration;
use crate::{proto, proto_field, ToProtobuf, TryFromProtobuf};
use fake::{Dummy, Fake, Faker};
use pathfinder_crypto::Felt;

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, PartialOrd, Ord)]
#[protobuf(name = "crate::proto::class::EntryPoint")]
pub struct EntryPoint {
    pub selector: Felt,
    pub offset: Felt,
}

#[derive(Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, PartialOrd, Ord)]
#[protobuf(name = "crate::proto::class::Cairo0Class")]
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

#[derive(Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, PartialOrd, Ord)]
#[protobuf(name = "crate::proto::class::Cairo1Class")]
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
    Cairo0 { class: Cairo0Class, domain: u32 },
    Cairo1 { class: Cairo1Class, domain: u32 },
}

impl ToProtobuf<proto::class::Class> for Class {
    fn to_protobuf(self) -> proto::class::Class {
        use proto::class::class::Class::{Cairo0, Cairo1};
        use proto::class::Class;
        match self {
            Self::Cairo0 { class, domain } => Class {
                class: Some(Cairo0(class.to_protobuf())),
                domain,
            },
            Self::Cairo1 { class, domain } => Class {
                class: Some(Cairo1(class.to_protobuf())),
                domain,
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
        Ok(match proto_field(input.class, field_name)? {
            Cairo0(c) => Self::Cairo0 {
                class: Cairo0Class::try_from_protobuf(c, field_name)?,
                domain: input.domain,
            },
            Cairo1(c) => Self::Cairo1 {
                class: Cairo1Class::try_from_protobuf(c, field_name)?,
                domain: input.domain,
            },
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::class::ClassesRequest")]
pub struct ClassesRequest {
    pub iteration: Iteration,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum ClassesResponse {
    Class(Class),
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
