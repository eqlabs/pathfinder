use fake::Dummy;

use crate::class::Class;
use crate::sync::common::Iteration;
use crate::{proto, proto_field, ToProtobuf, TryFromProtobuf};

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::class::ClassesRequest")]
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

impl ToProtobuf<proto::sync::class::ClassesResponse> for ClassesResponse {
    fn to_protobuf(self) -> proto::sync::class::ClassesResponse {
        use proto::sync::class::classes_response::ClassMessage::{Class, Fin};
        use proto::sync::class::ClassesResponse;
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

impl TryFromProtobuf<proto::sync::class::ClassesResponse> for ClassesResponse {
    fn try_from_protobuf(
        input: proto::sync::class::ClassesResponse,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::sync::class::classes_response::ClassMessage::{Class, Fin};
        match proto_field(input.class_message, field_name)? {
            Class(c) => Ok(Self::Class(TryFromProtobuf::try_from_protobuf(
                c, field_name,
            )?)),
            Fin(_) => Ok(Self::Fin),
        }
    }
}
