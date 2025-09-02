use p2p_proto_derive::*;

pub mod consensus;
//pub mod mempool;
pub mod sync;

pub mod class;
pub mod common;
pub mod transaction;

#[allow(clippy::module_inception)]
pub mod proto {

    pub mod capabilities {
        include!(concat!(env!("OUT_DIR"), "/starknet.capabilities.rs"));
    }

    #[allow(clippy::large_enum_variant)]
    pub mod class {
        include!(concat!(env!("OUT_DIR"), "/starknet.class.rs"));
    }

    pub mod common {
        include!(concat!(env!("OUT_DIR"), "/starknet.common.rs"));
    }

    pub mod consensus {
        pub mod consensus {
            include!(concat!(env!("OUT_DIR"), "/starknet.consensus.consensus.rs"));
        }
    }

    pub mod discovery {
        include!(concat!(env!("OUT_DIR"), "/starknet.discovery.rs"));
    }

    pub mod mempool {
        #[allow(clippy::large_enum_variant)]
        pub mod transaction {
            include!(concat!(env!("OUT_DIR"), "/starknet.mempool.transaction.rs"));
        }
    }

    pub mod snapshot {
        include!(concat!(env!("OUT_DIR"), "/starknet.snapshot.rs"));
    }

    pub mod sync {
        #[allow(clippy::large_enum_variant)]
        pub mod class {
            include!(concat!(env!("OUT_DIR"), "/starknet.sync.class.rs"));
        }
        pub mod common {
            include!(concat!(env!("OUT_DIR"), "/starknet.sync.common.rs"));
        }
        pub mod event {
            include!(concat!(env!("OUT_DIR"), "/starknet.sync.event.rs"));
        }
        #[allow(clippy::large_enum_variant)]
        pub mod header {
            include!(concat!(env!("OUT_DIR"), "/starknet.sync.header.rs"));
        }
        #[allow(clippy::large_enum_variant)]
        pub mod receipt {
            include!(concat!(env!("OUT_DIR"), "/starknet.sync.receipt.rs"));
        }
        pub mod state {
            include!(concat!(env!("OUT_DIR"), "/starknet.sync.state.rs"));
        }
        #[allow(clippy::large_enum_variant)]
        pub mod transaction {
            include!(concat!(env!("OUT_DIR"), "/starknet.sync.transaction.rs"));
        }
    }

    #[allow(clippy::large_enum_variant)]
    pub mod transaction {
        include!(concat!(env!("OUT_DIR"), "/starknet.transaction.rs"));
    }
}

pub trait ToProtobuf<Output>
where
    Self: Sized,
{
    fn to_protobuf(self) -> Output;
}

impl ToProtobuf<u64> for u64 {
    fn to_protobuf(self) -> u64 {
        self
    }
}

impl ToProtobuf<u32> for u32 {
    fn to_protobuf(self) -> u32 {
        self
    }
}

impl ToProtobuf<u8> for u8 {
    fn to_protobuf(self) -> u8 {
        self
    }
}

impl ToProtobuf<i32> for i32 {
    fn to_protobuf(self) -> i32 {
        self
    }
}

impl ToProtobuf<bool> for bool {
    fn to_protobuf(self) -> bool {
        self
    }
}

impl ToProtobuf<String> for String {
    fn to_protobuf(self) -> String {
        self
    }
}

impl<M, T: ToProtobuf<M>> ToProtobuf<Vec<M>> for Vec<T> {
    fn to_protobuf(self) -> Vec<M> {
        self.into_iter().map(ToProtobuf::to_protobuf).collect()
    }
}

impl<M, T: ToProtobuf<M>> ToProtobuf<Option<M>> for Option<T> {
    fn to_protobuf(self) -> Option<M> {
        self.map(ToProtobuf::to_protobuf)
    }
}

pub trait TryFromProtobuf<M>
where
    Self: Sized,
{
    fn try_from_protobuf(input: M, field_name: &'static str) -> Result<Self, std::io::Error>;
}

impl TryFromProtobuf<u64> for u64 {
    fn try_from_protobuf(input: u64, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl TryFromProtobuf<u32> for u32 {
    fn try_from_protobuf(input: u32, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl TryFromProtobuf<i32> for i32 {
    fn try_from_protobuf(input: i32, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl TryFromProtobuf<u8> for u8 {
    fn try_from_protobuf(input: u8, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl TryFromProtobuf<bool> for bool {
    fn try_from_protobuf(input: bool, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl TryFromProtobuf<String> for String {
    fn try_from_protobuf(input: String, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl<T: TryFromProtobuf<U>, U> TryFromProtobuf<Option<U>> for T {
    fn try_from_protobuf(
        input: Option<U>,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        let input = input.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing field {field_name}"),
            )
        })?;
        TryFromProtobuf::try_from_protobuf(input, field_name)
    }
}

impl<T: TryFromProtobuf<U>, U> TryFromProtobuf<Vec<U>> for Vec<T> {
    fn try_from_protobuf(input: Vec<U>, field_name: &'static str) -> Result<Self, std::io::Error> {
        input
            .into_iter()
            .map(|e| TryFromProtobuf::try_from_protobuf(e, field_name))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse {field_name}: {e}"),
                )
            })
    }
}

fn proto_field<T>(input: Option<T>, field_name: &'static str) -> Result<T, std::io::Error> {
    input.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Missing field {field_name}"),
        )
    })
}

/// Handles the conversion between domain types and protobuf messages.
pub trait ProtobufSerializable: Sized {
    fn to_protobuf_bytes(&self) -> Vec<u8>;
    fn from_protobuf_bytes(bytes: &[u8]) -> Result<Self, std::io::Error>;
}
