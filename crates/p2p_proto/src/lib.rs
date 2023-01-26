use stark_hash::Felt;

pub mod proto {
    pub mod common {
        include!(concat!(env!("OUT_DIR"), "/starknet.common.rs"));
    }
    pub mod propagation {
        include!(concat!(env!("OUT_DIR"), "/starknet.propagation.rs"));
    }
    pub mod sync {
        include!(concat!(env!("OUT_DIR"), "/starknet.sync.rs"));
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

impl ToProtobuf<String> for String {
    fn to_protobuf(self) -> String {
        self
    }
}

impl ToProtobuf<proto::common::FieldElement> for Felt {
    fn to_protobuf(self) -> proto::common::FieldElement {
        proto::common::FieldElement {
            elements: self.to_be_bytes().into(),
        }
    }
}

impl ToProtobuf<proto::common::EthereumAddress> for primitive_types::H160 {
    fn to_protobuf(self) -> proto::common::EthereumAddress {
        proto::common::EthereumAddress {
            elements: self.to_fixed_bytes().into(),
        }
    }
}

impl<M, T: ToProtobuf<M>> ToProtobuf<Vec<M>> for Vec<T> {
    fn to_protobuf(self) -> Vec<M> {
        self.into_iter().map(ToProtobuf::to_protobuf).collect()
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

impl TryFromProtobuf<String> for String {
    fn try_from_protobuf(input: String, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl TryFromProtobuf<proto::common::FieldElement> for Felt {
    fn try_from_protobuf(
        input: proto::common::FieldElement,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        let stark_hash = Felt::from_be_slice(&input.elements).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid field element {field_name}: {e}"),
            )
        })?;
        Ok(stark_hash)
    }
}

impl TryFromProtobuf<proto::common::EthereumAddress> for primitive_types::H160 {
    fn try_from_protobuf(
        input: proto::common::EthereumAddress,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        if input.elements.len() != primitive_types::H160::len_bytes() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length for Ethereum address {field_name}"),
            ));
        }

        // from_slice() panics if the input length is incorrect, but we've already checked that
        let address = primitive_types::H160::from_slice(&input.elements);
        Ok(address)
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

use p2p_proto_derive::*;
#[derive(ToProtobuf)]
#[protobuf(name = "crate::proto::common::Event")]
struct Event {
    pub from_address: Felt,
    pub keys: Vec<Felt>,
    pub data: Vec<Felt>,
}

pub mod common;
pub mod propagation;
pub mod sync;
