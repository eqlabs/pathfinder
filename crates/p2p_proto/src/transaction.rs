use fake::Dummy;
use pathfinder_crypto::Felt;

use crate::class::Cairo1Class;
use crate::common::{Address, Hash, VolitionDomain};
use crate::{ToProtobuf, TryFromProtobuf};

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::transaction::ResourceLimits")]
pub struct ResourceLimits {
    pub max_amount: Felt,
    pub max_price_per_unit: Felt,
}

impl<T> Dummy<T> for ResourceLimits {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            max_amount: Felt::from_u64(rng.gen()),
            max_price_per_unit: Felt::from_u128(rng.gen()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::ResourceBounds")]
pub struct ResourceBounds {
    pub l1_gas: ResourceLimits,
    pub l2_gas: ResourceLimits,
    #[optional]
    pub l1_data_gas: Option<ResourceLimits>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::AccountSignature")]
pub struct AccountSignature {
    pub parts: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::L1HandlerV0")]
pub struct L1HandlerV0 {
    pub nonce: Felt,
    pub address: Address,
    pub entry_point_selector: Felt,
    pub calldata: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::DeclareV3Common")]
pub struct DeclareV3Common {
    pub sender: Address,
    pub signature: AccountSignature,
    pub nonce: Felt,
    pub compiled_class_hash: Hash,
    pub resource_bounds: ResourceBounds,
    pub tip: u64,
    pub paymaster_data: Vec<Felt>,
    pub account_deployment_data: Vec<Felt>,
    pub nonce_data_availability_mode: VolitionDomain,
    pub fee_data_availability_mode: VolitionDomain,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::DeclareV3WithClass")]
pub struct DeclareV3WithClass {
    pub common: DeclareV3Common,
    pub class: Cairo1Class,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::InvokeV3")]
pub struct InvokeV3 {
    pub sender: Address,
    pub signature: AccountSignature,
    pub calldata: Vec<Felt>,
    pub resource_bounds: ResourceBounds,
    pub tip: u64,
    pub paymaster_data: Vec<Felt>,
    pub account_deployment_data: Vec<Felt>,
    pub nonce_data_availability_mode: VolitionDomain,
    pub fee_data_availability_mode: VolitionDomain,
    pub nonce: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::DeployAccountV3")]
pub struct DeployAccountV3 {
    pub signature: AccountSignature,
    pub class_hash: Hash,
    pub nonce: Felt,
    pub address_salt: Felt,
    pub calldata: Vec<Felt>,
    pub resource_bounds: ResourceBounds,
    pub tip: u64,
    pub paymaster_data: Vec<Felt>,
    pub nonce_data_availability_mode: VolitionDomain,
    pub fee_data_availability_mode: VolitionDomain,
}
