use crate::{
    prelude::*, AccountDeploymentDataElem, PaymasterDataElem, ResourceAmount, ResourcePricePerUnit,
    Tip,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub hash: TransactionHash,
    pub variant: TransactionVariant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionVariant {
    DeclareV0(DeclareTransactionV0V1),
    DeclareV1(DeclareTransactionV0V1),
    DeclareV2(DeclareTransactionV2),
    DeclareV3(DeclareTransactionV3),
    // Regenesis: deploy is a legacy variant and can be removed after regenesis.
    Deploy(DeployTransaction),
    DeployAccountV0V1(DeployAccountTransactionV0V1),
    DeployAccountV3(DeployAccountTransactionV3),
    InvokeV0(InvokeTransactionV0),
    InvokeV1(InvokeTransactionV1),
    InvokeV3(InvokeTransactionV3),
    L1Handler(L1HandlerTransaction),
}

impl From<DeclareTransactionV2> for TransactionVariant {
    fn from(value: DeclareTransactionV2) -> Self {
        Self::DeclareV2(value)
    }
}
impl From<DeclareTransactionV3> for TransactionVariant {
    fn from(value: DeclareTransactionV3) -> Self {
        Self::DeclareV3(value)
    }
}
impl From<DeployTransaction> for TransactionVariant {
    fn from(value: DeployTransaction) -> Self {
        Self::Deploy(value)
    }
}
impl From<DeployAccountTransactionV0V1> for TransactionVariant {
    fn from(value: DeployAccountTransactionV0V1) -> Self {
        Self::DeployAccountV0V1(value)
    }
}
impl From<DeployAccountTransactionV3> for TransactionVariant {
    fn from(value: DeployAccountTransactionV3) -> Self {
        Self::DeployAccountV3(value)
    }
}
impl From<InvokeTransactionV0> for TransactionVariant {
    fn from(value: InvokeTransactionV0) -> Self {
        Self::InvokeV0(value)
    }
}
impl From<InvokeTransactionV1> for TransactionVariant {
    fn from(value: InvokeTransactionV1) -> Self {
        Self::InvokeV1(value)
    }
}
impl From<InvokeTransactionV3> for TransactionVariant {
    fn from(value: InvokeTransactionV3) -> Self {
        Self::InvokeV3(value)
    }
}
impl From<L1HandlerTransaction> for TransactionVariant {
    fn from(value: L1HandlerTransaction) -> Self {
        Self::L1Handler(value)
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct DeclareTransactionV0V1 {
    pub class_hash: ClassHash,
    pub max_fee: Fee,
    pub nonce: TransactionNonce,
    pub signature: Vec<TransactionSignatureElem>,
    pub sender_address: ContractAddress,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct DeclareTransactionV2 {
    pub class_hash: ClassHash,
    pub max_fee: Fee,
    pub nonce: TransactionNonce,
    pub signature: Vec<TransactionSignatureElem>,
    pub sender_address: ContractAddress,
    pub compiled_class_hash: CasmHash,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct DeclareTransactionV3 {
    pub class_hash: ClassHash,
    pub nonce: TransactionNonce,
    pub nonce_data_availability_mode: DataAvailabilityMode,
    pub fee_data_availability_mode: DataAvailabilityMode,
    pub resource_bounds: ResourceBounds,
    pub tip: Tip,
    pub paymaster_data: Vec<PaymasterDataElem>,
    pub signature: Vec<TransactionSignatureElem>,
    pub account_deployment_data: Vec<AccountDeploymentDataElem>,
    pub sender_address: ContractAddress,
    pub compiled_class_hash: CasmHash,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct DeployTransaction {
    pub class_hash: ClassHash,
    pub contract_address: ContractAddress,
    pub version: TransactionVersion,
    pub contract_address_salt: ContractAddressSalt,
    pub constructor_calldata: Vec<ConstructorParam>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct DeployAccountTransactionV0V1 {
    pub contract_address: ContractAddress,
    pub max_fee: Fee,
    pub version: TransactionVersion,
    pub signature: Vec<TransactionSignatureElem>,
    pub nonce: TransactionNonce,
    pub contract_address_salt: ContractAddressSalt,
    pub constructor_calldata: Vec<CallParam>,
    pub class_hash: ClassHash,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct DeployAccountTransactionV3 {
    pub contract_address: ContractAddress,
    pub signature: Vec<TransactionSignatureElem>,
    pub nonce: TransactionNonce,
    pub nonce_data_availability_mode: DataAvailabilityMode,
    pub fee_data_availability_mode: DataAvailabilityMode,
    pub resource_bounds: ResourceBounds,
    pub tip: Tip,
    pub paymaster_data: Vec<PaymasterDataElem>,
    pub contract_address_salt: ContractAddressSalt,
    pub constructor_calldata: Vec<CallParam>,
    pub class_hash: ClassHash,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct InvokeTransactionV0 {
    pub calldata: Vec<CallParam>,
    pub sender_address: ContractAddress,
    pub entry_point_selector: EntryPoint,
    pub entry_point_type: Option<EntryPointType>,
    pub max_fee: Fee,
    pub signature: Vec<TransactionSignatureElem>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct InvokeTransactionV1 {
    pub calldata: Vec<CallParam>,
    pub sender_address: ContractAddress,
    pub max_fee: Fee,
    pub signature: Vec<TransactionSignatureElem>,
    pub nonce: TransactionNonce,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct InvokeTransactionV3 {
    pub signature: Vec<TransactionSignatureElem>,
    pub nonce: TransactionNonce,
    pub nonce_data_availability_mode: DataAvailabilityMode,
    pub fee_data_availability_mode: DataAvailabilityMode,
    pub resource_bounds: ResourceBounds,
    pub tip: Tip,
    pub paymaster_data: Vec<PaymasterDataElem>,
    pub account_deployment_data: Vec<AccountDeploymentDataElem>,
    pub calldata: Vec<CallParam>,
    pub sender_address: ContractAddress,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct L1HandlerTransaction {
    pub contract_address: ContractAddress,
    pub entry_point_selector: EntryPoint,
    pub nonce: TransactionNonce,
    pub calldata: Vec<CallParam>,
    pub version: TransactionVersion,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EntryPointType {
    External,
    L1Handler,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceBounds {
    pub l1_gas: ResourceBound,
    pub l2_gas: ResourceBound,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceBound {
    pub max_amount: ResourceAmount,
    pub max_price_per_unit: ResourcePricePerUnit,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum DataAvailabilityMode {
    #[default]
    L1,
}
