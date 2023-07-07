use crate::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    hash: TransactionHash,
    variant: TransactionVariant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionVariant {
    /// Identical to [Transaction::DeclareV1] and should be differentiated by the enum variant or version tag.
    DeclareV0(DeclareTransactionV0V1),
    /// Identical to [Transaction::DeclareV0] and should be differentiated by the enum variant or version tag.
    DeclareV1(DeclareTransactionV0V1),
    DeclareV2(DeclareTransactionV2),
    // Regenesis: deploy is a legacy variant and can be removed after regenesis.
    Deploy(DeployTransaction),
    DeployAccount(DeployAccountTransaction),
    InvokeV0(InvokeTransactionV0),
    InvokeV1(InvokeTransactionV1),
    L1Handler(L1HandlerTransaction),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclareTransactionV0V1 {
    pub class_hash: ClassHash,
    pub max_fee: Fee,
    pub nonce: TransactionNonce,
    pub sender_address: ContractAddress,
    pub signature: Vec<TransactionSignatureElem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclareTransactionV2 {
    pub class_hash: ClassHash,
    pub max_fee: Fee,
    pub nonce: TransactionNonce,
    pub sender_address: ContractAddress,
    pub signature: Vec<TransactionSignatureElem>,
    pub compiled_class_hash: CasmHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeployTransaction {
    pub contract_address: ContractAddress,
    pub contract_address_salt: ContractAddressSalt,
    pub class_hash: ClassHash,
    pub constructor_calldata: Vec<ConstructorParam>,
    pub version: TransactionVersion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeployAccountTransaction {
    pub contract_address: ContractAddress,
    pub max_fee: Fee,
    pub version: TransactionVersion,
    pub signature: Vec<TransactionSignatureElem>,
    pub nonce: TransactionNonce,
    pub contract_address_salt: ContractAddressSalt,
    pub constructor_calldata: Vec<CallParam>,
    pub class_hash: ClassHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokeTransactionV0 {
    pub calldata: Vec<CallParam>,
    pub sender_address: ContractAddress,
    pub entry_point_selector: EntryPoint,
    pub entry_point_type: Option<EntryPointType>,
    pub max_fee: Fee,
    pub signature: Vec<TransactionSignatureElem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokeTransactionV1 {
    pub calldata: Vec<CallParam>,
    pub sender_address: ContractAddress,
    pub max_fee: Fee,
    pub signature: Vec<TransactionSignatureElem>,
    pub nonce: TransactionNonce,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
