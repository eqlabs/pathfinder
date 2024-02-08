//! Conversions between DTOs and common types.
//!
//! Also includes some "bridging" types which should eventually be removed
use pathfinder_common::event::Event;
use pathfinder_common::transaction::{
    DataAvailabilityMode, DeclareTransactionV0V1, DeclareTransactionV2, DeclareTransactionV3,
    DeployAccountTransactionV0V1, DeployAccountTransactionV3, DeployTransaction,
    InvokeTransactionV0, InvokeTransactionV1, InvokeTransactionV3, L1HandlerTransaction,
    ResourceBound, ResourceBounds, TransactionVariant,
};
use pathfinder_common::{
    AccountDeploymentDataElem, CallParam, CasmHash, ClassHash, ConstructorParam, ContractAddress,
    ContractAddressSalt, EntryPoint, EventData, EventKey, Fee, PaymasterDataElem, Tip,
    TransactionNonce, TransactionSignatureElem, TransactionVersion,
};

/// We don't want to introduce circular dependencies between crates
/// and we need to work around for the orphan rule - implement conversion fns for types ourside our crate.
pub trait TryFromDto<T> {
    fn try_from_dto(dto: T) -> anyhow::Result<Self>
    where
        Self: Sized;
}

/// Deployed contract address has not been computed for deploy account transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawTransactionVariant {
    DeployAccount(RawDeployAccountTransaction),
    NonDeployAccount(NonDeployAccountTransaction),
}

/// Deployed contract address has not been computed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawDeployAccountTransaction {
    DeployAccountV0V1(RawDeployAccountTransactionV0V1),
    DeployAccountV3(RawDeployAccountTransactionV3),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NonDeployAccountTransaction {
    DeclareV0(DeclareTransactionV0V1),
    DeclareV1(DeclareTransactionV0V1),
    DeclareV2(DeclareTransactionV2),
    DeclareV3(DeclareTransactionV3),
    // Regenesis: deploy is a legacy variant and can be removed after regenesis.
    Deploy(DeployTransaction),
    InvokeV0(InvokeTransactionV0),
    InvokeV1(InvokeTransactionV1),
    InvokeV3(InvokeTransactionV3),
    L1Handler(L1HandlerTransaction),
}

/// Deployed contract address has not been computed.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct RawDeployAccountTransactionV0V1 {
    pub max_fee: Fee,
    pub version: TransactionVersion,
    pub signature: Vec<TransactionSignatureElem>,
    pub nonce: TransactionNonce,
    pub contract_address_salt: ContractAddressSalt,
    pub constructor_calldata: Vec<CallParam>,
    pub class_hash: ClassHash,
}

/// Deployed contract address has not been computed.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct RawDeployAccountTransactionV3 {
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

impl NonDeployAccountTransaction {
    pub fn into_variant(self) -> TransactionVariant {
        use NonDeployAccountTransaction::*;
        match self {
            DeclareV0(x) => TransactionVariant::DeclareV0(x),
            DeclareV1(x) => TransactionVariant::DeclareV1(x),
            DeclareV2(x) => TransactionVariant::DeclareV2(x),
            DeclareV3(x) => TransactionVariant::DeclareV3(x),
            Deploy(x) => TransactionVariant::Deploy(x),
            InvokeV0(x) => TransactionVariant::InvokeV0(x),
            InvokeV1(x) => TransactionVariant::InvokeV1(x),
            InvokeV3(x) => TransactionVariant::InvokeV3(x),
            L1Handler(x) => TransactionVariant::L1Handler(x),
        }
    }
}

impl From<TransactionVariant> for RawTransactionVariant {
    fn from(x: TransactionVariant) -> Self {
        use TransactionVariant::*;
        match x {
            DeclareV0(x) => Self::NonDeployAccount(NonDeployAccountTransaction::DeclareV0(x)),
            DeclareV1(x) => Self::NonDeployAccount(NonDeployAccountTransaction::DeclareV1(x)),
            DeclareV2(x) => Self::NonDeployAccount(NonDeployAccountTransaction::DeclareV2(x)),
            DeclareV3(x) => Self::NonDeployAccount(NonDeployAccountTransaction::DeclareV3(x)),
            Deploy(x) => Self::NonDeployAccount(NonDeployAccountTransaction::Deploy(x)),
            InvokeV0(x) => Self::NonDeployAccount(NonDeployAccountTransaction::InvokeV0(x)),
            InvokeV1(x) => Self::NonDeployAccount(NonDeployAccountTransaction::InvokeV1(x)),
            InvokeV3(x) => Self::NonDeployAccount(NonDeployAccountTransaction::InvokeV3(x)),
            L1Handler(x) => Self::NonDeployAccount(NonDeployAccountTransaction::L1Handler(x)),
            DeployAccountV0V1(x) => {
                Self::DeployAccount(RawDeployAccountTransaction::DeployAccountV0V1(x.into()))
            }
            DeployAccountV3(x) => {
                Self::DeployAccount(RawDeployAccountTransaction::DeployAccountV3(x.into()))
            }
        }
    }
}

impl From<DeployAccountTransactionV0V1> for RawDeployAccountTransactionV0V1 {
    fn from(x: DeployAccountTransactionV0V1) -> Self {
        Self {
            max_fee: x.max_fee,
            version: x.version,
            signature: x.signature,
            nonce: x.nonce,
            contract_address_salt: x.contract_address_salt,
            constructor_calldata: x.constructor_calldata,
            class_hash: x.class_hash,
        }
    }
}

impl From<DeployAccountTransactionV3> for RawDeployAccountTransactionV3 {
    fn from(x: DeployAccountTransactionV3) -> Self {
        Self {
            signature: x.signature,
            nonce: x.nonce,
            nonce_data_availability_mode: x.nonce_data_availability_mode,
            fee_data_availability_mode: x.fee_data_availability_mode,
            resource_bounds: x.resource_bounds,
            tip: x.tip,
            paymaster_data: x.paymaster_data,
            contract_address_salt: x.contract_address_salt,
            constructor_calldata: x.constructor_calldata,
            class_hash: x.class_hash,
        }
    }
}

impl TryFromDto<p2p_proto::transaction::TransactionVariant> for RawTransactionVariant {
    /// ## Important
    ///
    /// This conversion does not compute deployed contract address for deploy account transactions
    /// ([`TransactionVariant::DeployAccountV0V1`] and [`TransactionVariant::DeployAccountV3`]),
    /// filling it with a zero address instead. The caller is responsible for performing the computation after the conversion succeeds.
    fn try_from_dto(dto: p2p_proto::transaction::TransactionVariant) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        use p2p_proto::transaction::TransactionVariant::*;

        Ok(match dto {
            DeclareV0(x) => RawTransactionVariant::NonDeployAccount(
                NonDeployAccountTransaction::DeclareV0(DeclareTransactionV0V1 {
                    class_hash: ClassHash(x.class_hash.0),
                    max_fee: Fee(x.max_fee),
                    nonce: TransactionNonce::ZERO,
                    sender_address: ContractAddress(x.sender.0),
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                }),
            ),
            DeclareV1(x) => RawTransactionVariant::NonDeployAccount(
                NonDeployAccountTransaction::DeclareV1(DeclareTransactionV0V1 {
                    class_hash: ClassHash(x.class_hash.0),
                    max_fee: Fee(x.max_fee),
                    nonce: TransactionNonce(x.nonce),
                    sender_address: ContractAddress(x.sender.0),
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                }),
            ),
            DeclareV2(x) => RawTransactionVariant::NonDeployAccount(
                NonDeployAccountTransaction::DeclareV2(DeclareTransactionV2 {
                    class_hash: ClassHash(x.class_hash.0),
                    max_fee: Fee(x.max_fee),
                    nonce: TransactionNonce(x.nonce),
                    sender_address: ContractAddress(x.sender.0),
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                    compiled_class_hash: CasmHash(x.compiled_class_hash),
                }),
            ),
            DeclareV3(x) => RawTransactionVariant::NonDeployAccount(
                NonDeployAccountTransaction::DeclareV3(DeclareTransactionV3 {
                    class_hash: ClassHash(x.class_hash.0),
                    nonce: TransactionNonce(x.nonce),
                    nonce_data_availability_mode: DataAvailabilityMode::try_from_dto(
                        x.nonce_domain,
                    )?,
                    fee_data_availability_mode: DataAvailabilityMode::try_from_dto(x.fee_domain)?,
                    resource_bounds: ResourceBounds::try_from_dto(x.resource_bounds)?,
                    tip: pathfinder_common::Tip(x.tip.try_into()?),
                    paymaster_data: vec![pathfinder_common::PaymasterDataElem(x.paymaster_data.0)],
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                    account_deployment_data: vec![AccountDeploymentDataElem(
                        x.account_deployment_data.0,
                    )],
                    sender_address: ContractAddress(x.sender.0),
                    compiled_class_hash: CasmHash(x.compiled_class_hash),
                }),
            ),
            Deploy(x) => RawTransactionVariant::NonDeployAccount(
                NonDeployAccountTransaction::Deploy(DeployTransaction {
                    contract_address: ContractAddress::ZERO, // FIXME: compute deployed contract address
                    contract_address_salt: ContractAddressSalt(x.address_salt),
                    class_hash: ClassHash(x.class_hash.0),
                    constructor_calldata: x.calldata.into_iter().map(ConstructorParam).collect(),
                    version: match x.version {
                        0 => TransactionVersion::ZERO,
                        1 => TransactionVersion::ONE,
                        _ => anyhow::bail!("Invalid deploy transaction version"),
                    },
                }),
            ),
            DeployAccountV1(x) => RawTransactionVariant::DeployAccount(
                RawDeployAccountTransaction::DeployAccountV0V1(RawDeployAccountTransactionV0V1 {
                    max_fee: Fee(x.max_fee),
                    version: TransactionVersion::ONE,
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                    nonce: TransactionNonce(x.nonce),
                    contract_address_salt: ContractAddressSalt(x.address_salt),
                    constructor_calldata: x.calldata.into_iter().map(CallParam).collect(),
                    class_hash: ClassHash(x.class_hash.0),
                }),
            ),
            DeployAccountV3(x) => RawTransactionVariant::DeployAccount(
                RawDeployAccountTransaction::DeployAccountV3(RawDeployAccountTransactionV3 {
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                    nonce: TransactionNonce(x.nonce),
                    nonce_data_availability_mode: DataAvailabilityMode::try_from_dto(
                        x.nonce_domain,
                    )?,
                    fee_data_availability_mode: DataAvailabilityMode::try_from_dto(x.fee_domain)?,
                    resource_bounds: ResourceBounds::try_from_dto(x.resource_bounds)?,
                    tip: pathfinder_common::Tip(x.tip.try_into()?),
                    paymaster_data: vec![pathfinder_common::PaymasterDataElem(x.paymaster_data.0)],
                    contract_address_salt: ContractAddressSalt(x.address_salt),
                    constructor_calldata: x.calldata.into_iter().map(CallParam).collect(),
                    class_hash: ClassHash(x.class_hash.0),
                }),
            ),
            InvokeV0(x) => RawTransactionVariant::NonDeployAccount(
                NonDeployAccountTransaction::InvokeV0(InvokeTransactionV0 {
                    calldata: x.calldata.into_iter().map(CallParam).collect(),
                    sender_address: ContractAddress(x.address.0),
                    entry_point_selector: EntryPoint(x.entry_point_selector),
                    entry_point_type: None,
                    max_fee: Fee(x.max_fee),
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                }),
            ),
            InvokeV1(x) => RawTransactionVariant::NonDeployAccount(
                NonDeployAccountTransaction::InvokeV1(InvokeTransactionV1 {
                    calldata: x.calldata.into_iter().map(CallParam).collect(),
                    sender_address: ContractAddress(x.sender.0),
                    max_fee: Fee(x.max_fee),
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                    nonce: TransactionNonce(x.nonce),
                }),
            ),
            InvokeV3(x) => RawTransactionVariant::NonDeployAccount(
                NonDeployAccountTransaction::InvokeV3(InvokeTransactionV3 {
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                    nonce: TransactionNonce(x.nonce),
                    nonce_data_availability_mode: DataAvailabilityMode::try_from_dto(
                        x.nonce_domain,
                    )?,
                    fee_data_availability_mode: DataAvailabilityMode::try_from_dto(x.fee_domain)?,
                    resource_bounds: ResourceBounds::try_from_dto(x.resource_bounds)?,
                    tip: pathfinder_common::Tip(x.tip.try_into()?),
                    paymaster_data: vec![pathfinder_common::PaymasterDataElem(x.paymaster_data.0)],
                    account_deployment_data: vec![AccountDeploymentDataElem(
                        x.account_deployment_data.0,
                    )],
                    calldata: x.calldata.into_iter().map(CallParam).collect(),
                    sender_address: ContractAddress(x.sender.0),
                }),
            ),
            L1HandlerV0(x) => RawTransactionVariant::NonDeployAccount(
                NonDeployAccountTransaction::L1Handler(L1HandlerTransaction {
                    contract_address: ContractAddress(x.address.0),
                    entry_point_selector: EntryPoint(x.entry_point_selector),
                    nonce: TransactionNonce(x.nonce),
                    calldata: x.calldata.into_iter().map(CallParam).collect(),
                }),
            ),
        })
    }
}

impl TryFromDto<p2p_proto::transaction::ResourceBounds> for ResourceBounds {
    fn try_from_dto(dto: p2p_proto::transaction::ResourceBounds) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            l1_gas: ResourceBound {
                max_amount: pathfinder_common::ResourceAmount(dto.l1_gas.max_amount.try_into()?),
                max_price_per_unit: pathfinder_common::ResourcePricePerUnit(
                    dto.l1_gas.max_price_per_unit.try_into()?,
                ),
            },
            l2_gas: ResourceBound {
                max_amount: pathfinder_common::ResourceAmount(dto.l2_gas.max_amount.try_into()?),
                max_price_per_unit: pathfinder_common::ResourcePricePerUnit(
                    dto.l2_gas.max_price_per_unit.try_into()?,
                ),
            },
        })
    }
}

impl TryFromDto<p2p_proto::event::Event> for Event {
    fn try_from_dto(proto: p2p_proto::event::Event) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            from_address: ContractAddress(proto.from_address),
            keys: proto.keys.into_iter().map(EventKey).collect(),
            data: proto.data.into_iter().map(EventData).collect(),
        })
    }
}

impl TryFromDto<String> for DataAvailabilityMode {
    fn try_from_dto(dto: String) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        match dto.as_str() {
            "L1" => Ok(Self::L1),
            "L2" => Ok(Self::L2),
            _ => anyhow::bail!("Invalid data availability mode"),
        }
    }
}
