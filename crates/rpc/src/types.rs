//! Common data structures used by the JSON-RPC API methods.

pub(crate) mod class;
pub(crate) mod receipt;
pub mod syncing;

pub use class::*;

/// Groups all strictly input types of the RPC API.
pub mod request {
    use pathfinder_common::transaction::{DataAvailabilityMode, ResourceBounds};
    use pathfinder_common::{
        AccountDeploymentDataElem,
        BlockHash,
        BlockNumber,
        CallParam,
        CasmHash,
        ChainId,
        ClassHash,
        ContractAddress,
        ContractAddressSalt,
        EntryPoint,
        Fee,
        PaymasterDataElem,
        Tip,
        TipHex,
        TransactionNonce,
        TransactionSignatureElem,
        TransactionVersion,
    };
    use serde::de::Error;
    use serde::Deserialize;
    use serde_with::serde_as;

    use crate::dto::U64Hex;

    /// A way of identifying a block in a subscription request.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum SubscriptionBlockId {
        Number(BlockNumber),
        Hash(BlockHash),
        Latest,
    }

    impl From<SubscriptionBlockId> for pathfinder_storage::BlockId {
        fn from(value: SubscriptionBlockId) -> Self {
            match value {
                SubscriptionBlockId::Number(block_number) => {
                    pathfinder_storage::BlockId::Number(block_number)
                }
                SubscriptionBlockId::Hash(block_hash) => {
                    pathfinder_storage::BlockId::Hash(block_hash)
                }
                SubscriptionBlockId::Latest => pathfinder_storage::BlockId::Latest,
            }
        }
    }

    impl crate::dto::DeserializeForVersion for SubscriptionBlockId {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            if value.is_string() {
                let value: String = value.deserialize()?;
                match value.as_str() {
                    "latest" => Ok(Self::Latest),
                    _ => Err(serde_json::Error::custom("Invalid block id")),
                }
            } else {
                value.deserialize_map(|value| {
                    if value.contains_key("block_number") {
                        Ok(Self::Number(
                            pathfinder_common::BlockNumber::new(value.deserialize("block_number")?)
                                .ok_or_else(|| serde_json::Error::custom("Invalid block number"))?,
                        ))
                    } else if value.contains_key("block_hash") {
                        Ok(Self::Hash(pathfinder_common::BlockHash(
                            value.deserialize("block_hash")?,
                        )))
                    } else {
                        Err(serde_json::Error::custom("Invalid block id"))
                    }
                })
            }
        }
    }

    /// "Broadcasted" L2 transaction in requests the RPC API.
    ///
    /// "Broadcasted" transactions represent the data required to submit a new
    /// transaction. Notably, it's missing values computed during execution
    /// of the transaction, like transaction_hash or contract_address.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum BroadcastedTransaction {
        Declare(BroadcastedDeclareTransaction),
        Invoke(BroadcastedInvokeTransaction),
        DeployAccount(BroadcastedDeployAccountTransaction),
    }

    impl crate::dto::SerializeForVersion for BroadcastedTransaction {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;
            match self {
                Self::Declare(tx) => {
                    serializer.serialize_field("type", &"DECLARE")?;
                    match tx {
                        BroadcastedDeclareTransaction::V0(tx) => serializer.flatten(tx)?,
                        BroadcastedDeclareTransaction::V1(tx) => serializer.flatten(tx)?,
                        BroadcastedDeclareTransaction::V2(tx) => serializer.flatten(tx)?,
                        BroadcastedDeclareTransaction::V3(tx) => serializer.flatten(tx)?,
                    }
                }
                Self::Invoke(tx) => {
                    serializer.serialize_field("type", &"INVOKE")?;
                    match tx {
                        BroadcastedInvokeTransaction::V0(tx) => serializer.flatten(tx)?,
                        BroadcastedInvokeTransaction::V1(tx) => serializer.flatten(tx)?,
                        BroadcastedInvokeTransaction::V3(tx) => serializer.flatten(tx)?,
                    }
                }
                Self::DeployAccount(tx) => {
                    serializer.serialize_field("type", &"DEPLOY_ACCOUNT")?;
                    match tx {
                        BroadcastedDeployAccountTransaction::V1(tx) => serializer.flatten(tx)?,
                        BroadcastedDeployAccountTransaction::V3(tx) => serializer.flatten(tx)?,
                    }
                }
            }
            serializer.end()
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedTransaction {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            value.deserialize_map(|value| {
                let tag: String = value.deserialize("type")?;
                match tag.as_str() {
                    "DECLARE" => Ok(Self::Declare(BroadcastedDeclareTransaction::deserialize(
                        value,
                    )?)),
                    "INVOKE" => Ok(Self::Invoke(BroadcastedInvokeTransaction::deserialize(
                        value,
                    )?)),
                    "DEPLOY_ACCOUNT" => Ok(Self::DeployAccount(
                        BroadcastedDeployAccountTransaction::deserialize(value)?,
                    )),
                    _ => Err(serde_json::Error::custom("unknown transaction type")),
                }
            })
        }
    }

    impl BroadcastedTransaction {
        pub fn into_invoke(self) -> Option<BroadcastedInvokeTransaction> {
            match self {
                Self::Invoke(x) => Some(x),
                _ => None,
            }
        }

        pub fn into_declare(self) -> Option<BroadcastedDeclareTransaction> {
            match self {
                Self::Declare(x) => Some(x),
                _ => None,
            }
        }

        pub fn into_deploy_account(self) -> Option<BroadcastedDeployAccountTransaction> {
            match self {
                Self::DeployAccount(x) => Some(x),
                _ => None,
            }
        }

        pub fn version(&self) -> TransactionVersion {
            match self {
                BroadcastedTransaction::Declare(declare) => match declare {
                    BroadcastedDeclareTransaction::V0(tx) => tx.version,
                    BroadcastedDeclareTransaction::V1(tx) => tx.version,
                    BroadcastedDeclareTransaction::V2(tx) => tx.version,
                    BroadcastedDeclareTransaction::V3(tx) => tx.version,
                },
                BroadcastedTransaction::Invoke(invoke) => match invoke {
                    BroadcastedInvokeTransaction::V0(tx) => tx.version,
                    BroadcastedInvokeTransaction::V1(tx) => tx.version,
                    BroadcastedInvokeTransaction::V3(tx) => tx.version,
                },
                BroadcastedTransaction::DeployAccount(deploy_account) => match deploy_account {
                    BroadcastedDeployAccountTransaction::V1(tx) => tx.version,
                    BroadcastedDeployAccountTransaction::V3(tx) => tx.version,
                },
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum BroadcastedDeclareTransaction {
        V0(BroadcastedDeclareTransactionV0),
        V1(BroadcastedDeclareTransactionV1),
        V2(BroadcastedDeclareTransactionV2),
        V3(BroadcastedDeclareTransactionV3),
    }

    impl crate::dto::SerializeForVersion for BroadcastedDeclareTransaction {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            match self {
                Self::V0(tx) => {
                    let mut serializer = serializer.serialize_struct()?;
                    serializer.serialize_field("version", &tx.version)?;
                    serializer.serialize_field("max_fee", &tx.max_fee)?;
                    serializer.serialize_field("signature", &tx.signature)?;
                    serializer.serialize_field("contract_class", &tx.contract_class)?;
                    serializer.serialize_field("sender_address", &tx.sender_address)?;
                    serializer.end()
                }
                Self::V1(tx) => {
                    let mut serializer = serializer.serialize_struct()?;
                    serializer.serialize_field("version", &tx.version)?;
                    serializer.serialize_field("max_fee", &tx.max_fee)?;
                    serializer.serialize_field("signature", &tx.signature)?;
                    serializer.serialize_field("nonce", &tx.nonce)?;
                    serializer.serialize_field("contract_class", &tx.contract_class)?;
                    serializer.serialize_field("sender_address", &tx.sender_address)?;
                    serializer.end()
                }
                Self::V2(tx) => {
                    let mut serializer = serializer.serialize_struct()?;
                    serializer.serialize_field("version", &tx.version)?;
                    serializer.serialize_field("max_fee", &tx.max_fee)?;
                    serializer.serialize_field("signature", &tx.signature)?;
                    serializer.serialize_field("nonce", &tx.nonce)?;
                    serializer.serialize_field("compiled_class_hash", &tx.compiled_class_hash)?;
                    serializer.serialize_field("contract_class", &tx.contract_class)?;
                    serializer.serialize_field("sender_address", &tx.sender_address)?;
                    serializer.end()
                }
                Self::V3(tx) => {
                    let mut serializer = serializer.serialize_struct()?;
                    serializer.serialize_field("version", &tx.version)?;
                    serializer.serialize_field("signature", &tx.signature)?;
                    serializer.serialize_field("nonce", &tx.nonce)?;
                    serializer.serialize_field("resource_bounds", &tx.resource_bounds)?;
                    serializer.serialize_field("tip", &tx.tip)?;
                    serializer.serialize_field("paymaster_data", &tx.paymaster_data)?;
                    serializer
                        .serialize_field("account_deployment_data", &tx.account_deployment_data)?;
                    serializer.serialize_field(
                        "nonce_data_availability_mode",
                        &tx.nonce_data_availability_mode,
                    )?;
                    serializer.serialize_field(
                        "fee_data_availability_mode",
                        &tx.fee_data_availability_mode,
                    )?;
                    serializer.serialize_field("compiled_class_hash", &tx.compiled_class_hash)?;
                    serializer.serialize_field("contract_class", &tx.contract_class)?;
                    serializer.serialize_field("sender_address", &tx.sender_address)?;
                    serializer.end()
                }
            }
        }
    }

    impl BroadcastedDeclareTransaction {
        pub fn deserialize(value: &mut crate::dto::Map) -> Result<Self, serde_json::Error> {
            let version = value.deserialize("version").map(TransactionVersion)?;
            let signature = value.deserialize_array("signature", |value| {
                value.deserialize().map(TransactionSignatureElem)
            })?;
            let sender_address = value.deserialize("sender_address").map(ContractAddress)?;
            match version.without_query_version() {
                0 => Ok(Self::V0(BroadcastedDeclareTransactionV0 {
                    max_fee: value.deserialize("max_fee").map(Fee)?,
                    version,
                    signature,
                    contract_class: value.deserialize("contract_class")?,
                    sender_address,
                })),
                1 => Ok(Self::V1(BroadcastedDeclareTransactionV1 {
                    max_fee: value.deserialize("max_fee").map(Fee)?,
                    version,
                    signature,
                    nonce: value.deserialize("nonce").map(TransactionNonce)?,
                    contract_class: value.deserialize("contract_class")?,
                    sender_address,
                })),
                2 => Ok(Self::V2(BroadcastedDeclareTransactionV2 {
                    max_fee: value.deserialize("max_fee").map(Fee)?,
                    version,
                    signature,
                    nonce: value.deserialize("nonce").map(TransactionNonce)?,
                    compiled_class_hash: value.deserialize("compiled_class_hash").map(CasmHash)?,
                    contract_class: value.deserialize("contract_class")?,
                    sender_address,
                })),
                3 => Ok(Self::V3(BroadcastedDeclareTransactionV3 {
                    version,
                    signature,
                    nonce: value.deserialize("nonce").map(TransactionNonce)?,
                    resource_bounds: value.deserialize("resource_bounds")?,
                    tip: value.deserialize::<U64Hex>("tip").map(|tip| Tip(tip.0))?,
                    paymaster_data: value.deserialize_array("paymaster_data", |value| {
                        value.deserialize().map(PaymasterDataElem)
                    })?,
                    account_deployment_data: value
                        .deserialize_array("account_deployment_data", |value| {
                            value.deserialize().map(AccountDeploymentDataElem)
                        })?,
                    nonce_data_availability_mode: value
                        .deserialize("nonce_data_availability_mode")?,
                    fee_data_availability_mode: value.deserialize("fee_data_availability_mode")?,
                    compiled_class_hash: value.deserialize("compiled_class_hash").map(CasmHash)?,
                    contract_class: value.deserialize("contract_class")?,
                    sender_address,
                })),
                _ => Err(serde_json::Error::custom("unknown transaction version")),
            }
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedDeclareTransaction {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            #[serde_as]
            #[derive(serde::Deserialize)]
            struct Version {
                pub version: TransactionVersion,
            }

            let json_value = value.json_value();
            let version = Version::deserialize(&json_value)?;

            match version.version.without_query_version() {
                0 => Ok(Self::V0(BroadcastedDeclareTransactionV0::deserialize(
                    value,
                )?)),
                1 => Ok(Self::V1(BroadcastedDeclareTransactionV1::deserialize(
                    value,
                )?)),
                2 => Ok(Self::V2(BroadcastedDeclareTransactionV2::deserialize(
                    value,
                )?)),
                3 => Ok(Self::V3(BroadcastedDeclareTransactionV3::deserialize(
                    value,
                )?)),
                _v => Err(serde_json::Error::custom("version must be 0, 1, 2 or 3")),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BroadcastedDeclareTransactionV0 {
        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        pub max_fee: Fee,
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,

        pub contract_class: super::CairoContractClass,
        pub sender_address: ContractAddress,
    }

    impl crate::dto::SerializeForVersion for BroadcastedDeclareTransactionV0 {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;
            serializer.serialize_field("max_fee", &self.max_fee)?;
            serializer.serialize_field("version", &self.version)?;
            serializer.serialize_field("signature", &self.signature)?;
            serializer.serialize_field("contract_class", &self.contract_class)?;
            serializer.serialize_field("sender_address", &self.sender_address)?;
            serializer.end()
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedDeclareTransactionV0 {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            value.deserialize_map(|value| {
                Ok(Self {
                    max_fee: value.deserialize("max_fee").map(Fee)?,
                    version: value.deserialize("version").map(TransactionVersion)?,
                    signature: value.deserialize_array("signature", |value| {
                        value.deserialize().map(TransactionSignatureElem)
                    })?,
                    contract_class: value.deserialize("contract_class")?,
                    sender_address: value.deserialize("sender_address").map(ContractAddress)?,
                })
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BroadcastedDeclareTransactionV1 {
        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        pub max_fee: Fee,
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        pub contract_class: super::CairoContractClass,
        pub sender_address: ContractAddress,
    }

    impl crate::dto::SerializeForVersion for BroadcastedDeclareTransactionV1 {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;
            serializer.serialize_field("max_fee", &self.max_fee)?;
            serializer.serialize_field("version", &self.version)?;
            serializer.serialize_field("signature", &self.signature)?;
            serializer.serialize_field("nonce", &self.nonce)?;
            serializer.serialize_field("contract_class", &self.contract_class)?;
            serializer.serialize_field("sender_address", &self.sender_address)?;
            serializer.end()
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedDeclareTransactionV1 {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            value.deserialize_map(|value| {
                Ok(Self {
                    max_fee: value.deserialize("max_fee").map(Fee)?,
                    version: value.deserialize("version").map(TransactionVersion)?,
                    signature: value.deserialize_array("signature", |value| {
                        value.deserialize().map(TransactionSignatureElem)
                    })?,
                    nonce: value.deserialize("nonce").map(TransactionNonce)?,
                    contract_class: value.deserialize("contract_class")?,
                    sender_address: value.deserialize("sender_address").map(ContractAddress)?,
                })
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BroadcastedDeclareTransactionV2 {
        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        pub max_fee: Fee,
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        pub compiled_class_hash: CasmHash,
        pub contract_class: super::SierraContractClass,
        pub sender_address: ContractAddress,
    }

    impl crate::dto::SerializeForVersion for BroadcastedDeclareTransactionV2 {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;
            serializer.serialize_field("max_fee", &self.max_fee)?;
            serializer.serialize_field("version", &self.version)?;
            serializer.serialize_field("signature", &self.signature)?;
            serializer.serialize_field("nonce", &self.nonce)?;
            serializer.serialize_field("compiled_class_hash", &self.compiled_class_hash)?;
            serializer.serialize_field("contract_class", &self.contract_class)?;
            serializer.serialize_field("sender_address", &self.sender_address)?;
            serializer.end()
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedDeclareTransactionV2 {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            value.deserialize_map(|value| {
                Ok(Self {
                    max_fee: value.deserialize("max_fee").map(Fee)?,
                    version: value.deserialize("version").map(TransactionVersion)?,
                    signature: value.deserialize_array("signature", |value| {
                        value.deserialize().map(TransactionSignatureElem)
                    })?,
                    nonce: value.deserialize("nonce").map(TransactionNonce)?,
                    compiled_class_hash: value.deserialize("compiled_class_hash").map(CasmHash)?,
                    contract_class: value.deserialize("contract_class")?,
                    sender_address: value.deserialize("sender_address").map(ContractAddress)?,
                })
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BroadcastedDeclareTransactionV3 {
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
        pub resource_bounds: ResourceBounds,
        pub tip: Tip,
        pub paymaster_data: Vec<PaymasterDataElem>,
        pub account_deployment_data: Vec<AccountDeploymentDataElem>,
        pub nonce_data_availability_mode: DataAvailabilityMode,
        pub fee_data_availability_mode: DataAvailabilityMode,

        pub compiled_class_hash: CasmHash,
        pub contract_class: super::SierraContractClass,
        pub sender_address: ContractAddress,
    }

    impl crate::dto::SerializeForVersion for BroadcastedDeclareTransactionV3 {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;
            serializer.serialize_field("version", &self.version)?;
            serializer.serialize_field("signature", &self.signature)?;
            serializer.serialize_field("nonce", &self.nonce)?;
            serializer.serialize_field("resource_bounds", &self.resource_bounds)?;
            serializer.serialize_field("tip", &TipHex(self.tip))?;
            serializer.serialize_field("paymaster_data", &self.paymaster_data)?;
            serializer.serialize_field("account_deployment_data", &self.account_deployment_data)?;
            serializer.serialize_field(
                "nonce_data_availability_mode",
                &self.nonce_data_availability_mode,
            )?;
            serializer.serialize_field(
                "fee_data_availability_mode",
                &self.fee_data_availability_mode,
            )?;
            serializer.serialize_field("compiled_class_hash", &self.compiled_class_hash)?;
            serializer.serialize_field("contract_class", &self.contract_class)?;
            serializer.serialize_field("sender_address", &self.sender_address)?;
            serializer.end()
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedDeclareTransactionV3 {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            value.deserialize_map(|value| {
                Ok(Self {
                    version: value.deserialize("version").map(TransactionVersion)?,
                    signature: value.deserialize_array("signature", |value| {
                        value.deserialize().map(TransactionSignatureElem)
                    })?,
                    nonce: value.deserialize("nonce").map(TransactionNonce)?,
                    resource_bounds: value.deserialize("resource_bounds")?,
                    tip: value.deserialize::<U64Hex>("tip").map(|tip| Tip(tip.0))?,
                    paymaster_data: value.deserialize_array("paymaster_data", |value| {
                        value.deserialize().map(PaymasterDataElem)
                    })?,
                    account_deployment_data: value
                        .deserialize_array("account_deployment_data", |value| {
                            value.deserialize().map(AccountDeploymentDataElem)
                        })?,
                    nonce_data_availability_mode: value
                        .deserialize("nonce_data_availability_mode")?,
                    fee_data_availability_mode: value.deserialize("fee_data_availability_mode")?,
                    compiled_class_hash: value.deserialize("compiled_class_hash").map(CasmHash)?,
                    contract_class: value.deserialize("contract_class")?,
                    sender_address: value.deserialize("sender_address").map(ContractAddress)?,
                })
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum BroadcastedDeployAccountTransaction {
        V1(BroadcastedDeployAccountTransactionV1),
        V3(BroadcastedDeployAccountTransactionV3),
    }

    impl crate::dto::SerializeForVersion for BroadcastedDeployAccountTransaction {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            match self {
                Self::V1(tx) => {
                    let mut serializer = serializer.serialize_struct()?;
                    serializer.serialize_field("version", &tx.version)?;
                    serializer.serialize_field("max_fee", &tx.max_fee)?;
                    serializer.serialize_field("signature", &tx.signature)?;
                    serializer.serialize_field("nonce", &tx.nonce)?;
                    serializer
                        .serialize_field("contract_address_salt", &tx.contract_address_salt)?;
                    serializer.serialize_field("constructor_calldata", &tx.constructor_calldata)?;
                    serializer.serialize_field("class_hash", &tx.class_hash)?;
                    serializer.end()
                }
                Self::V3(tx) => {
                    let mut serializer = serializer.serialize_struct()?;
                    serializer.serialize_field("version", &tx.version)?;
                    serializer.serialize_field("signature", &tx.signature)?;
                    serializer.serialize_field("nonce", &tx.nonce)?;
                    serializer.serialize_field("resource_bounds", &tx.resource_bounds)?;
                    serializer.serialize_field("tip", &tx.tip)?;
                    serializer.serialize_field("paymaster_data", &tx.paymaster_data)?;
                    serializer.serialize_field(
                        "nonce_data_availability_mode",
                        &tx.nonce_data_availability_mode,
                    )?;
                    serializer.serialize_field(
                        "fee_data_availability_mode",
                        &tx.fee_data_availability_mode,
                    )?;
                    serializer
                        .serialize_field("contract_address_salt", &tx.contract_address_salt)?;
                    serializer.serialize_field("constructor_calldata", &tx.constructor_calldata)?;
                    serializer.serialize_field("class_hash", &tx.class_hash)?;
                    serializer.end()
                }
            }
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedDeployAccountTransaction {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            #[serde_as]
            #[derive(serde::Deserialize)]
            struct Version {
                pub version: TransactionVersion,
            }

            let json_value = value.json_value();
            let version = Version::deserialize(&json_value)?;

            match version.version.without_query_version() {
                1 => Ok(Self::V1(
                    BroadcastedDeployAccountTransactionV1::deserialize(value)?,
                )),
                3 => Ok(Self::V3(
                    BroadcastedDeployAccountTransactionV3::deserialize(value)?,
                )),
                v => Err(serde_json::Error::custom(format!("invalid version {v}"))),
            }
        }
    }

    impl BroadcastedDeployAccountTransaction {
        pub fn deserialize(value: &mut crate::dto::Map) -> Result<Self, serde_json::Error> {
            let version = value.deserialize("version").map(TransactionVersion)?;
            let signature = value.deserialize_array("signature", |value| {
                value.deserialize().map(TransactionSignatureElem)
            })?;
            let nonce = value.deserialize("nonce").map(TransactionNonce)?;
            let contract_address_salt = value
                .deserialize("contract_address_salt")
                .map(ContractAddressSalt)?;
            let constructor_calldata = value
                .deserialize_array("constructor_calldata", |value| {
                    value.deserialize().map(CallParam)
                })?;
            let class_hash = value.deserialize("class_hash").map(ClassHash)?;
            match version.without_query_version() {
                1 => Ok(Self::V1(BroadcastedDeployAccountTransactionV1 {
                    version,
                    max_fee: value.deserialize("max_fee").map(Fee)?,
                    signature,
                    nonce,
                    contract_address_salt,
                    constructor_calldata,
                    class_hash,
                })),
                3 => Ok(Self::V3(BroadcastedDeployAccountTransactionV3 {
                    version,
                    signature,
                    nonce,
                    resource_bounds: value.deserialize("resource_bounds")?,
                    tip: value.deserialize::<U64Hex>("tip").map(|tip| Tip(tip.0))?,
                    paymaster_data: value.deserialize_array("paymaster_data", |value| {
                        value.deserialize().map(PaymasterDataElem)
                    })?,
                    nonce_data_availability_mode: value
                        .deserialize("nonce_data_availability_mode")?,
                    fee_data_availability_mode: value.deserialize("fee_data_availability_mode")?,
                    contract_address_salt,
                    constructor_calldata,
                    class_hash,
                })),
                _ => Err(serde_json::Error::custom("unknown transaction version")),
            }
        }

        pub fn deployed_contract_address(&self) -> ContractAddress {
            match self {
                Self::V1(tx) => tx.deployed_contract_address(),
                Self::V3(tx) => tx.deployed_contract_address(),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BroadcastedDeployAccountTransactionV1 {
        // Fields from BROADCASTED_TXN_COMMON_PROPERTIES
        pub version: TransactionVersion,
        pub max_fee: Fee,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        // Fields from DEPLOY_ACCOUNT_TXN_PROPERTIES
        pub contract_address_salt: ContractAddressSalt,
        pub constructor_calldata: Vec<CallParam>,
        pub class_hash: ClassHash,
    }

    impl BroadcastedDeployAccountTransactionV1 {
        pub fn deployed_contract_address(&self) -> ContractAddress {
            ContractAddress::deployed_contract_address(
                self.constructor_calldata.iter().copied(),
                &self.contract_address_salt,
                &self.class_hash,
            )
        }
    }

    impl crate::dto::SerializeForVersion for BroadcastedDeployAccountTransactionV1 {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;
            serializer.serialize_field("version", &self.version)?;
            serializer.serialize_field("max_fee", &self.max_fee)?;
            serializer.serialize_field("signature", &self.signature)?;
            serializer.serialize_field("nonce", &self.nonce)?;
            serializer.serialize_field("contract_address_salt", &self.contract_address_salt)?;
            serializer.serialize_field("constructor_calldata", &self.constructor_calldata)?;
            serializer.serialize_field("class_hash", &self.class_hash)?;
            serializer.end()
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedDeployAccountTransactionV1 {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            value.deserialize_map(|value| {
                Ok(Self {
                    version: value.deserialize("version").map(TransactionVersion)?,
                    max_fee: value.deserialize("max_fee").map(Fee)?,
                    signature: value.deserialize_array("signature", |value| {
                        value.deserialize().map(TransactionSignatureElem)
                    })?,
                    nonce: value.deserialize("nonce").map(TransactionNonce)?,
                    contract_address_salt: value
                        .deserialize("contract_address_salt")
                        .map(ContractAddressSalt)?,
                    constructor_calldata: value
                        .deserialize_array("constructor_calldata", |value| {
                            value.deserialize().map(CallParam)
                        })?,
                    class_hash: value.deserialize("class_hash").map(ClassHash)?,
                })
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BroadcastedDeployAccountTransactionV3 {
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
        pub resource_bounds: ResourceBounds,
        pub tip: Tip,
        pub paymaster_data: Vec<PaymasterDataElem>,
        pub nonce_data_availability_mode: DataAvailabilityMode,
        pub fee_data_availability_mode: DataAvailabilityMode,

        pub contract_address_salt: ContractAddressSalt,
        pub constructor_calldata: Vec<CallParam>,
        pub class_hash: ClassHash,
    }

    impl BroadcastedDeployAccountTransactionV3 {
        pub fn deployed_contract_address(&self) -> ContractAddress {
            ContractAddress::deployed_contract_address(
                self.constructor_calldata.iter().copied(),
                &self.contract_address_salt,
                &self.class_hash,
            )
        }
    }

    impl crate::dto::SerializeForVersion for BroadcastedDeployAccountTransactionV3 {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;
            serializer.serialize_field("version", &self.version)?;
            serializer.serialize_field("signature", &self.signature)?;
            serializer.serialize_field("nonce", &self.nonce)?;
            serializer.serialize_field("resource_bounds", &self.resource_bounds)?;
            serializer.serialize_field("tip", &TipHex(self.tip))?;
            serializer.serialize_field("paymaster_data", &self.paymaster_data)?;
            serializer.serialize_field(
                "nonce_data_availability_mode",
                &self.nonce_data_availability_mode,
            )?;
            serializer.serialize_field(
                "fee_data_availability_mode",
                &self.fee_data_availability_mode,
            )?;
            serializer.serialize_field("contract_address_salt", &self.contract_address_salt)?;
            serializer.serialize_field("constructor_calldata", &self.constructor_calldata)?;
            serializer.serialize_field("class_hash", &self.class_hash)?;
            serializer.end()
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedDeployAccountTransactionV3 {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            value.deserialize_map(|value| {
                Ok(Self {
                    version: value.deserialize("version").map(TransactionVersion)?,
                    signature: value.deserialize_array("signature", |value| {
                        value.deserialize().map(TransactionSignatureElem)
                    })?,
                    nonce: value.deserialize("nonce").map(TransactionNonce)?,
                    resource_bounds: value.deserialize("resource_bounds")?,
                    tip: value.deserialize::<U64Hex>("tip").map(|tip| Tip(tip.0))?,
                    paymaster_data: value.deserialize_array("paymaster_data", |value| {
                        value.deserialize().map(PaymasterDataElem)
                    })?,
                    nonce_data_availability_mode: value
                        .deserialize("nonce_data_availability_mode")?,
                    fee_data_availability_mode: value.deserialize("fee_data_availability_mode")?,
                    contract_address_salt: value
                        .deserialize("contract_address_salt")
                        .map(ContractAddressSalt)?,
                    constructor_calldata: value
                        .deserialize_array("constructor_calldata", |value| {
                            value.deserialize().map(CallParam)
                        })?,
                    class_hash: value.deserialize("class_hash").map(ClassHash)?,
                })
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum BroadcastedInvokeTransaction {
        V0(BroadcastedInvokeTransactionV0),
        V1(BroadcastedInvokeTransactionV1),
        V3(BroadcastedInvokeTransactionV3),
    }

    impl crate::dto::SerializeForVersion for BroadcastedInvokeTransaction {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            match self {
                Self::V0(tx) => {
                    let mut serializer = serializer.serialize_struct()?;
                    serializer.serialize_field("version", &tx.version)?;
                    serializer.serialize_field("max_fee", &tx.max_fee)?;
                    serializer.serialize_field("signature", &tx.signature)?;
                    serializer.serialize_field("contract_address", &tx.contract_address)?;
                    serializer.serialize_field("entry_point_selector", &tx.entry_point_selector)?;
                    serializer.serialize_field("calldata", &tx.calldata)?;
                    serializer.end()
                }
                Self::V1(tx) => {
                    let mut serializer = serializer.serialize_struct()?;
                    serializer.serialize_field("version", &tx.version)?;
                    serializer.serialize_field("max_fee", &tx.max_fee)?;
                    serializer.serialize_field("signature", &tx.signature)?;
                    serializer.serialize_field("nonce", &tx.nonce)?;
                    serializer.serialize_field("sender_address", &tx.sender_address)?;
                    serializer.serialize_field("calldata", &tx.calldata)?;
                    serializer.end()
                }
                Self::V3(tx) => {
                    let mut serializer = serializer.serialize_struct()?;
                    serializer.serialize_field("version", &tx.version)?;
                    serializer.serialize_field("signature", &tx.signature)?;
                    serializer.serialize_field("nonce", &tx.nonce)?;
                    serializer.serialize_field("resource_bounds", &tx.resource_bounds)?;
                    serializer.serialize_field("tip", &tx.tip)?;
                    serializer.serialize_field("paymaster_data", &tx.paymaster_data)?;
                    serializer.serialize_field(
                        "nonce_data_availability_mode",
                        &tx.nonce_data_availability_mode,
                    )?;
                    serializer.serialize_field(
                        "fee_data_availability_mode",
                        &tx.fee_data_availability_mode,
                    )?;
                    serializer.serialize_field("sender_address", &tx.sender_address)?;
                    serializer.serialize_field("calldata", &tx.calldata)?;
                    serializer.end()
                }
            }
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedInvokeTransaction {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            #[serde_as]
            #[derive(serde::Deserialize)]
            struct Version {
                pub version: TransactionVersion,
            }

            let json_value = value.json_value();
            let version = Version::deserialize(&json_value)?;

            match version.version.without_query_version() {
                0 => Ok(Self::V0(BroadcastedInvokeTransactionV0::deserialize(
                    value,
                )?)),
                1 => Ok(Self::V1(BroadcastedInvokeTransactionV1::deserialize(
                    value,
                )?)),
                3 => Ok(Self::V3(BroadcastedInvokeTransactionV3::deserialize(
                    value,
                )?)),
                _ => Err(serde_json::Error::custom("version must be 0, 1 or 3")),
            }
        }
    }

    impl BroadcastedInvokeTransaction {
        pub fn deserialize(value: &mut crate::dto::Map) -> Result<Self, serde_json::Error> {
            let version = value.deserialize("version").map(TransactionVersion)?;
            let signature = value.deserialize_array("signature", |value| {
                value.deserialize().map(TransactionSignatureElem)
            })?;
            let calldata =
                value.deserialize_array("calldata", |value| value.deserialize().map(CallParam))?;
            match version.without_query_version() {
                0 => Ok(Self::V0(BroadcastedInvokeTransactionV0 {
                    version,
                    max_fee: value.deserialize("max_fee").map(Fee)?,
                    signature,
                    contract_address: value.deserialize("contract_address").map(ContractAddress)?,
                    entry_point_selector: value
                        .deserialize("entry_point_selector")
                        .map(EntryPoint)?,
                    calldata,
                })),
                1 => Ok(Self::V1(BroadcastedInvokeTransactionV1 {
                    version,
                    max_fee: value.deserialize("max_fee").map(Fee)?,
                    signature,
                    nonce: value.deserialize("nonce").map(TransactionNonce)?,
                    sender_address: value.deserialize("sender_address").map(ContractAddress)?,
                    calldata,
                })),
                3 => Ok(Self::V3(BroadcastedInvokeTransactionV3 {
                    version,
                    signature,
                    nonce: value.deserialize("nonce").map(TransactionNonce)?,
                    resource_bounds: value.deserialize("resource_bounds")?,
                    tip: value.deserialize::<U64Hex>("tip").map(|tip| Tip(tip.0))?,
                    paymaster_data: value.deserialize_array("paymaster_data", |value| {
                        value.deserialize().map(PaymasterDataElem)
                    })?,
                    account_deployment_data: value
                        .deserialize_array("account_deployment_data", |value| {
                            value.deserialize().map(AccountDeploymentDataElem)
                        })?,
                    nonce_data_availability_mode: value
                        .deserialize("nonce_data_availability_mode")?,
                    fee_data_availability_mode: value.deserialize("fee_data_availability_mode")?,
                    sender_address: value.deserialize("sender_address").map(ContractAddress)?,
                    calldata,
                })),
                _ => Err(serde_json::Error::custom("unknown transaction version")),
            }
        }

        pub fn into_v1(self) -> Option<BroadcastedInvokeTransactionV1> {
            match self {
                Self::V1(x) => Some(x),
                _ => None,
            }
        }

        pub fn into_v0(self) -> Option<BroadcastedInvokeTransactionV0> {
            match self {
                Self::V0(x) => Some(x),
                _ => None,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BroadcastedInvokeTransactionV0 {
        pub version: TransactionVersion,

        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        pub max_fee: Fee,
        pub signature: Vec<TransactionSignatureElem>,

        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        pub calldata: Vec<CallParam>,
    }

    impl crate::dto::SerializeForVersion for BroadcastedInvokeTransactionV0 {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;
            serializer.serialize_field("version", &self.version)?;
            serializer.serialize_field("max_fee", &self.max_fee)?;
            serializer.serialize_field("signature", &self.signature)?;
            serializer.serialize_field("contract_address", &self.contract_address)?;
            serializer.serialize_field("entry_point_selector", &self.entry_point_selector)?;
            serializer.serialize_field("calldata", &self.calldata)?;
            serializer.end()
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedInvokeTransactionV0 {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            value.deserialize_map(|value| {
                Ok(Self {
                    version: value.deserialize("version").map(TransactionVersion)?,
                    max_fee: value.deserialize("max_fee").map(Fee)?,
                    signature: value.deserialize_array("signature", |value| {
                        value.deserialize().map(TransactionSignatureElem)
                    })?,
                    contract_address: value.deserialize("contract_address").map(ContractAddress)?,
                    entry_point_selector: value
                        .deserialize("entry_point_selector")
                        .map(EntryPoint)?,
                    calldata: value.deserialize_array("calldata", |value| {
                        value.deserialize().map(CallParam)
                    })?,
                })
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BroadcastedInvokeTransactionV1 {
        pub version: TransactionVersion,

        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        pub max_fee: Fee,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        pub sender_address: ContractAddress,
        pub calldata: Vec<CallParam>,
    }

    impl crate::dto::SerializeForVersion for BroadcastedInvokeTransactionV1 {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;
            serializer.serialize_field("version", &self.version)?;
            serializer.serialize_field("max_fee", &self.max_fee)?;
            serializer.serialize_field("signature", &self.signature)?;
            serializer.serialize_field("nonce", &self.nonce)?;
            serializer.serialize_field("sender_address", &self.sender_address)?;
            serializer.serialize_field("calldata", &self.calldata)?;
            serializer.end()
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedInvokeTransactionV1 {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            value.deserialize_map(|value| {
                Ok(Self {
                    version: value.deserialize("version").map(TransactionVersion)?,
                    max_fee: value.deserialize("max_fee").map(Fee)?,
                    signature: value.deserialize_array("signature", |value| {
                        value.deserialize().map(TransactionSignatureElem)
                    })?,
                    nonce: value.deserialize("nonce").map(TransactionNonce)?,
                    sender_address: value.deserialize("sender_address").map(ContractAddress)?,
                    calldata: value.deserialize_array("calldata", |value| {
                        value.deserialize().map(CallParam)
                    })?,
                })
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BroadcastedInvokeTransactionV3 {
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
        pub resource_bounds: ResourceBounds,
        pub tip: Tip,
        pub paymaster_data: Vec<PaymasterDataElem>,
        pub account_deployment_data: Vec<AccountDeploymentDataElem>,
        pub nonce_data_availability_mode: DataAvailabilityMode,
        pub fee_data_availability_mode: DataAvailabilityMode,

        pub sender_address: ContractAddress,
        pub calldata: Vec<CallParam>,
    }

    impl crate::dto::SerializeForVersion for BroadcastedInvokeTransactionV3 {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;
            serializer.serialize_field("version", &self.version)?;
            serializer.serialize_field("signature", &self.signature)?;
            serializer.serialize_field("nonce", &self.nonce)?;
            serializer.serialize_field("resource_bounds", &self.resource_bounds)?;
            serializer.serialize_field("tip", &TipHex(self.tip))?;
            serializer.serialize_field("paymaster_data", &self.paymaster_data)?;
            serializer.serialize_field("account_deployment_data", &self.account_deployment_data)?;
            serializer.serialize_field(
                "nonce_data_availability_mode",
                &self.nonce_data_availability_mode,
            )?;
            serializer.serialize_field(
                "fee_data_availability_mode",
                &self.fee_data_availability_mode,
            )?;
            serializer.serialize_field("sender_address", &self.sender_address)?;
            serializer.serialize_field("calldata", &self.calldata)?;
            serializer.end()
        }
    }

    impl crate::dto::DeserializeForVersion for BroadcastedInvokeTransactionV3 {
        fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
            value.deserialize_map(|value| {
                Ok(Self {
                    version: value.deserialize("version").map(TransactionVersion)?,
                    signature: value.deserialize_array("signature", |value| {
                        value.deserialize().map(TransactionSignatureElem)
                    })?,
                    nonce: value.deserialize("nonce").map(TransactionNonce)?,
                    resource_bounds: value.deserialize("resource_bounds")?,
                    tip: value.deserialize::<U64Hex>("tip").map(|tip| Tip(tip.0))?,
                    paymaster_data: value.deserialize_array("paymaster_data", |value| {
                        value.deserialize().map(PaymasterDataElem)
                    })?,
                    account_deployment_data: value
                        .deserialize_array("account_deployment_data", |value| {
                            value.deserialize().map(AccountDeploymentDataElem)
                        })?,
                    nonce_data_availability_mode: value
                        .deserialize("nonce_data_availability_mode")?,
                    fee_data_availability_mode: value.deserialize("fee_data_availability_mode")?,
                    sender_address: value.deserialize("sender_address").map(ContractAddress)?,
                    calldata: value.deserialize_array("calldata", |value| {
                        value.deserialize().map(CallParam)
                    })?,
                })
            })
        }
    }

    impl BroadcastedTransaction {
        pub fn into_common(self, chain_id: ChainId) -> pathfinder_common::transaction::Transaction {
            use pathfinder_common::transaction::*;

            let query_only = self.version().has_query_version();

            let variant = match self {
                BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V0(declare)) => {
                    let class_hash = declare.contract_class.class_hash().unwrap().hash();
                    TransactionVariant::DeclareV0(DeclareTransactionV0V1 {
                        class_hash,
                        max_fee: declare.max_fee,
                        nonce: Default::default(),
                        signature: declare.signature,
                        sender_address: declare.sender_address,
                    })
                }
                BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V1(declare)) => {
                    let class_hash = declare.contract_class.class_hash().unwrap().hash();
                    TransactionVariant::DeclareV1(DeclareTransactionV0V1 {
                        class_hash,
                        max_fee: declare.max_fee,
                        nonce: declare.nonce,
                        signature: declare.signature,
                        sender_address: declare.sender_address,
                    })
                }
                BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(declare)) => {
                    let class_hash = declare.contract_class.class_hash().unwrap().hash();
                    TransactionVariant::DeclareV2(DeclareTransactionV2 {
                        class_hash,
                        max_fee: declare.max_fee,
                        nonce: declare.nonce,
                        sender_address: declare.sender_address,
                        signature: declare.signature,
                        compiled_class_hash: declare.compiled_class_hash,
                    })
                }
                BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V3(declare)) => {
                    let class_hash = declare.contract_class.class_hash().unwrap().hash();
                    TransactionVariant::DeclareV3(DeclareTransactionV3 {
                        class_hash,
                        nonce: declare.nonce,
                        sender_address: declare.sender_address,
                        signature: declare.signature,
                        compiled_class_hash: declare.compiled_class_hash,
                        nonce_data_availability_mode: declare.nonce_data_availability_mode,
                        fee_data_availability_mode: declare.fee_data_availability_mode,
                        resource_bounds: declare.resource_bounds,
                        tip: declare.tip,
                        paymaster_data: declare.paymaster_data,
                        account_deployment_data: declare.account_deployment_data,
                    })
                }
                BroadcastedTransaction::DeployAccount(BroadcastedDeployAccountTransaction::V1(
                    deploy,
                )) => TransactionVariant::DeployAccountV1(DeployAccountTransactionV1 {
                    contract_address: deploy.deployed_contract_address(),
                    max_fee: deploy.max_fee,
                    signature: deploy.signature,
                    nonce: deploy.nonce,
                    contract_address_salt: deploy.contract_address_salt,
                    constructor_calldata: deploy.constructor_calldata,
                    class_hash: deploy.class_hash,
                }),
                BroadcastedTransaction::DeployAccount(BroadcastedDeployAccountTransaction::V3(
                    deploy,
                )) => TransactionVariant::DeployAccountV3(DeployAccountTransactionV3 {
                    class_hash: deploy.class_hash,
                    nonce: deploy.nonce,
                    contract_address: deploy.deployed_contract_address(),
                    contract_address_salt: deploy.contract_address_salt,
                    constructor_calldata: deploy.constructor_calldata,
                    signature: deploy.signature,
                    nonce_data_availability_mode: deploy.nonce_data_availability_mode,
                    fee_data_availability_mode: deploy.fee_data_availability_mode,
                    resource_bounds: deploy.resource_bounds,
                    tip: deploy.tip,
                    paymaster_data: deploy.paymaster_data,
                }),
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(invoke)) => {
                    TransactionVariant::InvokeV0(InvokeTransactionV0 {
                        calldata: invoke.calldata,
                        sender_address: invoke.contract_address,
                        entry_point_type: Some(EntryPointType::External),
                        entry_point_selector: invoke.entry_point_selector,
                        max_fee: invoke.max_fee,
                        signature: invoke.signature,
                    })
                }
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(invoke)) => {
                    TransactionVariant::InvokeV1(InvokeTransactionV1 {
                        calldata: invoke.calldata,
                        sender_address: invoke.sender_address,
                        max_fee: invoke.max_fee,
                        signature: invoke.signature,
                        nonce: invoke.nonce,
                    })
                }
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V3(invoke)) => {
                    TransactionVariant::InvokeV3(InvokeTransactionV3 {
                        nonce: invoke.nonce,
                        sender_address: invoke.sender_address,
                        signature: invoke.signature,
                        nonce_data_availability_mode: invoke.nonce_data_availability_mode,
                        fee_data_availability_mode: invoke.fee_data_availability_mode,
                        resource_bounds: invoke.resource_bounds,
                        tip: invoke.tip,
                        paymaster_data: invoke.paymaster_data,
                        calldata: invoke.calldata,
                        account_deployment_data: invoke.account_deployment_data,
                    })
                }
            };

            let hash = variant.calculate_hash(chain_id, query_only);
            Transaction { hash, variant }
        }
    }

    #[cfg(test)]
    mod tests {

        /// The aim of these tests is to check if deserialization works
        /// correctly **without resorting to serialization to prepare
        /// the test data**, which in itself could contain an "opposite
        /// phase" bug that cancels out.
        ///
        /// Serialization is tested btw, because the fixture and the data is
        /// already available.
        ///
        /// These tests were added due to recurring regressions stemming from,
        /// among others:
        /// - `serde(flatten)` and it's side-effects (for example when used in
        ///   conjunction with `skip_serializing_none`),
        /// - `*AsDecimalStr*` creeping in from `sequencer::reply` as opposed to
        ///   spec.
        mod serde {
            use pathfinder_common::macro_prelude::*;
            use pathfinder_common::transaction::ResourceBound;
            use pathfinder_common::{felt, ResourceAmount, ResourcePricePerUnit};
            use pretty_assertions_sorted::assert_eq;
            use serde_json::json;

            use super::super::*;
            use crate::dto::DeserializeForVersion;
            use crate::types::{
                CairoContractClass,
                ContractEntryPoints,
                SierraContractClass,
                SierraEntryPoint,
                SierraEntryPoints,
            };

            #[rstest::rstest]
            #[case::number(json!({"block_number": 1}), SubscriptionBlockId::Number(BlockNumber::new_or_panic(1)))]
            #[case::hash(json!({"block_hash": "0xdeadbeef"}), SubscriptionBlockId::Hash(block_hash!("0xdeadbeef")))]
            #[case::latest(json!("latest"), SubscriptionBlockId::Latest)]
            #[test]
            fn subscription_block_id(
                #[case] input: serde_json::Value,
                #[case] expected: SubscriptionBlockId,
            ) {
                assert_eq!(
                    SubscriptionBlockId::deserialize(crate::dto::Value::new(
                        input,
                        crate::RpcVersion::V08
                    ))
                    .unwrap(),
                    expected
                );
            }

            #[test]
            fn subscription_block_id_deserialization_failure() {
                assert_eq!(
                    SubscriptionBlockId::deserialize(crate::dto::Value::new(
                        json!("pending"),
                        crate::RpcVersion::V08
                    ))
                    .unwrap_err()
                    .to_string(),
                    "Invalid block id"
                );
            }

            #[test]
            fn broadcasted_transaction() {
                let contract_class = CairoContractClass {
                    program: "program".to_owned(),
                    entry_points_by_type: ContractEntryPoints {
                        constructor: vec![],
                        external: vec![],
                        l1_handler: vec![],
                    },
                    abi: None,
                };
                let txs = vec![
                    BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V1(
                        BroadcastedDeclareTransactionV1 {
                            max_fee: fee!("0x5"),
                            version: TransactionVersion::ONE,
                            signature: vec![transaction_signature_elem!("0x7")],
                            nonce: transaction_nonce!("0x8"),
                            contract_class,
                            sender_address: contract_address!("0xa"),
                        },
                    )),
                    BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(
                        BroadcastedDeclareTransactionV2 {
                            max_fee: fee!("0x51"),
                            version: TransactionVersion::TWO,
                            signature: vec![transaction_signature_elem!("0x71")],
                            nonce: transaction_nonce!("0x81"),
                            compiled_class_hash: casm_hash!("0x91"),
                            contract_class: SierraContractClass {
                                sierra_program: vec![felt!("0x4"), felt!("0x5")],
                                contract_class_version: "0.1.0".into(),
                                entry_points_by_type: SierraEntryPoints {
                                    constructor: vec![SierraEntryPoint {
                                        function_idx: 1,
                                        selector: felt!("0x1"),
                                    }],
                                    external: vec![SierraEntryPoint {
                                        function_idx: 2,
                                        selector: felt!("0x2"),
                                    }],
                                    l1_handler: vec![SierraEntryPoint {
                                        function_idx: 3,
                                        selector: felt!("0x3"),
                                    }],
                                },
                                abi: r#"[{"type":"function","name":"foo"}]"#.into(),
                            },
                            sender_address: contract_address!("0xa1"),
                        },
                    )),
                    BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V3(
                        BroadcastedDeclareTransactionV3 {
                            version: TransactionVersion::THREE,
                            signature: vec![transaction_signature_elem!("0x71")],
                            nonce: transaction_nonce!("0x81"),
                            resource_bounds: ResourceBounds {
                                l1_gas: ResourceBound {
                                    max_amount: ResourceAmount(0x1111),
                                    max_price_per_unit: ResourcePricePerUnit(0x2222),
                                },
                                l2_gas: ResourceBound {
                                    max_amount: ResourceAmount(0),
                                    max_price_per_unit: ResourcePricePerUnit(0),
                                },
                                l1_data_gas: None,
                            },
                            tip: Tip(0x1234),
                            paymaster_data: vec![
                                paymaster_data_elem!("0x1"),
                                paymaster_data_elem!("0x2"),
                            ],
                            account_deployment_data: vec![
                                account_deployment_data_elem!("0x3"),
                                account_deployment_data_elem!("0x4"),
                            ],
                            nonce_data_availability_mode: DataAvailabilityMode::L1,
                            fee_data_availability_mode: DataAvailabilityMode::L2,
                            compiled_class_hash: casm_hash!("0x91"),
                            contract_class: SierraContractClass {
                                sierra_program: vec![felt!("0x4"), felt!("0x5")],
                                contract_class_version: "0.1.0".into(),
                                entry_points_by_type: SierraEntryPoints {
                                    constructor: vec![SierraEntryPoint {
                                        function_idx: 1,
                                        selector: felt!("0x1"),
                                    }],
                                    external: vec![SierraEntryPoint {
                                        function_idx: 2,
                                        selector: felt!("0x2"),
                                    }],
                                    l1_handler: vec![SierraEntryPoint {
                                        function_idx: 3,
                                        selector: felt!("0x3"),
                                    }],
                                },
                                abi: r#"[{"type":"function","name":"foo"}]"#.into(),
                            },
                            sender_address: contract_address!("0xa1"),
                        },
                    )),
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                        BroadcastedInvokeTransactionV1 {
                            version: TransactionVersion::ONE,
                            max_fee: fee!("0x6"),
                            signature: vec![transaction_signature_elem!("0x7")],
                            nonce: transaction_nonce!("0x8"),
                            sender_address: contract_address!("0xaaa"),
                            calldata: vec![call_param!("0xff")],
                        },
                    )),
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                        BroadcastedInvokeTransactionV1 {
                            version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                            max_fee: fee!("0x6"),
                            signature: vec![transaction_signature_elem!("0x7")],
                            nonce: transaction_nonce!("0x8"),
                            sender_address: contract_address!("0xaaa"),
                            calldata: vec![call_param!("0xff")],
                        },
                    )),
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V3(
                        BroadcastedInvokeTransactionV3 {
                            version: TransactionVersion::THREE_WITH_QUERY_VERSION,
                            signature: vec![transaction_signature_elem!("0x7")],
                            nonce: transaction_nonce!("0x8"),
                            resource_bounds: ResourceBounds {
                                l1_gas: ResourceBound {
                                    max_amount: ResourceAmount(0x1111),
                                    max_price_per_unit: ResourcePricePerUnit(0x2222),
                                },
                                l2_gas: ResourceBound {
                                    max_amount: ResourceAmount(0),
                                    max_price_per_unit: ResourcePricePerUnit(0),
                                },
                                l1_data_gas: None,
                            },
                            tip: Tip(0x1234),
                            paymaster_data: vec![
                                paymaster_data_elem!("0x1"),
                                paymaster_data_elem!("0x2"),
                            ],
                            account_deployment_data: vec![
                                account_deployment_data_elem!("0x3"),
                                account_deployment_data_elem!("0x4"),
                            ],
                            nonce_data_availability_mode: DataAvailabilityMode::L1,
                            fee_data_availability_mode: DataAvailabilityMode::L2,
                            sender_address: contract_address!("0xaaa"),
                            calldata: vec![call_param!("0xff")],
                        },
                    )),
                    BroadcastedTransaction::DeployAccount(BroadcastedDeployAccountTransaction::V3(
                        BroadcastedDeployAccountTransactionV3 {
                            version: TransactionVersion::THREE_WITH_QUERY_VERSION,
                            signature: vec![transaction_signature_elem!("0x7")],
                            nonce: transaction_nonce!("0x8"),
                            resource_bounds: ResourceBounds {
                                l1_gas: ResourceBound {
                                    max_amount: ResourceAmount(0x1111),
                                    max_price_per_unit: ResourcePricePerUnit(0x2222),
                                },
                                l2_gas: ResourceBound {
                                    max_amount: ResourceAmount(0),
                                    max_price_per_unit: ResourcePricePerUnit(0),
                                },
                                l1_data_gas: None,
                            },
                            tip: Tip(0x1234),
                            paymaster_data: vec![
                                paymaster_data_elem!("0x1"),
                                paymaster_data_elem!("0x2"),
                            ],
                            nonce_data_availability_mode: DataAvailabilityMode::L1,
                            fee_data_availability_mode: DataAvailabilityMode::L2,
                            contract_address_salt: contract_address_salt!("0x99999"),
                            class_hash: class_hash!("0xddde"),
                            constructor_calldata: vec![call_param!("0xfe")],
                        },
                    )),
                ];

                let json_fixture_str =
                    include_str!(concat!("../fixtures/0.6.0/broadcasted_transactions.json"));
                let json_fixture: serde_json::Value =
                    serde_json::from_str(json_fixture_str).unwrap();

                let serializer = crate::dto::Serializer::new(crate::RpcVersion::V07);
                let serialized = serializer
                    .serialize_iter(txs.len(), &mut txs.clone().into_iter())
                    .unwrap();
                assert_eq!(serialized, json_fixture);
                assert_eq!(
                    crate::dto::Value::new(json_fixture, crate::RpcVersion::V07)
                        .deserialize_array(
                            <BroadcastedTransaction as DeserializeForVersion>::deserialize
                        )
                        .unwrap(),
                    txs
                );
            }
        }
    }
}

/// Groups all strictly output types of the RPC API.
pub mod reply {
    use serde::de::Error;

    /// L2 Block status as returned by the RPC API.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum BlockStatus {
        Pending,
        AcceptedOnL2,
        AcceptedOnL1,
        Rejected,
    }

    impl BlockStatus {
        pub fn is_pending(&self) -> bool {
            self == &Self::Pending
        }
    }

    impl crate::dto::SerializeForVersion for BlockStatus {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            serializer.serialize_str(match self {
                Self::Pending => "PENDING",
                Self::AcceptedOnL2 => "ACCEPTED_ON_L2",
                Self::AcceptedOnL1 => "ACCEPTED_ON_L1",
                Self::Rejected => "REJECTED",
            })
        }
    }

    impl crate::dto::DeserializeForVersion for BlockStatus {
        fn deserialize(value: crate::dto::Value) -> Result<Self, crate::dto::Error> {
            let status: String = value.deserialize()?;
            match status.as_str() {
                "PENDING" => Ok(Self::Pending),
                "ACCEPTED_ON_L2" => Ok(Self::AcceptedOnL2),
                "ACCEPTED_ON_L1" => Ok(Self::AcceptedOnL1),
                "REJECTED" => Ok(Self::Rejected),
                _ => Err(serde_json::Error::custom("Invalid block status")),
            }
        }
    }

    impl From<starknet_gateway_types::reply::Status> for BlockStatus {
        fn from(status: starknet_gateway_types::reply::Status) -> Self {
            use starknet_gateway_types::reply::Status::*;

            match status {
                // TODO verify this mapping with Starkware
                AcceptedOnL1 => BlockStatus::AcceptedOnL1,
                AcceptedOnL2 => BlockStatus::AcceptedOnL2,
                NotReceived => BlockStatus::Rejected,
                Pending => BlockStatus::Pending,
                Received => BlockStatus::Pending,
                Rejected => BlockStatus::Rejected,
                Reverted => BlockStatus::Rejected,
                Aborted => BlockStatus::Rejected,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::transaction::{ResourceBound, ResourceBounds};
    use pathfinder_common::{ResourceAmount, ResourcePricePerUnit};
    use pretty_assertions_sorted::assert_eq;
    use serde_json::json;

    use crate::dto::{DeserializeForVersion, SerializeForVersion, Value};
    use crate::RpcVersion;

    #[test]
    fn resource_bounds_serde() {
        // Create test data
        let resource_bound = ResourceBound {
            max_amount: ResourceAmount(100),
            max_price_per_unit: ResourcePricePerUnit(200),
        };

        let resource_bounds = ResourceBounds {
            l1_gas: resource_bound,
            l2_gas: resource_bound,
            l1_data_gas: Some(resource_bound),
        };

        let resource_bounds_no_data = ResourceBounds {
            l1_gas: resource_bound,
            l2_gas: resource_bound,
            l1_data_gas: None,
        };

        // Test V07 serialization (should not include l1_data_gas)
        let v07_serialized = resource_bounds
            .serialize(crate::dto::Serializer::new(RpcVersion::V07))
            .unwrap();
        let v07_expected = json!({
            "l1_gas": {
                "max_amount": "0x64",
                "max_price_per_unit": "0xc8"
            },
            "l2_gas": {
                "max_amount": "0x64",
                "max_price_per_unit": "0xc8"
            }
        });
        assert_eq!(v07_serialized, v07_expected);

        // Test V08 serialization (should include l1_data_gas)
        let v08_serialized = resource_bounds
            .serialize(crate::dto::Serializer::new(RpcVersion::V08))
            .unwrap();
        let v08_expected = json!({
            "l1_gas": {
                "max_amount": "0x64",
                "max_price_per_unit": "0xc8"
            },
            "l2_gas": {
                "max_amount": "0x64",
                "max_price_per_unit": "0xc8"
            },
            "l1_data_gas": {
                "max_amount": "0x64",
                "max_price_per_unit": "0xc8"
            }
        });
        assert_eq!(v08_serialized, v08_expected);

        // Test V08 serialization with None l1_data_gas (should default to 0,0)
        let v08_serialized_none = resource_bounds_no_data
            .serialize(crate::dto::Serializer::new(RpcVersion::V08))
            .unwrap();
        let v08_expected_none = json!({
            "l1_gas": {
                "max_amount": "0x64",
                "max_price_per_unit": "0xc8"
            },
            "l2_gas": {
                "max_amount": "0x64",
                "max_price_per_unit": "0xc8"
            },
            "l1_data_gas": {
                "max_amount": "0x0",
                "max_price_per_unit": "0x0"
            }
        });
        assert_eq!(v08_serialized_none, v08_expected_none);

        // Test V07 deserialization
        let v07_value = Value::new(v07_expected, RpcVersion::V07);
        let v07_deserialized = ResourceBounds::deserialize(v07_value).unwrap();
        assert_eq!(v07_deserialized.l1_gas, resource_bound);
        assert_eq!(v07_deserialized.l2_gas, resource_bound);
        assert_eq!(v07_deserialized.l1_data_gas, None);

        // Test V08 deserialization
        let v08_value = Value::new(v08_expected, RpcVersion::V08);
        let v08_deserialized = ResourceBounds::deserialize(v08_value).unwrap();
        assert_eq!(v08_deserialized.l1_gas, resource_bound);
        assert_eq!(v08_deserialized.l2_gas, resource_bound);
        assert_eq!(v08_deserialized.l1_data_gas, Some(resource_bound));

        // Test V08 deserialization fails when l1_data_gas is missing
        let v08_missing_data = json!({
            "l1_gas": {
                "max_amount": "0x64",
                "max_price_per_unit": "0xc8"
            },
            "l2_gas": {
                "max_amount": "0x64",
                "max_price_per_unit": "0xc8"
            }
        });
        let v08_missing_value = Value::new(v08_missing_data, RpcVersion::V08);
        assert!(ResourceBounds::deserialize(v08_missing_value).is_err());
    }
}
