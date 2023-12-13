//! Common data structures used by the JSON-RPC API methods.

pub(crate) mod class;
pub use class::*;
use pathfinder_common::{ResourceAmount, ResourcePricePerUnit};
use serde_with::serde_as;
pub mod syncing;

#[derive(Copy, Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct ResourceBounds {
    pub l1_gas: ResourceBound,
    pub l2_gas: ResourceBound,
}

impl From<ResourceBounds> for pathfinder_common::transaction::ResourceBounds {
    fn from(resource_bounds: ResourceBounds) -> Self {
        Self {
            l1_gas: resource_bounds.l1_gas.into(),
            l2_gas: resource_bounds.l2_gas.into(),
        }
    }
}

impl From<ResourceBounds> for starknet_gateway_types::reply::transaction::ResourceBounds {
    fn from(resource_bounds: ResourceBounds) -> Self {
        Self {
            l1_gas: resource_bounds.l1_gas.into(),
            l2_gas: resource_bounds.l2_gas.into(),
        }
    }
}

impl From<starknet_gateway_types::reply::transaction::ResourceBounds> for ResourceBounds {
    fn from(resource_bounds: starknet_gateway_types::reply::transaction::ResourceBounds) -> Self {
        Self {
            l1_gas: resource_bounds.l1_gas.into(),
            l2_gas: resource_bounds.l2_gas.into(),
        }
    }
}

#[serde_as]
#[derive(Copy, Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct ResourceBound {
    #[serde_as(as = "pathfinder_serde::ResourceAmountAsHexStr")]
    pub max_amount: ResourceAmount,
    #[serde_as(as = "pathfinder_serde::ResourcePricePerUnitAsHexStr")]
    pub max_price_per_unit: ResourcePricePerUnit,
}

impl From<ResourceBound> for pathfinder_common::transaction::ResourceBound {
    fn from(resource_bound: ResourceBound) -> Self {
        Self {
            max_amount: resource_bound.max_amount,
            max_price_per_unit: resource_bound.max_price_per_unit,
        }
    }
}

impl From<ResourceBound> for starknet_gateway_types::reply::transaction::ResourceBound {
    fn from(resource_bound: ResourceBound) -> Self {
        Self {
            max_amount: resource_bound.max_amount,
            max_price_per_unit: resource_bound.max_price_per_unit,
        }
    }
}

impl From<starknet_gateway_types::reply::transaction::ResourceBound> for ResourceBound {
    fn from(resource_bound: starknet_gateway_types::reply::transaction::ResourceBound) -> Self {
        Self {
            max_amount: resource_bound.max_amount,
            max_price_per_unit: resource_bound.max_price_per_unit,
        }
    }
}

#[derive(Copy, Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub enum DataAvailabilityMode {
    #[default]
    L1,
    L2,
}

impl From<DataAvailabilityMode> for pathfinder_common::transaction::DataAvailabilityMode {
    fn from(data_availability_mode: DataAvailabilityMode) -> Self {
        match data_availability_mode {
            DataAvailabilityMode::L1 => Self::L1,
            DataAvailabilityMode::L2 => Self::L2,
        }
    }
}

impl From<DataAvailabilityMode>
    for starknet_gateway_types::reply::transaction::DataAvailabilityMode
{
    fn from(data_availability_mode: DataAvailabilityMode) -> Self {
        match data_availability_mode {
            DataAvailabilityMode::L1 => Self::L1,
            DataAvailabilityMode::L2 => Self::L2,
        }
    }
}

impl From<DataAvailabilityMode> for starknet_api::data_availability::DataAvailabilityMode {
    fn from(value: DataAvailabilityMode) -> Self {
        match value {
            DataAvailabilityMode::L1 => Self::L1,
            DataAvailabilityMode::L2 => Self::L2,
        }
    }
}

impl From<starknet_gateway_types::reply::transaction::DataAvailabilityMode>
    for DataAvailabilityMode
{
    fn from(
        data_availability_mode: starknet_gateway_types::reply::transaction::DataAvailabilityMode,
    ) -> Self {
        match data_availability_mode {
            starknet_gateway_types::reply::transaction::DataAvailabilityMode::L1 => Self::L1,
            starknet_gateway_types::reply::transaction::DataAvailabilityMode::L2 => Self::L2,
        }
    }
}

/// Groups all strictly input types of the RPC API.
pub mod request {
    use std::ops::Rem;

    use pathfinder_common::{
        AccountDeploymentDataElem, CallParam, CasmHash, ChainId, ClassHash, ContractAddress,
        ContractAddressSalt, EntryPoint, Fee, PaymasterDataElem, Tip, TransactionHash,
        TransactionNonce, TransactionSignatureElem, TransactionVersion,
    };
    use pathfinder_crypto::{
        hash::{HashChain, PoseidonHasher},
        Felt,
    };
    use serde::Deserialize;
    use serde_with::serde_as;
    use starknet_gateway_types::transaction_hash::compute_txn_hash;

    /// "Broadcasted" L2 transaction in requests the RPC API.
    ///
    /// "Broadcasted" transactions represent the data required to submit a new transaction.
    /// Notably, it's missing values computed during execution of the transaction, like
    /// transaction_hash or contract_address.
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields, tag = "type")]
    pub enum BroadcastedTransaction {
        #[serde(rename = "DECLARE")]
        Declare(BroadcastedDeclareTransaction),
        #[serde(rename = "INVOKE")]
        Invoke(BroadcastedInvokeTransaction),
        #[serde(rename = "DEPLOY_ACCOUNT")]
        DeployAccount(BroadcastedDeployAccountTransaction),
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

        pub fn transaction_hash(
            &self,
            chain_id: ChainId,
            class_hash: Option<ClassHash>,
        ) -> TransactionHash {
            match self {
                BroadcastedTransaction::Declare(tx) => {
                    let class_hash =
                        class_hash.expect("Declare transactions should supply class hash");
                    match tx {
                        BroadcastedDeclareTransaction::V0(tx) => {
                            tx.transaction_hash(chain_id, class_hash)
                        }
                        BroadcastedDeclareTransaction::V1(tx) => {
                            tx.transaction_hash(chain_id, class_hash)
                        }
                        BroadcastedDeclareTransaction::V2(tx) => {
                            tx.transaction_hash(chain_id, class_hash)
                        }
                        BroadcastedDeclareTransaction::V3(tx) => {
                            tx.transaction_hash(chain_id, class_hash)
                        }
                    }
                }
                BroadcastedTransaction::Invoke(tx) => match tx {
                    BroadcastedInvokeTransaction::V0(tx) => tx.transaction_hash(chain_id),
                    BroadcastedInvokeTransaction::V1(tx) => tx.transaction_hash(chain_id),
                    BroadcastedInvokeTransaction::V3(tx) => tx.transaction_hash(chain_id),
                },
                BroadcastedTransaction::DeployAccount(tx) => match tx {
                    BroadcastedDeployAccountTransaction::V0V1(tx) => tx.transaction_hash(chain_id),
                    BroadcastedDeployAccountTransaction::V3(tx) => tx.transaction_hash(chain_id),
                },
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(
        any(test, feature = "rpc-full-serde"),
        derive(serde::Serialize),
        serde(untagged)
    )]
    pub enum BroadcastedDeclareTransaction {
        V0(BroadcastedDeclareTransactionV0),
        V1(BroadcastedDeclareTransactionV1),
        V2(BroadcastedDeclareTransactionV2),
        V3(BroadcastedDeclareTransactionV3),
    }

    impl<'de> serde::Deserialize<'de> for BroadcastedDeclareTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de;

            #[serde_as]
            #[derive(serde::Deserialize)]
            struct Version {
                pub version: TransactionVersion,
            }

            let v = serde_json::Value::deserialize(deserializer)?;
            let version = Version::deserialize(&v).map_err(de::Error::custom)?;
            match version.version.without_query_version() {
                0 => Ok(Self::V0(
                    BroadcastedDeclareTransactionV0::deserialize(&v).map_err(de::Error::custom)?,
                )),
                1 => Ok(Self::V1(
                    BroadcastedDeclareTransactionV1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                2 => Ok(Self::V2(
                    BroadcastedDeclareTransactionV2::deserialize(&v).map_err(de::Error::custom)?,
                )),
                3 => Ok(Self::V3(
                    BroadcastedDeclareTransactionV3::deserialize(&v).map_err(de::Error::custom)?,
                )),
                _v => Err(de::Error::custom("version must be 0, 1, 2 or 3")),
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
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

    impl BroadcastedDeclareTransactionV0 {
        pub fn transaction_hash(
            &self,
            chain_id: ChainId,
            class_hash: ClassHash,
        ) -> TransactionHash {
            compute_txn_hash(
                b"declare",
                self.version,
                self.sender_address,
                None,
                HashChain::default().finalize(),
                None,
                chain_id,
                class_hash,
                None,
            )
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
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

    impl BroadcastedDeclareTransactionV1 {
        pub fn transaction_hash(
            &self,
            chain_id: ChainId,
            class_hash: ClassHash,
        ) -> TransactionHash {
            compute_txn_hash(
                b"declare",
                self.version,
                self.sender_address,
                None,
                {
                    let mut h = HashChain::default();
                    h.update(class_hash.0);
                    h.finalize()
                },
                Some(self.max_fee),
                chain_id,
                self.nonce,
                None,
            )
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
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

    impl BroadcastedDeclareTransactionV2 {
        pub fn transaction_hash(
            &self,
            chain_id: ChainId,
            class_hash: ClassHash,
        ) -> TransactionHash {
            compute_txn_hash(
                b"declare",
                self.version,
                self.sender_address,
                None,
                {
                    let mut h = HashChain::default();
                    h.update(class_hash.0);
                    h.finalize()
                },
                Some(self.max_fee),
                chain_id,
                self.nonce,
                Some(self.compiled_class_hash),
            )
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedDeclareTransactionV3 {
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
        pub resource_bounds: super::ResourceBounds,
        #[serde_as(as = "pathfinder_serde::TipAsHexStr")]
        pub tip: Tip,
        pub paymaster_data: Vec<PaymasterDataElem>,
        pub account_deployment_data: Vec<AccountDeploymentDataElem>,
        pub nonce_data_availability_mode: super::DataAvailabilityMode,
        pub fee_data_availability_mode: super::DataAvailabilityMode,

        pub compiled_class_hash: CasmHash,
        pub contract_class: super::SierraContractClass,
        pub sender_address: ContractAddress,
    }

    impl BroadcastedDeclareTransactionV3 {
        pub fn transaction_hash(
            &self,
            chain_id: ChainId,
            class_hash: ClassHash,
        ) -> TransactionHash {
            let declare_specific_data = [
                self.account_deployment_data
                    .iter()
                    .fold(PoseidonHasher::new(), |mut hh, e| {
                        hh.write(e.0.into());
                        hh
                    })
                    .finish()
                    .into(),
                class_hash.0,
                self.compiled_class_hash.0,
            ];
            starknet_gateway_types::transaction_hash::compute_v3_txn_hash(
                b"declare",
                self.version,
                self.sender_address,
                chain_id,
                self.nonce,
                &declare_specific_data,
                self.tip,
                &self.paymaster_data,
                self.nonce_data_availability_mode.into(),
                self.fee_data_availability_mode.into(),
                self.resource_bounds.into(),
            )
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(
        any(test, feature = "rpc-full-serde"),
        derive(serde::Serialize),
        serde(untagged)
    )]
    pub enum BroadcastedDeployAccountTransaction {
        V0V1(BroadcastedDeployAccountTransactionV0V1),
        V3(BroadcastedDeployAccountTransactionV3),
    }

    impl BroadcastedDeployAccountTransaction {
        pub fn deployed_contract_address(&self) -> ContractAddress {
            match self {
                Self::V0V1(tx) => tx.deployed_contract_address(),
                Self::V3(tx) => tx.deployed_contract_address(),
            }
        }
    }

    impl<'de> serde::Deserialize<'de> for BroadcastedDeployAccountTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de;

            #[serde_as]
            #[derive(serde::Deserialize)]
            struct Version {
                pub version: TransactionVersion,
            }

            let v = serde_json::Value::deserialize(deserializer)?;
            let version = Version::deserialize(&v).map_err(de::Error::custom)?;
            match version.version.without_query_version() {
                0 | 1 => Ok(Self::V0V1(
                    BroadcastedDeployAccountTransactionV0V1::deserialize(&v)
                        .map_err(de::Error::custom)?,
                )),
                3 => Ok(Self::V3(
                    BroadcastedDeployAccountTransactionV3::deserialize(&v)
                        .map_err(de::Error::custom)?,
                )),
                _v => Err(de::Error::custom("version must be 0 or 1")),
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedDeployAccountTransactionV0V1 {
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

    fn deployed_contract_address(
        constructor_calldata: &[CallParam],
        contract_address_salt: &ContractAddressSalt,
        class_hash: &ClassHash,
    ) -> ContractAddress {
        let constructor_calldata_hash = constructor_calldata
            .iter()
            .fold(HashChain::default(), |mut h, param| {
                h.update(param.0);
                h
            })
            .finalize();

        let contract_address = [
            Felt::from_be_slice(b"STARKNET_CONTRACT_ADDRESS").expect("prefix is convertible"),
            Felt::ZERO,
            contract_address_salt.0,
            class_hash.0,
            constructor_calldata_hash,
        ]
        .into_iter()
        .fold(HashChain::default(), |mut h, e| {
            h.update(e);
            h
        })
        .finalize();

        // Contract addresses are _less than_ 2**251 - 256
        let contract_address =
            primitive_types::U256::from_big_endian(contract_address.as_be_bytes());
        let max_address = primitive_types::U256::from_str_radix(
            "0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00",
            16,
        )
        .unwrap();

        let contract_address = contract_address.rem(max_address);
        let mut b = [0u8; 32];
        contract_address.to_big_endian(&mut b);
        let contract_address = Felt::from_be_slice(&b).unwrap();

        ContractAddress::new_or_panic(contract_address)
    }

    impl BroadcastedDeployAccountTransactionV0V1 {
        pub fn deployed_contract_address(&self) -> ContractAddress {
            deployed_contract_address(
                self.constructor_calldata.as_slice(),
                &self.contract_address_salt,
                &self.class_hash,
            )
        }

        pub fn transaction_hash(&self, chain_id: ChainId) -> TransactionHash {
            let contract_address = self.deployed_contract_address();

            compute_txn_hash(
                b"deploy_account",
                self.version,
                contract_address,
                None,
                {
                    let mut h = HashChain::default();
                    h.update(self.class_hash.0);
                    h.update(self.contract_address_salt.0);
                    h = self
                        .constructor_calldata
                        .iter()
                        .fold(h, |mut h, constructor_param| {
                            h.update(constructor_param.0);
                            h
                        });
                    h.finalize()
                },
                Some(self.max_fee),
                chain_id,
                self.nonce,
                None,
            )
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedDeployAccountTransactionV3 {
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
        pub resource_bounds: super::ResourceBounds,
        #[serde_as(as = "pathfinder_serde::TipAsHexStr")]
        pub tip: Tip,
        pub paymaster_data: Vec<PaymasterDataElem>,
        pub nonce_data_availability_mode: super::DataAvailabilityMode,
        pub fee_data_availability_mode: super::DataAvailabilityMode,

        pub contract_address_salt: ContractAddressSalt,
        pub constructor_calldata: Vec<CallParam>,
        pub class_hash: ClassHash,
    }

    impl BroadcastedDeployAccountTransactionV3 {
        pub fn deployed_contract_address(&self) -> ContractAddress {
            deployed_contract_address(
                self.constructor_calldata.as_slice(),
                &self.contract_address_salt,
                &self.class_hash,
            )
        }

        pub fn transaction_hash(&self, chain_id: ChainId) -> TransactionHash {
            let sender_address = self.deployed_contract_address();

            let deploy_account_specific_data = [
                self.constructor_calldata
                    .iter()
                    .fold(PoseidonHasher::new(), |mut hh, e| {
                        hh.write(e.0.into());
                        hh
                    })
                    .finish()
                    .into(),
                self.class_hash.0,
                self.contract_address_salt.0,
            ];
            starknet_gateway_types::transaction_hash::compute_v3_txn_hash(
                b"deploy_account",
                self.version,
                sender_address,
                chain_id,
                self.nonce,
                &deploy_account_specific_data,
                self.tip,
                &self.paymaster_data,
                self.nonce_data_availability_mode.into(),
                self.fee_data_availability_mode.into(),
                self.resource_bounds.into(),
            )
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(
        any(test, feature = "rpc-full-serde"),
        derive(serde::Serialize),
        serde(untagged)
    )]
    pub enum BroadcastedInvokeTransaction {
        V0(BroadcastedInvokeTransactionV0),
        V1(BroadcastedInvokeTransactionV1),
        V3(BroadcastedInvokeTransactionV3),
    }

    impl BroadcastedInvokeTransaction {
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

    impl<'de> Deserialize<'de> for BroadcastedInvokeTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de;

            #[serde_as]
            #[derive(Deserialize)]
            struct Version {
                pub version: TransactionVersion,
            }

            let v = serde_json::Value::deserialize(deserializer)?;
            let version = Version::deserialize(&v).map_err(de::Error::custom)?;
            match version.version.without_query_version() {
                0 => Ok(Self::V0(
                    BroadcastedInvokeTransactionV0::deserialize(&v).map_err(de::Error::custom)?,
                )),
                1 => Ok(Self::V1(
                    BroadcastedInvokeTransactionV1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                3 => Ok(Self::V3(
                    BroadcastedInvokeTransactionV3::deserialize(&v).map_err(de::Error::custom)?,
                )),
                _ => Err(de::Error::custom("version must be 0, 1 or 3")),
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
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

    impl BroadcastedInvokeTransactionV0 {
        pub fn transaction_hash(&self, chain_id: ChainId) -> TransactionHash {
            compute_txn_hash(
                b"invoke",
                self.version,
                self.contract_address,
                Some(self.entry_point_selector),
                {
                    self.calldata
                        .iter()
                        .fold(HashChain::default(), |mut hh, call_param| {
                            hh.update(call_param.0);
                            hh
                        })
                        .finalize()
                },
                Some(self.max_fee),
                chain_id,
                (),
                None,
            )
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
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

    impl BroadcastedInvokeTransactionV1 {
        pub fn transaction_hash(&self, chain_id: ChainId) -> TransactionHash {
            compute_txn_hash(
                b"invoke",
                self.version,
                self.sender_address,
                None,
                {
                    self.calldata
                        .iter()
                        .fold(HashChain::default(), |mut hh, call_param| {
                            hh.update(call_param.0);
                            hh
                        })
                        .finalize()
                },
                Some(self.max_fee),
                chain_id,
                self.nonce,
                None,
            )
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedInvokeTransactionV3 {
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
        pub resource_bounds: super::ResourceBounds,
        #[serde_as(as = "pathfinder_serde::TipAsHexStr")]
        pub tip: Tip,
        pub paymaster_data: Vec<PaymasterDataElem>,
        pub account_deployment_data: Vec<AccountDeploymentDataElem>,
        pub nonce_data_availability_mode: super::DataAvailabilityMode,
        pub fee_data_availability_mode: super::DataAvailabilityMode,

        pub sender_address: ContractAddress,
        pub calldata: Vec<CallParam>,
    }

    impl BroadcastedInvokeTransactionV3 {
        pub fn transaction_hash(&self, chain_id: ChainId) -> TransactionHash {
            let invoke_specific_data = [
                self.account_deployment_data
                    .iter()
                    .fold(PoseidonHasher::new(), |mut hh, e| {
                        hh.write(e.0.into());
                        hh
                    })
                    .finish()
                    .into(),
                self.calldata
                    .iter()
                    .fold(PoseidonHasher::new(), |mut hh, e| {
                        hh.write(e.0.into());
                        hh
                    })
                    .finish()
                    .into(),
            ];
            starknet_gateway_types::transaction_hash::compute_v3_txn_hash(
                b"invoke",
                self.version,
                self.sender_address,
                chain_id,
                self.nonce,
                &invoke_specific_data,
                self.tip,
                &self.paymaster_data,
                self.nonce_data_availability_mode.into(),
                self.fee_data_availability_mode.into(),
                self.resource_bounds.into(),
            )
        }
    }

    #[cfg(test)]
    mod tests {
        macro_rules! fixture {
            ($file_name:literal) => {
                include_str!(concat!("../../fixtures/0.6.0/", $file_name)).replace(&[' ', '\n'], "")
            };
        }

        /// The aim of these tests is to check if deserialization works correctly
        /// **without resorting to serialization to prepare the test data**,
        /// which in itself could contain an "opposite phase" bug that cancels out.
        ///
        /// Serialization is tested btw, because the fixture and the data is already available.
        ///
        /// These tests were added due to recurring regressions stemming from, among others:
        /// - `serde(flatten)` and it's side-effects (for example when used in conjunction with `skip_serializing_none`),
        /// - `*AsDecimalStr*` creeping in from `sequencer::reply` as opposed to spec.
        mod serde {
            use super::super::*;
            use crate::v02::types::{
                CairoContractClass, ContractEntryPoints, DataAvailabilityMode, SierraContractClass,
                SierraEntryPoint, SierraEntryPoints,
            };
            use crate::v02::types::{ResourceBound, ResourceBounds};
            use pathfinder_common::{felt, ResourcePricePerUnit};
            use pathfinder_common::{macro_prelude::*, ResourceAmount};
            use pretty_assertions::assert_eq;

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

                let json_fixture = fixture!("broadcasted_transactions.json");

                assert_eq!(serde_json::to_string(&txs).unwrap(), json_fixture);
                assert_eq!(
                    serde_json::from_str::<Vec<BroadcastedTransaction>>(&json_fixture).unwrap(),
                    txs
                );
            }
        }

        mod transaction_hash {
            use crate::v02::types::{
                ContractClass, DataAvailabilityMode, ResourceBound, ResourceBounds,
            };

            use super::super::*;

            use pathfinder_common::{macro_prelude::*, ResourceAmount, ResourcePricePerUnit};

            #[test]
            fn declare_v1() {
                // https://testnet.starkscan.co/tx/0x05c72f6fdbbddde03a9921e520273b4ff940d01f118793e7f9ed56f5a74cbfc0
                let contract_class = ContractClass::from_definition_bytes(starknet_gateway_test_fixtures::class_definitions::CAIRO_TESTNET_0331118F4E4EB8A8DDB0F4493E09612E380EF527991C49A15C42574AB48DD747).unwrap().as_cairo().unwrap();

                let tx = BroadcastedDeclareTransactionV1 {
                    max_fee: fee!("0x6c8737288fe"),
                    version: TransactionVersion::ONE,
                    signature: vec![
                        transaction_signature_elem!(
                            "0x1c7f348434157f917dcdb4ab62d32b26be5f859fd84502043bb6c3ed85bc53f"
                        ),
                        transaction_signature_elem!(
                            "0xd3f3c40d988f9b6471e371f45419ac0354cde6aa26b885a83775ded8a4f1ae"
                        ),
                    ],
                    nonce: transaction_nonce!("0x8c"),
                    contract_class,
                    sender_address: contract_address!(
                        "0x138aefdb281051e0cb93199bc88f133c2ba83cbd50fe6fc984b5588b087917c"
                    ),
                };

                let transaction =
                    BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V1(tx));
                assert_eq!(
                    transaction.transaction_hash(ChainId::GOERLI_TESTNET, Some(starknet_gateway_test_fixtures::class_definitions::CAIRO_TESTNET_0331118F4E4EB8A8DDB0F4493E09612E380EF527991C49A15C42574AB48DD747_CLASS_HASH)),
                    transaction_hash!(
                        "0x05c72f6fdbbddde03a9921e520273b4ff940d01f118793e7f9ed56f5a74cbfc0"
                    )
                );
            }

            #[test]
            fn declare_v2() {
                // https://testnet.starkscan.co/tx/0x055ab647f4aee18d9981fbe251ccf57a553ec3841b57e2f74a434b2aa6ba0513
                let contract_class = ContractClass::from_definition_bytes(starknet_gateway_test_fixtures::class_definitions::SIERRA_TESTNET_02E62A7336B45FA98668A6275168CE42B085665A9EC16B100D895968691A0BDC).unwrap().as_sierra().unwrap();

                let tx = BroadcastedDeclareTransactionV2 {
                    max_fee: fee!("0x5a1cdc61aaf"),
                    version: TransactionVersion::TWO,
                    signature: vec![
                        transaction_signature_elem!(
                            "0x3b871618705b5ba52e1f93dcacf4a1e4ffb465897cff33d4ac82de449f9f364"
                        ),
                        transaction_signature_elem!(
                            "0x51a63df7e26778461a275b827966a44ea279605958dde0be34f956f4818e06e"
                        ),
                    ],
                    nonce: transaction_nonce!("0x1b"),
                    compiled_class_hash: casm_hash!(
                        "0x6b04d63f49e58baea2ec5dda9c21c66cd220e3826fb6374d11de7d672d04e07"
                    ),
                    contract_class,
                    sender_address: contract_address!(
                        "0x69b5d9662b45fe3bc6602ff519c8449e30cadf3eb2617ce46ca2551ded86ef3"
                    ),
                };

                let transaction =
                    BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(tx));
                assert_eq!(
                transaction.transaction_hash(ChainId::GOERLI_TESTNET, Some(starknet_gateway_test_fixtures::class_definitions::SIERRA_TESTNET_02E62A7336B45FA98668A6275168CE42B085665A9EC16B100D895968691A0BDC_CLASS_HASH)),
                transaction_hash!(
                    "0x055ab647f4aee18d9981fbe251ccf57a553ec3841b57e2f74a434b2aa6ba0513"
                )
            );
            }

            #[test]
            fn invoke_v1() {
                // https://testnet.starkscan.co/tx/0x025d11606f1a73602099a359e4b5da03c45372a92eb0c9be2800c3123e7a26aa
                let tx = BroadcastedInvokeTransactionV1 {
                    version: TransactionVersion::ONE,
                    max_fee: fee!("0x2386f26fc10000"),
                    signature: vec![
                        transaction_signature_elem!(
                            "0x68ff0404a75dd45b25cfb43d8d5c6747ab602368a003a8acea4e28fae0c03d6"
                        ),
                        transaction_signature_elem!(
                            "0x5c5e346a92c58239c68fbc2756aa0a2c76f9af198313c397e96f78ef273a596"
                        ),
                    ],
                    nonce: transaction_nonce!("0xaa23"),
                    sender_address: contract_address!(
                        "0x58b7ee817bd2978c7657d05d3131e83e301ed1aa79d5ad16f01925fd52d1da7"
                    ),
                    calldata: vec![
                        call_param!("0x1"),
                        call_param!(
                            "0x51c6428132045e01eb6a779be05f0e3b88760cadb5a4ec988d9ab2729b12a67"
                        ),
                        call_param!(
                            "0x2d7cf5d5a324a320f9f37804b1615a533fde487400b41af80f13f7ac5581325"
                        ),
                        call_param!("0x0"),
                        call_param!("0x4"),
                        call_param!("0x4"),
                        call_param!("0xdc7f0b6facd8eabbac6d1c2c1cff73bece8dbbda"),
                        call_param!("0x2"),
                        call_param!(
                            "0x480817f9e0a8d41850dc4875df76a4990c7f6772221bb2a06a414b22a5fc709"
                        ),
                        call_param!(
                            "0x59f131a9ff4eb312f32ba82461d2165c12bd54d9f9d97935d7778fe9c3f82c1"
                        ),
                    ],
                };

                let transaction =
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(tx));
                assert_eq!(
                    transaction.transaction_hash(ChainId::GOERLI_TESTNET, None),
                    transaction_hash!(
                        "0x25d11606f1a73602099a359e4b5da03c45372a92eb0c9be2800c3123e7a26aa"
                    )
                );
            }

            #[test]
            fn invoke_v3() {
                // https://integration.starkscan.co/tx/0x00ffba4f15f2a1f04bfaf9c47da4d41e4a9a277bf8f7768b2402fc5db3b35b17
                let tx = BroadcastedInvokeTransactionV3 {
                    version: TransactionVersion::THREE,
                    signature: vec![
                        transaction_signature_elem!(
                            "0x477f5694ad01855fd178613eeb442541db745cf0d7070b0a67262e09481aec5"
                        ),
                        transaction_signature_elem!(
                            "0x15b28a9ce57a714da837ef7213c1b99992a89135c6fc7f7db6d1aaf824265a0"
                        ),
                    ],
                    nonce: transaction_nonce!("0xe19"),
                    resource_bounds: ResourceBounds {
                        l1_gas: ResourceBound {
                            max_amount: ResourceAmount(0x186a0),
                            max_price_per_unit: ResourcePricePerUnit(0x5af3107a4000),
                        },
                        l2_gas: ResourceBound {
                            max_amount: ResourceAmount(0),
                            max_price_per_unit: ResourcePricePerUnit(0),
                        },
                    },
                    tip: Tip(0x0),
                    paymaster_data: vec![],
                    account_deployment_data: vec![],
                    nonce_data_availability_mode: DataAvailabilityMode::L1,
                    fee_data_availability_mode: DataAvailabilityMode::L1,
                    sender_address: contract_address!(
                        "0x3f6f3bc663aedc5285d6013cc3ffcbc4341d86ab488b8b68d297f8258793c41"
                    ),
                    calldata: vec![
                        call_param!("0x2"),
                        call_param!(
                            "0x4c312760dfd17a954cdd09e76aa9f149f806d88ec3e402ffaf5c4926f568a42"
                        ),
                        call_param!(
                            "0x5df99ae77df976b4f0e5cf28c7dcfe09bd6e81aab787b19ac0c08e03d928cf"
                        ),
                        call_param!("0x0"),
                        call_param!("0x1"),
                        call_param!(
                            "0x4c312760dfd17a954cdd09e76aa9f149f806d88ec3e402ffaf5c4926f568a42"
                        ),
                        call_param!(
                            "0x241f3ff573208515225eb136d2132bb89bd593e4c844225ead202a1657cfe64"
                        ),
                        call_param!("0x1"),
                        call_param!("0x0"),
                        call_param!("0x1"),
                        call_param!(
                            "0x5968790bb8d5412021a972c44f8768b70368dd18b43a3393ac3f59bf8bdd5b5"
                        ),
                    ],
                };

                let transaction =
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V3(tx));
                assert_eq!(
                    transaction.transaction_hash(ChainId::GOERLI_INTEGRATION, None),
                    transaction_hash!(
                        "0xffba4f15f2a1f04bfaf9c47da4d41e4a9a277bf8f7768b2402fc5db3b35b17"
                    )
                );
            }

            #[test]
            fn deploy_account() {
                // https://testnet.starkscan.co/tx/0x0167486c4202020e510809ae1703111186de8d36a606ce948dcfab910cc18713
                let class_hash = class_hash!(
                    "0x25ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918"
                );
                let tx = BroadcastedDeployAccountTransactionV0V1 {
                    version: TransactionVersion::ONE,
                    max_fee: fee!("0x15e1e7c9a7a0"),
                    signature: vec![
                        transaction_signature_elem!(
                            "0x32628e08929f7cee80f82c4663546057868f7f50899df1b7b8c61d9eddbb111"
                        ),
                        transaction_signature_elem!(
                            "0x2fd6211adc5898cc6df61e5aeb13b1bfa79a88716cc5d8b6b2a0afffc7ccd83"
                        ),
                        transaction_signature_elem!(
                            "0x5ec0d11dc1588a68f04c6b4a01c67b4f772ed364cfb26ecca5f5f4d2462fafd"
                        ),
                    ],
                    nonce: transaction_nonce!("0x0"),
                    contract_address_salt: contract_address_salt!(
                        "0x32628e08929f7cee80f82c4663546057868f7f50899df1b7b8c61d9eddbb111"
                    ),
                    constructor_calldata: vec![
                        call_param!(
                            "0x4ba0f956a26b5e0d7e491661a0c56a6eb0fc25d49912677de09439673c3c828"
                        ),
                        call_param!(
                            "0x79dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463"
                        ),
                        call_param!("0x4"),
                        call_param!("0x2"),
                        call_param!("0x2"),
                        call_param!(
                            "0x32628e08929f7cee80f82c4663546057868f7f50899df1b7b8c61d9eddbb111"
                        ),
                        call_param!(
                            "0x235d794ee259b38bfec8fabb5efecf7b17f53e5be3d830ec0d076fb8b101fae"
                        ),
                    ],
                    class_hash,
                };

                assert_eq!(
                    tx.deployed_contract_address(),
                    contract_address!(
                        "0x53b40d3140504657fa11be5b65ef139bf9b82dba6691a1b0c84be85fad5f9e2"
                    )
                );

                let transaction = BroadcastedTransaction::DeployAccount(
                    BroadcastedDeployAccountTransaction::V0V1(tx),
                );
                assert_eq!(
                    transaction.transaction_hash(ChainId::GOERLI_TESTNET, Some(class_hash)),
                    transaction_hash!(
                        "0x0167486c4202020e510809ae1703111186de8d36a606ce948dcfab910cc18713"
                    )
                );
            }
        }
    }
}

/// Groups all strictly output types of the RPC API.
pub mod reply {
    use serde::Serialize;

    /// L2 Block status as returned by the RPC API.
    #[derive(Copy, Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub enum BlockStatus {
        #[serde(rename = "PENDING")]
        Pending,
        #[serde(rename = "ACCEPTED_ON_L2")]
        AcceptedOnL2,
        #[serde(rename = "ACCEPTED_ON_L1")]
        AcceptedOnL1,
        #[serde(rename = "REJECTED")]
        Rejected,
    }

    impl BlockStatus {
        pub fn is_pending(&self) -> bool {
            self == &Self::Pending
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
