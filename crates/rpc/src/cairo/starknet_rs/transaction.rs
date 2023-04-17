use std::borrow::Cow;
use std::str::FromStr;

use anyhow::Context;
use pathfinder_common::{ChainId, TransactionHash};

use starknet_in_rust::services::api::contract_classes::deprecated_contract_class::ContractClass;
use starknet_in_rust::transaction::error::TransactionError;
use starknet_in_rust::transaction::{
    Declare, DeclareV2, Deploy, DeployAccount, InvokeFunction, L1Handler, Transaction,
};
use starknet_in_rust::{felt::Felt252, SierraContractClass};

use super::felt::IntoFelt;
use crate::cairo::starknet_rs::felt::IntoFelt252;
use crate::v02::types::request::BroadcastedTransaction;

pub(super) fn transaction_hash(transaction: &Transaction) -> TransactionHash {
    TransactionHash(
        match transaction {
            Transaction::Declare(tx) => &tx.hash_value,
            Transaction::DeclareV2(tx) => &tx.hash_value,
            Transaction::Deploy(tx) => &tx.hash_value,
            Transaction::DeployAccount(tx) => tx.hash_value(),
            Transaction::InvokeFunction(tx) => tx.hash_value(),
            Transaction::L1Handler(tx) => tx.hash_value(),
        }
        .clone()
        .into_felt(),
    )
}

pub(super) fn map_broadcasted_transaction(
    transaction: BroadcastedTransaction,
    chain_id: ChainId,
) -> Result<Transaction, TransactionError> {
    use starknet_in_rust::utils::Address;

    match transaction {
        BroadcastedTransaction::Declare(tx) => match tx {
            crate::v02::types::request::BroadcastedDeclareTransaction::V1(tx) => {
                let signature = tx
                    .signature
                    .into_iter()
                    .map(|s| s.0.into_felt252())
                    .collect();

                // decode program
                let contract_class_json =
                    tx.contract_class.serialize_to_json().map_err(|error| {
                        tracing::error!(%error, "Failed to serialize Cairo class to JSON");
                        TransactionError::MissingCompiledClass
                    })?;

                let contract_class =
                    ContractClass::from_str(String::from_utf8_lossy(&contract_class_json).as_ref())
                        .map_err(|error| {
                            tracing::error!(%error, "Failed to re-parse Cairo class from JSON");
                            TransactionError::MissingCompiledClass
                        })?;

                let tx = Declare::new(
                    contract_class,
                    chain_id.0.into_felt252(),
                    Address(tx.sender_address.get().into_felt252()),
                    u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                    Felt252::from_bytes_be(tx.version.0.as_bytes()),
                    signature,
                    tx.nonce.0.into_felt252(),
                )?;
                Ok(Transaction::Declare(tx))
            }
            crate::v02::types::request::BroadcastedDeclareTransaction::V2(tx) => {
                let signature = tx
                    .signature
                    .into_iter()
                    .map(|s| s.0.into_felt252())
                    .collect();

                let sierra_class_hash = tx
                    .contract_class
                    .class_hash()
                    .map_err(|error| {
                        tracing::error!(%error, "Failed to compute Sierra class hash");
                        TransactionError::MissingCompiledClass
                    })?
                    .hash();

                // NOTE: we don't pass the ABI: it's not required for execution and we're computing the Sierra class
                // hash ourself because the starknet_in_rust API is broken and the original string representation
                // of the ABI is lost.
                let json = serde_json::json!({
                    "abi": [],
                    "sierra_program": tx.contract_class.sierra_program,
                    "contract_class_version": tx.contract_class.contract_class_version,
                    "entry_points_by_type": tx.contract_class.entry_points_by_type,
                });

                let contract_class =
                    serde_json::from_value::<SierraContractClass>(json).map_err(|error| {
                        tracing::error!(%error, "Failed to parse Sierra class");
                        TransactionError::MissingCompiledClass
                    })?;

                let tx = DeclareV2::new_with_sierra_class_hash(
                    &contract_class,
                    sierra_class_hash.0.into_felt252(),
                    None,
                    tx.compiled_class_hash.0.into_felt252(),
                    chain_id.0.into_felt252(),
                    Address(tx.sender_address.get().into_felt252()),
                    u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                    Felt252::from_bytes_be(tx.version.0.as_bytes()),
                    signature,
                    tx.nonce.0.into_felt252(),
                )?;

                Ok(Transaction::DeclareV2(tx.into()))
            }
        },
        BroadcastedTransaction::Invoke(tx) => match tx {
            crate::v02::types::request::BroadcastedInvokeTransaction::V1(tx) => {
                let calldata = tx
                    .calldata
                    .into_iter()
                    .map(|p| p.0.into_felt252())
                    .collect();
                let signature = tx
                    .signature
                    .into_iter()
                    .map(|s| s.0.into_felt252())
                    .collect();
                let tx = InvokeFunction::new(
                    Address(tx.sender_address.get().into_felt252()),
                    starknet_in_rust::definitions::constants::EXECUTE_ENTRY_POINT_SELECTOR.clone(),
                    u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                    Felt252::from_bytes_be(tx.version.0.as_bytes()),
                    calldata,
                    signature,
                    chain_id.0.into_felt252(),
                    Some(tx.nonce.0.into_felt252()),
                )?;
                Ok(Transaction::InvokeFunction(tx))
            }
        },
        BroadcastedTransaction::DeployAccount(tx) => {
            let constructor_calldata = tx
                .constructor_calldata
                .into_iter()
                .map(|p| p.0.into_felt252())
                .collect();
            let signature = tx
                .signature
                .into_iter()
                .map(|s| s.0.into_felt252())
                .collect();
            let tx = DeployAccount::new(
                tx.class_hash.0.to_be_bytes(),
                u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                Felt252::from_bytes_be(tx.version.0.as_bytes()),
                tx.nonce.0.into_felt252(),
                constructor_calldata,
                signature,
                tx.contract_address_salt.0.into_felt252(),
                chain_id.0.into_felt252(),
            )?;
            Ok(Transaction::DeployAccount(tx))
        }
    }
}

pub(super) fn map_gateway_transaction(
    transaction: starknet_gateway_types::reply::transaction::Transaction,
    chain_id: ChainId,
    db_transaction: &pathfinder_storage::Transaction<'_>,
) -> anyhow::Result<Transaction> {
    use starknet_in_rust::utils::Address;

    match transaction {
        starknet_gateway_types::reply::transaction::Transaction::Declare(tx) => match tx {
            starknet_gateway_types::reply::transaction::DeclareTransaction::V0(tx) => {
                let signature = tx
                    .signature
                    .into_iter()
                    .map(|s| s.0.into_felt252())
                    .collect();

                // decode program
                let contract_class = db_transaction
                    .class_definition(tx.class_hash)?
                    .context("Fetching class definition")?;
                let contract_class =
                    starknet_in_rust::services::api::contract_classes::deprecated_contract_class::ContractClass::from_str(
                        String::from_utf8_lossy(&contract_class).as_ref(),
                    )
                    .map_err(|e| anyhow::anyhow!("Failed to parse class definition: {}", e))?;

                let tx = Declare::new_with_tx_hash(
                    contract_class,
                    Address(tx.sender_address.get().into_felt252()),
                    u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                    0.into(),
                    signature,
                    tx.nonce.0.into_felt252(),
                    tx.transaction_hash.0.into_felt252(),
                )?;
                Ok(Transaction::Declare(tx))
            }
            starknet_gateway_types::reply::transaction::DeclareTransaction::V1(tx) => {
                let signature = tx
                    .signature
                    .into_iter()
                    .map(|s| s.0.into_felt252())
                    .collect();

                // decode program
                let contract_class = db_transaction
                    .class_definition(tx.class_hash)?
                    .context("Fetching class definition")?;

                let contract_class = String::from_utf8_lossy(&contract_class);

                let contract_class = ContractClass::from_str(contract_class.as_ref())
                    .map_err(|e| anyhow::anyhow!("Failed to parse class definition: {}", e))?;

                let tx = Declare::new_with_tx_hash(
                    contract_class,
                    Address(tx.sender_address.get().into_felt252()),
                    u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                    1.into(),
                    signature,
                    tx.nonce.0.into_felt252(),
                    tx.transaction_hash.0.into_felt252(),
                )?;
                Ok(Transaction::Declare(tx))
            }
            starknet_gateway_types::reply::transaction::DeclareTransaction::V2(tx) => {
                let signature = tx
                    .signature
                    .into_iter()
                    .map(|s| s.0.into_felt252())
                    .collect();

                // fetch program
                let contract_class = db_transaction
                    .class_definition(tx.class_hash)?
                    .context("Fetching class definition")?;

                let contract_class =
                    serde_json::from_slice::<FeederGatewayContractClass<'_>>(&contract_class)
                        .map_err(|error| {
                            tracing::error!(class_hash=%tx.class_hash, %error, "Failed to parse gateway class definition");
                            TransactionError::MissingCompiledClass
                        })?;

                // NOTE: we don't pass the ABI: it's not required for execution and we're computing the Sierra class
                // hash ourself because the starknet_in_rust API is broken and the original string representation
                // of the ABI is lost.
                let compiler_contract_class_json = serde_json::json!({
                    "abi": [],
                    "sierra_program": contract_class.sierra_program,
                    "contract_class_version": contract_class.contract_class_version,
                    "entry_points_by_type": contract_class.entry_points_by_type,
                });

                let contract_class =
                    serde_json::from_value::<SierraContractClass>(compiler_contract_class_json)
                        .map_err(|error| {
                            tracing::error!(class_hash=%tx.class_hash, %error, "Failed to parse Sierra class definition");
                            TransactionError::MissingCompiledClass
                        })?;

                let tx = DeclareV2::new_with_sierra_class_hash_and_tx_hash(
                    &contract_class,
                    tx.class_hash.0.into_felt252(),
                    None,
                    tx.compiled_class_hash.0.into_felt252(),
                    Address(tx.sender_address.get().into_felt252()),
                    u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                    2.into(),
                    signature,
                    tx.nonce.0.into_felt252(),
                    tx.transaction_hash.0.into_felt252(),
                )?;

                Ok(Transaction::DeclareV2(tx.into()))
            }
        },
        starknet_gateway_types::reply::transaction::Transaction::Deploy(tx) => {
            let constructor_calldata = tx
                .constructor_calldata
                .into_iter()
                .map(|p| p.0.into_felt252())
                .collect();

            let contract_class = db_transaction
                .class_definition(tx.class_hash)?
                .context("Fetching class definition")?;
            let contract_class =
                starknet_in_rust::services::api::contract_classes::deprecated_contract_class::ContractClass::from_str(
                    String::from_utf8_lossy(&contract_class).as_ref(),
                )
                .map_err(|_| TransactionError::MissingCompiledClass)?;
            let tx = Deploy::new_with_tx_hash(
                tx.contract_address_salt.0.into_felt252(),
                contract_class,
                constructor_calldata,
                tx.version.without_query_version().into(),
                tx.transaction_hash.0.into_felt252(),
            )?;

            Ok(Transaction::Deploy(tx))
        }
        starknet_gateway_types::reply::transaction::Transaction::DeployAccount(tx) => {
            let constructor_calldata = tx
                .constructor_calldata
                .into_iter()
                .map(|p| p.0.into_felt252())
                .collect();
            let signature = tx
                .signature
                .into_iter()
                .map(|s| s.0.into_felt252())
                .collect();
            let tx = DeployAccount::new_with_tx_hash(
                tx.class_hash.0.to_be_bytes(),
                u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                Felt252::from_bytes_be(tx.version.0.as_bytes()),
                tx.nonce.0.into_felt252(),
                constructor_calldata,
                signature,
                tx.contract_address_salt.0.into_felt252(),
                tx.transaction_hash.0.into_felt252(),
            )?;
            Ok(Transaction::DeployAccount(tx))
        }
        starknet_gateway_types::reply::transaction::Transaction::Invoke(tx) => match tx {
            starknet_gateway_types::reply::transaction::InvokeTransaction::V0(tx) => {
                let calldata = tx
                    .calldata
                    .into_iter()
                    .map(|p| p.0.into_felt252())
                    .collect();
                let signature = tx
                    .signature
                    .into_iter()
                    .map(|s| s.0.into_felt252())
                    .collect();

                let tx = InvokeFunction::new_with_tx_hash(
                    Address(tx.sender_address.get().into_felt252()),
                    tx.entry_point_selector.0.into_felt252(),
                    u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                    0.into(),
                    calldata,
                    signature,
                    None,
                    tx.transaction_hash.0.into_felt252(),
                )?;
                Ok(Transaction::InvokeFunction(tx))
            }
            starknet_gateway_types::reply::transaction::InvokeTransaction::V1(tx) => {
                let calldata = tx
                    .calldata
                    .into_iter()
                    .map(|p| p.0.into_felt252())
                    .collect();
                let signature = tx
                    .signature
                    .into_iter()
                    .map(|s| s.0.into_felt252())
                    .collect();

                let tx = InvokeFunction::new_with_tx_hash(
                    Address(tx.sender_address.get().into_felt252()),
                    starknet_in_rust::definitions::constants::EXECUTE_ENTRY_POINT_SELECTOR.clone(),
                    u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                    1.into(),
                    calldata,
                    signature,
                    Some(tx.nonce.0.into_felt252()),
                    tx.transaction_hash.0.into_felt252(),
                )?;
                Ok(Transaction::InvokeFunction(tx))
            }
        },
        starknet_gateway_types::reply::transaction::Transaction::L1Handler(tx) => {
            let calldata = tx
                .calldata
                .into_iter()
                .map(|p| p.0.into_felt252())
                .collect();

            let tx = L1Handler::new(
                Address(tx.contract_address.get().into_felt252()),
                tx.entry_point_selector.0.into_felt252(),
                calldata,
                tx.nonce.0.into_felt252(),
                chain_id.0.into_felt252(),
                None,
            )?;
            Ok(Transaction::L1Handler(tx))
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FeederGatewayContractClass<'a> {
    #[serde(borrow)]
    pub abi: Cow<'a, str>,

    #[serde(borrow)]
    pub sierra_program: &'a serde_json::value::RawValue,

    #[serde(borrow)]
    pub contract_class_version: &'a serde_json::value::RawValue,

    #[serde(borrow)]
    pub entry_points_by_type: &'a serde_json::value::RawValue,
}
