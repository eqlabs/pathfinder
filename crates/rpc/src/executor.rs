use anyhow::Context;
use pathfinder_common::transaction::TransactionVariant;
use pathfinder_common::{ChainId, StarknetVersion};
use pathfinder_executor::{ClassInfo, IntoStarkFelt};
use starknet_api::core::PatriciaKey;

use crate::types::request::{
    BroadcastedDeployAccountTransaction,
    BroadcastedInvokeTransaction,
    BroadcastedTransaction,
};
use crate::types::SierraContractClass;

pub enum ExecutionStateError {
    BlockNotFound,
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for ExecutionStateError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

pub const VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY:
    StarknetVersion = StarknetVersion::new(0, 13, 1, 1);

pub(crate) fn map_broadcasted_transaction(
    transaction: &BroadcastedTransaction,
    chain_id: ChainId,
) -> anyhow::Result<pathfinder_executor::Transaction> {
    use crate::types::request::BroadcastedDeclareTransaction;

    let class_info = match &transaction {
        BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V0(tx)) => {
            let contract_class_json = tx
                .contract_class
                .serialize_to_json()
                .context("Serializing Cairo class to JSON")?;

            let contract_class =
                pathfinder_executor::parse_deprecated_class_definition(contract_class_json)?;

            Some(ClassInfo::new(&contract_class, 0, 0)?)
        }
        BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V1(tx)) => {
            let contract_class_json = tx
                .contract_class
                .serialize_to_json()
                .context("Serializing Cairo class to JSON")?;

            let contract_class =
                pathfinder_executor::parse_deprecated_class_definition(contract_class_json)?;

            Some(ClassInfo::new(&contract_class, 0, 0)?)
        }
        BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(tx)) => {
            let casm_contract_definition = pathfinder_compiler::compile_to_casm(
                &tx.contract_class
                    .serialize_to_json()
                    .context("Serializing Sierra class definition")?,
            )
            .context("Compiling Sierra class definition to CASM")?;

            let casm_contract_definition =
                pathfinder_executor::parse_casm_definition(casm_contract_definition)
                    .context("Parsing CASM contract definition")?;
            Some(ClassInfo::new(
                &casm_contract_definition,
                tx.contract_class.sierra_program.len(),
                tx.contract_class.abi.len(),
            )?)
        }
        BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V3(tx)) => {
            let casm_contract_definition = pathfinder_compiler::compile_to_casm(
                &tx.contract_class
                    .serialize_to_json()
                    .context("Serializing Sierra class definition")?,
            )
            .context("Compiling Sierra class definition to CASM")?;

            let casm_contract_definition =
                pathfinder_executor::parse_casm_definition(casm_contract_definition)
                    .context("Parsing CASM contract definition")?;
            Some(ClassInfo::new(
                &casm_contract_definition,
                tx.contract_class.sierra_program.len(),
                tx.contract_class.abi.len(),
            )?)
        }
        BroadcastedTransaction::Invoke(_) | BroadcastedTransaction::DeployAccount(_) => None,
    };

    let deployed_address = match &transaction {
        BroadcastedTransaction::DeployAccount(BroadcastedDeployAccountTransaction::V1(tx)) => {
            Some(starknet_api::core::ContractAddress(
                PatriciaKey::try_from(tx.deployed_contract_address().0.into_starkfelt())
                    .expect("No sender address overflow expected"),
            ))
        }
        BroadcastedTransaction::DeployAccount(BroadcastedDeployAccountTransaction::V3(tx)) => {
            Some(starknet_api::core::ContractAddress(
                PatriciaKey::try_from(tx.deployed_contract_address().0.into_starkfelt())
                    .expect("No sender address overflow expected"),
            ))
        }
        BroadcastedTransaction::Declare(_) | BroadcastedTransaction::Invoke(_) => None,
    };

    let has_query_version = match &transaction {
        BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V0(tx)) => {
            tx.version.has_query_version()
        }
        BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V1(tx)) => {
            tx.version.has_query_version()
        }
        BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(tx)) => {
            tx.version.has_query_version()
        }
        BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V3(tx)) => {
            tx.version.has_query_version()
        }
        BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(tx)) => {
            tx.version.has_query_version()
        }
        BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(tx)) => {
            tx.version.has_query_version()
        }
        BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V3(tx)) => {
            tx.version.has_query_version()
        }
        BroadcastedTransaction::DeployAccount(BroadcastedDeployAccountTransaction::V1(tx)) => {
            tx.version.has_query_version()
        }
        BroadcastedTransaction::DeployAccount(BroadcastedDeployAccountTransaction::V3(tx)) => {
            tx.version.has_query_version()
        }
    };

    let transaction = transaction.clone().into_common(chain_id);
    let transaction_hash = transaction.hash;
    let transaction = map_transaction_variant(transaction.variant)?;

    let tx = pathfinder_executor::Transaction::from_api(
        transaction,
        starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt()),
        class_info,
        None,
        deployed_address,
        has_query_version,
    )?;

    Ok(tx)
}

fn map_transaction_variant(
    variant: TransactionVariant,
) -> anyhow::Result<starknet_api::transaction::Transaction> {
    match variant {
        TransactionVariant::DeclareV0(tx) => {
            let tx = starknet_api::transaction::DeclareTransactionV0V1 {
                max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                    tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                )),
                signature: starknet_api::transaction::TransactionSignature(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                ),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
                sender_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
            };

            Ok(starknet_api::transaction::Transaction::Declare(
                starknet_api::transaction::DeclareTransaction::V0(tx),
            ))
        }
        TransactionVariant::DeclareV1(tx) => {
            let tx = starknet_api::transaction::DeclareTransactionV0V1 {
                max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                    tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                )),
                signature: starknet_api::transaction::TransactionSignature(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                ),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
                sender_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
            };

            Ok(starknet_api::transaction::Transaction::Declare(
                starknet_api::transaction::DeclareTransaction::V1(tx),
            ))
        }
        TransactionVariant::DeclareV2(tx) => {
            let tx = starknet_api::transaction::DeclareTransactionV2 {
                max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                    tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                )),
                signature: starknet_api::transaction::TransactionSignature(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                ),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
                sender_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
                compiled_class_hash: starknet_api::core::CompiledClassHash(
                    tx.compiled_class_hash.0.into_starkfelt(),
                ),
            };

            Ok(starknet_api::transaction::Transaction::Declare(
                starknet_api::transaction::DeclareTransaction::V2(tx),
            ))
        }
        TransactionVariant::DeclareV3(tx) => {
            let tx = starknet_api::transaction::DeclareTransactionV3 {
                resource_bounds: map_resource_bounds(tx.resource_bounds)?,
                tip: starknet_api::transaction::Tip(tx.tip.0),
                signature: starknet_api::transaction::TransactionSignature(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                ),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
                compiled_class_hash: starknet_api::core::CompiledClassHash(
                    tx.compiled_class_hash.0.into_starkfelt(),
                ),
                sender_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
                nonce_data_availability_mode: tx
                    .nonce_data_availability_mode
                    .into_starkfelt()
                    .try_into()?,
                fee_data_availability_mode: tx
                    .fee_data_availability_mode
                    .into_starkfelt()
                    .try_into()?,
                paymaster_data: starknet_api::transaction::PaymasterData(
                    tx.paymaster_data
                        .iter()
                        .map(|p| p.0.into_starkfelt())
                        .collect(),
                ),
                account_deployment_data: starknet_api::transaction::AccountDeploymentData(
                    tx.account_deployment_data
                        .iter()
                        .map(|a| a.0.into_starkfelt())
                        .collect(),
                ),
            };

            Ok(starknet_api::transaction::Transaction::Declare(
                starknet_api::transaction::DeclareTransaction::V3(tx),
            ))
        }
        TransactionVariant::DeployV0(_) | TransactionVariant::DeployV1(_) => {
            anyhow::bail!("Deploy transactions are not yet supported in blockifier")
        }
        TransactionVariant::DeployAccountV1(tx) => {
            let tx = starknet_api::transaction::DeployAccountTransaction::V1(
                starknet_api::transaction::DeployAccountTransactionV1 {
                    max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                        tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                    )),
                    signature: starknet_api::transaction::TransactionSignature(
                        tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                    ),
                    nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                    class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),

                    contract_address_salt: starknet_api::transaction::ContractAddressSalt(
                        tx.contract_address_salt.0.into_starkfelt(),
                    ),
                    constructor_calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                        tx.constructor_calldata
                            .iter()
                            .map(|c| c.0.into_starkfelt())
                            .collect(),
                    )),
                },
            );

            Ok(starknet_api::transaction::Transaction::DeployAccount(tx))
        }
        TransactionVariant::DeployAccountV3(tx) => {
            let resource_bounds = map_resource_bounds(tx.resource_bounds)?;

            let tx = starknet_api::transaction::DeployAccountTransaction::V3(
                starknet_api::transaction::DeployAccountTransactionV3 {
                    resource_bounds,
                    tip: starknet_api::transaction::Tip(tx.tip.0),
                    signature: starknet_api::transaction::TransactionSignature(
                        tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                    ),
                    nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                    class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
                    contract_address_salt: starknet_api::transaction::ContractAddressSalt(
                        tx.contract_address_salt.0.into_starkfelt(),
                    ),
                    constructor_calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                        tx.constructor_calldata
                            .iter()
                            .map(|c| c.0.into_starkfelt())
                            .collect(),
                    )),
                    nonce_data_availability_mode: tx
                        .nonce_data_availability_mode
                        .into_starkfelt()
                        .try_into()?,
                    fee_data_availability_mode: tx
                        .fee_data_availability_mode
                        .into_starkfelt()
                        .try_into()?,
                    paymaster_data: starknet_api::transaction::PaymasterData(
                        tx.paymaster_data
                            .iter()
                            .map(|p| p.0.into_starkfelt())
                            .collect(),
                    ),
                },
            );

            Ok(starknet_api::transaction::Transaction::DeployAccount(tx))
        }
        TransactionVariant::InvokeV0(tx) => {
            let tx = starknet_api::transaction::InvokeTransactionV0 {
                // TODO: maybe we should store tx.max_fee as u128 internally?
                max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                    tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                )),
                signature: starknet_api::transaction::TransactionSignature(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                ),
                contract_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
                entry_point_selector: starknet_api::core::EntryPointSelector(
                    tx.entry_point_selector.0.into_starkfelt(),
                ),
                calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                    tx.calldata.iter().map(|c| c.0.into_starkfelt()).collect(),
                )),
            };

            Ok(starknet_api::transaction::Transaction::Invoke(
                starknet_api::transaction::InvokeTransaction::V0(tx),
            ))
        }
        TransactionVariant::InvokeV1(tx) => {
            let tx = starknet_api::transaction::InvokeTransactionV1 {
                // TODO: maybe we should store tx.max_fee as u128 internally?
                max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                    tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                )),
                signature: starknet_api::transaction::TransactionSignature(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                ),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                sender_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
                calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                    tx.calldata.iter().map(|c| c.0.into_starkfelt()).collect(),
                )),
            };

            Ok(starknet_api::transaction::Transaction::Invoke(
                starknet_api::transaction::InvokeTransaction::V1(tx),
            ))
        }
        TransactionVariant::InvokeV3(tx) => {
            let resource_bounds = map_resource_bounds(tx.resource_bounds)?;

            let tx = starknet_api::transaction::InvokeTransactionV3 {
                resource_bounds,
                tip: starknet_api::transaction::Tip(tx.tip.0),
                signature: starknet_api::transaction::TransactionSignature(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                ),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                sender_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
                calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                    tx.calldata.iter().map(|c| c.0.into_starkfelt()).collect(),
                )),
                nonce_data_availability_mode: tx
                    .nonce_data_availability_mode
                    .into_starkfelt()
                    .try_into()?,
                fee_data_availability_mode: tx
                    .fee_data_availability_mode
                    .into_starkfelt()
                    .try_into()?,
                paymaster_data: starknet_api::transaction::PaymasterData(
                    tx.paymaster_data
                        .iter()
                        .map(|p| p.0.into_starkfelt())
                        .collect(),
                ),
                account_deployment_data: starknet_api::transaction::AccountDeploymentData(
                    tx.account_deployment_data
                        .iter()
                        .map(|a| a.0.into_starkfelt())
                        .collect(),
                ),
            };

            Ok(starknet_api::transaction::Transaction::Invoke(
                starknet_api::transaction::InvokeTransaction::V3(tx),
            ))
        }
        TransactionVariant::L1Handler(tx) => {
            let tx = starknet_api::transaction::L1HandlerTransaction {
                version: starknet_api::transaction::TransactionVersion::ZERO,
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                contract_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.contract_address.get().into_starkfelt())
                        .expect("No contract address overflow expected"),
                ),
                entry_point_selector: starknet_api::core::EntryPointSelector(
                    tx.entry_point_selector.0.into_starkfelt(),
                ),
                calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                    tx.calldata.iter().map(|c| c.0.into_starkfelt()).collect(),
                )),
            };

            Ok(starknet_api::transaction::Transaction::L1Handler(tx))
        }
    }
}

/// Build the executor transaction out of the gateway one
/// while pulling necessary data from the DB along the way.
pub fn compose_executor_transaction(
    transaction: &pathfinder_common::transaction::Transaction,
    db_transaction: &pathfinder_storage::Transaction<'_>,
) -> anyhow::Result<pathfinder_executor::Transaction> {
    let tx_hash = starknet_api::transaction::TransactionHash(transaction.hash.0.into_starkfelt());

    let class_info = match &transaction.variant {
        TransactionVariant::DeclareV0(tx) => {
            let class_definition = db_transaction
                .class_definition(tx.class_hash)?
                .context("Fetching class definition")?;

            let contract_class =
                pathfinder_executor::parse_deprecated_class_definition(class_definition)?;
            Some(ClassInfo::new(&contract_class, 0, 0)?)
        }
        TransactionVariant::DeclareV1(tx) => {
            let class_definition = db_transaction
                .class_definition(tx.class_hash)?
                .context("Fetching class definition")?;

            let contract_class =
                pathfinder_executor::parse_deprecated_class_definition(class_definition)?;
            Some(ClassInfo::new(&contract_class, 0, 0)?)
        }
        TransactionVariant::DeclareV2(tx) => {
            let casm_definition = db_transaction
                .casm_definition(tx.class_hash)?
                .context("Fetching class CASM definition")?;
            let class_definition = db_transaction
                .class_definition(tx.class_hash)?
                .context("Fetching class definition")?;
            let class_definition: SierraContractClass =
                serde_json::from_str(&String::from_utf8(class_definition)?)
                    .context("Deserializing class definition")?;

            let contract_class = pathfinder_executor::parse_casm_definition(casm_definition)?;
            Some(ClassInfo::new(
                &contract_class,
                class_definition.sierra_program.len(),
                class_definition.abi.len(),
            )?)
        }
        TransactionVariant::DeclareV3(tx) => {
            let casm_definition = db_transaction
                .casm_definition(tx.class_hash)?
                .context("Fetching class CASM definition")?;
            let class_definition = db_transaction
                .class_definition(tx.class_hash)?
                .context("Fetching class definition")?;
            let class_definition: SierraContractClass =
                serde_json::from_str(&String::from_utf8(class_definition)?)
                    .context("Deserializing class definition")?;

            let contract_class = pathfinder_executor::parse_casm_definition(casm_definition)?;
            Some(ClassInfo::new(
                &contract_class,
                class_definition.sierra_program.len(),
                class_definition.abi.len(),
            )?)
        }
        TransactionVariant::DeployV0(_)
        | TransactionVariant::DeployV1(_)
        | TransactionVariant::DeployAccountV1(_)
        | TransactionVariant::DeployAccountV3(_)
        | TransactionVariant::InvokeV0(_)
        | TransactionVariant::InvokeV1(_)
        | TransactionVariant::InvokeV3(_)
        | TransactionVariant::L1Handler(_) => None,
    };

    let deployed_address = match &transaction.variant {
        TransactionVariant::DeployAccountV1(tx) => {
            let contract_address = starknet_api::core::ContractAddress(
                PatriciaKey::try_from(tx.contract_address.get().into_starkfelt())
                    .expect("No contract address overflow expected"),
            );

            Some(contract_address)
        }
        TransactionVariant::DeployAccountV3(tx) => {
            let contract_address = starknet_api::core::ContractAddress(
                PatriciaKey::try_from(tx.contract_address.get().into_starkfelt())
                    .expect("No contract address overflow expected"),
            );

            Some(contract_address)
        }
        TransactionVariant::DeclareV0(_)
        | TransactionVariant::DeclareV1(_)
        | TransactionVariant::DeclareV2(_)
        | TransactionVariant::DeclareV3(_)
        | TransactionVariant::DeployV0(_)
        | TransactionVariant::DeployV1(_)
        | TransactionVariant::InvokeV0(_)
        | TransactionVariant::InvokeV1(_)
        | TransactionVariant::InvokeV3(_)
        | TransactionVariant::L1Handler(_) => None,
    };

    let paid_fee_on_l1 = match &transaction.variant {
        TransactionVariant::L1Handler(_) => Some(starknet_api::transaction::Fee(1_000_000_000_000)),
        _ => None,
    };

    tracing::trace!(%tx_hash, "Converting transaction");

    let transaction = map_transaction_variant(transaction.variant.clone())?;

    let tx = pathfinder_executor::Transaction::from_api(
        transaction,
        tx_hash,
        class_info,
        paid_fee_on_l1,
        deployed_address,
        false,
    )?;

    Ok(tx)
}

fn map_resource_bounds(
    r: pathfinder_common::transaction::ResourceBounds,
) -> Result<starknet_api::transaction::ResourceBoundsMapping, starknet_api::StarknetApiError> {
    use starknet_api::transaction::{Resource, ResourceBounds};

    let bounds = vec![
        (
            Resource::L1Gas,
            ResourceBounds {
                max_amount: r.l1_gas.max_amount.0,
                max_price_per_unit: r.l1_gas.max_price_per_unit.0,
            },
        ),
        (
            Resource::L2Gas,
            ResourceBounds {
                max_amount: r.l2_gas.max_amount.0,
                max_price_per_unit: r.l2_gas.max_price_per_unit.0,
            },
        ),
    ];

    bounds.try_into()
}
