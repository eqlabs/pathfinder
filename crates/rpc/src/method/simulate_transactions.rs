use anyhow::Context;
use pathfinder_common::BlockId;
use pathfinder_executor::TransactionExecutionError;

use crate::context::RpcContext;
use crate::executor::ExecutionStateError;
use crate::types::request::BroadcastedTransaction;

#[derive(Debug)]
pub struct SimulateTransactionInput {
    pub block_id: BlockId,
    pub transactions: Vec<BroadcastedTransaction>,
    pub simulation_flags: crate::dto::SimulationFlags,
}

impl crate::dto::DeserializeForVersion for SimulateTransactionInput {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                block_id: value.deserialize("block_id")?,
                transactions: value.deserialize_array("transactions", |value| {
                    BroadcastedTransaction::deserialize(value)
                })?,
                simulation_flags: value.deserialize("simulation_flags")?,
            })
        })
    }
}

pub struct Output(Vec<pathfinder_executor::types::TransactionSimulation>);

pub async fn simulate_transactions(
    context: RpcContext,
    input: SimulateTransactionInput,
) -> Result<Output, SimulateTransactionError> {
    let span = tracing::Span::current();
    util::task::spawn_blocking(move |_| {
        let _g = span.enter();

        let skip_validate = input
            .simulation_flags
            .0
            .iter()
            .any(|flag| flag == &crate::dto::SimulationFlag::SkipValidate);

        let skip_fee_charge = input
            .simulation_flags
            .0
            .iter()
            .any(|flag| flag == &crate::dto::SimulationFlag::SkipFeeCharge);

        let mut db = context
            .execution_storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        let (header, pending) = match input.block_id {
            BlockId::Pending => {
                let pending = context
                    .pending_data
                    .get(&db)
                    .context("Querying pending data")?;

                (pending.header(), Some(pending.state_update.clone()))
            }
            other => {
                let block_id = other.try_into().expect("Only pending should fail");

                let header = db
                    .block_header(block_id)
                    .context("Fetching block header")?
                    .ok_or(SimulateTransactionError::BlockNotFound)?;

                (header, None)
            }
        };

        let state = pathfinder_executor::ExecutionState::simulation(
            &db,
            context.chain_id,
            header,
            pending,
            pathfinder_executor::L1BlobDataAvailability::Enabled,
            context.config.versioned_constants_map,
            context.contract_addresses.eth_l2_token_address,
            context.contract_addresses.strk_l2_token_address,
        );

        let transactions = input
            .transactions
            .into_iter()
            .map(|tx| {
                crate::executor::map_broadcasted_transaction(
                    &tx,
                    context.chain_id,
                    skip_validate,
                    skip_fee_charge,
                    false,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let txs = pathfinder_executor::simulate(
            state,
            transactions,
            context.config.fee_estimation_epsilon,
        )?;
        Ok(Output(txs))
    })
    .await
    .context("Simulating transaction")?
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_iter(self.0.len(), &mut self.0.iter().map(TransactionSimulation))
    }
}

struct TransactionSimulation<'a>(&'a pathfinder_executor::types::TransactionSimulation);

impl crate::dto::SerializeForVersion for TransactionSimulation<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("fee_estimation", &self.0.fee_estimation)?;
        serializer.serialize_field(
            "transaction_trace",
            &crate::dto::TransactionTrace {
                trace: self.0.trace.clone(),
                include_state_diff: true,
            },
        )?;
        serializer.end()
    }
}

#[derive(Debug)]
pub enum SimulateTransactionError {
    Internal(anyhow::Error),
    Custom(anyhow::Error),
    BlockNotFound,
    TransactionExecutionError {
        transaction_index: usize,
        error: String,
        error_stack: pathfinder_executor::ErrorStack,
    },
}

impl From<anyhow::Error> for SimulateTransactionError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<SimulateTransactionError> for crate::error::ApplicationError {
    fn from(e: SimulateTransactionError) -> Self {
        match e {
            SimulateTransactionError::Internal(internal) => Self::Internal(internal),
            SimulateTransactionError::Custom(internal) => Self::Custom(internal),
            SimulateTransactionError::BlockNotFound => Self::BlockNotFound,
            SimulateTransactionError::TransactionExecutionError {
                transaction_index,
                error,
                error_stack,
            } => Self::TransactionExecutionError {
                transaction_index,
                error,
                error_stack,
            },
        }
    }
}

impl From<TransactionExecutionError> for SimulateTransactionError {
    fn from(value: TransactionExecutionError) -> Self {
        use TransactionExecutionError::*;
        match value {
            ExecutionError {
                transaction_index,
                error,
                error_stack,
            } => Self::TransactionExecutionError {
                transaction_index,
                error,
                error_stack,
            },
            Internal(e) => Self::Internal(e),
            Custom(e) => Self::Custom(e),
        }
    }
}

impl From<ExecutionStateError> for SimulateTransactionError {
    fn from(error: ExecutionStateError) -> Self {
        match error {
            ExecutionStateError::BlockNotFound => Self::BlockNotFound,
            ExecutionStateError::Internal(e) => Self::Internal(e),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeMap, HashSet};

    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{
        felt,
        BlockHeader,
        BlockId,
        ClassHash,
        ContractAddress,
        EntryPoint,
        StarknetVersion,
        StorageAddress,
        StorageValue,
        TransactionVersion,
    };
    use pathfinder_crypto::Felt;
    use pathfinder_storage::Storage;
    use starknet_gateway_test_fixtures::class_definitions::ERC20_CONTRACT_DEFINITION_CLASS_HASH;

    use super::simulate_transactions;
    use crate::context::{RpcContext, ETH_FEE_TOKEN_ADDRESS};
    use crate::dto::{DeserializeForVersion, SerializeForVersion, Serializer};
    use crate::method::simulate_transactions::SimulateTransactionInput;
    use crate::types::request::{
        BroadcastedDeclareTransaction,
        BroadcastedDeclareTransactionV1,
        BroadcastedTransaction,
    };
    use crate::RpcVersion;

    pub(crate) async fn setup_storage_with_starknet_version(
        version: StarknetVersion,
    ) -> (
        Storage,
        BlockHeader,
        ContractAddress,
        ContractAddress,
        StorageValue,
    ) {
        let test_storage_key = StorageAddress::from_name(b"my_storage_var");
        let test_storage_value = storage_value!("0x09");

        // set test storage variable
        let (storage, last_block_header, account_contract_address, universal_deployer_address) =
            crate::test_setup::test_storage(version, |state_update| {
                state_update.with_storage_update(
                    fixtures::DEPLOYED_CONTRACT_ADDRESS,
                    test_storage_key,
                    test_storage_value,
                )
            })
            .await;

        (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        )
    }

    #[tokio::test]
    async fn test_simulate_transaction_with_skip_fee_charge() {
        let (context, _, _, _) = crate::test_setup::test_context().await;

        let input_json = serde_json::json!({
            "block_id": {"block_number": 1},
            "transactions": [
                {
                    "contract_address_salt": "0x46c0d4abf0192a788aca261e58d7031576f7d8ea5229f452b0f23e691dd5971",
                    "max_fee": "0x0",
                    "signature": [],
                    "class_hash": crate::test_setup::OPENZEPPELIN_ACCOUNT_CLASS_HASH,
                    "nonce": "0x0",
                    "version": TransactionVersion::ONE_WITH_QUERY_VERSION,
                    "constructor_calldata": ["0x1"],
                    "type": "DEPLOY_ACCOUNT"
                }
            ],
            "simulation_flags": ["SKIP_FEE_CHARGE"]
        });

        let value = crate::dto::Value::new(input_json, RpcVersion::V07);
        let input = SimulateTransactionInput::deserialize(value).unwrap();

        const DEPLOYED_CONTRACT_ADDRESS: ContractAddress =
            contract_address!("0xf3805e4f045a8b48e7e9e6cd5d910973a22360572207f3ae625c5cec2a3232");

        let expected = crate::method::simulate_transactions::Output(vec![
            pathfinder_executor::types::TransactionSimulation{
                fee_estimation: pathfinder_executor::types::FeeEstimate {
                    l1_gas_consumed: 0x15.into(),
                    l1_gas_price: 1.into(),
                    l1_data_gas_consumed: 0x160.into(),
                    l1_data_gas_price: 2.into(),
                    l2_gas_consumed: 0.into(),
                    l2_gas_price: 1.into(),
                    overall_fee: 0x2d5.into(),
                    unit: pathfinder_executor::types::PriceUnit::Wei,
                },
                trace: pathfinder_executor::types::TransactionTrace::DeployAccount(
                    pathfinder_executor::types::DeployAccountTransactionTrace {
                        constructor_invocation: Some(pathfinder_executor::types::FunctionInvocation {
                                call_type: pathfinder_executor::types::CallType::Call,
                                caller_address: felt!("0x0"),
                                class_hash: Some(crate::test_setup::OPENZEPPELIN_ACCOUNT_CLASS_HASH.0),
                                entry_point_type: pathfinder_executor::types::EntryPointType::Constructor,
                                events: vec![pathfinder_executor::types::Event {
                                    order: 0,
                                    data: vec![],
                                    keys: vec![
                                        felt!("0x38f6a5b87c23cee6e7294bcc3302e95019f70f81586ff3cac38581f5ca96381"),
                                        felt!("0x1"),
                                    ],
                                }],
                                calldata: vec![felt!("0x1")],
                                contract_address: DEPLOYED_CONTRACT_ADDRESS,
                                selector: entry_point!("0x028FFE4FF0F226A9107253E17A904099AA4F63A02A5621DE0576E5AA71BC5194").0,
                                messages: vec![],
                                result: vec![],
                                execution_resources: pathfinder_executor::types::InnerCallExecutionResources::default(),
                                internal_calls: vec![],
                                computation_resources: pathfinder_executor::types::ComputationResources {
                                    pedersen_builtin_applications: 2,
                                    range_check_builtin_applications: 8,
                                    steps: 312,
                                    ..Default::default()
                                },
                                is_reverted: false,
                            }),
                        validate_invocation: Some(
                            pathfinder_executor::types::FunctionInvocation {
                                call_type: pathfinder_executor::types::CallType::Call,
                                caller_address: felt!("0x0"),
                                class_hash: Some(crate::test_setup::OPENZEPPELIN_ACCOUNT_CLASS_HASH.0),
                                entry_point_type: pathfinder_executor::types::EntryPointType::External,
                                events: vec![],
                                calldata: vec![
                                    crate::test_setup::OPENZEPPELIN_ACCOUNT_CLASS_HASH.0,
                                    call_param!("0x046C0D4ABF0192A788ACA261E58D7031576F7D8EA5229F452B0F23E691DD5971").0,
                                    call_param!("0x1").0,
                                ],
                                contract_address: DEPLOYED_CONTRACT_ADDRESS,
                                selector: entry_point!("0x036FCBF06CD96843058359E1A75928BEACFAC10727DAB22A3972F0AF8AA92895").0,
                                messages: vec![],
                                result: vec![
                                    felt!("0x56414c4944")
                                ],
                                execution_resources: pathfinder_executor::types::InnerCallExecutionResources {
                                    l1_gas: 0,
                                    l2_gas: 0,
                                },
                                internal_calls: vec![],
                                computation_resources: pathfinder_executor::types::ComputationResources{
                                    memory_holes: 1,
                                    range_check_builtin_applications: 2,
                                    steps: 135,
                                    ..Default::default()
                                },
                                is_reverted: false,
                            },
                        ),
                        fee_transfer_invocation: None,
                        state_diff: pathfinder_executor::types::StateDiff {
                            storage_diffs: BTreeMap::from([
                                (
                                    DEPLOYED_CONTRACT_ADDRESS,
                                    vec![
                                        pathfinder_executor::types::StorageDiff {
                                            key: storage_address!("0x81ba5d1f84a6a8f0e7ae24720a20f43f81d9ee6eed98fd524ba8d53a49416b"),
                                            value: storage_value!("0x1"),
                                        },
                                        pathfinder_executor::types::StorageDiff {
                                            key: storage_address!("0x1379ac0624b939ceb9dede92211d7db5ee174fe28be72245b0a1a2abd81c98f"),
                                            value: storage_value!("0x1"),
                                        },
                                        pathfinder_executor::types::StorageDiff {
                                            key: storage_address!("0x7e79bbb6be5d418acd50c88b675e697f6f7094e203c9d7e29c6ad6731f931dd"),
                                            value: storage_value!("0x1"),
                                        },
                                    ]
                                )
                            ]),
                            deprecated_declared_classes: HashSet::new(),
                            declared_classes: vec![],
                            deployed_contracts: vec![
                                pathfinder_executor::types::DeployedContract {
                                    address: DEPLOYED_CONTRACT_ADDRESS,
                                    class_hash: crate::test_setup::OPENZEPPELIN_ACCOUNT_CLASS_HASH
                                }
                            ],
                            replaced_classes: vec![],
                            nonces: BTreeMap::from([(
                                DEPLOYED_CONTRACT_ADDRESS,
                                contract_nonce!("0x1"),
                            )]),
                        },
                        execution_resources: pathfinder_executor::types::ExecutionResources {
                            computation_resources: pathfinder_executor::types::ComputationResources{
                                memory_holes: 1,
                                pedersen_builtin_applications: 2,
                                range_check_builtin_applications: 10,
                                steps:447,
                                ..Default::default()
                            },
                            data_availability: pathfinder_executor::types::DataAvailabilityResources{
                                l1_gas:0,
                                l1_data_gas:352
                            },
                            l1_gas: 0,
                            l1_data_gas: 160,
                            l2_gas: 0,
                        },
                    },
                ),
            }
        ]).serialize(Serializer {
            version: RpcVersion::V07,
        }).unwrap();

        let result = simulate_transactions(context, input).await.expect("result");
        let result = result
            .serialize(Serializer {
                version: RpcVersion::V07,
            })
            .unwrap();
        pretty_assertions_sorted::assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn declare_cairo_v0_class() {
        pub const CAIRO0_DEFINITION: &[u8] =
            include_bytes!("../../fixtures/contracts/cairo0_test.json");

        pub const CAIRO0_HASH: ClassHash =
            class_hash!("02c52e7084728572ea940b4df708a2684677c19fa6296de2ea7ba5327e3a84ef");

        let contract_class = crate::types::ContractClass::from_definition_bytes(CAIRO0_DEFINITION)
            .unwrap()
            .as_cairo()
            .unwrap();

        assert_eq!(contract_class.class_hash().unwrap().hash(), CAIRO0_HASH);

        let (storage, last_block_header, account_contract_address, _, _) =
            setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 0)).await;
        let context = RpcContext::for_tests().with_storage(storage);

        let declare = BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V1(
            BroadcastedDeclareTransactionV1 {
                version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                max_fee: fee!("0x10000"),
                signature: vec![],
                nonce: transaction_nonce!("0x0"),
                contract_class,
                sender_address: account_contract_address,
            },
        ));

        let input = SimulateTransactionInput {
            block_id: last_block_header.number.into(),
            transactions: vec![declare],
            simulation_flags: crate::dto::SimulationFlags(vec![]),
        };

        const OVERALL_FEE: u64 = 15720;

        let expected = crate::method::simulate_transactions::Output(vec![
            pathfinder_executor::types::TransactionSimulation{
                trace: pathfinder_executor::types::TransactionTrace::Declare(pathfinder_executor::types::DeclareTransactionTrace {
                    validate_invocation: Some(
                        pathfinder_executor::types::FunctionInvocation {
                            call_type: pathfinder_executor::types::CallType::Call,
                            caller_address: felt!("0x0"),
                            class_hash: Some(crate::test_setup::OPENZEPPELIN_ACCOUNT_CLASS_HASH.0),
                            entry_point_type: pathfinder_executor::types::EntryPointType::External,
                            events: vec![],
                            contract_address: account_contract_address,
                            selector: EntryPoint::hashed(b"__validate_declare__").0,
                            calldata: vec![CAIRO0_HASH.0],
                            messages: vec![],
                            result: vec![felt!("0x56414c4944")],
                            execution_resources: pathfinder_executor::types::InnerCallExecutionResources::default(),
                            internal_calls: vec![],
                            computation_resources: pathfinder_executor::types::ComputationResources{
                                memory_holes: 1,
                                range_check_builtin_applications: 4,
                                steps: 203,
                                ..Default::default()
                            },
                            is_reverted: false,
                        }
                    ),
                    fee_transfer_invocation: Some(
                        pathfinder_executor::types::FunctionInvocation {
                            call_type: pathfinder_executor::types::CallType::Call,
                            caller_address: *account_contract_address.get(),
                            class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                            entry_point_type: pathfinder_executor::types::EntryPointType::External,
                            events: vec![pathfinder_executor::types::Event {
                                order: 0,
                                data: vec![
                                    *account_contract_address.get(),
                                    last_block_header.sequencer_address.0,
                                    Felt::from_u64(OVERALL_FEE),
                                    felt!("0x0"),
                                ],
                                keys: vec![felt!(
                                    "0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"
                                )],
                            }],
                            calldata: vec![
                                last_block_header.sequencer_address.0,
                                Felt::from_u64(OVERALL_FEE),
                                call_param!("0x0").0,
                            ],
                            contract_address: ETH_FEE_TOKEN_ADDRESS,
                            selector: EntryPoint::hashed(b"transfer").0,
                            messages: vec![],
                            result: vec![felt!("0x1")],
                            execution_resources: pathfinder_executor::types::InnerCallExecutionResources::default(),
                            internal_calls: vec![],
                            computation_resources: pathfinder_executor::types::ComputationResources{
                                steps: 1354,
                                memory_holes: 59,
                                range_check_builtin_applications: 31,
                                pedersen_builtin_applications: 4,
                                ..Default::default()
                            },
                            is_reverted: false,
                        }
                    ),
                    state_diff: pathfinder_executor::types::StateDiff {
                        storage_diffs: BTreeMap::from([
                            (ETH_FEE_TOKEN_ADDRESS, vec![
                                pathfinder_executor::types::StorageDiff {
                                    key: storage_address!("0x032a4edd4e4cffa71ee6d0971c54ac9e62009526cd78af7404aa968c3dc3408e"),
                                    value: storage_value!("0x000000000000000000000000000000000000ffffffffffffffffffffffffc298"),
                                },
                                pathfinder_executor::types::StorageDiff {
                                    key: storage_address!("0x05496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"),
                                    value: StorageValue(OVERALL_FEE.into()),
                                },
                            ]),
                        ]),
                        deprecated_declared_classes: HashSet::from([
                            CAIRO0_HASH
                        ]),
                        declared_classes: vec![],
                        deployed_contracts: vec![],
                        replaced_classes: vec![],
                        nonces: BTreeMap::from([
                            (account_contract_address, contract_nonce!("0x1")),
                        ]),
                    },
                    execution_resources: pathfinder_executor::types::ExecutionResources{
                        computation_resources: pathfinder_executor::types::ComputationResources{
                            steps: 1557,
                            memory_holes: 60,
                            range_check_builtin_applications: 35,
                            pedersen_builtin_applications: 4,
                            ..Default::default()
                        },
                        data_availability: pathfinder_executor::types::DataAvailabilityResources{
                            l1_gas: 0,
                            l1_data_gas: 128,
                        },
                        l1_gas: 0,
                        l1_data_gas: 128,
                        l2_gas: 0,
                    },
                }),
                fee_estimation: pathfinder_executor::types::FeeEstimate {
                    l1_gas_consumed: 15464.into(),
                    l1_gas_price: 1.into(),
                    l1_data_gas_consumed: 128.into(),
                    l1_data_gas_price: 2.into(),
                    l2_gas_consumed: 0.into(),
                    l2_gas_price: 1.into(),
                    overall_fee: OVERALL_FEE.into(),
                    unit: pathfinder_executor::types::PriceUnit::Wei,
                }
            }
        ]).serialize(Serializer {
            version: RpcVersion::V07,
        }).unwrap();

        let result = simulate_transactions(context, input).await.unwrap();

        pretty_assertions_sorted::assert_eq!(
            result
                .serialize(Serializer {
                    version: RpcVersion::V07,
                })
                .unwrap(),
            expected
        );
    }

    pub(crate) mod fixtures {
        use pathfinder_common::{CasmHash, ContractAddress, Fee};

        use super::*;

        pub const SIERRA_DEFINITION: &[u8] =
            include_bytes!("../../fixtures/contracts/storage_access.json");
        pub const SIERRA_HASH: ClassHash =
            class_hash!("0544b92d358447cb9e50b65092b7169f931d29e05c1404a2cd08c6fd7e32ba90");
        pub const CASM_HASH: CasmHash =
            casm_hash!("0x069032ff71f77284e1a0864a573007108ca5cc08089416af50f03260f5d6d4d8");
        pub const CASM_DEFINITION: &[u8] =
            include_bytes!("../../fixtures/contracts/storage_access.casm");
        const MAX_FEE: Fee = Fee(Felt::from_u64(10_000_000));
        pub const DEPLOYED_CONTRACT_ADDRESS: ContractAddress =
            contract_address!("0x012592426632af714f43ccb05536b6044fc3e897fa55288f658731f93590e7e7");
        pub const UNIVERSAL_DEPLOYER_CLASS_HASH: ClassHash =
            class_hash!("0x06f38fb91ddbf325a0625533576bb6f6eafd9341868a9ec3faa4b01ce6c4f4dc");

        // The input transactions are the same as in v04.
        pub mod input {
            use pathfinder_common::transaction::{
                DataAvailabilityMode,
                ResourceBound,
                ResourceBounds,
            };
            use pathfinder_common::{
                CallParam,
                EntryPoint,
                ResourceAmount,
                ResourcePricePerUnit,
                Tip,
            };

            use super::*;
            use crate::types::request::{
                BroadcastedDeclareTransactionV2,
                BroadcastedInvokeTransaction,
                BroadcastedInvokeTransactionV1,
                BroadcastedInvokeTransactionV3,
                BroadcastedTransaction,
            };

            pub fn declare(account_contract_address: ContractAddress) -> BroadcastedTransaction {
                let contract_class =
                    crate::types::ContractClass::from_definition_bytes(SIERRA_DEFINITION)
                        .unwrap()
                        .as_sierra()
                        .unwrap();

                assert_eq!(contract_class.class_hash().unwrap().hash(), SIERRA_HASH);

                BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(
                    BroadcastedDeclareTransactionV2 {
                        version: TransactionVersion::TWO,
                        max_fee: MAX_FEE,
                        signature: vec![],
                        nonce: transaction_nonce!("0x0"),
                        contract_class,
                        sender_address: account_contract_address,
                        compiled_class_hash: CASM_HASH,
                    },
                ))
            }

            pub fn universal_deployer(
                account_contract_address: ContractAddress,
                universal_deployer_address: ContractAddress,
            ) -> BroadcastedTransaction {
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                    BroadcastedInvokeTransactionV1 {
                        nonce: transaction_nonce!("0x1"),
                        version: TransactionVersion::ONE,
                        max_fee: MAX_FEE,
                        signature: vec![],
                        sender_address: account_contract_address,
                        calldata: vec![
                            // Number of calls
                            call_param!("0x1"),
                            CallParam(*universal_deployer_address.get()),
                            // Entry point selector for the called contract, i.e.
                            // AccountCallArray::selector
                            CallParam(EntryPoint::hashed(b"deployContract").0),
                            // Length of the call data for the called contract, i.e.
                            // AccountCallArray::data_len
                            call_param!("4"),
                            // classHash
                            CallParam(SIERRA_HASH.0),
                            // salt
                            call_param!("0x0"),
                            // unique
                            call_param!("0x0"),
                            // calldata_len
                            call_param!("0x0"),
                        ],
                    },
                ))
            }

            pub fn invoke(account_contract_address: ContractAddress) -> BroadcastedTransaction {
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                    BroadcastedInvokeTransactionV1 {
                        nonce: transaction_nonce!("0x2"),
                        version: TransactionVersion::ONE,
                        max_fee: MAX_FEE,
                        signature: vec![],
                        sender_address: account_contract_address,
                        calldata: vec![
                            // Number of calls
                            call_param!("0x1"),
                            CallParam(*DEPLOYED_CONTRACT_ADDRESS.get()),
                            // Entry point selector for the called contract, i.e.
                            // AccountCallArray::selector
                            CallParam(EntryPoint::hashed(b"get_data").0),
                            // Length of the call data for the called contract, i.e.
                            // AccountCallArray::data_len
                            call_param!("0"),
                        ],
                    },
                ))
            }

            pub fn invoke_v3(account_contract_address: ContractAddress) -> BroadcastedTransaction {
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V3(
                    BroadcastedInvokeTransactionV3 {
                        version: TransactionVersion::THREE,
                        signature: vec![],
                        nonce: transaction_nonce!("0x3"),
                        resource_bounds: ResourceBounds {
                            l1_gas: ResourceBound {
                                max_amount: ResourceAmount(10000),
                                max_price_per_unit: ResourcePricePerUnit(100000000),
                            },
                            l2_gas: ResourceBound {
                                max_amount: ResourceAmount(10000),
                                max_price_per_unit: ResourcePricePerUnit(100000000),
                            },
                            l1_data_gas: None,
                        },
                        tip: Tip(0),
                        paymaster_data: vec![],
                        account_deployment_data: vec![],
                        nonce_data_availability_mode: DataAvailabilityMode::L1,
                        fee_data_availability_mode: DataAvailabilityMode::L1,
                        sender_address: account_contract_address,
                        calldata: vec![
                            // Number of calls
                            call_param!("0x1"),
                            CallParam(*DEPLOYED_CONTRACT_ADDRESS.get()),
                            // Entry point selector for the called contract, i.e.
                            // AccountCallArray::selector
                            CallParam(EntryPoint::hashed(b"get_data").0),
                            // Length of the call data for the called contract, i.e.
                            // AccountCallArray::data_len
                            call_param!("0"),
                        ],
                    },
                ))
            }

            pub fn invoke_v3_with_data_gas_bound(
                account_contract_address: ContractAddress,
            ) -> BroadcastedTransaction {
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V3(
                    BroadcastedInvokeTransactionV3 {
                        version: TransactionVersion::THREE,
                        signature: vec![],
                        nonce: transaction_nonce!("0x2"),
                        resource_bounds: ResourceBounds {
                            l1_gas: ResourceBound {
                                max_amount: ResourceAmount(10000),
                                max_price_per_unit: ResourcePricePerUnit(100000000),
                            },
                            l2_gas: ResourceBound {
                                max_amount: ResourceAmount(10000000),
                                max_price_per_unit: ResourcePricePerUnit(100000000),
                            },
                            l1_data_gas: Some(ResourceBound {
                                max_amount: ResourceAmount(10000),
                                max_price_per_unit: ResourcePricePerUnit(100000000),
                            }),
                        },
                        tip: Tip(0),
                        paymaster_data: vec![],
                        account_deployment_data: vec![],
                        nonce_data_availability_mode: DataAvailabilityMode::L1,
                        fee_data_availability_mode: DataAvailabilityMode::L1,
                        sender_address: account_contract_address,
                        calldata: vec![
                            // Number of calls
                            call_param!("0x1"),
                            CallParam(*DEPLOYED_CONTRACT_ADDRESS.get()),
                            // Entry point selector for the called contract, i.e.
                            // AccountCallArray::selector
                            CallParam(EntryPoint::hashed(b"get_data").0),
                            // Length of the call data for the called contract, i.e.
                            // AccountCallArray::data_len
                            call_param!("0"),
                        ],
                    },
                ))
            }
        }

        pub mod expected_output_0_13_1_1 {

            use pathfinder_common::{BlockHeader, ContractAddress, SierraHash, StorageValue};

            use super::*;
            use crate::method::get_state_update::types::{StorageDiff, StorageEntry};

            const DECLARE_OVERALL_FEE: u64 = 1262;
            const DECLARE_GAS_CONSUMED: u64 = 878;
            const DECLARE_DATA_GAS_CONSUMED: u64 = 192;

            pub fn declare(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
            ) -> pathfinder_executor::types::TransactionSimulation {
                pathfinder_executor::types::TransactionSimulation {
                    fee_estimation: pathfinder_executor::types::FeeEstimate {
                        l1_gas_consumed: DECLARE_GAS_CONSUMED.into(),
                        l1_gas_price: 1.into(),
                        l1_data_gas_consumed: DECLARE_DATA_GAS_CONSUMED.into(),
                        l1_data_gas_price: 2.into(),
                        l2_gas_consumed: 0.into(),
                        l2_gas_price: 1.into(),
                        overall_fee: DECLARE_OVERALL_FEE.into(),
                        unit: pathfinder_executor::types::PriceUnit::Wei,
                    },
                    trace: pathfinder_executor::types::TransactionTrace::Declare(
                        pathfinder_executor::types::DeclareTransactionTrace {
                            fee_transfer_invocation: Some(declare_fee_transfer(
                                account_contract_address,
                                last_block_header,
                            )),
                            validate_invocation: Some(declare_validate(account_contract_address)),
                            state_diff: declare_state_diff(
                                account_contract_address,
                                declare_fee_transfer_storage_diffs(),
                            ),
                            execution_resources: pathfinder_executor::types::ExecutionResources {
                                computation_resources: declare_validate_computation_resources()
                                    + declare_fee_transfer_computation_resources(),
                                data_availability:
                                    pathfinder_executor::types::DataAvailabilityResources {
                                        l1_gas: 0,
                                        l1_data_gas: 192,
                                    },
                                l1_gas: 878,
                                l1_data_gas: 192,
                                l2_gas: 0,
                            },
                        },
                    ),
                }
            }

            fn declare_validate_computation_resources(
            ) -> pathfinder_executor::types::ComputationResources {
                pathfinder_executor::types::ComputationResources {
                    memory_holes: 1,
                    range_check_builtin_applications: 4,
                    steps: 203,
                    ..Default::default()
                }
            }

            fn declare_fee_transfer_computation_resources(
            ) -> pathfinder_executor::types::ComputationResources {
                pathfinder_executor::types::ComputationResources {
                    steps: 1354,
                    memory_holes: 59,
                    range_check_builtin_applications: 31,
                    pedersen_builtin_applications: 4,
                    ..Default::default()
                }
            }

            fn declare_state_diff(
                account_contract_address: ContractAddress,
                storage_diffs: Vec<StorageDiff>,
            ) -> pathfinder_executor::types::StateDiff {
                pathfinder_executor::types::StateDiff {
                    storage_diffs: BTreeMap::from_iter(
                        storage_diffs
                            .into_iter()
                            .map(|diff| {
                                (
                                    diff.address,
                                    diff.storage_entries
                                        .into_iter()
                                        .map(|entry| pathfinder_executor::types::StorageDiff {
                                            key: entry.key,
                                            value: entry.value,
                                        })
                                        .collect(),
                                )
                            })
                            .collect::<Vec<_>>(),
                    ),
                    deprecated_declared_classes: HashSet::new(),
                    declared_classes: vec![pathfinder_executor::types::DeclaredSierraClass {
                        class_hash: SierraHash(SIERRA_HASH.0),
                        compiled_class_hash: CASM_HASH,
                    }],
                    deployed_contracts: vec![],
                    replaced_classes: vec![],
                    nonces: BTreeMap::from([(account_contract_address, contract_nonce!("0x1"))]),
                }
            }

            fn declare_fee_transfer_storage_diffs() -> Vec<StorageDiff> {
                vec![StorageDiff {
                    address: ETH_FEE_TOKEN_ADDRESS,
                    storage_entries: vec![
                        StorageEntry {
                            key: storage_address!("0x032a4edd4e4cffa71ee6d0971c54ac9e62009526cd78af7404aa968c3dc3408e"),
                            value: storage_value!("0x000000000000000000000000000000000000fffffffffffffffffffffffffb12")
                        },
                        StorageEntry {
                            key: storage_address!("0x05496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"),
                            value: StorageValue(DECLARE_OVERALL_FEE.into()),
                        },
                    ],
                }]
            }

            fn declare_fee_transfer(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
            ) -> pathfinder_executor::types::FunctionInvocation {
                pathfinder_executor::types::FunctionInvocation {
                    call_type: pathfinder_executor::types::CallType::Call,
                    caller_address: *account_contract_address.get(),
                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                    entry_point_type: pathfinder_executor::types::EntryPointType::External,
                    events: vec![pathfinder_executor::types::Event {
                        order: 0,
                        data: vec![
                            *account_contract_address.get(),
                            last_block_header.sequencer_address.0,
                            Felt::from_u64(DECLARE_OVERALL_FEE),
                            felt!("0x0"),
                        ],
                        keys: vec![felt!(
                            "0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"
                        )],
                    }],
                    calldata: vec![
                        last_block_header.sequencer_address.0,
                        Felt::from_u64(DECLARE_OVERALL_FEE),
                        felt!("0x0"),
                    ],
                    contract_address: ETH_FEE_TOKEN_ADDRESS,
                    selector: EntryPoint::hashed(b"transfer").0,
                    internal_calls: vec![],
                    messages: vec![],
                    result: vec![felt!("0x1")],
                    computation_resources: declare_fee_transfer_computation_resources(),
                    execution_resources: pathfinder_executor::types::InnerCallExecutionResources {
                        l1_gas: 4,
                        l2_gas: 0,
                    },
                    is_reverted: false,
                }
            }

            fn declare_validate(
                account_contract_address: ContractAddress,
            ) -> pathfinder_executor::types::FunctionInvocation {
                pathfinder_executor::types::FunctionInvocation {
                    call_type: pathfinder_executor::types::CallType::Call,
                    caller_address: felt!("0x0"),
                    class_hash: Some(crate::test_setup::OPENZEPPELIN_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: pathfinder_executor::types::EntryPointType::External,
                    events: vec![],
                    contract_address: account_contract_address,
                    selector: EntryPoint::hashed(b"__validate_declare__").0,
                    calldata: vec![SIERRA_HASH.0],
                    internal_calls: vec![],
                    messages: vec![],
                    result: vec![felt!("0x56414c4944")],
                    computation_resources: declare_validate_computation_resources(),
                    execution_resources: pathfinder_executor::types::InnerCallExecutionResources {
                        l1_gas: 1,
                        l2_gas: 0,
                    },
                    is_reverted: false,
                }
            }

            const UNIVERSAL_DEPLOYER_OVERALL_FEE: u64 = 467;
            const UNIVERSAL_DEPLOYER_GAS_CONSUMED: u64 = 19;
            const UNIVERSAL_DEPLOYER_DATA_GAS_CONSUMED: u64 = 224;

            pub fn universal_deployer(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
                universal_deployer_address: ContractAddress,
            ) -> pathfinder_executor::types::TransactionSimulation {
                pathfinder_executor::types::TransactionSimulation {
                    fee_estimation: pathfinder_executor::types::FeeEstimate {
                        l1_gas_consumed: UNIVERSAL_DEPLOYER_GAS_CONSUMED.into(),
                        l1_gas_price: 1.into(),
                        l1_data_gas_consumed: UNIVERSAL_DEPLOYER_DATA_GAS_CONSUMED.into(),
                        l1_data_gas_price: 2.into(),
                        l2_gas_consumed: 0.into(),
                        l2_gas_price: 1.into(),
                        overall_fee: UNIVERSAL_DEPLOYER_OVERALL_FEE.into(),
                        unit: pathfinder_executor::types::PriceUnit::Wei,
                    },
                    trace: pathfinder_executor::types::TransactionTrace::Invoke(
                        pathfinder_executor::types::InvokeTransactionTrace {
                            validate_invocation: Some(universal_deployer_validate(
                                account_contract_address,
                                universal_deployer_address,
                            )),
                            execute_invocation:
                                pathfinder_executor::types::ExecuteInvocation::FunctionInvocation(
                                    Some(universal_deployer_execute(
                                        account_contract_address,
                                        universal_deployer_address,
                                    )),
                                ),
                            fee_transfer_invocation: Some(universal_deployer_fee_transfer(
                                account_contract_address,
                                last_block_header,
                                0,
                            )),
                            state_diff: universal_deployer_state_diff(
                                account_contract_address,
                                universal_deployer_fee_transfer_storage_diffs(0),
                            ),
                            execution_resources: pathfinder_executor::types::ExecutionResources {
                                computation_resources:
                                    universal_deployer_validate_computation_resources()
                                        + universal_deployer_execute_computation_resources()
                                        + universal_deployer_fee_transfer_computation_resources(),
                                data_availability:
                                    pathfinder_executor::types::DataAvailabilityResources {
                                        l1_gas: 0,
                                        l1_data_gas: 224,
                                    },
                                l1_gas: 19,
                                l1_data_gas: 224,
                                l2_gas: 0,
                            },
                        },
                    ),
                }
            }

            fn universal_deployer_validate_computation_resources(
            ) -> pathfinder_executor::types::ComputationResources {
                pathfinder_executor::types::ComputationResources {
                    memory_holes: 4,
                    range_check_builtin_applications: 14,
                    steps: 341,
                    ..Default::default()
                }
            }

            fn universal_deployer_execute_computation_resources(
            ) -> pathfinder_executor::types::ComputationResources {
                pathfinder_executor::types::ComputationResources {
                    steps: 2574,
                    memory_holes: 20,
                    range_check_builtin_applications: 66,
                    pedersen_builtin_applications: 7,
                    ..Default::default()
                }
            }

            fn universal_deployer_fee_transfer_computation_resources(
            ) -> pathfinder_executor::types::ComputationResources {
                pathfinder_executor::types::ComputationResources {
                    steps: 1354,
                    memory_holes: 59,
                    range_check_builtin_applications: 31,
                    pedersen_builtin_applications: 4,
                    ..Default::default()
                }
            }

            fn universal_deployer_state_diff(
                account_contract_address: ContractAddress,
                storage_diffs: Vec<StorageDiff>,
            ) -> pathfinder_executor::types::StateDiff {
                pathfinder_executor::types::StateDiff {
                    storage_diffs: BTreeMap::from_iter(
                        storage_diffs
                            .into_iter()
                            .map(|diff| {
                                (
                                    diff.address,
                                    diff.storage_entries
                                        .into_iter()
                                        .map(|entry| pathfinder_executor::types::StorageDiff {
                                            key: entry.key,
                                            value: entry.value,
                                        })
                                        .collect(),
                                )
                            })
                            .collect::<Vec<_>>(),
                    ),
                    deprecated_declared_classes: HashSet::new(),
                    declared_classes: vec![],
                    deployed_contracts: vec![pathfinder_executor::types::DeployedContract {
                        address: DEPLOYED_CONTRACT_ADDRESS,
                        class_hash: SIERRA_HASH,
                    }],
                    replaced_classes: vec![],
                    nonces: BTreeMap::from([(account_contract_address, contract_nonce!("0x2"))]),
                }
            }

            fn universal_deployer_fee_transfer_storage_diffs(
                overall_fee_correction: u64,
            ) -> Vec<StorageDiff> {
                vec![StorageDiff {
                    address: ETH_FEE_TOKEN_ADDRESS,
                    storage_entries: vec![
                        StorageEntry {
                            key: storage_address!("0x032a4edd4e4cffa71ee6d0971c54ac9e62009526cd78af7404aa968c3dc3408e"),
                            value: StorageValue((0xfffffffffffffffffffffffff93fu128 + u128::from(overall_fee_correction)).into()),
                        },
                        StorageEntry {
                            key: storage_address!("0x05496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"),
                            value: StorageValue((DECLARE_OVERALL_FEE + UNIVERSAL_DEPLOYER_OVERALL_FEE - overall_fee_correction).into()),
                        },
                    ],
                }]
            }

            fn universal_deployer_validate(
                account_contract_address: ContractAddress,
                universal_deployer_address: ContractAddress,
            ) -> pathfinder_executor::types::FunctionInvocation {
                pathfinder_executor::types::FunctionInvocation {
                    call_type: pathfinder_executor::types::CallType::Call,
                    caller_address: felt!("0x0"),
                    class_hash: Some(crate::test_setup::OPENZEPPELIN_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: pathfinder_executor::types::EntryPointType::External,
                    internal_calls: vec![],
                    events: vec![],
                    contract_address: account_contract_address,
                    selector: EntryPoint::hashed(b"__validate__").0,
                    calldata: vec![
                        call_param!("0x1").0,
                        universal_deployer_address.0,
                        EntryPoint::hashed(b"deployContract").0,
                        // calldata_len
                        call_param!("0x4").0,
                        // classHash
                        SIERRA_HASH.0,
                        // salt
                        call_param!("0x0").0,
                        // unique
                        call_param!("0x0").0,
                        // calldata_len
                        call_param!("0x0").0,
                    ],
                    messages: vec![],
                    result: vec![felt!("0x56414c4944")],
                    computation_resources: universal_deployer_validate_computation_resources(),
                    execution_resources: pathfinder_executor::types::InnerCallExecutionResources {
                        l1_gas: 1,
                        l2_gas: 0,
                    },
                    is_reverted: false,
                }
            }

            fn universal_deployer_execute(
                account_contract_address: ContractAddress,
                universal_deployer_address: ContractAddress,
            ) -> pathfinder_executor::types::FunctionInvocation {
                pathfinder_executor::types::FunctionInvocation {
                    call_type: pathfinder_executor::types::CallType::Call,
                    caller_address: felt!("0x0"),
                    internal_calls: vec![
                        pathfinder_executor::types::FunctionInvocation {
                            call_type: pathfinder_executor::types::CallType::Call,
                            caller_address: *account_contract_address.get(),
                            internal_calls: vec![
                                pathfinder_executor::types::FunctionInvocation {
                                    call_type: pathfinder_executor::types::CallType::Call,
                                    caller_address: *universal_deployer_address.get(),
                                    internal_calls: vec![],
                                    class_hash: Some(SIERRA_HASH.0),
                                    entry_point_type: pathfinder_executor::types::EntryPointType::Constructor,
                                    events: vec![],
                                    contract_address: DEPLOYED_CONTRACT_ADDRESS,
                                    selector: EntryPoint::hashed(b"constructor").0,
                                    calldata: vec![],
                                    messages: vec![],
                                    result: vec![],
                                    computation_resources: pathfinder_executor::types::ComputationResources::default(),
                                    execution_resources: pathfinder_executor::types::InnerCallExecutionResources::default(),
                                    is_reverted: false,
                                },
                            ],
                            class_hash: Some(UNIVERSAL_DEPLOYER_CLASS_HASH.0),
                            entry_point_type: pathfinder_executor::types::EntryPointType::External,
                            events: vec![
                                pathfinder_executor::types::Event {
                                    order: 0,
                                    data: vec![
                                        *DEPLOYED_CONTRACT_ADDRESS.get(),
                                        *account_contract_address.get(),
                                        felt!("0x0"),
                                        SIERRA_HASH.0,
                                        felt!("0x0"),
                                        felt!("0x0"),
                                    ],
                                    keys: vec![
                                        felt!("0x026B160F10156DEA0639BEC90696772C640B9706A47F5B8C52EA1ABE5858B34D"),
                                    ]
                                },
                            ],
                            contract_address: universal_deployer_address,
                            selector: EntryPoint::hashed(b"deployContract").0,
                            calldata: vec![
                                // classHash
                                SIERRA_HASH.0,
                                // salt
                                call_param!("0x0").0,
                                // unique
                                call_param!("0x0").0,
                                //  calldata_len
                                call_param!("0x0").0,
                            ],
                            messages: vec![],
                            result: vec![
                                *DEPLOYED_CONTRACT_ADDRESS.get(),
                            ],
                            computation_resources: pathfinder_executor::types::ComputationResources {
                                steps: 1262,
                                memory_holes: 2,
                                range_check_builtin_applications: 23,
                                pedersen_builtin_applications: 7,
                                ..Default::default()
                            },
                            execution_resources: pathfinder_executor::types::InnerCallExecutionResources { l1_gas: 5, l2_gas: 0 },
                            is_reverted: false,
                        }
                    ],
                    class_hash: Some(crate::test_setup::OPENZEPPELIN_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: pathfinder_executor::types::EntryPointType::External,
                    events: vec![],
                    contract_address: account_contract_address,
                    selector: EntryPoint::hashed(b"__execute__").0,
                    calldata: vec![
                        call_param!("0x1").0,
                        universal_deployer_address.0,
                        EntryPoint::hashed(b"deployContract").0,
                        call_param!("0x4").0,
                        // classHash
                        SIERRA_HASH.0,
                        // salt
                        call_param!("0x0").0,
                        // unique
                        call_param!("0x0").0,
                        // calldata_len
                        call_param!("0x0").0,
                    ],
                    messages: vec![],
                    result: vec![
                        felt!("0x1"),
                        felt!("0x1"),
                        *DEPLOYED_CONTRACT_ADDRESS.get(),
                    ],
                    computation_resources: universal_deployer_execute_computation_resources(),
                    execution_resources: pathfinder_executor::types::InnerCallExecutionResources {
                        l1_gas: 8,
                        l2_gas: 0,
                    },
                    is_reverted: false,
                }
            }

            fn universal_deployer_fee_transfer(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
                overall_fee_correction: u64,
            ) -> pathfinder_executor::types::FunctionInvocation {
                pathfinder_executor::types::FunctionInvocation {
                    call_type: pathfinder_executor::types::CallType::Call,
                    caller_address: *account_contract_address.get(),
                    internal_calls: vec![],
                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                    entry_point_type: pathfinder_executor::types::EntryPointType::External,
                    events: vec![pathfinder_executor::types::Event {
                        order: 0,
                        data: vec![
                            *account_contract_address.get(),
                            last_block_header.sequencer_address.0,
                            (UNIVERSAL_DEPLOYER_OVERALL_FEE - overall_fee_correction).into(),
                            felt!("0x0"),
                        ],
                        keys: vec![felt!(
                            "0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"
                        )],
                    }],
                    calldata: vec![
                        last_block_header.sequencer_address.0,
                        (UNIVERSAL_DEPLOYER_OVERALL_FEE - overall_fee_correction).into(),
                        // calldata_len
                        call_param!("0x0").0,
                    ],
                    contract_address: ETH_FEE_TOKEN_ADDRESS,
                    selector: EntryPoint::hashed(b"transfer").0,
                    messages: vec![],
                    result: vec![felt!("0x1")],
                    computation_resources: universal_deployer_fee_transfer_computation_resources(),
                    execution_resources: pathfinder_executor::types::InnerCallExecutionResources {
                        l1_gas: 4,
                        l2_gas: 0,
                    },
                    is_reverted: false,
                }
            }

            const INVOKE_OVERALL_FEE: u64 = 270;
            const INVOKE_GAS_CONSUMED: u64 = 14;
            const INVOKE_DATA_GAS_CONSUMED: u64 = 128;

            pub fn invoke(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
                test_storage_value: StorageValue,
            ) -> pathfinder_executor::types::TransactionSimulation {
                pathfinder_executor::types::TransactionSimulation {
                    fee_estimation: pathfinder_executor::types::FeeEstimate {
                        l1_gas_consumed: INVOKE_GAS_CONSUMED.into(),
                        l1_gas_price: 1.into(),
                        l1_data_gas_consumed: INVOKE_DATA_GAS_CONSUMED.into(),
                        l1_data_gas_price: 2.into(),
                        l2_gas_consumed: 0.into(),
                        l2_gas_price: 1.into(),
                        overall_fee: INVOKE_OVERALL_FEE.into(),
                        unit: pathfinder_executor::types::PriceUnit::Wei,
                    },
                    trace: pathfinder_executor::types::TransactionTrace::Invoke(
                        pathfinder_executor::types::InvokeTransactionTrace {
                            validate_invocation: Some(invoke_validate(account_contract_address)),
                            execute_invocation:
                                pathfinder_executor::types::ExecuteInvocation::FunctionInvocation(
                                    Some(invoke_execute(
                                        account_contract_address,
                                        test_storage_value,
                                    )),
                                ),
                            fee_transfer_invocation: Some(invoke_fee_transfer(
                                account_contract_address,
                                last_block_header,
                                0,
                            )),
                            state_diff: invoke_state_diff(
                                account_contract_address,
                                invoke_fee_transfer_storage_diffs(0),
                            ),
                            execution_resources: pathfinder_executor::types::ExecutionResources {
                                computation_resources: invoke_validate_computation_resources()
                                    + invoke_execute_computation_resources()
                                    + invoke_fee_transfer_computation_resources(),
                                data_availability:
                                    pathfinder_executor::types::DataAvailabilityResources {
                                        l1_gas: 0,
                                        l1_data_gas: 128,
                                    },
                                l1_gas: 14,
                                l1_data_gas: 128,
                                l2_gas: 0,
                            },
                        },
                    ),
                }
            }

            fn invoke_validate_computation_resources(
            ) -> pathfinder_executor::types::ComputationResources {
                pathfinder_executor::types::ComputationResources {
                    steps: 341,
                    range_check_builtin_applications: 14,
                    memory_holes: 4,
                    ..Default::default()
                }
            }

            fn invoke_execute_computation_resources(
            ) -> pathfinder_executor::types::ComputationResources {
                pathfinder_executor::types::ComputationResources {
                    steps: 1477,
                    range_check_builtin_applications: 46,
                    memory_holes: 18,
                    ..Default::default()
                }
            }

            fn invoke_fee_transfer_computation_resources(
            ) -> pathfinder_executor::types::ComputationResources {
                pathfinder_executor::types::ComputationResources {
                    steps: 1354,
                    memory_holes: 59,
                    range_check_builtin_applications: 31,
                    pedersen_builtin_applications: 4,
                    ..Default::default()
                }
            }

            fn invoke_state_diff(
                account_contract_address: ContractAddress,
                storage_diffs: Vec<StorageDiff>,
            ) -> pathfinder_executor::types::StateDiff {
                pathfinder_executor::types::StateDiff {
                    storage_diffs: BTreeMap::from_iter(
                        storage_diffs
                            .into_iter()
                            .map(|diff| {
                                (
                                    diff.address,
                                    diff.storage_entries
                                        .into_iter()
                                        .map(|entry| pathfinder_executor::types::StorageDiff {
                                            key: entry.key,
                                            value: entry.value,
                                        })
                                        .collect(),
                                )
                            })
                            .collect::<Vec<_>>(),
                    ),
                    deprecated_declared_classes: HashSet::new(),
                    declared_classes: vec![],
                    deployed_contracts: vec![],
                    replaced_classes: vec![],
                    nonces: BTreeMap::from([(account_contract_address, contract_nonce!("0x3"))]),
                }
            }

            fn invoke_fee_transfer_storage_diffs(overall_fee_correction: u64) -> Vec<StorageDiff> {
                vec![StorageDiff {
                    address: ETH_FEE_TOKEN_ADDRESS,
                    storage_entries: vec![
                        StorageEntry {
                            key: storage_address!("0x032a4edd4e4cffa71ee6d0971c54ac9e62009526cd78af7404aa968c3dc3408e"),
                            value: StorageValue((0xfffffffffffffffffffffffff831u128 + u128::from(2 * overall_fee_correction)).into()),
                        },
                        StorageEntry {
                            key: storage_address!("0x05496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"),
                            value: StorageValue((DECLARE_OVERALL_FEE + UNIVERSAL_DEPLOYER_OVERALL_FEE + INVOKE_OVERALL_FEE - 2 * overall_fee_correction).into()),
                        },
                    ],
                }]
            }

            fn invoke_validate(
                account_contract_address: ContractAddress,
            ) -> pathfinder_executor::types::FunctionInvocation {
                pathfinder_executor::types::FunctionInvocation {
                    call_type: pathfinder_executor::types::CallType::Call,
                    caller_address: felt!("0x0"),
                    class_hash: Some(crate::test_setup::OPENZEPPELIN_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: pathfinder_executor::types::EntryPointType::External,
                    internal_calls: vec![],
                    events: vec![],
                    contract_address: account_contract_address,
                    selector: EntryPoint::hashed(b"__validate__").0,
                    calldata: vec![
                        call_param!("0x1").0,
                        DEPLOYED_CONTRACT_ADDRESS.0,
                        EntryPoint::hashed(b"get_data").0,
                        // calldata_len
                        call_param!("0x0").0,
                    ],
                    messages: vec![],
                    result: vec![felt!("0x56414c4944")],
                    execution_resources: pathfinder_executor::types::InnerCallExecutionResources {
                        l1_gas: 1,
                        l2_gas: 0,
                    },
                    computation_resources: invoke_validate_computation_resources(),
                    is_reverted: false,
                }
            }

            fn invoke_execute(
                account_contract_address: ContractAddress,
                test_storage_value: StorageValue,
            ) -> pathfinder_executor::types::FunctionInvocation {
                pathfinder_executor::types::FunctionInvocation {
                    call_type: pathfinder_executor::types::CallType::Call,
                    caller_address: felt!("0x0"),
                    internal_calls: vec![pathfinder_executor::types::FunctionInvocation {
                        call_type: pathfinder_executor::types::CallType::Call,
                        caller_address: *account_contract_address.get(),
                        class_hash: Some(SIERRA_HASH.0),
                        entry_point_type: pathfinder_executor::types::EntryPointType::External,
                        events: vec![],
                        internal_calls: vec![],
                        contract_address: DEPLOYED_CONTRACT_ADDRESS,
                        selector: EntryPoint::hashed(b"get_data").0,
                        calldata: vec![],
                        messages: vec![],
                        result: vec![test_storage_value.0],
                        computation_resources: pathfinder_executor::types::ComputationResources {
                            steps: 165,
                            range_check_builtin_applications: 3,
                            ..Default::default()
                        },
                        execution_resources:
                            pathfinder_executor::types::InnerCallExecutionResources {
                                l1_gas: 1,
                                l2_gas: 0,
                            },
                        is_reverted: false,
                    }],
                    class_hash: Some(crate::test_setup::OPENZEPPELIN_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: pathfinder_executor::types::EntryPointType::External,
                    events: vec![],
                    contract_address: account_contract_address,
                    selector: EntryPoint::hashed(b"__execute__").0,
                    calldata: vec![
                        call_param!("0x1").0,
                        DEPLOYED_CONTRACT_ADDRESS.0,
                        EntryPoint::hashed(b"get_data").0,
                        // calldata_len
                        call_param!("0x0").0,
                    ],
                    messages: vec![],
                    result: vec![felt!("0x1"), felt!("0x1"), test_storage_value.0],
                    computation_resources: invoke_execute_computation_resources(),
                    execution_resources: pathfinder_executor::types::InnerCallExecutionResources {
                        l1_gas: 4,
                        l2_gas: 0,
                    },
                    is_reverted: false,
                }
            }

            fn invoke_fee_transfer(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
                overall_fee_correction: u64,
            ) -> pathfinder_executor::types::FunctionInvocation {
                pathfinder_executor::types::FunctionInvocation {
                    call_type: pathfinder_executor::types::CallType::Call,
                    caller_address: *account_contract_address.get(),
                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                    entry_point_type: pathfinder_executor::types::EntryPointType::External,
                    internal_calls: vec![],
                    events: vec![pathfinder_executor::types::Event {
                        order: 0,
                        data: vec![
                            *account_contract_address.get(),
                            last_block_header.sequencer_address.0,
                            Felt::from_u64(INVOKE_OVERALL_FEE - overall_fee_correction),
                            felt!("0x0"),
                        ],
                        keys: vec![felt!(
                            "0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"
                        )],
                    }],
                    calldata: vec![
                        last_block_header.sequencer_address.0,
                        Felt::from_u64(INVOKE_OVERALL_FEE - overall_fee_correction),
                        call_param!("0x0").0,
                    ],
                    contract_address: ETH_FEE_TOKEN_ADDRESS,
                    selector: EntryPoint::hashed(b"transfer").0,
                    messages: vec![],
                    result: vec![felt!("0x1")],
                    computation_resources: invoke_fee_transfer_computation_resources(),
                    execution_resources: pathfinder_executor::types::InnerCallExecutionResources {
                        l1_gas: 4,
                        l2_gas: 0,
                    },
                    is_reverted: false,
                }
            }
        }
    }

    #[rstest::rstest]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[test_log::test(tokio::test)]
    async fn declare_deploy_and_invoke_sierra_class(#[case] version: RpcVersion) {
        let (storage, last_block_header, account_contract_address, universal_deployer_address, _) =
            setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 1)).await;
        let context = RpcContext::for_tests().with_storage(storage);

        let input = SimulateTransactionInput {
            transactions: vec![
                fixtures::input::declare(account_contract_address),
                fixtures::input::universal_deployer(
                    account_contract_address,
                    universal_deployer_address,
                ),
                fixtures::input::invoke(account_contract_address),
                fixtures::input::invoke_v3(account_contract_address),
            ],
            block_id: BlockId::Number(last_block_header.number),
            simulation_flags: crate::dto::SimulationFlags(vec![]),
        };
        let result = simulate_transactions(context, input).await.unwrap();

        let serializer = crate::dto::Serializer { version };
        let result_serializable = result.0.into_iter().collect::<Vec<_>>();
        let result_serialized = serializer
            .serialize_iter(
                result_serializable.len(),
                &mut result_serializable.into_iter(),
            )
            .unwrap();

        crate::assert_json_matches_fixture!(
            result_serialized,
            version,
            "simulations/declare_deploy_and_invoke_sierra_class.json"
        );
    }

    #[rstest::rstest]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[test_log::test(tokio::test)]
    async fn declare_deploy_and_invoke_sierra_class_with_skip_fee_charge(
        #[case] version: RpcVersion,
    ) {
        let (storage, last_block_header, account_contract_address, universal_deployer_address, _) =
            setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 1)).await;
        let context = RpcContext::for_tests().with_storage(storage);

        let input = SimulateTransactionInput {
            transactions: vec![
                fixtures::input::declare(account_contract_address),
                fixtures::input::universal_deployer(
                    account_contract_address,
                    universal_deployer_address,
                ),
                fixtures::input::invoke(account_contract_address),
                fixtures::input::invoke_v3(account_contract_address),
            ],
            block_id: BlockId::Number(last_block_header.number),
            simulation_flags: crate::dto::SimulationFlags(vec![
                crate::dto::SimulationFlag::SkipFeeCharge,
            ]),
        };
        let result = simulate_transactions(context, input).await.unwrap();

        let serializer = crate::dto::Serializer { version };
        let result_serializable = result.0.into_iter().collect::<Vec<_>>();
        let result_serialized = serializer
            .serialize_iter(
                result_serializable.len(),
                &mut result_serializable.into_iter(),
            )
            .unwrap();

        crate::assert_json_matches_fixture!(
            result_serialized,
            version,
            "simulations/declare_deploy_and_invoke_sierra_class_with_skip_fee_charge.json"
        );
    }

    #[rstest::rstest]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[test_log::test(tokio::test)]
    async fn declare_deploy_and_invoke_sierra_class_with_skip_validate(
        #[case] version: RpcVersion,
    ) {
        let (storage, last_block_header, account_contract_address, universal_deployer_address, _) =
            setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 1)).await;
        let context = RpcContext::for_tests().with_storage(storage);

        let input = SimulateTransactionInput {
            transactions: vec![
                fixtures::input::declare(account_contract_address),
                fixtures::input::universal_deployer(
                    account_contract_address,
                    universal_deployer_address,
                ),
                fixtures::input::invoke(account_contract_address),
                fixtures::input::invoke_v3(account_contract_address),
            ],
            block_id: BlockId::Number(last_block_header.number),
            simulation_flags: crate::dto::SimulationFlags(vec![
                crate::dto::SimulationFlag::SkipValidate,
            ]),
        };

        let result = simulate_transactions(context, input).await.unwrap();

        let serializer = crate::dto::Serializer { version };
        let result_serializable = result.0.into_iter().collect::<Vec<_>>();
        let result_serialized = serializer
            .serialize_iter(
                result_serializable.len(),
                &mut result_serializable.into_iter(),
            )
            .unwrap();

        crate::assert_json_matches_fixture!(
            result_serialized,
            version,
            "simulations/declare_deploy_and_invoke_sierra_class_with_skip_validate.json"
        );
    }

    #[test_log::test(tokio::test)]
    async fn declare_deploy_and_invoke_sierra_class_starknet_0_13_4() {
        let (storage, last_block_header, account_contract_address, universal_deployer_address, _) =
            setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 4, 0)).await;
        let context = RpcContext::for_tests().with_storage(storage);

        let input = SimulateTransactionInput {
            transactions: vec![
                fixtures::input::declare(account_contract_address),
                fixtures::input::universal_deployer(
                    account_contract_address,
                    universal_deployer_address,
                ),
                fixtures::input::invoke_v3_with_data_gas_bound(account_contract_address),
            ],
            block_id: BlockId::Number(last_block_header.number),
            simulation_flags: crate::dto::SimulationFlags(vec![]),
        };
        let result = simulate_transactions(context, input).await.unwrap();

        let serializer = crate::dto::Serializer {
            version: RpcVersion::V08,
        };
        let result_serializable = result.0.into_iter().collect::<Vec<_>>();
        let result_serialized = serializer
            .serialize_iter(
                result_serializable.len(),
                &mut result_serializable.into_iter(),
            )
            .unwrap();

        let expected_str = include_str!(
            "../../fixtures/0.8.0/simulations/\
             declare_deploy_and_invoke_sierra_class_starknet_0_13_4.json"
        );
        let expected_json: serde_json::Value =
            serde_json::from_str(expected_str).expect("Failed to parse fixture as JSON");

        pretty_assertions_sorted::assert_eq!(
            result_serialized,
            expected_json,
            "\nExpected fixture content from {}\nGot output",
            "simulations/declare_deploy_and_invoke_sierra_class_starknet_0_13_4.json"
        );
    }
}
