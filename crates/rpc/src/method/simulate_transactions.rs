use anyhow::Context;
use pathfinder_common::BlockId;
use pathfinder_executor::TransactionExecutionError;

use crate::context::RpcContext;
use crate::executor::ExecutionStateError;
use crate::v06::method::simulate_transactions as v06;

pub struct Output(Vec<pathfinder_executor::types::TransactionSimulation>);

pub async fn simulate_transactions(
    context: RpcContext,
    input: v06::SimulateTransactionInput,
) -> Result<Output, SimulateTransactionError> {
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let skip_validate = input
            .simulation_flags
            .0
            .iter()
            .any(|flag| flag == &v06::dto::SimulationFlag::SkipValidate);

        let skip_fee_charge = input
            .simulation_flags
            .0
            .iter()
            .any(|flag| flag == &v06::dto::SimulationFlag::SkipFeeCharge);

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
            context.config.custom_versioned_constants,
        );

        let transactions = input
            .transactions
            .into_iter()
            .map(|tx| crate::executor::map_broadcasted_transaction(&tx, context.chain_id))
            .collect::<Result<Vec<_>, _>>()?;

        let txs =
            pathfinder_executor::simulate(state, transactions, skip_validate, skip_fee_charge)?;
        Ok(Output(txs))
    })
    .await
    .context("Simulating transaction")?
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        serializer.serialize_iter(self.0.len(), &mut self.0.iter().map(TransactionSimulation))
    }
}

struct TransactionSimulation<'a>(&'a pathfinder_executor::types::TransactionSimulation);

impl crate::dto::serialize::SerializeForVersion for TransactionSimulation<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field(
            "fee_estimation",
            &crate::dto::FeeEstimate(&self.0.fee_estimation),
        )?;
        serializer.serialize_field(
            "transaction_trace",
            &crate::dto::TransactionTrace {
                trace: &self.0.trace,
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
            } => Self::TransactionExecutionError {
                transaction_index,
                error,
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
            } => Self::TransactionExecutionError {
                transaction_index,
                error,
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
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{
        felt,
        BlockId,
        CallParam,
        ClassHash,
        EntryPoint,
        StarknetVersion,
        StorageValue,
        TransactionVersion,
    };
    use pathfinder_crypto::Felt;
    use serde::Deserialize;
    use starknet_gateway_test_fixtures::class_definitions::{
        DUMMY_ACCOUNT_CLASS_HASH,
        ERC20_CONTRACT_DEFINITION_CLASS_HASH,
    };

    use super::simulate_transactions;
    use crate::context::RpcContext;
    use crate::dto::serialize::{SerializeForVersion, Serializer};
    use crate::v02::types::request::{
        BroadcastedDeclareTransaction,
        BroadcastedDeclareTransactionV1,
        BroadcastedTransaction,
    };
    use crate::v02::types::ContractClass;
    use crate::v03::method::get_state_update::types::{DeployedContract, Nonce, StateDiff};
    use crate::v06::method::call::FunctionCall;
    use crate::v06::method::simulate_transactions::tests::setup_storage_with_starknet_version;
    use crate::v06::method::simulate_transactions::{dto, SimulateTransactionInput};
    use crate::v06::types::PriceUnit;
    use crate::RpcVersion;

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
                    "class_hash": DUMMY_ACCOUNT_CLASS_HASH,
                    "nonce": "0x0",
                    "version": TransactionVersion::ONE_WITH_QUERY_VERSION,
                    "constructor_calldata": [],
                    "type": "DEPLOY_ACCOUNT"
                }
            ],
            "simulation_flags": ["SKIP_FEE_CHARGE"]
        });
        let input = SimulateTransactionInput::deserialize(&input_json).unwrap();

        let expected: Vec<dto::SimulatedTransaction> = {
            use dto::*;
            let tx =
            SimulatedTransaction {
                fee_estimation:
                    FeeEstimate {
                        gas_consumed: 19.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: Some(160.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: 339.into(),
                        unit: PriceUnit::Wei,
                    }
                ,
                transaction_trace:
                    TransactionTrace::DeployAccount(
                        DeployAccountTxnTrace {
                            constructor_invocation: FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: felt!("0x0"),
                                    calls: vec![],
                                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::Constructor,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        calldata: vec![],
                                        contract_address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        entry_point_selector: entry_point!("0x028FFE4FF0F226A9107253E17A904099AA4F63A02A5621DE0576E5AA71BC5194"),
                                    },
                                    messages: vec![],
                                    result: vec![],
                                    execution_resources: ComputationResources::default(),
                                },
                            validate_invocation: Some(
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: felt!("0x0"),
                                    calls: vec![],
                                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::External,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        calldata: vec![
                                            CallParam(DUMMY_ACCOUNT_CLASS_HASH.0),
                                            call_param!("0x046C0D4ABF0192A788ACA261E58D7031576F7D8EA5229F452B0F23E691DD5971"),
                                        ],
                                        contract_address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        entry_point_selector: entry_point!("0x036FCBF06CD96843058359E1A75928BEACFAC10727DAB22A3972F0AF8AA92895"),
                                    },
                                    messages: vec![],
                                    result: vec![],
                                    execution_resources: ComputationResources {
                                        steps: 13,
                                        ..Default::default()
                                    },
                                },
                            ),
                            fee_transfer_invocation: None,
                            state_diff: Some(StateDiff {
                                storage_diffs: vec![],
                                deprecated_declared_classes: vec![],
                                declared_classes: vec![],
                                deployed_contracts: vec![
                                    DeployedContract {
                                        address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        class_hash: DUMMY_ACCOUNT_CLASS_HASH
                                    }
                                ],
                                replaced_classes: vec![],
                                nonces: vec![
                                    Nonce {
                                        contract_address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        nonce: contract_nonce!("0x1")
                                    }
                                ]
                            }),
                            execution_resources: Some(ExecutionResources {
                                computation_resources: ComputationResources {
                                    steps: 13,
                                    ..Default::default()
                                },
                                data_availability: DataAvailabilityResources { l1_gas: 0, l1_data_gas: 160 }
                            }),
                        },
                    ),
            };
            vec![tx]
        };
        let expected = serde_json::to_value(expected).unwrap();

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

        let contract_class = ContractClass::from_definition_bytes(CAIRO0_DEFINITION)
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
            simulation_flags: dto::SimulationFlags(vec![]),
        };

        let result = simulate_transactions(context, input).await.unwrap();

        const OVERALL_FEE: u64 = 15720;
        use dto::*;

        use crate::v03::method::get_state_update::types::{StorageDiff, StorageEntry};

        pretty_assertions_sorted::assert_eq!(
            result.serialize(Serializer {
                version: RpcVersion::V07,
            }).unwrap(),
            serde_json::to_value(
                vec![SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: 15464.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: Some(128.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: 15720.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Declare(DeclareTxnTrace {
                        fee_transfer_invocation: Some(
                            FunctionInvocation {
                                call_type: CallType::Call,
                                caller_address: *account_contract_address.get(),
                                calls: vec![],
                                class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                                entry_point_type: EntryPointType::External,
                                events: vec![OrderedEvent {
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
                                function_call: FunctionCall {
                                    calldata: vec![
                                        CallParam(last_block_header.sequencer_address.0),
                                        CallParam(Felt::from_u64(OVERALL_FEE)),
                                        call_param!("0x0"),
                                    ],
                                    contract_address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                                    entry_point_selector: EntryPoint::hashed(b"transfer"),
                                },
                                messages: vec![],
                                result: vec![felt!("0x1")],
                                execution_resources: ComputationResources {
                                    steps: 1354,
                                    memory_holes: 59,
                                    range_check_builtin_applications: 31,
                                    pedersen_builtin_applications: 4,
                                    ..Default::default()
                                },
                            }
                        ),
                        validate_invocation: Some(
                            FunctionInvocation {
                                call_type: CallType::Call,
                                caller_address: felt!("0x0"),
                                calls: vec![],
                                class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                entry_point_type: EntryPointType::External,
                                events: vec![],
                                function_call: FunctionCall {
                                    contract_address: account_contract_address,
                                    entry_point_selector: EntryPoint::hashed(b"__validate_declare__"),
                                    calldata: vec![CallParam(CAIRO0_HASH.0)],
                                },
                                messages: vec![],
                                result: vec![],
                                execution_resources: ComputationResources {
                                    steps: 12,
                                    ..Default::default()
                                },
                            }
                        ),
                        state_diff: Some(StateDiff {
                            storage_diffs: vec![StorageDiff {
                                address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                                storage_entries: vec![
                                    StorageEntry {
                                        key: storage_address!("0x032a4edd4e4cffa71ee6d0971c54ac9e62009526cd78af7404aa968c3dc3408e"),
                                        value: storage_value!("0x000000000000000000000000000000000000ffffffffffffffffffffffffc298")
                                    },
                                    StorageEntry {
                                        key: storage_address!("0x05496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"),
                                        value: StorageValue(OVERALL_FEE.into()),
                                    },
                                ],
                            }],
                            deprecated_declared_classes: vec![
                                CAIRO0_HASH
                            ],
                            declared_classes: vec![],
                            deployed_contracts: vec![],
                            replaced_classes: vec![],
                            nonces: vec![Nonce {
                                contract_address: account_contract_address,
                                nonce: contract_nonce!("0x1"),
                            }],
                        }),
                        execution_resources: Some(ExecutionResources {
                            computation_resources: ComputationResources {
                                steps: 1366,
                                memory_holes: 59,
                                range_check_builtin_applications: 31,
                                pedersen_builtin_applications: 4,
                                ..Default::default()
                            },
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 128,
                            }
                        }),
                    }),
                }]
            ).unwrap()
        );
    }

    pub(crate) mod fixtures {
        use super::*;
        pub use crate::v06::method::simulate_transactions::tests::fixtures::{
            CASM_DEFINITION,
            CASM_HASH,
            DEPLOYED_CONTRACT_ADDRESS,
            SIERRA_DEFINITION,
            SIERRA_HASH,
            UNIVERSAL_DEPLOYER_CLASS_HASH,
        };

        // The input transactions are the same as in v06.
        pub mod input {
            pub use crate::v06::method::simulate_transactions::tests::fixtures::input::*;
        }

        pub mod expected_output_0_13_1_1 {
            use pathfinder_common::{BlockHeader, ContractAddress, SierraHash, StorageValue};

            use super::dto::*;
            use super::*;
            use crate::v03::method::get_state_update::types::{
                DeclaredSierraClass,
                StorageDiff,
                StorageEntry,
            };

            const DECLARE_OVERALL_FEE: u64 = 1262;
            const DECLARE_GAS_CONSUMED: u64 = 878;
            const DECLARE_DATA_GAS_CONSUMED: u64 = 192;

            pub fn declare(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: DECLARE_GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: Some(DECLARE_DATA_GAS_CONSUMED.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: DECLARE_OVERALL_FEE.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Declare(DeclareTxnTrace {
                        fee_transfer_invocation: Some(declare_fee_transfer(
                            account_contract_address,
                            last_block_header,
                        )),
                        validate_invocation: Some(declare_validate(account_contract_address)),
                        state_diff: Some(declare_state_diff(
                            account_contract_address,
                            declare_fee_transfer_storage_diffs(),
                        )),
                        execution_resources: Some(ExecutionResources {
                            computation_resources: declare_validate_computation_resources()
                                + declare_fee_transfer_computation_resources(),
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 192,
                            },
                        }),
                    }),
                }
            }

            pub fn declare_without_fee_transfer(
                account_contract_address: ContractAddress,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: DECLARE_GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: Some(DECLARE_DATA_GAS_CONSUMED.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: DECLARE_OVERALL_FEE.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Declare(DeclareTxnTrace {
                        fee_transfer_invocation: None,
                        validate_invocation: Some(declare_validate(account_contract_address)),
                        state_diff: Some(declare_state_diff(account_contract_address, vec![])),
                        execution_resources: Some(ExecutionResources {
                            computation_resources: declare_validate_computation_resources(),
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 192,
                            },
                        }),
                    }),
                }
            }

            pub fn declare_without_validate(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: DECLARE_GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: Some(DECLARE_DATA_GAS_CONSUMED.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: DECLARE_OVERALL_FEE.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Declare(DeclareTxnTrace {
                        fee_transfer_invocation: Some(declare_fee_transfer(
                            account_contract_address,
                            last_block_header,
                        )),
                        validate_invocation: None,
                        state_diff: Some(declare_state_diff(
                            account_contract_address,
                            declare_fee_transfer_storage_diffs(),
                        )),
                        execution_resources: Some(ExecutionResources {
                            computation_resources: declare_fee_transfer_computation_resources(),
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 192,
                            },
                        }),
                    }),
                }
            }

            fn declare_validate_computation_resources() -> ComputationResources {
                ComputationResources {
                    steps: 12,
                    ..Default::default()
                }
            }

            fn declare_fee_transfer_computation_resources() -> ComputationResources {
                ComputationResources {
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
            ) -> StateDiff {
                StateDiff {
                    storage_diffs,
                    deprecated_declared_classes: vec![],
                    declared_classes: vec![DeclaredSierraClass {
                        class_hash: SierraHash(SIERRA_HASH.0),
                        compiled_class_hash: CASM_HASH,
                    }],
                    deployed_contracts: vec![],
                    replaced_classes: vec![],
                    nonces: vec![Nonce {
                        contract_address: account_contract_address,
                        nonce: contract_nonce!("0x1"),
                    }],
                }
            }

            fn declare_fee_transfer_storage_diffs() -> Vec<StorageDiff> {
                vec![StorageDiff {
                    address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
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
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: *account_contract_address.get(),
                    calls: vec![],
                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![OrderedEvent {
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
                    function_call: FunctionCall {
                        calldata: vec![
                            CallParam(last_block_header.sequencer_address.0),
                            CallParam(Felt::from_u64(DECLARE_OVERALL_FEE)),
                            call_param!("0x0"),
                        ],
                        contract_address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                        entry_point_selector: EntryPoint::hashed(b"transfer"),
                    },
                    messages: vec![],
                    result: vec![felt!("0x1")],
                    execution_resources: declare_fee_transfer_computation_resources(),
                }
            }

            fn declare_validate(account_contract_address: ContractAddress) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: felt!("0x0"),
                    calls: vec![],
                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![],
                    function_call: FunctionCall {
                        contract_address: account_contract_address,
                        entry_point_selector: EntryPoint::hashed(b"__validate_declare__"),
                        calldata: vec![CallParam(SIERRA_HASH.0)],
                    },
                    messages: vec![],
                    result: vec![],
                    execution_resources: declare_validate_computation_resources(),
                }
            }

            const UNIVERSAL_DEPLOYER_OVERALL_FEE: u64 = 464;
            const UNIVERSAL_DEPLOYER_GAS_CONSUMED: u64 = 16;
            const UNIVERSAL_DEPLOYER_DATA_GAS_CONSUMED: u64 = 224;

            pub fn universal_deployer(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
                universal_deployer_address: ContractAddress,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: UNIVERSAL_DEPLOYER_GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: Some(UNIVERSAL_DEPLOYER_DATA_GAS_CONSUMED.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: UNIVERSAL_DEPLOYER_OVERALL_FEE.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Invoke(InvokeTxnTrace {
                        validate_invocation: Some(universal_deployer_validate(
                            account_contract_address,
                            universal_deployer_address,
                        )),
                        execute_invocation: ExecuteInvocation::FunctionInvocation(
                            universal_deployer_execute(
                                account_contract_address,
                                universal_deployer_address,
                            ),
                        ),
                        fee_transfer_invocation: Some(universal_deployer_fee_transfer(
                            account_contract_address,
                            last_block_header,
                        )),
                        state_diff: Some(universal_deployer_state_diff(
                            account_contract_address,
                            universal_deployer_fee_transfer_storage_diffs(),
                        )),
                        execution_resources: Some(ExecutionResources {
                            computation_resources: universal_deployer_validate_computation_resources(
                            )
                                + universal_deployer_execute_computation_resources()
                                + universal_deployer_fee_transfer_computation_resources(),
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 224,
                            },
                        }),
                    }),
                }
            }

            pub fn universal_deployer_without_fee_transfer(
                account_contract_address: ContractAddress,
                universal_deployer_address: ContractAddress,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: UNIVERSAL_DEPLOYER_GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: Some(UNIVERSAL_DEPLOYER_DATA_GAS_CONSUMED.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: UNIVERSAL_DEPLOYER_OVERALL_FEE.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Invoke(InvokeTxnTrace {
                        validate_invocation: Some(universal_deployer_validate(
                            account_contract_address,
                            universal_deployer_address,
                        )),
                        execute_invocation: ExecuteInvocation::FunctionInvocation(
                            universal_deployer_execute(
                                account_contract_address,
                                universal_deployer_address,
                            ),
                        ),
                        fee_transfer_invocation: None,
                        state_diff: Some(universal_deployer_state_diff(
                            account_contract_address,
                            vec![],
                        )),
                        execution_resources: Some(ExecutionResources {
                            computation_resources: universal_deployer_validate_computation_resources(
                            )
                                + universal_deployer_execute_computation_resources(),
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 224,
                            },
                        }),
                    }),
                }
            }

            pub fn universal_deployer_without_validate(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
                universal_deployer_address: ContractAddress,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: UNIVERSAL_DEPLOYER_GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: Some(UNIVERSAL_DEPLOYER_DATA_GAS_CONSUMED.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: UNIVERSAL_DEPLOYER_OVERALL_FEE.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Invoke(InvokeTxnTrace {
                        validate_invocation: None,
                        execute_invocation: ExecuteInvocation::FunctionInvocation(
                            universal_deployer_execute(
                                account_contract_address,
                                universal_deployer_address,
                            ),
                        ),
                        fee_transfer_invocation: Some(universal_deployer_fee_transfer(
                            account_contract_address,
                            last_block_header,
                        )),
                        state_diff: Some(universal_deployer_state_diff(
                            account_contract_address,
                            universal_deployer_fee_transfer_storage_diffs(),
                        )),
                        execution_resources: Some(ExecutionResources {
                            computation_resources:
                                universal_deployer_fee_transfer_computation_resources()
                                    + universal_deployer_execute_computation_resources(),
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 224,
                            },
                        }),
                    }),
                }
            }

            fn universal_deployer_validate_computation_resources() -> ComputationResources {
                ComputationResources {
                    steps: 21,
                    range_check_builtin_applications: 1,
                    ..Default::default()
                }
            }

            fn universal_deployer_execute_computation_resources() -> ComputationResources {
                ComputationResources {
                    steps: 2061,
                    memory_holes: 2,
                    range_check_builtin_applications: 44,
                    pedersen_builtin_applications: 7,
                    ..Default::default()
                }
            }

            fn universal_deployer_fee_transfer_computation_resources() -> ComputationResources {
                ComputationResources {
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
            ) -> StateDiff {
                StateDiff {
                    storage_diffs,
                    deprecated_declared_classes: vec![],
                    declared_classes: vec![],
                    deployed_contracts: vec![DeployedContract {
                        address: DEPLOYED_CONTRACT_ADDRESS,
                        class_hash: SIERRA_HASH,
                    }],
                    replaced_classes: vec![],
                    nonces: vec![Nonce {
                        contract_address: account_contract_address,
                        nonce: contract_nonce!("0x2"),
                    }],
                }
            }

            fn universal_deployer_fee_transfer_storage_diffs() -> Vec<StorageDiff> {
                vec![StorageDiff {
                    address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                    storage_entries: vec![
                        StorageEntry {
                            key: storage_address!("0x032a4edd4e4cffa71ee6d0971c54ac9e62009526cd78af7404aa968c3dc3408e"),
                            value: storage_value!("0x000000000000000000000000000000000000fffffffffffffffffffffffff942")
                        },
                        StorageEntry {
                            key: storage_address!("0x05496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"),
                            value: StorageValue((DECLARE_OVERALL_FEE + UNIVERSAL_DEPLOYER_OVERALL_FEE).into()),
                        },
                    ],
                }]
            }

            fn universal_deployer_validate(
                account_contract_address: ContractAddress,
                universal_deployer_address: ContractAddress,
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: felt!("0x0"),
                    calls: vec![],
                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![],
                    function_call: FunctionCall {
                        contract_address: account_contract_address,
                        entry_point_selector: EntryPoint::hashed(b"__validate__"),
                        calldata: vec![
                            CallParam(universal_deployer_address.0),
                            CallParam(EntryPoint::hashed(b"deployContract").0),
                            // calldata_len
                            call_param!("0x4"),
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
                    messages: vec![],
                    result: vec![],
                    execution_resources: universal_deployer_validate_computation_resources(),
                }
            }

            fn universal_deployer_execute(
                account_contract_address: ContractAddress,
                universal_deployer_address: ContractAddress,
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: felt!("0x0"),
                    calls: vec![
                        FunctionInvocation {
                            call_type: CallType::Call,
                            caller_address: *account_contract_address.get(),
                            calls: vec![
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: *universal_deployer_address.get(),
                                    calls: vec![],
                                    class_hash: Some(SIERRA_HASH.0),
                                    entry_point_type: EntryPointType::Constructor,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        contract_address: DEPLOYED_CONTRACT_ADDRESS,
                                        entry_point_selector: EntryPoint::hashed(b"constructor"),
                                        calldata: vec![],
                                    },
                                    messages: vec![],
                                    result: vec![],
                                    execution_resources: ComputationResources::default(),
                                },
                            ],
                            class_hash: Some(UNIVERSAL_DEPLOYER_CLASS_HASH.0),
                            entry_point_type: EntryPointType::External,
                            events: vec![
                                OrderedEvent {
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
                            function_call: FunctionCall {
                                contract_address: universal_deployer_address,
                                entry_point_selector: EntryPoint::hashed(b"deployContract"),
                                calldata: vec![
                                    // classHash
                                    CallParam(SIERRA_HASH.0),
                                    // salt
                                    call_param!("0x0"),
                                    // unique
                                    call_param!("0x0"),
                                    //  calldata_len
                                    call_param!("0x0"),
                                ],
                            },
                            messages: vec![],
                            result: vec![
                                *DEPLOYED_CONTRACT_ADDRESS.get(),
                            ],
                            execution_resources: ComputationResources {
                                steps: 1262,
                                memory_holes: 2,
                                range_check_builtin_applications: 23,
                                pedersen_builtin_applications: 7,
                                ..Default::default()
                            },
                        }
                    ],
                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![],
                    function_call: FunctionCall {
                        contract_address: account_contract_address,
                        entry_point_selector: EntryPoint::hashed(b"__execute__"),
                        calldata: vec![
                            CallParam(universal_deployer_address.0),
                            CallParam(EntryPoint::hashed(b"deployContract").0),
                            call_param!("0x4"),
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
                    messages: vec![],
                    result: vec![
                        *DEPLOYED_CONTRACT_ADDRESS.get(),
                    ],
                    execution_resources: universal_deployer_execute_computation_resources(),
                }
            }

            fn universal_deployer_fee_transfer(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: *account_contract_address.get(),
                    calls: vec![],
                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![OrderedEvent {
                        order: 0,
                        data: vec![
                            *account_contract_address.get(),
                            last_block_header.sequencer_address.0,
                            Felt::from_u64(UNIVERSAL_DEPLOYER_OVERALL_FEE),
                            felt!("0x0"),
                        ],
                        keys: vec![felt!(
                            "0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"
                        )],
                    }],
                    function_call: FunctionCall {
                        calldata: vec![
                            CallParam(last_block_header.sequencer_address.0),
                            CallParam(Felt::from_u64(UNIVERSAL_DEPLOYER_OVERALL_FEE)),
                            // calldata_len
                            call_param!("0x0"),
                        ],
                        contract_address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                        entry_point_selector: EntryPoint::hashed(b"transfer"),
                    },
                    messages: vec![],
                    result: vec![felt!("0x1")],
                    execution_resources: universal_deployer_fee_transfer_computation_resources(),
                }
            }

            const INVOKE_OVERALL_FEE: u64 = 268;
            const INVOKE_GAS_CONSUMED: u64 = 12;
            const INVOKE_DATA_GAS_CONSUMED: u64 = 128;

            pub fn invoke(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
                test_storage_value: StorageValue,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: INVOKE_GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: Some(INVOKE_DATA_GAS_CONSUMED.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: INVOKE_OVERALL_FEE.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Invoke(InvokeTxnTrace {
                        validate_invocation: Some(invoke_validate(account_contract_address)),
                        execute_invocation: ExecuteInvocation::FunctionInvocation(invoke_execute(
                            account_contract_address,
                            test_storage_value,
                        )),
                        fee_transfer_invocation: Some(invoke_fee_transfer(
                            account_contract_address,
                            last_block_header,
                        )),
                        state_diff: Some(invoke_state_diff(
                            account_contract_address,
                            invoke_fee_transfer_storage_diffs(),
                        )),
                        execution_resources: Some(ExecutionResources {
                            computation_resources: invoke_validate_computation_resources()
                                + invoke_execute_computation_resources()
                                + invoke_fee_transfer_computation_resources(),
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 128,
                            },
                        }),
                    }),
                }
            }

            pub fn invoke_without_fee_transfer(
                account_contract_address: ContractAddress,
                test_storage_value: StorageValue,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: INVOKE_GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: Some(INVOKE_DATA_GAS_CONSUMED.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: INVOKE_OVERALL_FEE.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Invoke(InvokeTxnTrace {
                        validate_invocation: Some(invoke_validate(account_contract_address)),
                        execute_invocation: ExecuteInvocation::FunctionInvocation(invoke_execute(
                            account_contract_address,
                            test_storage_value,
                        )),
                        fee_transfer_invocation: None,
                        state_diff: Some(invoke_state_diff(account_contract_address, vec![])),
                        execution_resources: Some(ExecutionResources {
                            computation_resources: invoke_execute_computation_resources()
                                + invoke_validate_computation_resources(),
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 128,
                            },
                        }),
                    }),
                }
            }

            pub fn invoke_without_validate(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
                test_storage_value: StorageValue,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: INVOKE_GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: Some(INVOKE_DATA_GAS_CONSUMED.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: INVOKE_OVERALL_FEE.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Invoke(InvokeTxnTrace {
                        validate_invocation: None,
                        execute_invocation: ExecuteInvocation::FunctionInvocation(invoke_execute(
                            account_contract_address,
                            test_storage_value,
                        )),
                        fee_transfer_invocation: Some(invoke_fee_transfer(
                            account_contract_address,
                            last_block_header,
                        )),
                        state_diff: Some(invoke_state_diff(
                            account_contract_address,
                            invoke_fee_transfer_storage_diffs(),
                        )),
                        execution_resources: Some(ExecutionResources {
                            computation_resources: invoke_execute_computation_resources()
                                + invoke_fee_transfer_computation_resources(),
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 128,
                            },
                        }),
                    }),
                }
            }

            fn invoke_validate_computation_resources() -> ComputationResources {
                ComputationResources {
                    steps: 21,
                    range_check_builtin_applications: 1,
                    ..Default::default()
                }
            }

            fn invoke_execute_computation_resources() -> ComputationResources {
                ComputationResources {
                    steps: 964,
                    range_check_builtin_applications: 24,
                    ..Default::default()
                }
            }

            fn invoke_fee_transfer_computation_resources() -> ComputationResources {
                ComputationResources {
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
            ) -> StateDiff {
                StateDiff {
                    storage_diffs,
                    deprecated_declared_classes: vec![],
                    declared_classes: vec![],
                    deployed_contracts: vec![],
                    replaced_classes: vec![],
                    nonces: vec![Nonce {
                        contract_address: account_contract_address,
                        nonce: contract_nonce!("0x3"),
                    }],
                }
            }

            fn invoke_fee_transfer_storage_diffs() -> Vec<StorageDiff> {
                vec![StorageDiff {
                    address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                    storage_entries: vec![
                        StorageEntry {
                            key: storage_address!("0x032a4edd4e4cffa71ee6d0971c54ac9e62009526cd78af7404aa968c3dc3408e"),
                            value: storage_value!("0x000000000000000000000000000000000000fffffffffffffffffffffffff836")
                        },
                        StorageEntry {
                            key: storage_address!("0x05496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"),
                            value: StorageValue((DECLARE_OVERALL_FEE + UNIVERSAL_DEPLOYER_OVERALL_FEE + INVOKE_OVERALL_FEE).into()),
                        },
                    ],
                }]
            }

            fn invoke_validate(account_contract_address: ContractAddress) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: felt!("0x0"),
                    calls: vec![],
                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![],
                    function_call: FunctionCall {
                        contract_address: account_contract_address,
                        entry_point_selector: EntryPoint::hashed(b"__validate__"),
                        calldata: vec![
                            CallParam(DEPLOYED_CONTRACT_ADDRESS.0),
                            CallParam(EntryPoint::hashed(b"get_data").0),
                            // calldata_len
                            call_param!("0x0"),
                        ],
                    },
                    messages: vec![],
                    result: vec![],
                    execution_resources: invoke_validate_computation_resources(),
                }
            }

            fn invoke_execute(
                account_contract_address: ContractAddress,
                test_storage_value: StorageValue,
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: felt!("0x0"),
                    calls: vec![FunctionInvocation {
                        call_type: CallType::Call,
                        caller_address: *account_contract_address.get(),
                        calls: vec![],
                        class_hash: Some(SIERRA_HASH.0),
                        entry_point_type: EntryPointType::External,
                        events: vec![],
                        function_call: FunctionCall {
                            contract_address: DEPLOYED_CONTRACT_ADDRESS,
                            entry_point_selector: EntryPoint::hashed(b"get_data"),
                            calldata: vec![],
                        },
                        messages: vec![],
                        result: vec![test_storage_value.0],
                        execution_resources: ComputationResources {
                            steps: 165,
                            range_check_builtin_applications: 3,
                            ..Default::default()
                        },
                    }],
                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![],
                    function_call: FunctionCall {
                        contract_address: account_contract_address,
                        entry_point_selector: EntryPoint::hashed(b"__execute__"),
                        calldata: vec![
                            CallParam(DEPLOYED_CONTRACT_ADDRESS.0),
                            CallParam(EntryPoint::hashed(b"get_data").0),
                            // calldata_len
                            call_param!("0x0"),
                        ],
                    },
                    messages: vec![],
                    result: vec![test_storage_value.0],
                    execution_resources: invoke_execute_computation_resources(),
                }
            }

            fn invoke_fee_transfer(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: *account_contract_address.get(),
                    calls: vec![],
                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![OrderedEvent {
                        order: 0,
                        data: vec![
                            *account_contract_address.get(),
                            last_block_header.sequencer_address.0,
                            Felt::from_u64(INVOKE_OVERALL_FEE),
                            felt!("0x0"),
                        ],
                        keys: vec![felt!(
                            "0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"
                        )],
                    }],
                    function_call: FunctionCall {
                        calldata: vec![
                            CallParam(last_block_header.sequencer_address.0),
                            CallParam(Felt::from_u64(INVOKE_OVERALL_FEE)),
                            call_param!("0x0"),
                        ],
                        contract_address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                        entry_point_selector: EntryPoint::hashed(b"transfer"),
                    },
                    messages: vec![],
                    result: vec![felt!("0x1")],
                    execution_resources: invoke_fee_transfer_computation_resources(),
                }
            }

            const INVOKE_V3_OVERALL_FEE: u64 = 280;
            const INVOKE_V3_GAS_CONSUMED: u64 = 12;
            const INVOKE_V3_DATA_GAS_CONSUMED: u64 = 128;

            pub fn invoke_v3(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
                test_storage_value: StorageValue,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: INVOKE_V3_GAS_CONSUMED.into(),
                        gas_price: 2.into(),
                        data_gas_consumed: Some(INVOKE_V3_DATA_GAS_CONSUMED.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: INVOKE_V3_OVERALL_FEE.into(),
                        unit: PriceUnit::Fri,
                    },
                    transaction_trace: TransactionTrace::Invoke(InvokeTxnTrace {
                        validate_invocation: Some(invoke_validate(account_contract_address)),
                        execute_invocation: ExecuteInvocation::FunctionInvocation(invoke_execute(
                            account_contract_address,
                            test_storage_value,
                        )),
                        fee_transfer_invocation: Some(invoke_v3_fee_transfer(
                            account_contract_address,
                            last_block_header,
                        )),
                        state_diff: Some(invoke_v3_state_diff(
                            account_contract_address,
                            invoke_v3_fee_transfer_storage_diffs(),
                        )),
                        execution_resources: Some(ExecutionResources {
                            computation_resources: invoke_validate_computation_resources()
                                + invoke_execute_computation_resources()
                                + invoke_fee_transfer_computation_resources(),
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 128,
                            },
                        }),
                    }),
                }
            }

            pub fn invoke_v3_without_fee_transfer(
                account_contract_address: ContractAddress,
                test_storage_value: StorageValue,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: INVOKE_V3_GAS_CONSUMED.into(),
                        gas_price: 2.into(),
                        data_gas_consumed: Some(INVOKE_V3_DATA_GAS_CONSUMED.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: INVOKE_V3_OVERALL_FEE.into(),
                        unit: PriceUnit::Fri,
                    },
                    transaction_trace: TransactionTrace::Invoke(InvokeTxnTrace {
                        validate_invocation: Some(invoke_validate(account_contract_address)),
                        execute_invocation: ExecuteInvocation::FunctionInvocation(invoke_execute(
                            account_contract_address,
                            test_storage_value,
                        )),
                        fee_transfer_invocation: None,
                        state_diff: Some(invoke_v3_state_diff(account_contract_address, vec![])),
                        execution_resources: Some(ExecutionResources {
                            computation_resources: invoke_validate_computation_resources()
                                + invoke_execute_computation_resources(),
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 128,
                            },
                        }),
                    }),
                }
            }

            pub fn invoke_v3_without_validate(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
                test_storage_value: StorageValue,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: INVOKE_V3_GAS_CONSUMED.into(),
                        gas_price: 2.into(),
                        data_gas_consumed: Some(INVOKE_V3_DATA_GAS_CONSUMED.into()),
                        data_gas_price: Some(2.into()),
                        overall_fee: INVOKE_V3_OVERALL_FEE.into(),
                        unit: PriceUnit::Fri,
                    },
                    transaction_trace: TransactionTrace::Invoke(InvokeTxnTrace {
                        validate_invocation: None,
                        execute_invocation: ExecuteInvocation::FunctionInvocation(invoke_execute(
                            account_contract_address,
                            test_storage_value,
                        )),
                        fee_transfer_invocation: Some(invoke_v3_fee_transfer(
                            account_contract_address,
                            last_block_header,
                        )),
                        state_diff: Some(invoke_v3_state_diff(
                            account_contract_address,
                            invoke_v3_fee_transfer_storage_diffs(),
                        )),
                        execution_resources: Some(ExecutionResources {
                            computation_resources: invoke_execute_computation_resources()
                                + invoke_fee_transfer_computation_resources(),
                            data_availability: DataAvailabilityResources {
                                l1_gas: 0,
                                l1_data_gas: 128,
                            },
                        }),
                    }),
                }
            }

            fn invoke_v3_fee_transfer(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: *account_contract_address.get(),
                    calls: vec![],
                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![OrderedEvent {
                        order: 0,
                        data: vec![
                            *account_contract_address.get(),
                            last_block_header.sequencer_address.0,
                            Felt::from_u64(INVOKE_V3_OVERALL_FEE),
                            felt!("0x0"),
                        ],
                        keys: vec![felt!(
                            "0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"
                        )],
                    }],
                    function_call: FunctionCall {
                        calldata: vec![
                            CallParam(last_block_header.sequencer_address.0),
                            CallParam(Felt::from_u64(INVOKE_V3_OVERALL_FEE)),
                            call_param!("0x0"),
                        ],
                        contract_address: pathfinder_executor::STRK_FEE_TOKEN_ADDRESS,
                        entry_point_selector: EntryPoint::hashed(b"transfer"),
                    },
                    messages: vec![],
                    result: vec![felt!("0x1")],
                    execution_resources: invoke_fee_transfer_computation_resources(),
                }
            }

            fn invoke_v3_state_diff(
                account_contract_address: ContractAddress,
                storage_diffs: Vec<StorageDiff>,
            ) -> StateDiff {
                StateDiff {
                    storage_diffs,
                    deprecated_declared_classes: vec![],
                    declared_classes: vec![],
                    deployed_contracts: vec![],
                    replaced_classes: vec![],
                    nonces: vec![Nonce {
                        contract_address: account_contract_address,
                        nonce: contract_nonce!("0x4"),
                    }],
                }
            }

            fn invoke_v3_fee_transfer_storage_diffs() -> Vec<StorageDiff> {
                vec![StorageDiff {
                    address: pathfinder_executor::STRK_FEE_TOKEN_ADDRESS,
                    storage_entries: vec![
                        StorageEntry {
                            key: storage_address!("0x032a4edd4e4cffa71ee6d0971c54ac9e62009526cd78af7404aa968c3dc3408e"),
                            value: storage_value!("0x000000000000000000000000000000000000fffffffffffffffffffffffffee8")
                        },
                        StorageEntry {
                            key: storage_address!("0x05496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"),
                            value: StorageValue((INVOKE_V3_OVERALL_FEE).into()),
                        },
                    ],
                }]
            }
        }
    }

    #[test_log::test(tokio::test)]
    async fn declare_deploy_and_invoke_sierra_class() {
        let (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        ) = setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 1)).await;
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
            simulation_flags: dto::SimulationFlags(vec![]),
        };
        let result = simulate_transactions(context, input).await.unwrap();

        pretty_assertions_sorted::assert_eq!(
            result
                .serialize(Serializer {
                    version: RpcVersion::V07
                })
                .unwrap(),
            serde_json::to_value(vec![
                fixtures::expected_output_0_13_1_1::declare(
                    account_contract_address,
                    &last_block_header
                ),
                fixtures::expected_output_0_13_1_1::universal_deployer(
                    account_contract_address,
                    &last_block_header,
                    universal_deployer_address,
                ),
                fixtures::expected_output_0_13_1_1::invoke(
                    account_contract_address,
                    &last_block_header,
                    test_storage_value,
                ),
                fixtures::expected_output_0_13_1_1::invoke_v3(
                    account_contract_address,
                    &last_block_header,
                    test_storage_value,
                ),
            ])
            .unwrap()
        );
    }

    #[test_log::test(tokio::test)]
    async fn declare_deploy_and_invoke_sierra_class_with_skip_fee_charge() {
        let (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        ) = setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 1)).await;
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
            simulation_flags: dto::SimulationFlags(vec![dto::SimulationFlag::SkipFeeCharge]),
        };
        let result = simulate_transactions(context, input).await.unwrap();

        pretty_assertions_sorted::assert_eq!(
            result
                .serialize(Serializer {
                    version: RpcVersion::V07
                })
                .unwrap(),
            serde_json::to_value(vec![
                fixtures::expected_output_0_13_1_1::declare_without_fee_transfer(
                    account_contract_address
                ),
                fixtures::expected_output_0_13_1_1::universal_deployer_without_fee_transfer(
                    account_contract_address,
                    universal_deployer_address,
                ),
                fixtures::expected_output_0_13_1_1::invoke_without_fee_transfer(
                    account_contract_address,
                    test_storage_value,
                ),
                fixtures::expected_output_0_13_1_1::invoke_v3_without_fee_transfer(
                    account_contract_address,
                    test_storage_value,
                ),
            ])
            .unwrap()
        );
    }

    #[test_log::test(tokio::test)]
    async fn declare_deploy_and_invoke_sierra_class_with_skip_validate() {
        let (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        ) = setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 1)).await;
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
            simulation_flags: dto::SimulationFlags(vec![dto::SimulationFlag::SkipValidate]),
        };
        let result = simulate_transactions(context, input).await.unwrap();

        pretty_assertions_sorted::assert_eq!(
            result
                .serialize(Serializer {
                    version: RpcVersion::V07
                })
                .unwrap(),
            serde_json::to_value(vec![
                fixtures::expected_output_0_13_1_1::declare_without_validate(
                    account_contract_address,
                    &last_block_header,
                ),
                fixtures::expected_output_0_13_1_1::universal_deployer_without_validate(
                    account_contract_address,
                    &last_block_header,
                    universal_deployer_address,
                ),
                fixtures::expected_output_0_13_1_1::invoke_without_validate(
                    account_contract_address,
                    &last_block_header,
                    test_storage_value,
                ),
                fixtures::expected_output_0_13_1_1::invoke_v3_without_validate(
                    account_contract_address,
                    &last_block_header,
                    test_storage_value,
                ),
            ])
            .unwrap()
        );
    }
}
