use crate::context::RpcContext;

use crate::v06::method::estimate_fee as v06;

pub async fn estimate_fee(
    context: RpcContext,
    input: v06::EstimateFeeInput,
) -> Result<Vec<v06::FeeEstimate>, v06::EstimateFeeError> {
    v06::estimate_fee_impl(
        context,
        input,
        pathfinder_executor::L1BlobDataAvailability::Enabled,
    )
    .await
}

#[cfg(test)]
mod tests {
    use crate::v06::method::estimate_fee::*;
    use crate::v06::types::PriceUnit;
    use pretty_assertions_sorted::assert_eq;

    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::prelude::*;
    use pathfinder_common::BlockId;
    use pathfinder_common::Tip;

    use pathfinder_common::felt;

    use crate::v02::types::request::{
        BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV2,
        BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV0,
        BroadcastedInvokeTransactionV1, BroadcastedInvokeTransactionV3, BroadcastedTransaction,
    };
    use crate::v02::types::{
        ContractClass, DataAvailabilityMode, ResourceBounds, SierraContractClass,
    };

    fn declare_transaction(account_contract_address: ContractAddress) -> BroadcastedTransaction {
        let sierra_definition = include_bytes!("../../../fixtures/contracts/storage_access.json");
        let sierra_hash =
            class_hash!("0544b92d358447cb9e50b65092b7169f931d29e05c1404a2cd08c6fd7e32ba90");
        let casm_hash =
            casm_hash!("0x069032ff71f77284e1a0864a573007108ca5cc08089416af50f03260f5d6d4d8");

        let contract_class: SierraContractClass =
            ContractClass::from_definition_bytes(sierra_definition)
                .unwrap()
                .as_sierra()
                .unwrap();

        assert_eq!(contract_class.class_hash().unwrap().hash(), sierra_hash);

        let max_fee = Fee::default();

        BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(
            BroadcastedDeclareTransactionV2 {
                version: TransactionVersion::TWO,
                max_fee,
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class,
                sender_address: account_contract_address,
                compiled_class_hash: casm_hash,
            },
        ))
    }

    fn deploy_transaction(
        account_contract_address: ContractAddress,
        universal_deployer_address: ContractAddress,
    ) -> BroadcastedTransaction {
        let max_fee = Fee::default();
        let sierra_hash =
            class_hash!("0544b92d358447cb9e50b65092b7169f931d29e05c1404a2cd08c6fd7e32ba90");

        BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
            BroadcastedInvokeTransactionV1 {
                nonce: transaction_nonce!("0x1"),
                version: TransactionVersion::ONE,
                max_fee,
                signature: vec![],
                sender_address: account_contract_address,
                calldata: vec![
                    CallParam(*universal_deployer_address.get()),
                    // Entry point selector for the called contract, i.e. AccountCallArray::selector
                    CallParam(EntryPoint::hashed(b"deployContract").0),
                    // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                    call_param!("4"),
                    // classHash
                    CallParam(sierra_hash.0),
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

    fn invoke_transaction(account_contract_address: ContractAddress) -> BroadcastedTransaction {
        let max_fee = Fee::default();

        BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
            BroadcastedInvokeTransactionV1 {
                nonce: transaction_nonce!("0x2"),
                version: TransactionVersion::ONE,
                max_fee,
                signature: vec![],
                sender_address: account_contract_address,
                calldata: vec![
                    // address of the deployed test contract
                    CallParam(felt!(
                        "0x012592426632af714f43ccb05536b6044fc3e897fa55288f658731f93590e7e7"
                    )),
                    // Entry point selector for the called contract, i.e. AccountCallArray::selector
                    CallParam(EntryPoint::hashed(b"get_data").0),
                    // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                    call_param!("0"),
                ],
            },
        ))
    }

    fn invoke_v0_transaction() -> BroadcastedTransaction {
        let max_fee = Fee::default();

        BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
            BroadcastedInvokeTransactionV0 {
                version: TransactionVersion::ONE,
                max_fee,
                signature: vec![],
                contract_address: contract_address!(
                    "0x012592426632af714f43ccb05536b6044fc3e897fa55288f658731f93590e7e7"
                ),
                entry_point_selector: EntryPoint::hashed(b"get_data"),
                calldata: vec![],
            },
        ))
    }

    fn invoke_v3_transaction(account_contract_address: ContractAddress) -> BroadcastedTransaction {
        BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V3(
            BroadcastedInvokeTransactionV3 {
                version: TransactionVersion::THREE,
                signature: vec![],
                sender_address: account_contract_address,
                calldata: vec![
                    // address of the deployed test contract
                    CallParam(felt!(
                        "0x012592426632af714f43ccb05536b6044fc3e897fa55288f658731f93590e7e7"
                    )),
                    // Entry point selector for the called contract, i.e. AccountCallArray::selector
                    CallParam(EntryPoint::hashed(b"get_data").0),
                    // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                    call_param!("0"),
                ],
                nonce: transaction_nonce!("0x3"),
                resource_bounds: ResourceBounds::default(),
                tip: Tip(0),
                paymaster_data: vec![],
                account_deployment_data: vec![],
                nonce_data_availability_mode: DataAvailabilityMode::L1,
                fee_data_availability_mode: DataAvailabilityMode::L1,
            },
        ))
    }

    #[tokio::test]
    async fn declare_deploy_and_invoke_sierra_class_starknet_0_13_1() {
        let (context, last_block_header, account_contract_address, universal_deployer_address) =
            crate::test_setup::test_context_with_starknet_version(StarknetVersion::new(
                0, 13, 1, 0,
            ))
            .await;

        // declare test class
        let declare_transaction = declare_transaction(account_contract_address);
        // deploy with unversal deployer contract
        let deploy_transaction =
            deploy_transaction(account_contract_address, universal_deployer_address);
        // invoke deployed contract
        let invoke_transaction = invoke_transaction(account_contract_address);
        // do the same invoke with a v0 transaction
        let invoke_v0_transaction = invoke_v0_transaction();
        // do the same invoke with a v3 transaction
        let invoke_v3_transaction = invoke_v3_transaction(account_contract_address);

        let input = EstimateFeeInput {
            request: vec![
                declare_transaction,
                deploy_transaction,
                invoke_transaction,
                invoke_v0_transaction,
                invoke_v3_transaction,
            ],
            simulation_flags: SimulationFlags(vec![]),
            block_id: BlockId::Number(last_block_header.number),
        };
        let result = super::estimate_fee(context, input).await.unwrap();
        let declare_expected = FeeEstimate {
            gas_consumed: 23817.into(),
            gas_price: 1.into(),
            overall_fee: 24201.into(),
            unit: PriceUnit::Wei,
            data_gas_consumed: Some(192.into()),
            data_gas_price: Some(2.into()),
        };
        let deploy_expected = FeeEstimate {
            gas_consumed: 16.into(),
            gas_price: 1.into(),
            overall_fee: 464.into(),
            unit: PriceUnit::Wei,
            data_gas_consumed: Some(224.into()),
            data_gas_price: Some(2.into()),
        };
        let invoke_expected = FeeEstimate {
            gas_consumed: 12.into(),
            gas_price: 1.into(),
            overall_fee: 268.into(),
            unit: PriceUnit::Wei,
            data_gas_consumed: Some(128.into()),
            data_gas_price: Some(2.into()),
        };
        let invoke_v0_expected = FeeEstimate {
            gas_consumed: 10.into(),
            gas_price: 1.into(),
            overall_fee: 266.into(),
            unit: PriceUnit::Wei,
            data_gas_consumed: Some(128.into()),
            data_gas_price: Some(2.into()),
        };
        let invoke_v3_expected = FeeEstimate {
            gas_consumed: 12.into(),
            // STRK gas price is 2
            gas_price: 2.into(),
            overall_fee: 280.into(),
            unit: PriceUnit::Fri,
            data_gas_consumed: Some(128.into()),
            data_gas_price: Some(2.into()),
        };
        assert_eq!(
            result,
            vec![
                declare_expected,
                deploy_expected,
                invoke_expected,
                invoke_v0_expected,
                invoke_v3_expected,
            ]
        );
    }

    #[tokio::test]
    async fn declare_deploy_and_invoke_sierra_class_starknet_0_13_1_1() {
        let (context, last_block_header, account_contract_address, universal_deployer_address) =
            crate::test_setup::test_context_with_starknet_version(StarknetVersion::new(
                0, 13, 1, 1,
            ))
            .await;

        // declare test class
        let declare_transaction = declare_transaction(account_contract_address);
        // deploy with unversal deployer contract
        let deploy_transaction =
            deploy_transaction(account_contract_address, universal_deployer_address);
        // invoke deployed contract
        let invoke_transaction = invoke_transaction(account_contract_address);
        // do the same invoke with a v0 transaction
        let invoke_v0_transaction = invoke_v0_transaction();
        // do the same invoke with a v3 transaction
        let invoke_v3_transaction = invoke_v3_transaction(account_contract_address);

        let input = EstimateFeeInput {
            request: vec![
                declare_transaction,
                deploy_transaction,
                invoke_transaction,
                invoke_v0_transaction,
                invoke_v3_transaction,
            ],
            simulation_flags: SimulationFlags(vec![]),
            block_id: BlockId::Number(last_block_header.number),
        };
        let result = super::estimate_fee(context, input).await.unwrap();
        let declare_expected = FeeEstimate {
            gas_consumed: 878.into(),
            gas_price: 1.into(),
            overall_fee: 1262.into(),
            unit: PriceUnit::Wei,
            data_gas_consumed: Some(192.into()),
            data_gas_price: Some(2.into()),
        };
        let deploy_expected = FeeEstimate {
            gas_consumed: 16.into(),
            gas_price: 1.into(),
            overall_fee: 464.into(),
            unit: PriceUnit::Wei,
            data_gas_consumed: Some(224.into()),
            data_gas_price: Some(2.into()),
        };
        let invoke_expected = FeeEstimate {
            gas_consumed: 12.into(),
            gas_price: 1.into(),
            overall_fee: 268.into(),
            unit: PriceUnit::Wei,
            data_gas_consumed: Some(128.into()),
            data_gas_price: Some(2.into()),
        };
        let invoke_v0_expected = FeeEstimate {
            gas_consumed: 10.into(),
            gas_price: 1.into(),
            overall_fee: 266.into(),
            unit: PriceUnit::Wei,
            data_gas_consumed: Some(128.into()),
            data_gas_price: Some(2.into()),
        };
        let invoke_v3_expected = FeeEstimate {
            gas_consumed: 12.into(),
            // STRK gas price is 2
            gas_price: 2.into(),
            overall_fee: 280.into(),
            unit: PriceUnit::Fri,
            data_gas_consumed: Some(128.into()),
            data_gas_price: Some(2.into()),
        };
        assert_eq!(
            result,
            vec![
                declare_expected,
                deploy_expected,
                invoke_expected,
                invoke_v0_expected,
                invoke_v3_expected,
            ]
        );
    }
}
