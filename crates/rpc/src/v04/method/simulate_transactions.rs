#[cfg(test)]
pub(crate) mod tests {
    use crate::v02::types::request::{
        BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV2,
        BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV1,
    };
    use crate::v02::types::ContractClass;
    use pathfinder_common::{macro_prelude::*, Fee, StarknetVersion};
    use pathfinder_common::{
        //felt,
        BlockHeader,
        ContractAddress,
        StorageAddress,
        StorageValue,
        TransactionVersion,
    };
    use pathfinder_storage::Storage;

    pub(crate) mod fixtures {
        use pathfinder_common::{CasmHash, ClassHash, ContractAddress};
        use pathfinder_crypto::Felt;

        use super::*;

        pub const SIERRA_DEFINITION: &[u8] =
            include_bytes!("../../../fixtures/contracts/storage_access.json");
        pub const SIERRA_HASH: ClassHash =
            class_hash!("0544b92d358447cb9e50b65092b7169f931d29e05c1404a2cd08c6fd7e32ba90");
        pub const CASM_HASH: CasmHash =
            casm_hash!("0x069032ff71f77284e1a0864a573007108ca5cc08089416af50f03260f5d6d4d8");
        pub const CASM_DEFINITION: &[u8] =
            include_bytes!("../../../fixtures/contracts/storage_access.casm");
        const MAX_FEE: Fee = Fee(Felt::from_u64(10_000_000));
        pub const DEPLOYED_CONTRACT_ADDRESS: ContractAddress =
            contract_address!("0x012592426632af714f43ccb05536b6044fc3e897fa55288f658731f93590e7e7");
        pub const UNIVERSAL_DEPLOYER_CLASS_HASH: ClassHash =
            class_hash!("0x06f38fb91ddbf325a0625533576bb6f6eafd9341868a9ec3faa4b01ce6c4f4dc");

        pub mod input {
            use pathfinder_common::{CallParam, EntryPoint};

            use crate::v02::types::request::BroadcastedTransaction;

            use super::*;

            pub fn declare(account_contract_address: ContractAddress) -> BroadcastedTransaction {
                let contract_class = ContractClass::from_definition_bytes(SIERRA_DEFINITION)
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
                            CallParam(*universal_deployer_address.get()),
                            // Entry point selector for the called contract, i.e. AccountCallArray::selector
                            CallParam(EntryPoint::hashed(b"deployContract").0),
                            // Length of the call data for the called contract, i.e. AccountCallArray::data_len
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
                            CallParam(*DEPLOYED_CONTRACT_ADDRESS.get()),
                            // Entry point selector for the called contract, i.e. AccountCallArray::selector
                            CallParam(EntryPoint::hashed(b"get_data").0),
                            // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                            call_param!("0"),
                        ],
                    },
                ))
            }
        }
    }

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

    pub(crate) async fn setup_storage() -> (
        Storage,
        BlockHeader,
        ContractAddress,
        ContractAddress,
        StorageValue,
    ) {
        setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 0)).await
    }
}
