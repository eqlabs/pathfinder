use crate::context::RpcContext;
use crate::felt::RpcFelt;
use crate::v02::types::request::BroadcastedDeclareTransaction;
use pathfinder_common::{ClassHash, TransactionHash};
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::error::SequencerError;
use starknet_gateway_types::request::add_transaction::{
    CairoContractDefinition, ContractDefinition, SierraContractDefinition,
};

#[derive(Debug)]
pub enum AddDeclareTransactionError {
    ClassAlreadyDeclared,
    InvalidTransactionNonce,
    InsufficientMaxFee,
    InsufficientAccountBalance,
    ValidationFailure,
    CompilationFailed,
    ContractClassSizeIsTooLarge,
    DuplicateTransaction,
    CompiledClassHashMismatch,
    NonAccount,
    UnsupportedTransactionVersion,
    UnsupportedContractClassVersion,
    UnexpectedError(String),
}

impl From<AddDeclareTransactionError> for crate::error::RpcError {
    fn from(value: AddDeclareTransactionError) -> Self {
        match value {
            AddDeclareTransactionError::ClassAlreadyDeclared => Self::ClassAlreadyDeclared,
            AddDeclareTransactionError::InvalidTransactionNonce => Self::InvalidTransactionNonce,
            AddDeclareTransactionError::InsufficientMaxFee => Self::InsufficientMaxFee,
            AddDeclareTransactionError::InsufficientAccountBalance => {
                Self::InsufficientAccountBalance
            }
            AddDeclareTransactionError::ValidationFailure => Self::ValidationFailure,
            AddDeclareTransactionError::CompilationFailed => Self::CompilationFailed,
            AddDeclareTransactionError::ContractClassSizeIsTooLarge => {
                Self::ContractClassSizeIsTooLarge
            }
            AddDeclareTransactionError::DuplicateTransaction => Self::DuplicateTransaction,
            AddDeclareTransactionError::CompiledClassHashMismatch => {
                Self::CompiledClassHashMismatch
            }
            AddDeclareTransactionError::NonAccount => Self::NonAccount,
            AddDeclareTransactionError::UnsupportedTransactionVersion => Self::UnsupportedTxVersion,
            AddDeclareTransactionError::UnsupportedContractClassVersion => {
                Self::UnsupportedContractClassVersion
            }
            AddDeclareTransactionError::UnexpectedError(data) => Self::UnexpectedError { data },
        }
    }
}

impl From<anyhow::Error> for AddDeclareTransactionError {
    fn from(value: anyhow::Error) -> Self {
        AddDeclareTransactionError::UnexpectedError(value.to_string())
    }
}

impl From<SequencerError> for AddDeclareTransactionError {
    fn from(e: SequencerError) -> Self {
        use starknet_gateway_types::error::KnownStarknetErrorCode::{
            ClassAlreadyDeclared, CompilationFailed, ContractBytecodeSizeTooLarge,
            ContractClassObjectSizeTooLarge, DuplicatedTransaction, EntryPointNotFound,
            InsufficientAccountBalance, InsufficientMaxFee, InvalidCompiledClassHash,
            InvalidContractClassVersion, InvalidTransactionNonce, InvalidTransactionVersion,
            ValidateFailure,
        };
        match e {
            SequencerError::StarknetError(e) if e.code == ClassAlreadyDeclared.into() => {
                AddDeclareTransactionError::ClassAlreadyDeclared
            }
            SequencerError::StarknetError(e) if e.code == CompilationFailed.into() => {
                AddDeclareTransactionError::CompilationFailed
            }
            SequencerError::StarknetError(e)
                if e.code == ContractBytecodeSizeTooLarge.into()
                    || e.code == ContractClassObjectSizeTooLarge.into() =>
            {
                AddDeclareTransactionError::ContractClassSizeIsTooLarge
            }
            SequencerError::StarknetError(e) if e.code == DuplicatedTransaction.into() => {
                AddDeclareTransactionError::DuplicateTransaction
            }
            SequencerError::StarknetError(e) if e.code == InsufficientAccountBalance.into() => {
                AddDeclareTransactionError::InsufficientAccountBalance
            }
            SequencerError::StarknetError(e) if e.code == InsufficientMaxFee.into() => {
                AddDeclareTransactionError::InsufficientMaxFee
            }
            SequencerError::StarknetError(e) if e.code == InvalidTransactionNonce.into() => {
                AddDeclareTransactionError::InvalidTransactionNonce
            }
            SequencerError::StarknetError(e) if e.code == ValidateFailure.into() => {
                AddDeclareTransactionError::ValidationFailure
            }
            SequencerError::StarknetError(e) if e.code == InvalidCompiledClassHash.into() => {
                AddDeclareTransactionError::CompiledClassHashMismatch
            }
            SequencerError::StarknetError(e) if e.code == InvalidTransactionVersion.into() => {
                AddDeclareTransactionError::UnsupportedTransactionVersion
            }
            SequencerError::StarknetError(e) if e.code == InvalidContractClassVersion.into() => {
                AddDeclareTransactionError::UnsupportedContractClassVersion
            }
            SequencerError::StarknetError(e) if e.code == EntryPointNotFound.into() => {
                AddDeclareTransactionError::NonAccount
            }
            _ => AddDeclareTransactionError::UnexpectedError(e.to_string()),
        }
    }
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Transaction {
    #[serde(rename = "DECLARE")]
    Declare(BroadcastedDeclareTransaction),
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct AddDeclareTransactionInput {
    declare_transaction: Transaction,
    // An undocumented parameter that we forward to the sequencer API
    // A deploy token is required to deploy contracts on Starknet mainnet only.
    #[serde(default)]
    token: Option<String>,
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub struct AddDeclareTransactionOutput {
    #[serde_as(as = "RpcFelt")]
    transaction_hash: TransactionHash,
    #[serde_as(as = "RpcFelt")]
    class_hash: ClassHash,
}

pub async fn add_declare_transaction(
    context: RpcContext,
    input: AddDeclareTransactionInput,
) -> Result<AddDeclareTransactionOutput, AddDeclareTransactionError> {
    match input.declare_transaction {
        Transaction::Declare(BroadcastedDeclareTransaction::V1(tx)) => {
            let contract_definition: CairoContractDefinition = tx
                .contract_class
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert contract definition: {}", e))?;

            let response = context
                .sequencer
                .add_declare_transaction(
                    tx.version,
                    tx.max_fee,
                    tx.signature,
                    tx.nonce,
                    ContractDefinition::Cairo(contract_definition),
                    tx.sender_address,
                    None,
                    input.token,
                )
                .await?;

            Ok(AddDeclareTransactionOutput {
                transaction_hash: response.transaction_hash,
                class_hash: response.class_hash,
            })
        }
        Transaction::Declare(BroadcastedDeclareTransaction::V2(tx)) => {
            let contract_definition: SierraContractDefinition = tx
                .contract_class
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert contract definition: {}", e))?;

            let response = context
                .sequencer
                .add_declare_transaction(
                    tx.version,
                    tx.max_fee,
                    tx.signature,
                    tx.nonce,
                    ContractDefinition::Sierra(contract_definition),
                    tx.sender_address,
                    Some(tx.compiled_class_hash),
                    input.token,
                )
                .await?;

            Ok(AddDeclareTransactionOutput {
                transaction_hash: response.transaction_hash,
                class_hash: response.class_hash,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v02::types::request::{
        BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV1,
        BroadcastedDeclareTransactionV2,
    };
    use crate::v02::types::{CairoContractClass, ContractClass, SierraContractClass};
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{CasmHash, ContractAddress, Fee, TransactionNonce, TransactionVersion};
    use stark_hash::Felt;
    use starknet_gateway_test_fixtures::class_definitions::{
        CAIRO_2_0_0_STACK_OVERFLOW, CONTRACT_DEFINITION,
    };

    lazy_static::lazy_static! {
        pub static ref CONTRACT_CLASS: CairoContractClass = {
            ContractClass::from_definition_bytes(CONTRACT_DEFINITION).unwrap().as_cairo().unwrap()
        };

        pub static ref CONTRACT_CLASS_WITH_INVALID_PRIME: CairoContractClass = {
            let mut definition: serde_json::Value = serde_json::from_slice(CONTRACT_DEFINITION).unwrap();
            // change program.prime to an invalid one
            *definition.get_mut("program").unwrap().get_mut("prime").unwrap() = serde_json::json!("0x1");
            let definition = serde_json::to_vec(&definition).unwrap();
            ContractClass::from_definition_bytes(&definition).unwrap().as_cairo().unwrap()
        };

        pub static ref CONTRACT_CLASS_JSON: String = {
            serde_json::to_string(&*CONTRACT_CLASS).unwrap()
        };

        pub static ref SIERRA_CLASS_JSON: String = {
            serde_json::to_string(&*SIERRA_CLASS).unwrap()
        };

        pub static ref SIERRA_CLASS: SierraContractClass = {
            ContractClass::from_definition_bytes(CAIRO_2_0_0_STACK_OVERFLOW).unwrap().as_sierra().unwrap()
        };
    }

    mod parsing {
        mod v1 {
            use super::super::*;
            use crate::v02::types::request::BroadcastedDeclareTransactionV1;

            fn test_declare_txn() -> Transaction {
                Transaction::Declare(BroadcastedDeclareTransaction::V1(
                    BroadcastedDeclareTransactionV1 {
                        max_fee: fee!("0x1"),
                        version: TransactionVersion::ONE,
                        signature: vec![],
                        nonce: TransactionNonce(Felt::ZERO),
                        contract_class: CONTRACT_CLASS.clone(),
                        sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                    },
                ))
            }

            #[test]
            fn positional_args() {
                use jsonrpsee::types::Params;

                let positional = format!(
                    r#"[
                        {{
                            "type": "DECLARE",
                            "version": "0x1",
                            "max_fee": "0x1",
                            "signature": [],
                            "nonce": "0x0",
                            "contract_class": {},
                            "sender_address": "0x1"
                        }}
                    ]"#,
                    CONTRACT_CLASS_JSON.clone()
                );
                let positional = Params::new(Some(&positional));

                let input = positional.parse::<AddDeclareTransactionInput>().unwrap();
                let expected = AddDeclareTransactionInput {
                    declare_transaction: test_declare_txn(),
                    token: None,
                };
                assert_eq!(input, expected);
            }

            #[test]
            fn named_args() {
                use jsonrpsee::types::Params;

                let named = format!(
                    r#"{{
                        "declare_transaction": {{
                            "type": "DECLARE",
                            "version": "0x1",
                            "max_fee": "0x1",
                            "signature": [],
                            "nonce": "0x0",
                            "contract_class": {},
                            "sender_address": "0x1"
                        }},
                        "token": "token"
                    }}"#,
                    CONTRACT_CLASS_JSON.clone()
                );
                let named = Params::new(Some(&named));

                let input = named.parse::<AddDeclareTransactionInput>().unwrap();
                let expected = AddDeclareTransactionInput {
                    declare_transaction: test_declare_txn(),
                    token: Some("token".to_owned()),
                };
                assert_eq!(input, expected);
            }
        }

        mod v2 {
            use super::super::*;
            use crate::v02::types::request::BroadcastedDeclareTransactionV2;

            fn test_declare_txn() -> Transaction {
                Transaction::Declare(BroadcastedDeclareTransaction::V2(
                    BroadcastedDeclareTransactionV2 {
                        max_fee: fee!("0x1"),
                        version: TransactionVersion::TWO,
                        signature: vec![],
                        nonce: TransactionNonce(Felt::ZERO),
                        contract_class: SIERRA_CLASS.clone(),
                        sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                        compiled_class_hash: CasmHash(Felt::from_u64(1)),
                    },
                ))
            }

            #[test]
            fn positional_args() {
                use jsonrpsee::types::Params;

                let positional = format!(
                    r#"[
                        {{
                            "type": "DECLARE",
                            "version": "0x2",
                            "max_fee": "0x1",
                            "signature": [],
                            "nonce": "0x0",
                            "contract_class": {},
                            "sender_address": "0x1",
                            "compiled_class_hash": "0x1"
                        }}
                    ]"#,
                    SIERRA_CLASS_JSON.clone()
                );
                let positional = Params::new(Some(&positional));

                let input = positional.parse::<AddDeclareTransactionInput>().unwrap();
                let expected = AddDeclareTransactionInput {
                    declare_transaction: test_declare_txn(),
                    token: None,
                };
                pretty_assertions::assert_eq!(input, expected);
            }

            #[test]
            fn named_args() {
                use jsonrpsee::types::Params;

                let named = format!(
                    r#"{{
                        "declare_transaction": {{
                            "type": "DECLARE",
                            "version": "0x2",
                            "max_fee": "0x1",
                            "signature": [],
                            "nonce": "0x0",
                            "contract_class": {},
                            "sender_address": "0x1",
                            "compiled_class_hash": "0x1"
                        }},
                        "token": "token"
                    }}"#,
                    SIERRA_CLASS_JSON.clone()
                );
                let named = Params::new(Some(&named));

                let input = named.parse::<AddDeclareTransactionInput>().unwrap();
                let expected = AddDeclareTransactionInput {
                    declare_transaction: test_declare_txn(),
                    token: Some("token".to_owned()),
                };
                pretty_assertions::assert_eq!(input, expected);
            }
        }
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn invalid_contract_definition_v1() {
        let context = RpcContext::for_tests();

        let invalid_contract_class = CairoContractClass {
            program: "".to_owned(),
            ..CONTRACT_CLASS.clone()
        };

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V1(
            BroadcastedDeclareTransactionV1 {
                version: TransactionVersion::ONE,
                max_fee: Fee(Default::default()),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: invalid_contract_class,
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
            },
        ));

        let input = AddDeclareTransactionInput {
            declare_transaction,
            token: None,
        };
        let error = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, AddDeclareTransactionError::UnexpectedError(_));
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn invalid_contract_definition_v2() {
        let context = RpcContext::for_tests_on(pathfinder_common::Chain::Integration);

        let invalid_contract_class = SierraContractClass {
            sierra_program: vec![],
            ..SIERRA_CLASS.clone()
        };

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V2(
            BroadcastedDeclareTransactionV2 {
                version: TransactionVersion::TWO,
                max_fee: Fee(Felt::from_be_slice(&u64::MAX.to_be_bytes()).unwrap()),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: invalid_contract_class,
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                // Taken from
                // https://external.integration.starknet.io/feeder_gateway/get_state_update?blockNumber=283364
                compiled_class_hash: casm_hash!(
                    "0x711c0c3e56863e29d3158804aac47f424241eda64db33e2cc2999d60ee5105"
                ),
            },
        ));

        let input = AddDeclareTransactionInput {
            declare_transaction,
            token: None,
        };
        let error = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, AddDeclareTransactionError::UnexpectedError(_));
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn invalid_contract_class() {
        let context = RpcContext::for_tests();

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V1(
            BroadcastedDeclareTransactionV1 {
                version: TransactionVersion::ONE,
                max_fee: fee!("0xfffffffffff"),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: CONTRACT_CLASS_WITH_INVALID_PRIME.clone(),
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
            },
        ));

        let input = AddDeclareTransactionInput {
            declare_transaction,
            token: None,
        };
        let error = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, AddDeclareTransactionError::UnexpectedError(_));
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn duplicate_transaction() {
        let context = RpcContext::for_tests();

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V1(
            BroadcastedDeclareTransactionV1 {
                version: TransactionVersion::ONE,
                max_fee: Fee(Felt::from_be_slice(&u64::MAX.to_be_bytes()).unwrap()),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: CONTRACT_CLASS.clone(),
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
            },
        ));

        let input = AddDeclareTransactionInput {
            declare_transaction,
            token: None,
        };
        let error = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, AddDeclareTransactionError::DuplicateTransaction);
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn insufficient_max_fee() {
        let context = RpcContext::for_tests_on(pathfinder_common::Chain::Integration);

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V2(
            BroadcastedDeclareTransactionV2 {
                version: TransactionVersion::TWO,
                max_fee: Fee(felt!("0x01")),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: SIERRA_CLASS.clone(),
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                compiled_class_hash: casm_hash!(
                    "0x688e44b1d8612222a25cf742c8e1493af4640fa74b1a7707bde2002df51ea8c"
                ),
            },
        ));

        let input = AddDeclareTransactionInput {
            declare_transaction,
            token: None,
        };
        let err = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(
            err,
            AddDeclareTransactionError::InsufficientAccountBalance
        );
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn insufficient_account_balance() {
        let context = RpcContext::for_tests_on(pathfinder_common::Chain::Integration);

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V2(
            BroadcastedDeclareTransactionV2 {
                version: TransactionVersion::TWO,
                max_fee: Fee(Felt::from_be_slice(&u64::MAX.to_be_bytes()).unwrap()),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: SIERRA_CLASS.clone(),
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                compiled_class_hash: casm_hash!(
                    "0x688e44b1d8612222a25cf742c8e1493af4640fa74b1a7707bde2002df51ea8c"
                ),
            },
        ));

        let input = AddDeclareTransactionInput {
            declare_transaction,
            token: None,
        };
        let err = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(
            err,
            AddDeclareTransactionError::InsufficientAccountBalance
        );
    }
}
