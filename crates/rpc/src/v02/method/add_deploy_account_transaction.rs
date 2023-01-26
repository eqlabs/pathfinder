use crate::felt::{RpcFelt, RpcFelt251};
use crate::v02::{types::request::BroadcastedDeployAccountTransaction, RpcContext};
use anyhow::Context;
use pathfinder_common::{ContractAddress, StarknetTransactionHash};
use starknet_gateway_client::ClientApi;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Transaction {
    #[serde(rename = "DEPLOY_ACCOUNT")]
    DeployAccount(BroadcastedDeployAccountTransaction),
}

#[derive(Debug, serde::Deserialize, PartialEq, Eq)]
pub struct AddDeployAccountTransactionInput {
    deploy_account_transaction: Transaction,
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub struct AddDeployAccountTransactionOutput {
    #[serde_as(as = "RpcFelt")]
    transaction_hash: StarknetTransactionHash,
    #[serde_as(as = "RpcFelt251")]
    contract_address: ContractAddress,
}

crate::error::generate_rpc_error_subset!(AddDeployAccountTransactionError: ClassHashNotFound);

pub async fn add_deploy_account_transaction(
    context: RpcContext,
    input: AddDeployAccountTransactionInput,
) -> Result<AddDeployAccountTransactionOutput, AddDeployAccountTransactionError> {
    let Transaction::DeployAccount(tx) = input.deploy_account_transaction;
    let response = context
        .sequencer
        .add_deploy_account(
            tx.version,
            tx.max_fee,
            tx.signature,
            tx.nonce,
            tx.contract_address_salt,
            tx.class_hash,
            tx.constructor_calldata,
        )
        .await
        .context("Sending Deploy Account Transaction to the gateway")?;

    Ok(AddDeployAccountTransactionOutput {
        transaction_hash: response.transaction_hash,
        contract_address: response.address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::{
        felt, CallParam, ClassHash, ContractAddressSalt, Fee, TransactionNonce,
        TransactionSignatureElem, TransactionVersion,
    };

    const INPUT_JSON: &str = r#"{
        "max_fee": "0xbf391377813",
        "version": "0x1",
        "constructor_calldata": [
            "0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"
        ],
        "signature": [
            "07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5",
            "071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
        ],
        "nonce": "0x0",
        "class_hash": "01fac3074c9d5282f0acc5c69a4781a1c711efea5e73c550c5d9fb253cf7fd3d",
        "contract_address_salt": "06d44a6aecb4339e23a9619355f101cf3cb9baec289fcd9fd51486655c1bb8a8",
        "type": "DEPLOY_ACCOUNT"
    }"#;

    #[tokio::test]
    async fn test_parse_input_named() {
        let json = format!("{{\"deploy_account_transaction\":{INPUT_JSON}}}");
        let input: AddDeployAccountTransactionInput =
            serde_json::from_str(&json).expect("parse named input");

        assert_eq!(input, get_input());
    }

    #[tokio::test]
    async fn test_parse_input_positional() {
        let json = format!("[{INPUT_JSON}]");
        let input: AddDeployAccountTransactionInput =
            serde_json::from_str(&json).expect("parse positional input");

        assert_eq!(input, get_input());
    }

    fn get_input() -> AddDeployAccountTransactionInput {
        AddDeployAccountTransactionInput {
            deploy_account_transaction: Transaction::DeployAccount(
                BroadcastedDeployAccountTransaction {
                    version: TransactionVersion::ONE,
                    max_fee: Fee([
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0xf3,
                        0x91, 0x37, 0x78, 0x13,
                    ]
                    .into()),
                    signature: vec![
                        TransactionSignatureElem(felt!(
                            "07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5"
                        )),
                        TransactionSignatureElem(felt!(
                            "071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                        )),
                    ],
                    nonce: TransactionNonce::ZERO,

                    contract_address_salt: ContractAddressSalt(felt!(
                        "06d44a6aecb4339e23a9619355f101cf3cb9baec289fcd9fd51486655c1bb8a8"
                    )),
                    constructor_calldata: vec![CallParam(felt!(
                        "0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"
                    ))],
                    class_hash: ClassHash(felt!(
                        "01fac3074c9d5282f0acc5c69a4781a1c711efea5e73c550c5d9fb253cf7fd3d"
                    )),
                },
            ),
        }
    }

    #[tokio::test]
    #[ignore = "gateway 429"]
    async fn test_add_deploy_account_transaction() {
        let context = RpcContext::for_tests();

        let input = get_input();

        let expected = AddDeployAccountTransactionOutput {
            transaction_hash: StarknetTransactionHash(felt!(
                "0273FB3C38B20037839D6BAD8811CD0AFD82F2BC3C95C061EB8F30CE5CEDC377"
            )),
            contract_address: ContractAddress::new_or_panic(felt!(
                "042AE26AB2B8236242BB384C23E74C69AF7204BB2FC711A99DA63E0DD6ADF33F"
            )),
        };

        let response = add_deploy_account_transaction(context, input)
            .await
            .expect("add_deploy_account_transaction");

        assert_eq!(response, expected);
    }
}
