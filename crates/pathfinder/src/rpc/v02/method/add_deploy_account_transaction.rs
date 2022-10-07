use anyhow::Context;
use serde_with::serde_as;

use crate::rpc::serde::{FeeAsHexStr, TransactionVersionAsHexStr};
use crate::{
    core::{
        CallParam, ClassHash, ContractAddress, ContractAddressSalt, Fee, StarknetTransactionHash,
        TransactionNonce, TransactionSignatureElem, TransactionVersion,
    },
    rpc::v02::RpcContext,
    sequencer::ClientApi,
};

const fn transaction_version_zero() -> TransactionVersion {
    TransactionVersion(web3::types::H256::zero())
}

#[serde_as]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AddDeployAccountTransactionInput {
    // Fields from BROADCASTED_TXN_COMMON_PROPERTIES
    #[serde_as(as = "TransactionVersionAsHexStr")]
    #[serde(default = "transaction_version_zero")]
    pub version: TransactionVersion,
    #[serde_as(as = "FeeAsHexStr")]
    pub max_fee: Fee,
    pub signature: Vec<TransactionSignatureElem>,
    pub nonce: TransactionNonce,

    // Fields from DEPLOY_ACCOUNT_TXN_PROPERTIES
    pub contract_address_salt: ContractAddressSalt,
    pub constructor_calldata: Vec<CallParam>,
    pub class_hash: ClassHash,
}

#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub struct AddDeployAccountTransactionOutput {
    transaction_hash: StarknetTransactionHash,
    contract_address: ContractAddress,
}

crate::rpc::error::generate_rpc_error_subset!(AddDeployAccountTransactionError: ClassHashNotFound);

pub async fn add_deploy_account_transaction(
    context: RpcContext,
    input: AddDeployAccountTransactionInput,
) -> Result<AddDeployAccountTransactionOutput, AddDeployAccountTransactionError> {
    let response = context
        .sequencer
        .add_deploy_account(
            input.version,
            input.max_fee,
            input.signature,
            input.nonce,
            input.contract_address_salt,
            input.class_hash,
            input.constructor_calldata,
        )
        .await
        .context("Senging Deplpy Account Transaction to the gateway")?;

    Ok(AddDeployAccountTransactionOutput {
        transaction_hash: response.transaction_hash,
        contract_address: response.address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{core::Chain, starkhash};

    #[tokio::test]
    async fn test_add_deploy_account_transaction() {
        // Fall-back to RpcContext::for_tests() once 0.10.1 hits TestNet.
        let context = RpcContext::for_tests_on(Chain::Integration);

        let input = AddDeployAccountTransactionInput {
            version: TransactionVersion::ONE,
            max_fee: Fee([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0xf3, 0x91, 0x37,
                0x78, 0x13,
            ]
            .into()),
            signature: vec![
                TransactionSignatureElem(starkhash!(
                    "07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5"
                )),
                TransactionSignatureElem(starkhash!(
                    "071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                )),
            ],
            nonce: TransactionNonce::ZERO,

            contract_address_salt: ContractAddressSalt(starkhash!(
                "06d44a6aecb4339e23a9619355f101cf3cb9baec289fcd9fd51486655c1bb8a8"
            )),
            constructor_calldata: vec![CallParam(starkhash!(
                "0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"
            ))],
            class_hash: ClassHash(starkhash!(
                "01fac3074c9d5282f0acc5c69a4781a1c711efea5e73c550c5d9fb253cf7fd3d"
            )),
        };

        let expected = AddDeployAccountTransactionOutput {
            transaction_hash: StarknetTransactionHash(starkhash!(
                "0273FB3C38B20037839D6BAD8811CD0AFD82F2BC3C95C061EB8F30CE5CEDC377"
            )),
            contract_address: ContractAddress::new_or_panic(starkhash!(
                "042AE26AB2B8236242BB384C23E74C69AF7204BB2FC711A99DA63E0DD6ADF33F"
            )),
        };

        let response = add_deploy_account_transaction(context, input)
            .await
            .expect("add_deploy_account_transaction");

        assert_eq!(response, expected);
    }
}
