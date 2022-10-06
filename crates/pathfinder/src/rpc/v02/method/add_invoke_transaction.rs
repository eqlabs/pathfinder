use anyhow::Context;

use crate::core::StarknetTransactionHash;
use crate::rpc::v02::types::request::BroadcastedInvokeTransaction;
use crate::rpc::v02::RpcContext;
use crate::sequencer::ClientApi;

crate::rpc::error::generate_rpc_error_subset!(AddInvokeTransactionError);

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct AddInvokeTransactionInput {
    invoke_transaction: BroadcastedInvokeTransaction,
}

#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub struct AddInvokeTransactionOutput {
    transaction_hash: StarknetTransactionHash,
}

pub async fn add_invoke_transaction(
    context: RpcContext,
    input: AddInvokeTransactionInput,
) -> Result<AddInvokeTransactionOutput, AddInvokeTransactionError> {
    let response = match input.invoke_transaction {
        BroadcastedInvokeTransaction::V0(v0) => context
            .sequencer
            .add_invoke_transaction(
                v0.version,
                v0.max_fee,
                v0.signature,
                // Nonce is part of the RPC specification for V0 but this
                // is a bug in the spec. The gateway won't accept it, so
                // we null it out.
                None,
                v0.contract_address,
                Some(v0.entry_point_selector),
                v0.calldata,
            )
            .await
            .context("Sending V0 invoke transaction to gateway")?,
        BroadcastedInvokeTransaction::V1(v1) => context
            .sequencer
            .add_invoke_transaction(
                v1.version,
                v1.max_fee,
                v1.signature,
                Some(v1.nonce),
                v1.sender_address,
                None,
                v1.calldata,
            )
            .await
            .context("Sending V1 invoke transaction to gateway")?,
    };

    Ok(AddInvokeTransactionOutput {
        transaction_hash: response.transaction_hash,
    })
}

#[cfg(test)]
mod tests {
    use crate::core::{
        CallParam, ContractAddress, EntryPoint, Fee, TransactionNonce, TransactionSignatureElem,
        TransactionVersion,
    };
    use crate::starkhash;

    use super::*;

    #[tokio::test]
    async fn invoke_v0() {
        use crate::rpc::v02::types::request::BroadcastedInvokeTransactionV0;

        let context = RpcContext::for_tests();
        let input = BroadcastedInvokeTransactionV0 {
            version: TransactionVersion::ZERO,
            max_fee: Fee(5444010076217u128.to_be_bytes().into()),
            signature: vec![
                TransactionSignatureElem(starkhash!(
                    "07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5"
                )),
                TransactionSignatureElem(starkhash!(
                    "071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                )),
            ],
            nonce: None,
            contract_address: ContractAddress::new_or_panic(starkhash!(
                "023371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd"
            )),
            entry_point_selector: EntryPoint(starkhash!(
                "015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"
            )),
            calldata: vec![
                CallParam(starkhash!("01")),
                CallParam(starkhash!(
                    "0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"
                )),
                CallParam(starkhash!(
                    "0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"
                )),
                CallParam(starkhash!("00")),
                CallParam(starkhash!("01")),
                CallParam(starkhash!("01")),
                CallParam(starkhash!("2b")),
                CallParam(starkhash!("00")),
            ],
        };
        let input = AddInvokeTransactionInput {
            invoke_transaction: BroadcastedInvokeTransaction::V0(input),
        };
        let expected = AddInvokeTransactionOutput {
            transaction_hash: StarknetTransactionHash(starkhash!(
                "0389dd0629f42176cc8b6c43acefc0713d0064ecdfc0470e0fc179f53421a38b"
            )),
        };

        let result = add_invoke_transaction(context, input).await.unwrap();
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn invoke_v1() {
        use crate::rpc::v02::types::request::BroadcastedInvokeTransactionV1;

        let context = RpcContext::for_tests();
        let input = BroadcastedInvokeTransactionV1 {
            version: TransactionVersion::ONE,
            max_fee: Fee(web3::types::H128::from_low_u64_be(0x630a0aff77)),
            signature: vec![
                TransactionSignatureElem(starkhash!(
                    "07ccc81b438581c9360120e0ba0ef52c7d031bdf20a4c2bc3820391b29a8945f"
                )),
                TransactionSignatureElem(starkhash!(
                    "02c11c60d11daaa0043eccdc824bb44f87bc7eb2e9c2437e1654876ab8fa7cad"
                )),
            ],
            nonce: TransactionNonce(starkhash!("02")),
            sender_address: ContractAddress::new_or_panic(starkhash!(
                "03fdcbeb68e607c8febf01d7ef274cbf68091a0bd1556c0b8f8e80d732f7850f"
            )),
            calldata: vec![
                CallParam(starkhash!("01")),
                CallParam(starkhash!(
                    "01d809111da75d5e735b6f9573a1ddff78fb6ff7633a0b34273e0c5ddeae349a"
                )),
                CallParam(starkhash!(
                    "0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"
                )),
                CallParam(starkhash!("00")),
                CallParam(starkhash!("01")),
                CallParam(starkhash!("01")),
                CallParam(starkhash!("01")),
            ],
        };

        let input = AddInvokeTransactionInput {
            invoke_transaction: BroadcastedInvokeTransaction::V1(input),
        };
        let expected = AddInvokeTransactionOutput {
            transaction_hash: StarknetTransactionHash(starkhash!(
                "040397a2e590c9707d73cc63ec54683c2d155b65d2e990d6f53d48a395eb3997"
            )),
        };

        let result = add_invoke_transaction(context, input).await.unwrap();
        assert_eq!(result, expected);
    }
}
