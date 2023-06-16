use crate::{
    context::RpcContext,
    v02::{method::call::FunctionCall, types::reply::FeeEstimate},
};
use pathfinder_common::{BlockId, EthereumAddress};
use serde::Deserialize;

use super::common::prepare_handle_and_block;

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct EstimateMessageFeeInput {
    message: FunctionCall,
    sender_address: EthereumAddress,
    block_id: BlockId,
}

crate::error::generate_rpc_error_subset!(
    EstimateMessageFeeError: BlockNotFound,
    ContractNotFound,
    ContractError
);

impl From<crate::cairo::ext_py::CallFailure> for EstimateMessageFeeError {
    fn from(c: crate::cairo::ext_py::CallFailure) -> Self {
        use crate::cairo::ext_py::CallFailure::*;
        match c {
            NoSuchBlock => Self::BlockNotFound,
            NoSuchContract => Self::ContractNotFound,
            ExecutionFailed(_) | InvalidEntryPoint => Self::ContractError,
            Internal(_) | Shutdown => Self::Internal(anyhow::anyhow!("Internal error")),
        }
    }
}

pub async fn estimate_message_fee(
    context: RpcContext,
    input: EstimateMessageFeeInput,
) -> Result<FeeEstimate, EstimateMessageFeeError> {
    let (handle, gas_price, when, pending_timestamp, pending_update) =
        prepare_handle_and_block(&context, input.block_id).await?;

    let result = handle
        .estimate_message_fee(
            input.message.into(),
            when,
            gas_price,
            pending_update,
            pending_timestamp,
        )
        .await?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pathfinder_common::{
        felt, BlockHash, BlockHeader, BlockNumber, BlockTimestamp, CallParam, Chain, ClassHash,
        ContractAddress, EntryPoint, GasPrice,
    };
    use pathfinder_storage::{JournalMode, Storage};
    use primitive_types::{H160, H256};
    use starknet_gateway_test_fixtures::class_definitions::CAIRO_0_11_WITH_DECIMAL_ENTRY_POINT_OFFSET;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_parse_input_named() {
        let input_json = serde_json::json!({
            "message": {
                "contract_address": "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
                "entry_point_selector": "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01",
                "calldata": ["0x1", "0x2"],
            },
            "sender_address": "0x0000000000000000000000000000000000000000",
            "block_id": {"block_number": 1},
        });
        let input = EstimateMessageFeeInput::deserialize(&input_json).unwrap();

        assert_eq!(
            input,
            EstimateMessageFeeInput {
                message: FunctionCall {
                    contract_address: ContractAddress::new_or_panic(felt!(
                        "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                    )),
                    entry_point_selector: EntryPoint(felt!(
                        "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01"
                    )),
                    calldata: vec![CallParam(felt!("0x1")), CallParam(felt!("0x2")),],
                },
                sender_address: EthereumAddress(H160::zero()),
                block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
            }
        );
    }

    #[test]
    fn test_parse_input_positional() {
        let input_json = serde_json::json!([
            {
                "contract_address": "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
                "entry_point_selector": "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01",
                "calldata": ["0x1", "0x2"],
            },
            "0x0000000000000000000000000000000000000000",
            {"block_number": 1},
        ]);
        let input = EstimateMessageFeeInput::deserialize(&input_json).unwrap();

        assert_eq!(
            input,
            EstimateMessageFeeInput {
                message: FunctionCall {
                    contract_address: ContractAddress::new_or_panic(felt!(
                        "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                    )),
                    entry_point_selector: EntryPoint(felt!(
                        "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01"
                    )),
                    calldata: vec![CallParam(felt!("0x1")), CallParam(felt!("0x2")),],
                },
                sender_address: EthereumAddress(H160::zero()),
                block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
            }
        );
    }

    #[tokio::test]
    async fn test_estimate_message_fee() {
        let dir = tempdir().expect("tempdir");
        let mut db_path = dir.path().to_path_buf();
        db_path.push("db.sqlite");

        let storage = Storage::migrate(db_path, JournalMode::WAL).expect("storage");

        {
            let mut db = storage.connection().expect("db connection");
            let tx = db.transaction().expect("tx");

            let hash = ClassHash(felt!(
                "0x0484c163658bcce5f9916f486171ac60143a92897533aa7ff7ac800b16c63311"
            ));
            tx.insert_cairo_class(hash, CAIRO_0_11_WITH_DECIMAL_ENTRY_POINT_OFFSET)
                .expect("insert class");

            let header = BlockHeader::builder()
                .with_number(BlockNumber::GENESIS + 1)
                .with_timestamp(BlockTimestamp::new_or_panic(1))
                .with_gas_price(GasPrice(1))
                .finalize_with_hash(BlockHash::ZERO);

            tx.insert_block_header(&header).unwrap();

            let addr = ContractAddress::new_or_panic(felt!(
                "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
            ));
            tx.insert_contract_class_hash(BlockNumber::GENESIS + 1, addr, hash)
                .unwrap();

            tx.commit().unwrap();
        }

        let (call_handle, _join_handle) = crate::cairo::ext_py::start(
            storage.path().into(),
            std::num::NonZeroUsize::try_from(1).unwrap(),
            futures::future::pending(),
            Chain::Testnet,
        )
        .await
        .unwrap();

        let rpc = RpcContext::for_tests()
            .with_storage(storage)
            .with_call_handling(call_handle);

        let input = EstimateMessageFeeInput {
            message: FunctionCall {
                contract_address: ContractAddress::new_or_panic(felt!(
                    "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                )),
                entry_point_selector: EntryPoint(felt!(
                    "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01"
                )),
                calldata: vec![CallParam(felt!("0x1")), CallParam(felt!("0x2"))],
            },
            sender_address: EthereumAddress(H160::zero()),
            block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
        };

        let result = estimate_message_fee(rpc, input).await.expect("result");
        assert_eq!(
            result,
            FeeEstimate {
                gas_consumed: H256::from_str(
                    "0x000000000000000000000000000000000000000000000000000000000000479a"
                )
                .unwrap(),
                gas_price: H256::from_str(
                    "0x0000000000000000000000000000000000000000000000000000000000000001"
                )
                .unwrap(),
                overall_fee: H256::from_str(
                    "0x000000000000000000000000000000000000000000000000000000000000479a"
                )
                .unwrap(),
            }
        );
    }
}
