use crate::{
    context::RpcContext,
    v05::method::estimate_fee::FeeEstimate,
    v06::method::estimate_message_fee::{EstimateMessageFeeError, EstimateMessageFeeInput},
};

pub async fn estimate_message_fee(
    context: RpcContext,
    input: EstimateMessageFeeInput,
) -> Result<FeeEstimate, EstimateMessageFeeError> {
    let result =
        crate::v06::method::estimate_message_fee::estimate_message_fee_impl(context, input).await?;

    Ok(FeeEstimate {
        gas_consumed: result.gas_consumed,
        gas_price: result.gas_price,
        overall_fee: result.overall_fee,
    })
}

#[cfg(test)]
mod tests {
    use pathfinder_common::{
        felt, BlockHash, BlockHeader, BlockId, BlockNumber, BlockTimestamp, GasPrice, StateUpdate,
    };
    use pathfinder_common::{macro_prelude::*, EthereumAddress};
    use pathfinder_storage::{JournalMode, Storage};
    use primitive_types::H160;
    use serde::Deserialize;
    use starknet_gateway_test_fixtures::class_definitions::{
        CAIRO_1_1_0_BALANCE_CASM_JSON, CAIRO_1_1_0_BALANCE_SIERRA_JSON,
    };
    use tempfile::tempdir;

    use crate::v06::method::estimate_message_fee::MsgFromL1;

    use super::*;

    #[test]
    fn test_parse_input_named() {
        let input_json = serde_json::json!({
            "message": {
                "to_address": "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
                "entry_point_selector": "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01",
                "payload": ["0x1", "0x2"],
                "from_address": "0x0000000000000000000000000000000000000000"
            },
            "block_id": {"block_number": 1},
        });
        let input = EstimateMessageFeeInput::deserialize(&input_json).unwrap();

        assert_eq!(
            input,
            EstimateMessageFeeInput {
                message: MsgFromL1 {
                    to_address: contract_address!(
                        "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                    ),
                    entry_point_selector: entry_point!(
                        "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01"
                    ),
                    payload: vec![call_param!("0x1"), call_param!("0x2"),],
                    from_address: EthereumAddress(H160::zero()),
                },
                block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
            }
        );
    }

    #[test]
    fn test_parse_input_positional() {
        let input_json = serde_json::json!([
            {
                "to_address": "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
                "entry_point_selector": "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01",
                "payload": ["0x1", "0x2"],
                "from_address": "0x0000000000000000000000000000000000000000"
            },
            {"block_number": 1},
        ]);
        let input = EstimateMessageFeeInput::deserialize(&input_json).unwrap();

        assert_eq!(
            input,
            EstimateMessageFeeInput {
                message: MsgFromL1 {
                    to_address: contract_address!(
                        "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                    ),
                    entry_point_selector: entry_point!(
                        "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01"
                    ),
                    payload: vec![call_param!("0x1"), call_param!("0x2"),],
                    from_address: EthereumAddress(H160::zero()),
                },
                block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
            }
        );
    }

    enum Setup {
        Full,
        SkipBlock,
        SkipContract,
    }

    async fn setup(mode: Setup) -> anyhow::Result<RpcContext> {
        let dir = tempdir().expect("tempdir");
        let mut db_path = dir.path().to_path_buf();
        db_path.push("db.sqlite");

        let storage = Storage::migrate(db_path, JournalMode::WAL, 1)
            .expect("storage")
            .create_pool(std::num::NonZeroU32::new(1).expect("one"))
            .expect("storage");

        {
            let mut db = storage.connection().expect("db connection");
            let tx = db.transaction().expect("tx");

            let class_hash =
                class_hash!("0x0484c163658bcce5f9916f486171ac60143a92897533aa7ff7ac800b16c63311");
            tx.insert_sierra_class(
                &sierra_hash!("0x0484c163658bcce5f9916f486171ac60143a92897533aa7ff7ac800b16c63311"),
                CAIRO_1_1_0_BALANCE_SIERRA_JSON,
                &casm_hash!("0x0484c163658bcce5f9916f486171ac60143a92897533aa7ff7ac800b16c63311"),
                CAIRO_1_1_0_BALANCE_CASM_JSON,
            )
            .expect("insert class");

            let block1_number = BlockNumber::GENESIS + 1;
            let block1_hash = BlockHash(felt!("0xb01"));

            if !matches!(mode, Setup::SkipBlock) {
                let header = BlockHeader::builder()
                    .with_number(BlockNumber::GENESIS)
                    .with_timestamp(BlockTimestamp::new_or_panic(0))
                    .finalize_with_hash(BlockHash(felt!("0xb00")));
                tx.insert_block_header(&header).unwrap();

                let header = BlockHeader::builder()
                    .with_number(block1_number)
                    .with_timestamp(BlockTimestamp::new_or_panic(1))
                    .with_eth_l1_gas_price(GasPrice(1))
                    .finalize_with_hash(block1_hash);
                tx.insert_block_header(&header).unwrap();
            }

            if !matches!(mode, Setup::SkipBlock | Setup::SkipContract) {
                let contract_address = contract_address!(
                    "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                );
                let state_update =
                    StateUpdate::default().with_deployed_contract(contract_address, class_hash);
                tx.insert_state_update(block1_number, &state_update)
                    .unwrap();
            }

            tx.commit().unwrap();
        }

        let rpc = RpcContext::for_tests().with_storage(storage);

        Ok(rpc)
    }

    fn input() -> EstimateMessageFeeInput {
        EstimateMessageFeeInput {
            message: MsgFromL1 {
                to_address: contract_address!(
                    "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                ),
                entry_point_selector: entry_point!(
                    "0x31ee153a27e249dc4bade6b861b37ef1e1ea0a4c0bf73b7405a02e9e72f7be3"
                ),
                payload: vec![call_param!("0x1")],
                from_address: EthereumAddress(H160::zero()),
            },
            block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
        }
    }

    #[tokio::test]
    async fn test_estimate_message_fee() {
        let expected = FeeEstimate {
            gas_consumed: 16302.into(),
            gas_price: 1.into(),
            overall_fee: 16302.into(),
        };

        let rpc = setup(Setup::Full).await.expect("RPC context");
        let result = estimate_message_fee(rpc, input()).await.expect("result");
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_error_missing_contract() {
        let rpc = setup(Setup::SkipContract).await.expect("RPC context");
        assert_matches::assert_matches!(
            estimate_message_fee(rpc, input()).await,
            Err(EstimateMessageFeeError::ContractNotFound)
        );
    }

    #[tokio::test]
    async fn test_error_missing_block() {
        let rpc = setup(Setup::SkipBlock).await.expect("RPC context");
        assert_matches::assert_matches!(
            estimate_message_fee(rpc, input()).await,
            Err(EstimateMessageFeeError::BlockNotFound)
        );
    }

    #[tokio::test]
    async fn test_error_invalid_selector() {
        let mut input = input();
        let invalid_selector = entry_point!("0xDEADBEEF");
        input.message.entry_point_selector = invalid_selector;

        let rpc = setup(Setup::Full).await.expect("RPC context");
        assert_matches::assert_matches!(
            estimate_message_fee(rpc, input).await,
            Err(EstimateMessageFeeError::ContractErrorV05 { .. })
        );
    }
}
