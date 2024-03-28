use crate::context::RpcContext;
use crate::v06::method::estimate_fee::FeeEstimate;
use crate::v06::method::estimate_message_fee as v06;

pub async fn estimate_message_fee(
    context: RpcContext,
    input: v06::EstimateMessageFeeInput,
) -> Result<FeeEstimate, v06::EstimateMessageFeeError> {
    let result = v06::estimate_message_fee_impl(
        context,
        input,
        pathfinder_executor::L1BlobDataAvailability::Enabled,
    )
    .await?;

    Ok(FeeEstimate {
        gas_consumed: result.gas_consumed,
        gas_price: result.gas_price,
        overall_fee: result.overall_fee,
        unit: result.unit.into(),
        data_gas_consumed: Some(result.data_gas_consumed),
        data_gas_price: Some(result.data_gas_price),
    })
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::prelude::*;
    use pathfinder_common::BlockId;
    use pathfinder_common::L1DataAvailabilityMode;
    use pathfinder_storage::{JournalMode, Storage};
    use primitive_types::H160;

    use crate::context::RpcContext;
    use crate::v06::method::estimate_fee::FeeEstimate;
    use crate::v06::method::estimate_message_fee::*;
    use crate::v06::types::PriceUnit;

    use pretty_assertions_sorted::assert_eq;

    enum Setup {
        Full,
        _SkipBlock,
        _SkipContract,
    }

    async fn setup(mode: Setup) -> anyhow::Result<RpcContext> {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut db_path = dir.path().to_path_buf();
        db_path.push("db.sqlite");

        let storage = Storage::migrate(db_path, JournalMode::WAL, 1)
            .expect("storage")
            .create_pool(std::num::NonZeroU32::new(1).expect("one"))
            .expect("storage");

        {
            let mut db = storage.connection().expect("db connection");
            let tx = db.transaction().expect("tx");

            let sierra_json = include_bytes!("../../../fixtures/contracts/l1_handler.json");
            let casm_json = include_bytes!("../../../fixtures/contracts/l1_handler.casm");

            let class_hash =
                class_hash!("0x032908a85d43275f8509ba5f2acae88811b293463a3521dc05ab06d534b40848");
            tx.insert_sierra_class(
                &SierraHash(class_hash.0),
                sierra_json,
                &casm_hash!("0x0564bc2cef7e8e8ded01da5999b2028ac5962669a12e12b33aee1b17b0332435"),
                casm_json,
            )
            .expect("insert class");

            let block1_number = BlockNumber::GENESIS + 1;
            let block1_hash = BlockHash(felt!("0xb01"));

            if !matches!(mode, Setup::_SkipBlock) {
                let header = BlockHeader::builder()
                    .with_number(BlockNumber::GENESIS)
                    .with_timestamp(BlockTimestamp::new_or_panic(0))
                    .with_l1_da_mode(pathfinder_common::L1DataAvailabilityMode::Blob)
                    .with_strk_l1_data_gas_price(GasPrice(0x10))
                    .with_eth_l1_data_gas_price(GasPrice(0x12))
                    .finalize_with_hash(BlockHash(felt!("0xb00")));
                tx.insert_block_header(&header).unwrap();

                let header = BlockHeader::builder()
                    .with_number(block1_number)
                    .with_timestamp(BlockTimestamp::new_or_panic(1))
                    .with_eth_l1_gas_price(GasPrice(2))
                    .with_eth_l1_data_gas_price(GasPrice(1))
                    .with_starknet_version(StarknetVersion::new(0, 13, 1, 0))
                    .with_l1_da_mode(L1DataAvailabilityMode::Blob)
                    .finalize_with_hash(block1_hash);
                tx.insert_block_header(&header).unwrap();
            }

            if !matches!(mode, Setup::_SkipBlock | Setup::_SkipContract) {
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
                entry_point_selector: EntryPoint::hashed(b"my_l1_handler"),
                payload: vec![call_param!("0xa")],
                from_address: EthereumAddress(H160::zero()),
            },
            block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
        }
    }

    #[tokio::test]
    async fn test_estimate_message_fee() {
        dbg!(EntryPoint::hashed(b"l1_handler"));

        let expected = FeeEstimate {
            gas_consumed: 14647.into(),
            gas_price: 2.into(),
            data_gas_consumed: Some(128.into()),
            data_gas_price: Some(1.into()),
            overall_fee: 29422.into(),
            unit: PriceUnit::Wei,
        };

        let rpc = setup(Setup::Full).await.expect("RPC context");
        let result = super::estimate_message_fee(rpc, input())
            .await
            .expect("result");
        assert_eq!(result, expected);
    }
}
