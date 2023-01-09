use goose::prelude::*;
use rand::{Rng, SeedableRng};
use stark_hash::Felt;

use crate::requests::v02::*;

/// Fetch a random block, then fetch all individual transactions and receipts in the block.
pub async fn block_explorer(user: &mut GooseUser) -> TransactionResult {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let block_number: u64 = rng.gen_range(1..1800);

    let block = get_block_by_number(user, block_number).await?;
    let block_by_hash = get_block_by_hash(user, block.block_hash).await?;
    assert_eq!(block, block_by_hash);

    let state_update = get_state_update(user, block.block_hash).await?;
    assert_eq!(state_update.block_hash, block.block_hash);

    for (idx, hash) in block.transactions.iter().enumerate() {
        let transaction = get_transaction_by_hash(user, *hash).await?;

        let transaction_by_hash_and_index =
            get_transaction_by_block_hash_and_index(user, block.block_hash, idx).await?;
        assert_eq!(transaction, transaction_by_hash_and_index);

        let transaction_by_number_and_index =
            get_transaction_by_block_number_and_index(user, block.block_number, idx).await?;
        assert_eq!(transaction, transaction_by_number_and_index);

        let _receipt = get_transaction_receipt_by_hash(user, *hash).await?;
    }

    Ok(())
}

pub async fn task_block_by_number(user: &mut GooseUser) -> TransactionResult {
    get_block_by_number(user, 1000).await?;
    Ok(())
}

pub async fn task_block_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_block_by_hash(
        user,
        Felt::from_hex_str("0x58d8604f22510af5b120d1204ebf25292a79bfb09c4882c2e456abc2763d4a")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_state_update_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_state_update(
        user,
        Felt::from_hex_str("0x58d8604f22510af5b120d1204ebf25292a79bfb09c4882c2e456abc2763d4a")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_class_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_class(
        user,
        Felt::from_hex_str("0x037cb14332210a0eb0088c914d6516bae855c0012f499cef87f2109566180a8e")
            .unwrap(),
        Felt::from_hex_str("0x02cdf5ac65a41b135969dcefa9d52799a48994d4d3aee24732b78580a9fa7c63")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_class_hash_at(user: &mut GooseUser) -> TransactionResult {
    get_class_hash_at(
        user,
        Felt::from_hex_str("0x037cb14332210a0eb0088c914d6516bae855c0012f499cef87f2109566180a8e")
            .unwrap(),
        Felt::from_hex_str("0x00da8054260ec00606197a4103eb2ef08d6c8af0b6a808b610152d1ce498f8c3")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_class_at(user: &mut GooseUser) -> TransactionResult {
    get_class_at(
        user,
        Felt::from_hex_str("0x037cb14332210a0eb0088c914d6516bae855c0012f499cef87f2109566180a8e")
            .unwrap(),
        Felt::from_hex_str("0x00da8054260ec00606197a4103eb2ef08d6c8af0b6a808b610152d1ce498f8c3")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_block_transaction_count_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_block_transaction_count_by_hash(
        user,
        Felt::from_hex_str("0x58d8604f22510af5b120d1204ebf25292a79bfb09c4882c2e456abc2763d4a")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_block_transaction_count_by_number(user: &mut GooseUser) -> TransactionResult {
    get_block_transaction_count_by_number(user, 1000).await?;
    Ok(())
}

pub async fn task_transaction_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_transaction_by_hash(
        user,
        Felt::from_hex_str("0x39ee26a0251338f1ef96b66c0ffacbc7a41f36bd465055e39621673ff10fb60")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_transaction_by_block_number_and_index(user: &mut GooseUser) -> TransactionResult {
    get_transaction_by_block_number_and_index(user, 1000, 3).await?;
    Ok(())
}

pub async fn task_transaction_by_block_hash_and_index(user: &mut GooseUser) -> TransactionResult {
    get_transaction_by_block_hash_and_index(
        user,
        Felt::from_hex_str("0x58d8604f22510af5b120d1204ebf25292a79bfb09c4882c2e456abc2763d4a")
            .unwrap(),
        3,
    )
    .await?;
    Ok(())
}

pub async fn task_transaction_receipt_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_transaction_receipt_by_hash(
        user,
        Felt::from_hex_str("0x39ee26a0251338f1ef96b66c0ffacbc7a41f36bd465055e39621673ff10fb60")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_block_number(user: &mut GooseUser) -> TransactionResult {
    block_number(user).await?;
    Ok(())
}

pub async fn task_syncing(user: &mut GooseUser) -> TransactionResult {
    syncing(user).await?;
    Ok(())
}

pub async fn task_call(user: &mut GooseUser) -> TransactionResult {
    // call a test contract deployed in block 0
    // https://voyager.online/contract/0x06ee3440b08a9c805305449ec7f7003f27e9f7e287b83610952ec36bdc5a6bae
    call(
        user,
        Felt::from_hex_str("0x06ee3440b08a9c805305449ec7f7003f27e9f7e287b83610952ec36bdc5a6bae")
            .unwrap(),
        &[
            // address
            "0x01e2cd4b3588e8f6f9c4e89fb0e293bf92018c96d7a93ee367d29a284223b6ff",
            // value
            "0x071d1e9d188c784a0bde95c1d508877a0d93e9102b37213d1e13f3ebc54a7751",
        ],
        // "set_value" entry point
        "0x3d7905601c217734671143d457f0db37f7f8883112abd34b92c4abfeafde0c3",
        // hash of mainnet block 0
        Felt::from_hex_str("0x47c3637b57c2b079b93c61539950c17e868a28f46cdef28f88521067f21e943")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_estimate_fee(user: &mut GooseUser) -> TransactionResult {
    // estimate invoke on a test contract deployed in block 0
    // https://voyager.online/contract/0x06ee3440b08a9c805305449ec7f7003f27e9f7e287b83610952ec36bdc5a6bae
    estimate_fee_for_invoke(
        user,
        Felt::from_hex_str("0x06ee3440b08a9c805305449ec7f7003f27e9f7e287b83610952ec36bdc5a6bae")
            .unwrap(),
        &[
            // address
            Felt::from_hex_str(
                "0x01e2cd4b3588e8f6f9c4e89fb0e293bf92018c96d7a93ee367d29a284223b6ff",
            )
            .unwrap(),
            // value
            Felt::from_hex_str(
                "0x071d1e9d188c784a0bde95c1d508877a0d93e9102b37213d1e13f3ebc54a7751",
            )
            .unwrap(),
        ],
        // "set_value" entry point
        Felt::from_hex_str("0x3d7905601c217734671143d457f0db37f7f8883112abd34b92c4abfeafde0c3")
            .unwrap(),
        Felt::ZERO,
        // hash of mainnet block 0
        Felt::from_hex_str("0x47c3637b57c2b079b93c61539950c17e868a28f46cdef28f88521067f21e943")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_chain_id(user: &mut GooseUser) -> TransactionResult {
    chain_id(user).await?;
    Ok(())
}

pub async fn task_get_events(user: &mut GooseUser) -> TransactionResult {
    // This returns a single event.
    let events = get_events(
        user,
        EventFilter {
            from_block: Some(1000),
            to_block: Some(1100),
            address: Some(
                Felt::from_hex_str(
                    "0x103114c4c5ac233a360d39a9217b9067be6979f3d08e1cf971fd22baf8f8713",
                )
                .unwrap(),
            ),
            keys: vec![],
            page_size: 1024,
            page_number: 0,
        },
    )
    .await?;

    assert_eq!(events.events.len(), 1);

    Ok(())
}

pub async fn task_get_storage_at(user: &mut GooseUser) -> TransactionResult {
    // Taken from:
    // https://alpha-mainnet.starknet.io/feeder_gateway/get_state_update?blockNumber=1700
    //
    // "block_hash": "0x58cfbc4ebe276882a28badaa9fe0fb545cba57314817e5f229c2c9cf1f7cc87"
    //
    // "storage_diffs": {"0x27a761524e94ed6d0c882e232bb4d34f12aae1b906e29c62dc682b526349056":
    // [{"key": "0x79deb98f1f7fc9a64df7073f93ce645a5f6a7588c34773ba76fdc879a2346e1",
    // "value": "0x44054cde571399c485119e55cf0b9fc7dcc151fb3486f70020d3ee4d7b20f8d"}]
    get_storage_at(
        user,
        Felt::from_hex_str("0x27a761524e94ed6d0c882e232bb4d34f12aae1b906e29c62dc682b526349056")
            .unwrap(),
        Felt::from_hex_str("0x79deb98f1f7fc9a64df7073f93ce645a5f6a7588c34773ba76fdc879a2346e1")
            .unwrap(),
        Felt::from_hex_str("0x58cfbc4ebe276882a28badaa9fe0fb545cba57314817e5f229c2c9cf1f7cc87")
            .unwrap(),
    )
    .await?;
    Ok(())
}
