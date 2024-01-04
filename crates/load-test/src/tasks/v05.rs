use goose::prelude::*;
use pathfinder_crypto::Felt;
use rand::{Rng, SeedableRng};

use crate::requests::v05::*;

/// Fetch a random block, then fetch all individual transactions and receipts in the block.
pub async fn block_explorer(user: &mut GooseUser) -> TransactionResult {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let block_number: u64 = rng.gen_range(1..290000);

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
        Felt::from_hex_str("0x02c3adae98c15fb062687afb51f8a950b4e59d996e303e073c098b2adc61003d")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_state_update_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_state_update(
        user,
        Felt::from_hex_str("0x02c3adae98c15fb062687afb51f8a950b4e59d996e303e073c098b2adc61003d")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_class_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_class(
        user,
        Felt::from_hex_str("0x010d0c5c9ed1d31eb4f63aeed292433189c0684ed911cf7cf2f7fb00c055855e")
            .unwrap(),
        Felt::from_hex_str("0x019d709fa1783cf5533cc66827b0df9993a4252cb510aff36d4e9576dd63daea")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_class_hash_at(user: &mut GooseUser) -> TransactionResult {
    get_class_hash_at(
        user,
        Felt::from_hex_str("0x010d0c5c9ed1d31eb4f63aeed292433189c0684ed911cf7cf2f7fb00c055855e")
            .unwrap(),
        Felt::from_hex_str("0x019d709fa1783cf5533cc66827b0df9993a4252cb510aff36d4e9576dd63daea")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_class_at(user: &mut GooseUser) -> TransactionResult {
    get_class_at(
        user,
        Felt::from_hex_str("0x010d0c5c9ed1d31eb4f63aeed292433189c0684ed911cf7cf2f7fb00c055855e")
            .unwrap(),
        Felt::from_hex_str("0x019d709fa1783cf5533cc66827b0df9993a4252cb510aff36d4e9576dd63daea")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_block_transaction_count_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_block_transaction_count_by_hash(
        user,
        Felt::from_hex_str("0x02c3adae98c15fb062687afb51f8a950b4e59d996e303e073c098b2adc61003d")
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
        Felt::from_hex_str("0x042278d003d257ca86fffd97e3e59dc435afe3771ee5b233a8ffad10e7eb8abd")
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
        Felt::from_hex_str("0x02c3adae98c15fb062687afb51f8a950b4e59d996e303e073c098b2adc61003d")
            .unwrap(),
        3,
    )
    .await?;
    Ok(())
}

pub async fn task_transaction_receipt_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_transaction_receipt_by_hash(
        user,
        Felt::from_hex_str("0x042278d003d257ca86fffd97e3e59dc435afe3771ee5b233a8ffad10e7eb8abd")
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
    call(
        user,
        Felt::from_hex_str("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
            .unwrap(),
        &[
            // account contract address
            "0x01518e1e27ad1bde8b2d7b83c68be6fb417f2135cb7683ff8af4ce62c830c3c9",
        ],
        // "balanceOf" entry point
        "0x2e4263afad30923c891518314c3c95dbe830a16874e8abc5777a9a20b54c76e",
    )
    .await?;
    Ok(())
}

pub async fn task_estimate_fee(user: &mut GooseUser) -> TransactionResult {
    // estimate invoke on a test contract deployed in block 0
    // https://voyager.online/contract/0x06ee3440b08a9c805305449ec7f7003f27e9f7e287b83610952ec36bdc5a6bae
    estimate_fee_for_invoke(
        user,
        Felt::from_hex_str("0x040cc450c7078f03db6a404eb506e2e99f76a4d772f8b4a62a7bd41c5bdfea42")
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
        // hash of testnet block 0
        Felt::from_hex_str("0x07d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b")
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
            from_block: Some(927800),
            to_block: Some(927900),
            address: Some(
                Felt::from_hex_str(
                    "0x02aa71f660f517253c94aeb16e3a0fdbb6540e10606b6c006c21b8929f320095",
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
    get_storage_at(
        user,
        Felt::from_hex_str("0x02aa71f660f517253c94aeb16e3a0fdbb6540e10606b6c006c21b8929f320095")
            .unwrap(),
        Felt::from_hex_str("0x03a858959e825b7a94eb8d55c738f59c7bf4685267af5064bed5fd9c6bbc26de")
            .unwrap(),
        Felt::from_hex_str("0x06dc3f487f80d284214da146af75402a7612d15c197354413cbd6192e8bd977c")
            .unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn task_get_nonce(user: &mut GooseUser) -> TransactionResult {
    let _ = get_nonce(
        user,
        Felt::from_hex_str("0x0117f284fdf09ed10a9ee3f435926d7066191ff7ab437b0c7e284817a677fa5f")
            .unwrap(),
    )
    .await?;

    Ok(())
}
