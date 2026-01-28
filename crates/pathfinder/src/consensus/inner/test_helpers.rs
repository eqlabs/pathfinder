//! Test helpers for consensus transaction testing
//!
//! This module provides utilities for creating realistic test transactions
//! and testing consensus scenarios with actual transaction execution.

use p2p_proto::common::{Address, L1DataAvailabilityMode};
use p2p_proto::consensus as proto_consensus;
use pathfinder_common::{ChainId, ContractAddress};
use pathfinder_crypto::Felt;

/// Creates a realistic L1Handler transaction for testing
pub fn create_l1_handler_transaction(
    index: usize,
    chain_id: ChainId,
) -> proto_consensus::Transaction {
    let nonce = Felt::from_hex_str(&format!("0x{index}")).unwrap();
    let address = Felt::from_hex_str(&format!("0x{index:x}")).unwrap();
    let entry_point_selector = Felt::from_hex_str(&format!("0x{index}")).unwrap();
    let calldata = vec![Felt::from_hex_str(&format!("0x{index}")).unwrap()];

    // Create the L1Handler transaction
    let txn = p2p_proto::consensus::TransactionVariant::L1HandlerV0(
        p2p_proto::transaction::L1HandlerV0 {
            nonce,
            address: Address(address),
            entry_point_selector,
            calldata: calldata.clone(),
        },
    );

    // Calculate the correct hash
    let l1_handler = pathfinder_common::transaction::L1HandlerTransaction {
        nonce: pathfinder_common::TransactionNonce(nonce),
        contract_address: ContractAddress::new_or_panic(address),
        entry_point_selector: pathfinder_common::EntryPoint(entry_point_selector),
        calldata: vec![pathfinder_common::CallParam(calldata[0])],
    };

    let hash = l1_handler.calculate_hash(chain_id);

    proto_consensus::Transaction {
        transaction_hash: p2p_proto::common::Hash(hash.0),
        txn,
    }
}

/// Creates a realistic L1Handler transaction for testing
///
/// `seed` is used to vary the transaction content independently of `index`, so
/// that we don't encounter duplicate transaction hashes across multiple
/// blocks.
pub fn create_l1_handler_transaction_0(
    seed: u32,
    index: usize,
    chain_id: ChainId,
) -> proto_consensus::Transaction {
    // base is a seed and index dependent value to avoid collisions but at the same
    // time easily allow to trace back which seed/index produced the transaction
    let base = index as u64 + ((seed as u64) << 32);
    let base = Felt::from_u64(base);

    // Create the L1Handler transaction
    let txn = p2p_proto::consensus::TransactionVariant::L1HandlerV0(
        p2p_proto::transaction::L1HandlerV0 {
            nonce: base,
            address: Address(base),
            entry_point_selector: base,
            calldata: vec![base],
        },
    );

    // Calculate the correct hash
    let l1_handler = pathfinder_common::transaction::L1HandlerTransaction {
        nonce: pathfinder_common::TransactionNonce(base),
        contract_address: ContractAddress::new_or_panic(base),
        entry_point_selector: pathfinder_common::EntryPoint(base),
        calldata: vec![pathfinder_common::CallParam(base)],
    };

    let hash = l1_handler.calculate_hash(chain_id);

    proto_consensus::Transaction {
        transaction_hash: p2p_proto::common::Hash(hash.0),
        txn,
    }
}

/// Creates a batch of transactions for testing
pub fn create_transaction_batch(
    start_index: usize,
    count: usize,
    chain_id: ChainId,
) -> Vec<proto_consensus::Transaction> {
    (start_index..start_index + count)
        .map(|i| create_l1_handler_transaction(i, chain_id))
        .collect()
}

/// Creates a batch of transactions for testing
pub fn create_transaction_batch_0(
    seed: u32,
    start_index: usize,
    count: usize,
    chain_id: ChainId,
) -> Vec<proto_consensus::Transaction> {
    (start_index..start_index + count)
        .map(|i| create_l1_handler_transaction_0(seed, i, chain_id))
        .collect()
}

/// Creates a test proposal with transactions
pub fn create_test_proposal(
    _chain_id: ChainId,
    height: u64,
    round: u32,
    proposer: ContractAddress,
    _transactions: Vec<proto_consensus::Transaction>,
) -> (proto_consensus::ProposalInit, proto_consensus::BlockInfo) {
    let proposer_address = Address(proposer.0);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let proposal_init = proto_consensus::ProposalInit {
        height,
        round,
        valid_round: None,
        proposer: proposer_address,
    };

    let block_info = proto_consensus::BlockInfo {
        height,
        timestamp,
        builder: proposer_address,
        l1_da_mode: L1DataAvailabilityMode::default(),
        l2_gas_price_fri: 1,
        l1_gas_price_wei: 1_000_000_000,
        l1_data_gas_price_wei: 1,
        eth_to_fri_rate: 1_000_000_000,
    };

    (proposal_init, block_info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_l1_handler_transaction() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let tx = create_l1_handler_transaction(1, chain_id);

        // Verify the transaction has a valid hash
        assert!(!tx.transaction_hash.0.is_zero());

        // Verify it's an L1Handler transaction
        match tx.txn {
            proto_consensus::TransactionVariant::L1HandlerV0(_) => {}
            _ => panic!("Expected L1Handler transaction"),
        }
    }

    #[test]
    fn test_create_transaction_batch() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let batch = create_transaction_batch(10, 5, chain_id);

        assert_eq!(batch.len(), 5);

        // Verify all transactions have different hashes
        let hashes: std::collections::HashSet<_> =
            batch.iter().map(|tx| tx.transaction_hash.0).collect();
        assert_eq!(hashes.len(), 5); // All unique
    }

    #[test]
    fn test_create_test_proposal() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let height = 100;
        let round = 1;
        let proposer = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let transactions = create_transaction_batch(1, 3, chain_id);

        let (proposal_init, block_info) =
            create_test_proposal(chain_id, height, round, proposer, transactions);

        assert_eq!(proposal_init.height, height);
        assert_eq!(proposal_init.round, round);
        assert_eq!(block_info.height, height);
        assert_eq!(block_info.builder.0, proposer.0);
    }
}
