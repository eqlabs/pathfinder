use anyhow::Context;
use p2p_proto::consensus::ProposalPart;
use pathfinder_common::{ConsensusFinalizedL2Block, ContractAddress};
use pathfinder_storage::consensus::ConsensusTransaction;
use pathfinder_storage::StorageError;

use crate::consensus::inner::conv::{IntoModel, TryIntoDto};
use crate::consensus::inner::dto;

/// A wrapper around a consensus database transaction that provides
/// methods for persisting and retrieving proposal parts and finalized blocks.
pub struct ConsensusProposals<'tx> {
    tx: ConsensusTransaction<'tx>,
}

impl<'tx> ConsensusProposals<'tx> {
    /// Create a new `ConsensusProposals` wrapper around a transaction.
    pub fn new(tx: ConsensusTransaction<'tx>) -> Self {
        Self { tx }
    }

    /// Get a reference to the inner transaction.
    pub fn inner(&self) -> &ConsensusTransaction<'tx> {
        &self.tx
    }

    /// Commit the underlying transaction.
    pub fn commit(self) -> Result<(), StorageError> {
        self.tx
            .commit()
            .map_err(|e| e.with_context("Committing consensus proposals transaction"))
    }

    /// Persist proposal parts for a given height, round, and proposer.
    /// Returns `true` if an existing entry was updated, `false` if a new entry
    /// was created.
    pub fn persist_parts(
        &self,
        height: u64,
        round: u32,
        proposer: &ContractAddress,
        parts: &[ProposalPart],
    ) -> Result<bool, StorageError> {
        let serde_parts = parts
            .iter()
            .map(|p| dto::ProposalPart::try_into_dto(p.clone()))
            .collect::<Result<Vec<dto::ProposalPart>, _>>()?;
        let proposal_parts = dto::ProposalParts::V0(serde_parts);
        let buf = bincode::serde::encode_to_vec(proposal_parts, bincode::config::standard())
            .context("Serializing proposal parts")?;
        let updated =
            self.tx
                .persist_consensus_proposal_parts(height, round, proposer, &buf[..])?;
        Ok(updated)
    }

    /// Retrieve proposal parts that we created (where proposer == validator).
    pub fn own_parts(
        &self,
        height: u64,
        round: u32,
        validator: &ContractAddress,
    ) -> Result<Option<Vec<ProposalPart>>, StorageError> {
        if let Some(buf) = self
            .tx
            .own_consensus_proposal_parts(height, round, validator)?
        {
            let parts = Self::decode_proposal_parts(&buf[..])?;
            Ok(Some(parts))
        } else {
            Ok(None)
        }
    }

    /// Retrieve proposal parts from other validators (where proposer !=
    /// validator).
    pub fn foreign_parts(
        &self,
        height: u64,
        round: u32,
        validator: &ContractAddress,
    ) -> Result<Option<Vec<ProposalPart>>, StorageError> {
        if let Some(buf) = self
            .tx
            .foreign_consensus_proposal_parts(height, round, validator)?
        {
            let parts = Self::decode_proposal_parts(&buf[..])?;
            Ok(Some(parts))
        } else {
            Ok(None)
        }
    }

    /// Retrieve the last proposal parts for a given height from other
    /// validators. Returns the round number and the proposal parts.
    pub fn last_parts(
        &self,
        height: u64,
        validator: &ContractAddress,
    ) -> Result<Option<(u32, Vec<ProposalPart>)>, StorageError> {
        if let Some((round, buf)) = self.tx.last_consensus_proposal_parts(height, validator)? {
            let parts = Self::decode_proposal_parts(&buf[..])?;
            let last_round = round.try_into().context("Invalid round")?;
            Ok(Some((last_round, parts)))
        } else {
            Ok(None)
        }
    }

    /// Remove proposal parts for a given height and optionally a specific
    /// round. If `round` is `None`, all rounds for that height are removed.
    pub fn remove_parts(&self, height: u64, round: Option<u32>) -> Result<(), StorageError> {
        self.tx.remove_consensus_proposal_parts(height, round)
    }

    /// Persist a consensus-finalized block for a given height and round.
    /// Returns `true` if an existing entry was updated, `false` if a new entry
    /// was created.
    pub fn persist_consensus_finalized_block(
        &self,
        height: u64,
        round: u32,
        block: ConsensusFinalizedL2Block,
    ) -> Result<bool, StorageError> {
        let serde_block = dto::ConsensusFinalizedBlock::try_into_dto(block)?;
        let finalized_block = dto::PersistentConsensusFinalizedBlock::V0(serde_block);
        let buf = bincode::serde::encode_to_vec(finalized_block, bincode::config::standard())
            .context("Serializing finalized block")?;
        let updated = self
            .tx
            .persist_consensus_finalized_block(height, round, &buf[..])?;
        Ok(updated)
    }

    /// Read a consensus-finalized block for a given height and round.
    pub fn read_consensus_finalized_block(
        &self,
        height: u64,
        round: u32,
    ) -> Result<Option<ConsensusFinalizedL2Block>, StorageError> {
        if let Some(buf) = self.tx.read_consensus_finalized_block(height, round)? {
            let block = Self::decode_finalized_block(&buf[..])?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    /// Read a consensus-finalized block for a given height and highest round
    /// available. In practice this should be the only round left in the DB
    /// for that height.
    pub fn read_consensus_finalized_block_for_last_round(
        &self,
        height: u64,
    ) -> Result<Option<ConsensusFinalizedL2Block>, StorageError> {
        if let Some(buf) = self
            .tx
            .read_consensus_finalized_block_for_last_round(height)?
        {
            let block = Self::decode_finalized_block(&buf[..])?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    /// Remove all finalized blocks for the given height **except** the one from
    /// `commit_round`.
    pub fn remove_uncommitted_consensus_finalized_blocks(
        &self,
        height: u64,
        commit_round: u32,
    ) -> Result<(), StorageError> {
        self.tx
            .remove_uncommitted_consensus_finalized_blocks(height, commit_round)
    }

    /// Remove all finalized blocks for a given height.
    pub fn remove_consensus_finalized_blocks(&self, height: u64) -> Result<(), StorageError> {
        self.tx.remove_consensus_finalized_blocks(height)
    }

    fn decode_proposal_parts(buf: &[u8]) -> anyhow::Result<Vec<ProposalPart>> {
        let proposal_parts: dto::ProposalParts =
            bincode::serde::decode_from_slice(buf, bincode::config::standard())
                .context("Deserializing proposal parts")?
                .0;
        let dto::ProposalParts::V0(serde_parts) = proposal_parts;
        let parts = serde_parts.into_iter().map(|p| p.into_model()).collect();
        Ok(parts)
    }

    fn decode_finalized_block(buf: &[u8]) -> anyhow::Result<ConsensusFinalizedL2Block> {
        let persistent_block: dto::PersistentConsensusFinalizedBlock =
            bincode::serde::decode_from_slice(buf, bincode::config::standard())
                .context("Deserializing finalized block")?
                .0;
        let dto::PersistentConsensusFinalizedBlock::V0(dto_block) = persistent_block;
        Ok(dto_block.into_model())
    }
}

#[cfg(test)]
mod tests {
    use fake::{Fake, Faker};
    use p2p_proto::common::Address;
    use p2p_proto::consensus::{BlockInfo, ProposalInit};
    use pathfinder_common::prelude::*;
    use pathfinder_crypto::Felt;
    use pathfinder_storage::consensus::{ConsensusConnection, ConsensusStorage};

    use super::*;

    fn setup_test_db() -> (ConsensusStorage, ConsensusConnection) {
        let consensus_storage =
            ConsensusStorage::in_tempdir().expect("Failed to create temp database");
        let mut conn = consensus_storage.connection().unwrap();
        let tx = conn.transaction().unwrap();
        tx.ensure_consensus_proposals_table_exists().unwrap();
        tx.ensure_consensus_finalized_blocks_table_exists().unwrap();
        tx.commit().unwrap();
        (consensus_storage, conn)
    }

    fn create_test_proposal_parts(
        height: u64,
        round: u32,
        proposer: ContractAddress,
    ) -> Vec<ProposalPart> {
        let proposer_addr = Address(proposer.0);
        vec![
            ProposalPart::Init({
                let mut init: ProposalInit = Faker.fake();
                init.height = height;
                init.round = round;
                init.valid_round = None;
                init.proposer = proposer_addr;
                init
            }),
            ProposalPart::BlockInfo({
                let mut block_info: BlockInfo = Faker.fake();
                block_info.height = height;
                block_info.builder = proposer_addr;
                block_info
            }),
            ProposalPart::TransactionBatch(vec![]),
            ProposalPart::ExecutedTransactionCount(Faker.fake()),
            ProposalPart::Fin(Faker.fake()),
        ]
    }

    fn create_test_consensus_finalized_block(height: u64) -> ConsensusFinalizedL2Block {
        use pathfinder_common::{BlockNumber, ConsensusFinalizedBlockHeader};

        let mut header: ConsensusFinalizedBlockHeader = Faker.fake();
        header.number = BlockNumber::new_or_panic(height);

        ConsensusFinalizedL2Block {
            header,
            state_update: Faker.fake(),
            transactions_and_receipts: vec![],
            events: vec![],
        }
    }

    /// Tests that proposal parts can be persisted and retrieved as own parts
    /// within and across transactions.
    #[test]
    fn test_persist_and_retrieve_own_parts() {
        let (_storage, mut conn) = setup_test_db();
        let tx = conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(tx);

        let height = 100u64;
        let round = 1u32;
        let proposer = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let parts = create_test_proposal_parts(height, round, proposer);

        // Persist new parts
        let updated = proposals_db
            .persist_parts(height, round, &proposer, &parts)
            .unwrap();
        assert!(!updated, "Should return false for new entry");

        // Retrieve own parts (within same transaction)
        let retrieved = proposals_db.own_parts(height, round, &proposer).unwrap();
        assert!(retrieved.is_some(), "Should retrieve persisted parts");
        assert_eq!(
            retrieved.unwrap(),
            parts,
            "Retrieved parts should match persisted parts exactly"
        );

        // Commit transaction to verify persistence
        proposals_db.commit().unwrap();

        // Verify persistence across transactions
        let tx2 = conn.transaction().unwrap();
        let proposals_db2 = ConsensusProposals::new(tx2);
        let retrieved = proposals_db2.own_parts(height, round, &proposer).unwrap();
        assert!(
            retrieved.is_some(),
            "Should retrieve persisted parts after commit"
        );
        assert_eq!(retrieved.unwrap(), parts, "Parts should match after commit");
    }

    /// Tests that updating existing proposal parts with different data
    /// correctly replaces the old data.
    #[test]
    fn test_update_with_different_data() {
        let (_storage, mut conn) = setup_test_db();
        let tx = conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(tx);

        let height = 100u64;
        let round = 1u32;
        let proposer = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let initial_parts = create_test_proposal_parts(height, round, proposer);

        // Persist initial parts
        let updated = proposals_db
            .persist_parts(height, round, &proposer, &initial_parts)
            .unwrap();
        assert!(!updated, "Should return false for new entry");
        proposals_db.commit().unwrap();

        // Update with different parts (different proposer address in parts)
        let different_proposer =
            ContractAddress::new_or_panic(Felt::from_hex_str("0x999").unwrap());
        let different_parts = create_test_proposal_parts(height, round, different_proposer);

        let tx2 = conn.transaction().unwrap();
        let proposals_db2 = ConsensusProposals::new(tx2);
        let updated = proposals_db2
            .persist_parts(height, round, &proposer, &different_parts)
            .unwrap();
        assert!(updated, "Should return true for updated entry");
        proposals_db2.commit().unwrap();

        // Verify the update actually changed the data
        let tx3 = conn.transaction().unwrap();
        let proposals_db3 = ConsensusProposals::new(tx3);
        let retrieved = proposals_db3.own_parts(height, round, &proposer).unwrap();
        assert!(retrieved.is_some());
        let retrieved_parts = retrieved.unwrap();
        assert_eq!(
            retrieved_parts, different_parts,
            "Retrieved parts should match the updated data"
        );
        assert_ne!(
            retrieved_parts, initial_parts,
            "Retrieved parts should NOT match the original data"
        );
    }

    /// Tests that proposal parts from a different proposer can be retrieved as
    /// foreign parts but not as own parts.
    #[test]
    fn test_foreign_parts() {
        let (_storage, mut conn) = setup_test_db();
        let tx = conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(tx);

        let height = 100u64;
        let round = 1u32;
        let proposer = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let validator = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());
        let parts = create_test_proposal_parts(height, round, proposer);

        // Persist parts from a different proposer
        proposals_db
            .persist_parts(height, round, &proposer, &parts)
            .unwrap();

        // Commit to verify persistence
        proposals_db.commit().unwrap();

        // Retrieve as foreign parts (validator != proposer) in new transaction
        let tx2 = conn.transaction().unwrap();
        let proposals_db2 = ConsensusProposals::new(tx2);
        let foreign = proposals_db2
            .foreign_parts(height, round, &validator)
            .unwrap();
        assert!(foreign.is_some(), "Should retrieve foreign parts");
        assert_eq!(
            foreign.unwrap(),
            parts,
            "Retrieved foreign parts should match persisted parts exactly"
        );

        // Should not retrieve as own parts
        let own = proposals_db2.own_parts(height, round, &validator).unwrap();
        assert!(own.is_none(), "Should not retrieve as own parts");
    }

    /// Tests that when proposer equals validator, foreign_parts returns None
    /// but own_parts returns the parts. This prevents a validator from seeing
    /// their own proposals as "foreign" and ensures the two queries are
    /// mutually exclusive.
    #[test]
    fn test_foreign_parts_proposer_equals_validator() {
        let (_storage, mut conn) = setup_test_db();
        let tx = conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(tx);

        let height = 100u64;
        let round = 1u32;
        let proposer = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let parts = create_test_proposal_parts(height, round, proposer);

        // Persist parts
        proposals_db
            .persist_parts(height, round, &proposer, &parts)
            .unwrap();
        proposals_db.commit().unwrap();

        // Query foreign_parts with proposer == validator
        // Should return None (since it's not "foreign" - it's our own)
        let tx2 = conn.transaction().unwrap();
        let proposals_db2 = ConsensusProposals::new(tx2);
        let foreign = proposals_db2
            .foreign_parts(height, round, &proposer)
            .unwrap();
        assert!(
            foreign.is_none(),
            "Should return None when proposer == validator (not foreign)"
        );

        // But should retrieve as own parts
        let own = proposals_db2.own_parts(height, round, &proposer).unwrap();
        assert!(own.is_some(), "Should retrieve as own parts");
        assert_eq!(own.unwrap(), parts);
    }

    /// Tests that last_parts returns the highest round for a given height,
    /// handling both single and multiple rounds.
    #[test]
    fn test_last_parts() {
        let (_storage, mut conn) = setup_test_db();
        let tx = conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(tx);

        let height = 100u64;
        let validator = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());

        // Test 1: Single round - should return that round
        let proposer = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let parts1 = create_test_proposal_parts(height, 1, proposer);
        proposals_db
            .persist_parts(height, 1, &proposer, &parts1)
            .unwrap();
        proposals_db.commit().unwrap();

        let tx2 = conn.transaction().unwrap();
        let proposals_db2 = ConsensusProposals::new(tx2);
        let last = proposals_db2.last_parts(height, &validator).unwrap();
        assert!(
            last.is_some(),
            "Should retrieve last parts even with single round"
        );
        let (round, retrieved_parts) = last.unwrap();
        assert_eq!(round, 1, "Should return the only round");
        assert_eq!(retrieved_parts, parts1, "Retrieved parts should match");

        // Test 2: Multiple rounds - should return highest round
        let proposer2 = ContractAddress::new_or_panic(Felt::from_hex_str("0x789").unwrap());
        let parts2 = create_test_proposal_parts(height, 2, proposer2);
        proposals_db2
            .persist_parts(height, 2, &proposer2, &parts2)
            .unwrap();
        let proposer3 = ContractAddress::new_or_panic(Felt::from_hex_str("0x999").unwrap());
        let parts3 = create_test_proposal_parts(height, 3, proposer3);
        proposals_db2
            .persist_parts(height, 3, &proposer3, &parts3)
            .unwrap();
        proposals_db2.commit().unwrap();

        let tx3 = conn.transaction().unwrap();
        let proposals_db3 = ConsensusProposals::new(tx3);
        let last = proposals_db3.last_parts(height, &validator).unwrap();
        assert!(last.is_some(), "Should retrieve last parts");
        let (round, retrieved_parts) = last.unwrap();
        assert_eq!(round, 3, "Should return the highest round");
        assert_eq!(
            retrieved_parts, parts3,
            "Retrieved last parts should match persisted parts exactly"
        );
    }

    /// Tests that last_parts returns None when no rounds exist for a given
    /// height.
    #[test]
    fn test_last_parts_no_rounds() {
        let (_storage, mut conn) = setup_test_db();
        let tx = conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(tx);

        let height = 100u64;
        let validator = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());

        // Don't persist any parts for this height
        // Query for last parts - should return None
        let last = proposals_db.last_parts(height, &validator).unwrap();
        assert!(last.is_none(), "Should return None when no rounds exist");
    }

    /// Tests that removing parts for a specific round works correctly.
    #[test]
    fn test_remove_parts() {
        let (_storage, mut conn) = setup_test_db();
        let tx = conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(tx);

        let height = 100u64;
        let round = 1u32;
        let proposer = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let parts = create_test_proposal_parts(height, round, proposer);

        // Persist parts
        proposals_db
            .persist_parts(height, round, &proposer, &parts)
            .unwrap();
        proposals_db.commit().unwrap();

        // Verify they exist in new transaction
        let tx2 = conn.transaction().unwrap();
        let proposals_db2 = ConsensusProposals::new(tx2);
        let retrieved = proposals_db2.own_parts(height, round, &proposer).unwrap();
        assert!(retrieved.is_some());

        // Remove specific round
        proposals_db2.remove_parts(height, Some(round)).unwrap();
        proposals_db2.commit().unwrap();

        // Verify they're gone in new transaction
        let tx3 = conn.transaction().unwrap();
        let proposals_db3 = ConsensusProposals::new(tx3);
        let retrieved = proposals_db3.own_parts(height, round, &proposer).unwrap();
        assert!(retrieved.is_none(), "Parts should be removed");
    }

    /// Tests that removing all parts for a height removes all rounds for that
    /// height.
    #[test]
    fn test_remove_all_parts_for_height() {
        let (_storage, mut conn) = setup_test_db();
        let tx = conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(tx);

        let height = 100u64;
        let proposer1 = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let proposer2 = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());

        // Persist parts for multiple rounds
        proposals_db
            .persist_parts(
                height,
                1,
                &proposer1,
                &create_test_proposal_parts(height, 1, proposer1),
            )
            .unwrap();
        proposals_db
            .persist_parts(
                height,
                2,
                &proposer2,
                &create_test_proposal_parts(height, 2, proposer2),
            )
            .unwrap();
        proposals_db.commit().unwrap();

        // Remove all rounds for height in new transaction
        let tx2 = conn.transaction().unwrap();
        let proposals_db2 = ConsensusProposals::new(tx2);
        proposals_db2.remove_parts(height, None).unwrap();
        proposals_db2.commit().unwrap();

        // Verify all are gone in new transaction
        let tx3 = conn.transaction().unwrap();
        let proposals_db3 = ConsensusProposals::new(tx3);
        let validator = ContractAddress::new_or_panic(Felt::from_hex_str("0x999").unwrap());
        assert!(proposals_db3
            .foreign_parts(height, 1, &validator)
            .unwrap()
            .is_none());
        assert!(proposals_db3
            .foreign_parts(height, 2, &validator)
            .unwrap()
            .is_none());
    }

    /// Tests that finalized blocks can be persisted and retrieved correctly.
    #[test]
    fn test_persist_and_read_finalized_block() {
        let (_storage, mut conn) = setup_test_db();
        let tx = conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(tx);

        let height = 100u64;
        let round = 1u32;
        let block = create_test_consensus_finalized_block(height);

        // Persist new block
        let updated = proposals_db
            .persist_consensus_finalized_block(height, round, block.clone())
            .unwrap();
        assert!(!updated, "Should return false for new entry");
        proposals_db.commit().unwrap();

        // Read it back in new transaction
        let tx2 = conn.transaction().unwrap();
        let proposals_db2 = ConsensusProposals::new(tx2);
        let retrieved = proposals_db2
            .read_consensus_finalized_block(height, round)
            .unwrap();
        assert!(retrieved.is_some(), "Should retrieve persisted block");
        let retrieved_block = retrieved.unwrap();
        assert_eq!(retrieved_block.header.number.get(), height);
        // We can just verify the header. `StateUpdateData` is not comparable...
        assert_eq!(
            retrieved_block.header, block.header,
            "Retrieved block header should match persisted header exactly"
        );
    }

    /// Tests that finalized blocks for different rounds at the same height are
    /// isolated and can be removed together.
    #[test]
    fn test_finalized_blocks_isolation_and_removal() {
        let (_storage, mut conn) = setup_test_db();
        let tx = conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(tx);

        let height = 100u64;
        let block1 = create_test_consensus_finalized_block(height);
        let block2 = create_test_consensus_finalized_block(height);

        // Persist blocks for multiple rounds
        proposals_db
            .persist_consensus_finalized_block(height, 1, block1)
            .unwrap();
        proposals_db
            .persist_consensus_finalized_block(height, 2, block2)
            .unwrap();
        proposals_db.commit().unwrap();

        // Verify isolation: both should exist independently
        let tx2 = conn.transaction().unwrap();
        let proposals_db2 = ConsensusProposals::new(tx2);
        let retrieved1 = proposals_db2
            .read_consensus_finalized_block(height, 1)
            .unwrap();
        let retrieved2 = proposals_db2
            .read_consensus_finalized_block(height, 2)
            .unwrap();

        assert!(retrieved1.is_some(), "Round 1 block should exist");
        assert!(retrieved2.is_some(), "Round 2 block should exist");
        // Verify they can be retrieved independently (isolation test)
        assert_eq!(retrieved1.unwrap().header.number.get(), height);
        assert_eq!(retrieved2.unwrap().header.number.get(), height);

        // Remove all blocks for height (should remove all rounds)
        proposals_db2
            .remove_consensus_finalized_blocks(height)
            .unwrap();
        proposals_db2.commit().unwrap();

        // Verify all rounds are gone
        let tx3 = conn.transaction().unwrap();
        let proposals_db3 = ConsensusProposals::new(tx3);
        assert!(
            proposals_db3
                .read_consensus_finalized_block(height, 1)
                .unwrap()
                .is_none(),
            "Round 1 should be removed"
        );
        assert!(
            proposals_db3
                .read_consensus_finalized_block(height, 2)
                .unwrap()
                .is_none(),
            "Round 2 should be removed"
        );
    }

    /// Tests that multiple proposers can have parts for the same height and
    /// round, and they coexist independently.
    #[test]
    fn test_multiple_proposers_same_height_round() {
        let (_storage, mut conn) = setup_test_db();
        let tx = conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(tx);

        let height = 100u64;
        let round = 1u32;
        let proposer1 = ContractAddress::new_or_panic(Felt::from_hex_str("0x111").unwrap());
        let proposer2 = ContractAddress::new_or_panic(Felt::from_hex_str("0x222").unwrap());

        // Persist parts from proposer1 for (100, 1)
        let parts1 = create_test_proposal_parts(height, round, proposer1);
        proposals_db
            .persist_parts(height, round, &proposer1, &parts1)
            .unwrap();

        // Persist parts from proposer2 for (100, 1) - same height/round, different
        // proposer
        let parts2 = create_test_proposal_parts(height, round, proposer2);
        proposals_db
            .persist_parts(height, round, &proposer2, &parts2)
            .unwrap();
        proposals_db.commit().unwrap();

        // Verify both can coexist
        let tx2 = conn.transaction().unwrap();
        let proposals_db2 = ConsensusProposals::new(tx2);

        // Retrieve proposer1's parts
        let retrieved1 = proposals_db2.own_parts(height, round, &proposer1).unwrap();
        assert!(retrieved1.is_some(), "Proposer1's parts should exist");
        let parts1_retrieved = retrieved1.unwrap();
        assert_eq!(parts1_retrieved, parts1);

        // Retrieve proposer2's parts
        let retrieved2 = proposals_db2.own_parts(height, round, &proposer2).unwrap();
        assert!(retrieved2.is_some(), "Proposer2's parts should exist");
        let parts2_retrieved = retrieved2.unwrap();
        assert_eq!(parts2_retrieved, parts2);

        // Verify they're different
        assert_ne!(
            parts1_retrieved, parts2_retrieved,
            "Parts from different proposers should be different"
        );
    }

    /// Tests that parts for different heights and rounds are isolated and can
    /// be removed independently.
    #[test]
    fn test_multiple_heights_and_rounds() {
        let (_storage, mut conn) = setup_test_db();
        let tx = conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(tx);

        let proposer1 = ContractAddress::new_or_panic(Felt::from_hex_str("0x111").unwrap());
        let proposer2 = ContractAddress::new_or_panic(Felt::from_hex_str("0x222").unwrap());
        let validator = ContractAddress::new_or_panic(Felt::from_hex_str("0x999").unwrap());

        // Persist parts for different heights and rounds
        let parts_100_1 = create_test_proposal_parts(100, 1, proposer1);
        let parts_100_2 = create_test_proposal_parts(100, 2, proposer2);
        let parts_101_1 = create_test_proposal_parts(101, 1, proposer1);
        proposals_db
            .persist_parts(100, 1, &proposer1, &parts_100_1)
            .unwrap();
        proposals_db
            .persist_parts(100, 2, &proposer2, &parts_100_2)
            .unwrap();
        proposals_db
            .persist_parts(101, 1, &proposer1, &parts_101_1)
            .unwrap();
        proposals_db.commit().unwrap();

        // Verify isolation between heights in new transaction
        let tx2 = conn.transaction().unwrap();
        let proposals_db2 = ConsensusProposals::new(tx2);
        let retrieved_100_1 = proposals_db2.foreign_parts(100, 1, &validator).unwrap();
        assert!(retrieved_100_1.is_some());
        assert_eq!(retrieved_100_1.unwrap(), parts_100_1);
        let retrieved_100_2 = proposals_db2.foreign_parts(100, 2, &validator).unwrap();
        assert!(retrieved_100_2.is_some());
        assert_eq!(retrieved_100_2.unwrap(), parts_100_2);
        let retrieved_101_1 = proposals_db2.foreign_parts(101, 1, &validator).unwrap();
        assert!(retrieved_101_1.is_some());
        assert_eq!(retrieved_101_1.unwrap(), parts_101_1);

        // Remove only one height
        proposals_db2.remove_parts(100, None).unwrap();
        proposals_db2.commit().unwrap();

        // Verify height 100 is gone but 101 remains in new transaction
        let tx3 = conn.transaction().unwrap();
        let proposals_db3 = ConsensusProposals::new(tx3);
        assert!(proposals_db3
            .foreign_parts(100, 1, &validator)
            .unwrap()
            .is_none());
        assert!(proposals_db3
            .foreign_parts(100, 2, &validator)
            .unwrap()
            .is_none());
        let remaining = proposals_db3.foreign_parts(101, 1, &validator).unwrap();
        assert!(remaining.is_some());
        assert_eq!(remaining.unwrap(), parts_101_1);
    }
}
