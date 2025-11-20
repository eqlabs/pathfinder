use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use pathfinder_consensus::{DefaultConsensus, *};
use tokio::sync::mpsc;
use tokio::time::{pause, Duration};
use tracing::{debug, error, info};

mod common;
use common::{drive_until, ConsensusValue, NodeAddress};

/// A static validator set provider for tests.
/// Returns the same validator set regardless of height.
#[derive(Clone)]
pub struct StaticSet<A: ValidatorAddress>(pub ValidatorSet<A>);

impl<A: ValidatorAddress> ValidatorSetProvider<A> for StaticSet<A> {
    fn get_validator_set(&self, _height: u64) -> Result<ValidatorSet<A>, anyhow::Error> {
        Ok(self.0.clone())
    }
}

/// Creates a single validator with the given address.
pub fn create_validator(addr: NodeAddress) -> Validator<NodeAddress> {
    use pathfinder_consensus::{PublicKey, SigningKey};
    use rand::rngs::OsRng;

    let sk = SigningKey::new(OsRng);
    let pk = sk.verification_key();
    let pubkey = PublicKey::from_bytes(pk.to_bytes());

    Validator {
        address: addr.clone(),
        public_key: pubkey,
        voting_power: 1,
    }
}

/// Creates a validator set with a single validator.
pub fn create_single_validator_set(addr: NodeAddress) -> ValidatorSet<NodeAddress> {
    ValidatorSet::new(vec![create_validator(addr)])
}

/// Handles WAL file backup and recovery operations in tests to avoid code
/// duplication.
pub struct WalTestHelper<'a> {
    wal_dir: &'a Path,
    addr: &'a NodeAddress,
}

impl<'a> WalTestHelper<'a> {
    /// Creates a new `WalTestHelper` with the given WAL directory and validator
    /// address.
    pub fn new(wal_dir: &'a Path, addr: &'a NodeAddress) -> Self {
        Self { wal_dir, addr }
    }

    /// Backs up a WAL file before it gets deleted.
    /// Returns the backup path if the WAL file existed.
    pub fn backup(&self, height: u64) -> Option<PathBuf> {
        let wal_filename = format!("wal-{}-{height}.json", self.addr);
        let wal_path = self.wal_dir.join(&wal_filename);
        let wal_path_backup = self.wal_dir.join(format!("{wal_filename}.backup"));

        if wal_path.exists() {
            std::fs::copy(&wal_path, &wal_path_backup)
                .expect("Failed to copy WAL file for recovery test");
            Some(wal_path_backup)
        } else {
            None
        }
    }

    /// Restores a WAL file from backup and cleans up the backup file.
    pub fn restore_from_backup(&self, height: u64) {
        let wal_filename = format!("wal-{}-{height}.json", self.addr);
        let wal_path = self.wal_dir.join(&wal_filename);
        let wal_path_backup = self.wal_dir.join(format!("{wal_filename}.backup"));

        if wal_path_backup.exists() {
            std::fs::copy(&wal_path_backup, &wal_path)
                .expect("Failed to restore WAL file for recovery test");
            // Clean up the backup file
            let _ = std::fs::remove_file(&wal_path_backup);
        }
    }

    /// Verifies that a WAL file exists for the given height.
    pub fn verify_exists(&self, height: u64) {
        let wal_filename = format!("wal-{}-{height}.json", self.addr);
        let wal_path = self.wal_dir.join(&wal_filename);
        assert!(
            wal_path.exists(),
            "WAL file for height {height} should exist",
        );
    }
}

#[tokio::test]
async fn wal_concurrent_heights_retention_test() {
    //common::setup_tracing_full();

    const NUM_VALIDATORS: usize = 2;
    const NUM_HEIGHTS: u64 = 15; // More than config.history_depth

    let consensus_value = ConsensusValue("Hello, world!".to_string());

    // Create a temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let wal_dir = temp_dir.path();

    // Create validators and channels
    let mut validators = vec![];
    let mut validator_set = vec![];
    let mut senders = HashMap::new();
    let mut receivers = HashMap::new();

    for i in 1..=NUM_VALIDATORS {
        let sk = SigningKey::new(rand::rngs::OsRng);
        let pk = sk.verification_key();
        let addr = NodeAddress(format!("0x{i}"));
        let pubkey = PublicKey::from_bytes(pk.to_bytes());

        validator_set.push(Validator {
            address: addr.clone(),
            public_key: pubkey,
            voting_power: 1,
        });

        let (tx, rx) = mpsc::unbounded_channel();
        senders.insert(addr.clone(), tx);
        receivers.insert(addr.clone(), rx);

        validators.push((addr, sk));
    }

    // Create validator set
    let validator_set = ValidatorSet::new(validator_set);

    // Track decisions for each height
    let decisions = Arc::new(Mutex::new(HashMap::new()));

    // Spawn each validator in its own task
    let mut handles = vec![];
    for (addr, _) in validators {
        let mut rx = receivers.remove(&addr).unwrap();
        let peers = senders.clone();
        let validator_set = validator_set.clone();
        let decisions = Arc::clone(&decisions);
        let consensus_value = consensus_value.clone();
        let wal_dir = wal_dir.to_path_buf();

        let handle = tokio::spawn(async move {
            let config = Config::new(addr.clone()).with_wal_dir(wal_dir);
            let mut consensus: DefaultConsensus<ConsensusValue, NodeAddress> =
                DefaultConsensus::new(config);
            // Start all heights up front
            for current_height in 1..=NUM_HEIGHTS {
                let height = current_height;
                consensus
                    .handle_command(ConsensusCommand::StartHeight(height, validator_set.clone()));
            }

            // Now process events for all heights
            loop {
                while let Some(event) = consensus.next_event().await {
                    match event {
                        ConsensusEvent::RequestProposal {
                            height: h,
                            round: r,
                            ..
                        } => {
                            info!(
                                "🔍 {} is proposing at height {h}, round {r:?}",
                                pretty_addr(&addr)
                            );

                            let proposal = Proposal {
                                height: h,
                                round: Round::new(r),
                                proposer: addr.clone(),
                                pol_round: Round::nil(),
                                value: consensus_value.clone(),
                            };

                            consensus.handle_command(ConsensusCommand::Propose(proposal));
                        }

                        ConsensusEvent::Gossip(msg) => {
                            for (peer, chan) in peers.iter() {
                                if peer != &addr {
                                    info!("🔍 {} sending to {peer}", pretty_addr(&addr));
                                    let _ = chan.send(msg.clone());
                                }
                            }
                        }

                        ConsensusEvent::Decision {
                            height: h,
                            round: r,
                            value,
                        } => {
                            info!(
                                "✅ {} decided on {value:?} at height {h} round {r}",
                                pretty_addr(&addr)
                            );
                            let mut decisions = decisions.lock().unwrap();
                            decisions.insert((addr.clone(), h), value);
                        }

                        ConsensusEvent::Error(error) => {
                            error!("❌ {} error: {error:?}", pretty_addr(&addr));
                            break;
                        }
                    }
                }
                while let Ok(msg) = rx.try_recv() {
                    info!(
                        "💌 Validator {} received command: {msg:?}",
                        pretty_addr(&addr)
                    );
                    let cmd = match msg {
                        NetworkMessage::Proposal(p) => ConsensusCommand::Proposal(p),
                        NetworkMessage::Vote(v) => ConsensusCommand::Vote(v),
                    };
                    consensus.handle_command(cmd);
                }
                // Break if all heights are decided
                if decisions.lock().unwrap().len() == (NUM_HEIGHTS as usize * NUM_VALIDATORS) {
                    break;
                }
                // Small yield to avoid busy-waiting and allow other tasks to run
                tokio::task::yield_now().await;
            }
        });

        handles.push(handle);
    }

    // Wait for validator tasks to make progress and create WAL files
    // This test checks WAL file retention, not consensus correctness, so we don't
    // need to wait for all decisions. A short sleep allows tasks to run and create
    // files.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check that at least config.history_depth WAL files exist
    let files = std::fs::read_dir(wal_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("wal-"))
        .collect::<Vec<_>>();
    assert!(
        files.len() >= 10, // 10 is the default config.history_depth
        "Expected at least 10 WAL files in {}, found {}",
        wal_dir.display(),
        files.len()
    );
}

fn pretty_addr(addr: &NodeAddress) -> String {
    let addr_str = addr.to_string();
    addr_str.chars().skip(addr_str.len() - 4).collect()
}

#[tokio::test]
async fn recover_from_wal_restores_and_continues() {
    use std::sync::Arc;

    use pathfinder_consensus::{Config, ConsensusCommand, ConsensusEvent, Proposal, Round};

    //common::setup_tracing_full();
    pause();

    // Create a temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let wal_dir = temp_dir.path();

    // Static validator
    let addr = NodeAddress("0x1".to_string());
    let validators = create_single_validator_set(addr.clone());

    // Config with temporary WAL directory
    let config = Config::new(addr.clone()).with_wal_dir(wal_dir.to_path_buf());

    let height = 42;

    // Create and run consensus to log data to WAL
    {
        let mut consensus: DefaultConsensus<ConsensusValue, NodeAddress> =
            DefaultConsensus::new(config.clone());
        consensus.handle_command(ConsensusCommand::StartHeight(height, validators.clone()));

        // Expect RequestProposal for round 0
        let _ = drive_until(
            &mut consensus,
            Duration::from_secs(1),
            5,
            |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == 0),
        )
        .await;

        // Send a proposal to enter prevote
        let value = ConsensusValue("Hello, world!".to_string());
        let proposal = Proposal {
            height,
            round: Round::new(0),
            value,
            pol_round: Round::nil(),
            proposer: addr.clone(),
        };
        let signed = SignedProposal {
            proposal,
            signature: Signature::from_bytes([0u8; 64]),
        };
        consensus.handle_command(ConsensusCommand::Proposal(signed));
    }

    debug!("---------------------- Recovering from WAL ----------------------");

    // Now recover from WAL
    let mut consensus: DefaultConsensus<ConsensusValue, NodeAddress> =
        DefaultConsensus::recover(config.clone(), Arc::new(StaticSet(validators)), None).unwrap();

    debug!("------------ Driving consensus post WAL recovery ----------------");

    // Expect RequestProposal again for round 0
    let event = drive_until(
        &mut consensus,
        Duration::from_secs(5),
        10,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == 0),
    )
    .await;

    assert!(
        event.is_some(),
        "Recovered consensus should continue to operate and advance rounds"
    );

    // Verify last_decided_height is None since no decision was reached
    assert_eq!(
        consensus.last_decided_height(),
        None,
        "last_decided_height should be None when no decisions were made"
    );
}

#[tokio::test]
async fn recover_from_wal_tracks_last_decided_height() {
    use std::sync::Arc;

    use pathfinder_consensus::{Config, ConsensusCommand, ConsensusEvent, Proposal, Round};

    //common::setup_tracing_full();
    pause();

    // Create a temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let wal_dir = temp_dir.path();

    // Static validator
    let addr = NodeAddress("0x1".to_string());
    let validators = create_single_validator_set(addr.clone());

    // WAL helper for managing WAL files
    let wal_helper = WalTestHelper::new(wal_dir, &addr);

    // Config with temporary WAL directory
    let config = Config::new(addr.clone()).with_wal_dir(wal_dir.to_path_buf());

    // This is the height we'll reach a Decision at and thus the one we'll be
    // checking for
    let height = 100;

    // Create and run consensus to reach a Decision
    {
        let mut consensus: DefaultConsensus<ConsensusValue, NodeAddress> =
            DefaultConsensus::new(config.clone());
        consensus.handle_command(ConsensusCommand::StartHeight(height, validators.clone()));

        // Verify last_decided_height is None to start with
        assert_eq!(consensus.last_decided_height(), None);

        // Wait for RequestProposal
        let _ = drive_until(&mut consensus, Duration::from_secs(1), 5, |evt| {
            matches!(evt, ConsensusEvent::RequestProposal { .. })
        })
        .await;

        // Send a proposal
        let value = ConsensusValue("Test decision".to_string());
        let proposal = Proposal {
            height,
            round: Round::new(0),
            value: value.clone(),
            pol_round: Round::nil(),
            proposer: addr.clone(),
        };
        let signed = SignedProposal {
            proposal,
            signature: Signature::from_bytes([0u8; 64]),
        };
        consensus.handle_command(ConsensusCommand::Proposal(signed));

        // Wait for Decision event
        let decision_event = drive_until(&mut consensus, Duration::from_secs(1), 10, |evt| {
            matches!(evt, ConsensusEvent::Decision { .. })
        })
        .await;

        assert!(
            decision_event.is_some(),
            "Consensus should reach a Decision"
        );

        // Verify last_decided_height is set during normal operation
        assert_eq!(
            consensus.last_decided_height(),
            Some(height),
            "last_decided_height should be set after Decision"
        );

        // Copy the WAL file before consensus is dropped (which will delete it)
        // This allows us to test recovery from a WAL file with a Decision entry
        wal_helper.backup(height);
    }

    // At this point, the consensus is dropped and the original WAL file is deleted.
    // But we have a backup copy that we can use for recovery testing.

    // Restore the WAL file from backup so we can test recovery
    wal_helper.restore_from_backup(height);

    debug!("---------------------- Recovering from WAL ----------------------");

    // Now recover from WAL (using the restored WAL file with Decision entry)
    let consensus: DefaultConsensus<ConsensusValue, NodeAddress> =
        DefaultConsensus::recover(config.clone(), Arc::new(StaticSet(validators)), None).unwrap();

    // Verify last_decided_height is correctly recovered from WAL Decision entry
    assert_eq!(
        consensus.last_decided_height(),
        Some(height),
        "last_decided_height should be recovered from WAL Decision entry"
    );
}

#[tokio::test]
async fn recover_restores_finalized_heights_within_history_depth() {
    use std::sync::Arc;

    use pathfinder_consensus::{
        Config,
        ConsensusCommand,
        ConsensusEvent,
        Proposal,
        Round,
        SignedVote,
        Vote,
        VoteType,
    };

    //common::setup_tracing_full();
    pause();

    // Create a temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let wal_dir = temp_dir.path();

    // Static validator
    let addr = NodeAddress("0x1".to_string());
    let validators = create_single_validator_set(addr.clone());

    // WAL helper for managing WAL files
    let wal_helper = WalTestHelper::new(wal_dir, &addr);

    // Config with temporary WAL directory and history_depth = 5
    let history_depth = 5;
    let config = Config::new(addr.clone())
        .with_wal_dir(wal_dir.to_path_buf())
        .with_history_depth(history_depth);

    // Height 100: Will be finalized (Decision reached)
    // Height 101: Will be incomplete (establishes max_height = 101)
    // min_height_to_restore = 101 - 5 = 96
    // So height 100 should be restored (100 >= 96)
    let finalized_height = 100;
    let incomplete_height = 101;

    // Create and run consensus to reach a Decision at finalized_height
    {
        let mut consensus: DefaultConsensus<ConsensusValue, NodeAddress> =
            DefaultConsensus::new(config.clone());
        consensus.handle_command(ConsensusCommand::StartHeight(
            finalized_height,
            validators.clone(),
        ));

        // Wait for RequestProposal
        let _ = drive_until(&mut consensus, Duration::from_secs(1), 5, |evt| {
            matches!(evt, ConsensusEvent::RequestProposal { .. })
        })
        .await;

        // Send a proposal to reach Decision
        let value = ConsensusValue("Finalized value".to_string());
        let proposal = Proposal {
            height: finalized_height,
            round: Round::new(0),
            value: value.clone(),
            pol_round: Round::nil(),
            proposer: addr.clone(),
        };
        let signed = SignedProposal {
            proposal,
            signature: Signature::from_bytes([0u8; 64]),
        };
        consensus.handle_command(ConsensusCommand::Proposal(signed));

        // Wait for Decision event
        let decision_event = drive_until(&mut consensus, Duration::from_secs(1), 10, |evt| {
            matches!(evt, ConsensusEvent::Decision { .. })
        })
        .await;

        assert!(
            decision_event.is_some(),
            "Consensus should reach a Decision at height {finalized_height}",
        );

        // Copy the WAL file before consensus is dropped (which will delete it)
        wal_helper.backup(finalized_height);
    }

    // Create an incomplete height to establish max_height
    {
        let mut consensus: DefaultConsensus<ConsensusValue, NodeAddress> =
            DefaultConsensus::new(config.clone());
        consensus.handle_command(ConsensusCommand::StartHeight(
            incomplete_height,
            validators.clone(),
        ));

        // Wait for RequestProposal but don't complete the height
        let _ = drive_until(&mut consensus, Duration::from_secs(1), 5, |evt| {
            matches!(evt, ConsensusEvent::RequestProposal { .. })
        })
        .await;

        // Verify the incomplete height WAL file exists for recovery
        wal_helper.verify_exists(incomplete_height);
    }

    // Restore the finalized height WAL file from backup
    wal_helper.restore_from_backup(finalized_height);

    debug!("---------------------- Recovering from WAL ----------------------");

    // Now recover from WAL
    let mut consensus: DefaultConsensus<ConsensusValue, NodeAddress> =
        DefaultConsensus::recover(config.clone(), Arc::new(StaticSet(validators)), None).unwrap();

    // Verify the finalized height is restored (within history_depth)
    assert!(
        consensus.is_height_active(finalized_height),
        "Finalized height {finalized_height} should be restored (within history_depth)",
    );

    assert!(
        consensus.is_height_finalized(finalized_height),
        "Height {finalized_height} should be marked as finalized",
    );

    // Verify the incomplete height is also restored
    assert!(
        consensus.is_height_active(incomplete_height),
        "Incomplete height {incomplete_height} should be restored",
    );

    // Verify that votes for the restored finalized height are accepted (not
    // ignored) This is the key test - before the fix, this would trigger a
    // warning
    let vote = Vote {
        r#type: VoteType::Prevote,
        height: finalized_height,
        round: Round::new(0),
        value: Some(ConsensusValue("Finalized value".to_string())),
        validator_address: addr.clone(),
    };
    let signed_vote = SignedVote {
        vote,
        signature: Signature::from_bytes([0u8; 64]),
    };

    // This should NOT trigger the "Received command for unknown height" warning
    // because the height is now in the internal map
    consensus.handle_command(ConsensusCommand::Vote(signed_vote));

    // Verify that heights below the expected minimum are considered finalized
    // (this indirectly verifies min_kept_height is set correctly)
    let expected_min = incomplete_height.checked_sub(history_depth);
    if let Some(min_height) = expected_min {
        // Heights below min_kept_height should be considered finalized
        // even if not in the internal map
        assert!(
            consensus.is_height_finalized(min_height - 1),
            "Height below min_kept_height should be considered finalized"
        );
    }
}

#[tokio::test]
async fn recover_skips_finalized_heights_outside_history_depth() {
    use std::sync::Arc;

    use pathfinder_consensus::{Config, ConsensusCommand, ConsensusEvent, Proposal, Round};

    //common::setup_tracing_full();
    pause();

    // Create a temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let wal_dir = temp_dir.path();

    // Static validator
    let addr = NodeAddress("0x1".to_string());
    let validators = create_single_validator_set(addr.clone());

    // WAL helper for managing WAL files
    let wal_helper = WalTestHelper::new(wal_dir, &addr);

    // Config with temporary WAL directory and history_depth = 5
    let history_depth = 5;
    let config = Config::new(addr.clone())
        .with_wal_dir(wal_dir.to_path_buf())
        .with_history_depth(history_depth);

    // Height 90: Will be finalized (Decision reached)
    // Height 101: Will be incomplete (establishes max_height = 101)
    // min_height_to_restore = 101 - 5 = 96
    // So height 90 should NOT be restored (90 < 96)
    let finalized_height = 90;
    let incomplete_height = 101;

    // Create and run consensus to reach a Decision at finalized_height
    {
        let mut consensus: DefaultConsensus<ConsensusValue, NodeAddress> =
            DefaultConsensus::new(config.clone());
        consensus.handle_command(ConsensusCommand::StartHeight(
            finalized_height,
            validators.clone(),
        ));

        // Wait for RequestProposal
        let _ = drive_until(&mut consensus, Duration::from_secs(1), 5, |evt| {
            matches!(evt, ConsensusEvent::RequestProposal { .. })
        })
        .await;

        // Send a proposal to reach Decision
        let value = ConsensusValue("Finalized value".to_string());
        let proposal = Proposal {
            height: finalized_height,
            round: Round::new(0),
            value: value.clone(),
            pol_round: Round::nil(),
            proposer: addr.clone(),
        };
        let signed = SignedProposal {
            proposal,
            signature: Signature::from_bytes([0u8; 64]),
        };
        consensus.handle_command(ConsensusCommand::Proposal(signed));

        // Wait for Decision event
        let decision_event = drive_until(&mut consensus, Duration::from_secs(1), 10, |evt| {
            matches!(evt, ConsensusEvent::Decision { .. })
        })
        .await;

        assert!(
            decision_event.is_some(),
            "Consensus should reach a Decision at height {finalized_height}",
        );

        // Copy the WAL file before consensus is dropped (which will delete it)
        wal_helper.backup(finalized_height);
    }

    // Create an incomplete height to establish max_height
    {
        let mut consensus: DefaultConsensus<ConsensusValue, NodeAddress> =
            DefaultConsensus::new(config.clone());
        consensus.handle_command(ConsensusCommand::StartHeight(
            incomplete_height,
            validators.clone(),
        ));

        // Wait for RequestProposal but don't complete the height
        let _ = drive_until(&mut consensus, Duration::from_secs(1), 5, |evt| {
            matches!(evt, ConsensusEvent::RequestProposal { .. })
        })
        .await;

        // Verify the incomplete height WAL file exists for recovery
        wal_helper.verify_exists(incomplete_height);
    }

    // Restore the finalized height WAL file from backup
    wal_helper.restore_from_backup(finalized_height);

    debug!("---------------------- Recovering from WAL ----------------------");

    // Now recover from WAL
    let mut consensus: DefaultConsensus<ConsensusValue, NodeAddress> =
        DefaultConsensus::recover(config.clone(), Arc::new(StaticSet(validators)), None).unwrap();

    // Verify the finalized height is NOT restored (outside history_depth)
    assert!(
        !consensus.is_height_active(finalized_height),
        "Finalized height {finalized_height} should NOT be restored (outside history_depth)",
    );

    // But it should still be considered finalized (because it's below
    // min_kept_height)
    assert!(
        consensus.is_height_finalized(finalized_height),
        "Height {finalized_height} should still be considered finalized even if not restored",
    );

    // Verify the incomplete height is restored
    assert!(
        consensus.is_height_active(incomplete_height),
        "Incomplete height {incomplete_height} should be restored",
    );

    // Verify that finalized_height is below the expected minimum
    // (this indirectly verifies min_kept_height is set correctly)
    let expected_min = incomplete_height.checked_sub(history_depth);
    if let Some(min_height) = expected_min {
        assert!(
            finalized_height < min_height,
            "Finalized height {finalized_height} should be below min_kept_height {min_height}",
        );
        // Verify that heights below min_kept_height are considered finalized
        assert!(
            consensus.is_height_finalized(min_height - 1),
            "Height below min_kept_height should be considered finalized"
        );
    }

    // Verify that votes for non-restored finalized heights are handled correctly.
    // Since the height is finalized but not in the internal map (outside
    // history_depth), votes should be properly handled (either accepted if the
    // system allows it, or properly ignored without causing errors).
    let vote = Vote {
        r#type: VoteType::Prevote,
        height: finalized_height,
        round: Round::new(0),
        value: Some(ConsensusValue("Finalized value".to_string())),
        validator_address: addr.clone(),
    };
    let signed_vote = SignedVote {
        vote,
        signature: Signature::from_bytes([0u8; 64]),
    };

    // This should not cause errors even though the height is not in the internal
    // map. The system should handle votes for finalized heights gracefully.
    consensus.handle_command(ConsensusCommand::Vote(signed_vote));
}
