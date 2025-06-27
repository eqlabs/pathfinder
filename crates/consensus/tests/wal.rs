use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ed25519_consensus::SigningKey;
use malachite_signing_ed25519::PublicKey;
use p2p_proto::common::{Address, Hash};
use pathfinder_consensus::*;
use pathfinder_crypto::Felt;
use tokio::sync::mpsc;
use tokio::time::{pause, sleep, Duration};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod common;
use common::drive_until;

#[allow(dead_code)]
fn setup_tracing_full() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("trace"));

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_env_filter(filter)
        .with_target(true)
        .without_time()
        .try_init();
}

#[tokio::test]
async fn wal_concurrent_heights_retention_test() {
    //setup_tracing_full();

    const NUM_VALIDATORS: usize = 2;
    const NUM_HEIGHTS: u64 = 15; // More than config.history_depth

    let value_hash = Hash(Felt::from_hex_str("0xabcdef").unwrap());
    let value_id = ValueId::new(value_hash);
    let consensus_value = ConsensusValue::new(value_id.clone());

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
        let addr = ValidatorAddress::from(Address(Felt::from_hex_str(&format!("0x{i}")).unwrap()));
        let pubkey = PublicKey::from_bytes(pk.to_bytes());

        validator_set.push(Validator {
            address: addr,
            public_key: pubkey,
            voting_power: 1,
        });

        let (tx, rx) = mpsc::unbounded_channel();
        senders.insert(addr, tx);
        receivers.insert(addr, rx);

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
            let config = Config::new(addr).with_wal_dir(wal_dir);
            let mut consensus = Consensus::new(config);
            // Start all heights up front
            for current_height in 1..=NUM_HEIGHTS {
                let height = Height::new(current_height);
                consensus
                    .handle_command(ConsensusCommand::StartHeight(height, validator_set.clone()));
            }

            sleep(Duration::from_millis(100)).await;

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
                                round: r,
                                proposer: addr,
                                pol_round: Round::from(0),
                                value_id: consensus_value.clone(),
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

                        ConsensusEvent::Decision { height: h, hash } => {
                            info!(
                                "✅ {} decided on {hash:?} at height {h}",
                                pretty_addr(&addr)
                            );
                            let mut decisions = decisions.lock().unwrap();
                            decisions.insert((addr, h), hash);
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
                sleep(Duration::from_millis(5)).await;
            }
        });

        handles.push(handle);
    }

    // Instead of waiting for all to finish, just sleep for a while
    tokio::time::sleep(Duration::from_secs(2)).await;

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

fn pretty_addr(addr: &ValidatorAddress) -> String {
    let addr_str = addr.to_string();
    addr_str.chars().skip(addr_str.len() - 4).collect()
}

#[tokio::test]
async fn recover_from_wal_restores_and_continues() {
    use std::sync::Arc;

    use pathfinder_consensus::{
        Config,
        Consensus,
        ConsensusCommand,
        ConsensusEvent,
        ConsensusValue,
        Height,
        Proposal,
        Round,
        ValidatorSetProvider,
        ValueId,
    };
    use pathfinder_crypto::Felt;

    //setup_tracing_full();
    pause();

    // Create a temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let wal_dir = temp_dir.path();

    // Static validator
    let addr = ValidatorAddress::from(Address(Felt::from_hex_str("0x1").unwrap()));
    let sk = SigningKey::new(rand::rngs::OsRng);
    let pk = sk.verification_key();
    let pubkey = PublicKey::from_bytes(pk.to_bytes());
    let validator = Validator {
        address: addr,
        public_key: pubkey,
        voting_power: 1,
    };
    let validators = ValidatorSet::new(vec![validator.clone()]);

    // Config with temporary WAL directory
    let config = Config::new(addr).with_wal_dir(wal_dir.to_path_buf());

    let height = Height::new(42);

    // Create and run consensus to log data to WAL
    {
        let mut consensus = Consensus::new(config.clone());
        consensus.handle_command(ConsensusCommand::StartHeight(height, validators.clone()));

        // Expect RequestProposal for round 0
        let _ = drive_until(
            &mut consensus,
            Duration::from_secs(1),
            5,
            |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == Round::new(malachite_types::Round::ZERO)),
        ).await;

        // Send a proposal to enter prevote
        let value_id = ValueId::new(Hash(Felt::from_hex_str("0xabc123").unwrap()));
        let proposal = Proposal {
            height,
            round: Round::new(malachite_types::Round::ZERO),
            value_id: ConsensusValue::new(value_id),
            pol_round: Round::new(malachite_types::Round::ZERO),
            proposer: addr,
        };
        let signed = SignedProposal {
            proposal,
            signature: Signature::from_bytes([0u8; 64]),
        };
        consensus.handle_command(ConsensusCommand::Proposal(signed));
    }

    // Create a validator set provider
    #[derive(Clone)]
    struct StaticSet(ValidatorSet);
    impl ValidatorSetProvider for StaticSet {
        fn get_validator_set(&self, _height: &Height) -> ValidatorSet {
            self.0.clone()
        }
    }

    // Now recover from WAL
    let mut consensus = Consensus::recover(config.clone(), Arc::new(StaticSet(validators)));

    // Expect RequestProposal again for round 1
    let event = drive_until(
        &mut consensus,
        Duration::from_secs(5),
        10,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == Round::new(malachite_types::Round::Some(1))),
    ).await;

    assert!(
        event.is_some(),
        "Recovered consensus should continue to operate and advance rounds"
    );
}
