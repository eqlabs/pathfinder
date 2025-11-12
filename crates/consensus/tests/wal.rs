use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pathfinder_consensus::{DefaultConsensus, *};
use tokio::sync::mpsc;
use tokio::time::{pause, sleep, Duration};
use tracing::{debug, error, info};

mod common;
use common::{drive_until, ConsensusValue, NodeAddress};

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

fn pretty_addr(addr: &NodeAddress) -> String {
    let addr_str = addr.to_string();
    addr_str.chars().skip(addr_str.len() - 4).collect()
}

#[tokio::test]
async fn recover_from_wal_restores_and_continues() {
    use std::sync::Arc;

    use pathfinder_consensus::{
        Config,
        ConsensusCommand,
        ConsensusEvent,
        Proposal,
        Round,
        ValidatorSetProvider,
    };

    //common::setup_tracing_full();
    pause();

    // Create a temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let wal_dir = temp_dir.path();

    // Static validator
    let addr = NodeAddress("0x1".to_string());
    let sk = SigningKey::new(rand::rngs::OsRng);
    let pk = sk.verification_key();
    let pubkey = PublicKey::from_bytes(pk.to_bytes());
    let validator = Validator {
        address: addr.clone(),
        public_key: pubkey,
        voting_power: 1,
    };
    let validators = ValidatorSet::new(vec![validator.clone()]);

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

    // Create a validator set provider
    #[derive(Clone)]
    struct StaticSet(ValidatorSet<NodeAddress>);
    impl ValidatorSetProvider<NodeAddress> for StaticSet {
        fn get_validator_set(
            &self,
            _height: u64,
        ) -> Result<ValidatorSet<NodeAddress>, anyhow::Error> {
            Ok(self.0.clone())
        }
    }

    debug!("---------------------- Recovering from WAL ----------------------");

    // Now recover from WAL
    let mut consensus: DefaultConsensus<ConsensusValue, NodeAddress> =
        DefaultConsensus::recover(config.clone(), Arc::new(StaticSet(validators)), None)
            .unwrap()
            .0;

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
}
