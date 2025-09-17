use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::{ConsensusValue, NodeAddress};
use pathfinder_consensus::*;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Duration};
use tracing::{error, info};

mod common;

#[tokio::test]
async fn consensus_simulation() {
    //common::setup_tracing_full();

    const NUM_VALIDATORS: usize = 3;
    const NUM_HEIGHTS: u64 = 10;

    let consensus_value = ConsensusValue("Hello, world!".to_string());

    // Create validators and channels
    let mut validators = vec![];
    let mut validator_set = vec![];
    let mut senders = HashMap::new();
    let mut receivers = HashMap::new();

    // Create a (single) temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let temp_dir = temp_dir.path().to_path_buf();

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

        validators.push((addr.clone(), sk));
    }

    let proposer = validators[0].0.clone();

    // Create validator set
    let validator_set = ValidatorSet::new(validator_set, proposer);

    // Track decisions for each height
    let decisions = Arc::new(Mutex::new(HashMap::new()));

    // Spawn each validator in its own task
    let mut handles = vec![];
    for (addr, _) in validators {
        let mut rx = receivers.remove(&addr).unwrap();
        let peers = senders.clone();
        let validator_set = validator_set.clone();

        // Clone decisions for this validator
        let decisions = Arc::clone(&decisions);
        let consensus_value = consensus_value.clone();

        let wal_dir = temp_dir.clone();
        let handle = tokio::spawn(async move {
            let mut current_height = 1;

            while current_height <= NUM_HEIGHTS {
                let height = current_height;
                let config = Config::new(addr.clone()).with_wal_dir(wal_dir.clone());
                let mut consensus = Consensus::new(config);
                consensus
                    .handle_command(ConsensusCommand::StartHeight(height, validator_set.clone()));

                sleep(Duration::from_millis(100)).await;

                loop {
                    // Poll event from consensus engine
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

                    // Process inbound network messages
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

                    // Break if all validators have decided for current height
                    if decisions
                        .lock()
                        .unwrap()
                        .keys()
                        .filter(|(_, h)| *h == height)
                        .count()
                        == NUM_VALIDATORS
                    {
                        break;
                    }

                    sleep(Duration::from_millis(5)).await;
                }

                current_height += 1;
            }
        });

        handles.push(handle);
    }

    // Wait until all have reached a decision or timeout
    let result = timeout(
        Duration::from_secs(NUM_VALIDATORS as u64 * NUM_HEIGHTS),
        async {
            for h in handles {
                let _ = h.await;
            }
        },
    )
    .await;

    assert!(
        result.is_ok(),
        "Timed out waiting for consensus to complete"
    );

    // Verify decisions for each height
    for height in 1..=NUM_HEIGHTS {
        let decisions_guard = decisions.lock().unwrap();
        let height_decisions: Vec<_> = decisions_guard
            .iter()
            .filter(|((_, h), _)| *h == height)
            .map(|(_, hash)| hash)
            .collect();

        assert_eq!(height_decisions.len(), NUM_VALIDATORS);
        let first = height_decisions[0];
        assert!(height_decisions.iter().all(|h| h == &first));
    }
}

fn pretty_addr(addr: &NodeAddress) -> String {
    let addr_str = addr.to_string();
    addr_str.chars().skip(addr_str.len() - 4).collect()
}
