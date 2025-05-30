use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use ed25519_consensus::SigningKey;
use malachite_signing_ed25519::{PublicKey, Signature};
use p2p_proto::common::{Address, Hash};
use pathfinder_consensus::*;
use pathfinder_crypto::Felt;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{error, info};

fn setup_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}

#[tokio::test]
async fn consensus_simulation_two_validators() {
    setup_tracing();

    const HEIGHT: u64 = 1;
    const ROUND: u32 = 0;

    let height = Height::new(HEIGHT);
    let round = Round::new(ROUND);
    let value_hash = Hash(Felt::from_hex_str("0xabcdef").unwrap());
    let value_id = ValueId::new(value_hash);
    let consensus_value = ConsensusValue::new(value_id.clone());

    // Shared result collection
    let decisions = Arc::new(Mutex::new(HashMap::new()));

    // Network setup
    let mut validators = vec![];
    let mut validator_set = vec![];
    let mut senders = HashMap::new();
    let mut handles = vec![];

    for i in 1..=2 {
        let sk = SigningKey::new(rand::rngs::OsRng);
        let pk = sk.verification_key();
        let addr = ValidatorAddress::from(Address(Felt::from_hex_str(&format!("0x{i}")).unwrap()));
        let pubkey = PublicKey::from_bytes(pk.to_bytes());

        validator_set.push(Validator {
            address: addr.clone(),
            public_key: pubkey,
            voting_power: 1,
        });

        validators.push((addr.clone(), sk));
    }

    let validator_set = ValidatorSet::new(validator_set);
    let shared_validator_set = validator_set.clone();

    // Spawn each validator in its own task
    for (addr, sk) in validators {
        let (tx, mut rx) = mpsc::unbounded_channel::<NetworkMessage>();
        senders.insert(addr.clone(), tx);

        let peers = senders.clone();
        let validator_set = shared_validator_set.clone();
        let decisions = Arc::clone(&decisions);
        let consensus_value = consensus_value.clone();

        let mut engine = Consensus::new(addr.clone());
        engine.handle_command(ConsensusCommand::StartHeight(height, validator_set.clone()));

        let handle = tokio::spawn(async move {
            loop {
                // Poll event from consensus engine
                if let Some(event) = engine.next_event().await {
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
                                proposer: addr.clone(),
                                pol_round: Round::new(0),
                                value_id: consensus_value.clone(),
                            };

                            engine.handle_command(ConsensusCommand::Propose(proposal));
                        }

                        ConsensusEvent::Gossip(msg) => {
                            info!("🔍 {} gossipping {msg:?}", pretty_addr(&addr));
                            info!("🔍 {} peers: {peers:?}", pretty_addr(&addr));
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
                            decisions.lock().unwrap().insert(addr.clone(), hash);
                            break;
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
                        "🔍 Validator {} received command: {msg:?}",
                        pretty_addr(&addr)
                    );
                    let cmd = match msg {
                        NetworkMessage::Proposal(p) => ConsensusCommand::Proposal(p),
                        NetworkMessage::Vote(v) => ConsensusCommand::Vote(v),
                    };
                    engine.handle_command(cmd);
                }

                sleep(Duration::from_millis(5)).await;
            }
        });

        handles.push(handle);
    }

    // Wait until all have reached a decision or timeout
    for h in handles {
        let _ = h.await;
    }

    let decided = decisions.lock().unwrap();
    assert_eq!(decided.len(), 2);
    let mut iter = decided.values();
    let first = iter.next().unwrap();
    assert!(iter.all(|h| h == first));
}

fn pretty_addr(addr: &ValidatorAddress) -> String {
    let addr_str = addr.to_string();
    addr_str.chars().skip(addr_str.len() - 4).collect()
}
