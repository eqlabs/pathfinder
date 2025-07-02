/*
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ed25519_consensus::SigningKey;
use malachite_signing_ed25519::PublicKey;
use p2p_proto::common::{Address, Hash};
use pathfinder_consensus::*;
use pathfinder_crypto::Felt;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Duration};
use tracing::{error, info};
*/
use clap::Parser;
use pathfinder_common::ChainId;
use pathfinder_lib::config::p2p::{P2PConsensusCli, P2PConsensusConfig};
use pathfinder_lib::p2p_network::consensus;
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
pub struct Cli {
    #[arg(
        long = "network",
        long_help = "mainnet or sepolia (testnet)",
        value_name = "NETWORK",
        default_value = "sepolia"
    )]
    network: String,
    #[clap(flatten)]
    consensus: P2PConsensusCli,
}

fn setup_tracing_full() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("trace"));

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_env_filter(filter)
        .with_target(true)
        .without_time()
        .try_init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_tracing_full();

    let mut term_signal = signal(SignalKind::terminate())?;
    let mut int_signal = signal(SignalKind::interrupt())?;

    let config = Cli::parse();
    let network = config.network;
    let config = P2PConsensusConfig::parse_or_exit(config.consensus);
    let chain_id = match network.as_str() {
        "mainnet" => ChainId::MAINNET,
        "sepolia" => ChainId::SEPOLIA_TESTNET,
        _ => anyhow::bail!("Unsupported network: {}", network),
    };
    let (_jh, client) = consensus::start(chain_id, config).await;

    tokio::select! {
        result = _jh => {
            eprintln!("Consensus task finished with result: {:?}", result);
        }
        _ = term_signal.recv() => {
            tracing::info!("TERM signal received");
        }
        _ = int_signal.recv() => {
            tracing::info!("INT signal received");
        }
    }

    /*
        let network; // ... Our P2P Consensus network

        let mut consensus = Consensus::new(my_address);
        consensus.handle_command(ConsensusCommand::StartHeight(height, validator_set));

        loop {
            if let Some(event) = consensus.next_event().await {
                match event {
                    ConsensusEvent::RequestProposal { height, round, .. } => {
                        // We're the proposer — pick a value and propose it.
                        let proposal = Proposal {
                            height,
                            round,
                            proposer: my_address,
                            pol_round: Round::new(0),
                            value_id: ConsensusValue::new(value_id),
                        };
                        consensus.handle_command(ConsensusCommand::Propose(proposal));
                    }

                    ConsensusEvent::Gossip(msg) => {
                        // Send this message to our peers.
                        network.gossip(msg);
                    }

                    ConsensusEvent::Decision { height, hash } => {
                        // Reached consensus on a value.
                        commit_block(height, hash);
                        break;
                    }

                    ConsensusEvent::Error(err) => {
                        eprintln!("Consensus error: {err:?}");
                        break;
                    }
                }
            }

            // Feed in messages from network...
            while let Ok(msg) = network.try_recv() {
                let cmd = match msg {
                    NetworkMessage::Proposal(p) => ConsensusCommand::Proposal(p),
                    NetworkMessage::Vote(v) => ConsensusCommand::Vote(v),
                };
                consensus.handle_command(cmd);
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    */
    Ok(())
}

/*
#[tokio::test]
async fn consensus_simulation() {
    //setup_tracing_full();

    const NUM_VALIDATORS: usize = 3;
    const NUM_HEIGHTS: u64 = 10;

    let value_hash = Hash(Felt::from_hex_str("0xabcdef").unwrap());
    let value_id = ValueId::new(value_hash);
    let consensus_value = ConsensusValue::new(value_id.clone());

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

        // Clone decisions for this validator
        let decisions = Arc::clone(&decisions);
        let consensus_value = consensus_value.clone();

        let handle = tokio::spawn(async move {
            let mut current_height = 1;

            while current_height <= NUM_HEIGHTS {
                let height = Height::new(current_height);
                let mut consensus = Consensus::new(Config::new(addr));
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
            .filter(|((_, h), _)| *h == Height::new(height))
            .map(|(_, hash)| hash)
            .collect();

        assert_eq!(height_decisions.len(), NUM_VALIDATORS);
        let first = height_decisions[0];
        assert!(height_decisions.iter().all(|h| h == &first));
    }
}

fn pretty_addr(addr: &ValidatorAddress) -> String {
    let addr_str = addr.to_string();
    addr_str.chars().skip(addr_str.len() - 4).collect()
}
*/
