use std::time::Duration;

use anyhow::Context;
use cached::{Cached, TimedCache};
use clap::Parser;
use ed25519_consensus::SigningKey;
use malachite_signing_ed25519::PublicKey;
use p2p::consensus::{Event, HeightAndRound};
use p2p_proto::common::{Address, Hash};
use p2p_proto::consensus::ProposalPart;
use pathfinder_common::ChainId;
use pathfinder_consensus::{
    Config,
    Consensus,
    ConsensusCommand,
    ConsensusEvent,
    ConsensusValue,
    Height,
    Proposal,
    Round,
    Signature,
    SignedVote,
    Validator,
    ValidatorAddress,
    ValidatorSet,
    ValueId,
};
use pathfinder_crypto::Felt;
use pathfinder_lib::config::p2p::{P2PConsensusCli, P2PConsensusConfig};
use pathfinder_lib::p2p_network::consensus;
// use pathfinder_lib::validator; TODO
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::EnvFilter;
use util::task;

#[derive(Parser)]
pub struct Cli {
    #[arg(
        long = "network",
        long_help = "mainnet or sepolia (testnet)",
        value_name = "NETWORK",
        default_value = "sepolia"
    )]
    network: String,
    #[arg(
        long = "validator-address",
        long_help = "Validator address to use for this node",
        value_name = "ADDRESS"
    )]
    validator_address: String,
    #[arg(
        long = "validators",
        long_help = "A comma-separated list of the other validator addresses",
        value_name = "ADDRESS_LIST",
        value_delimiter = ','
    )]
    validators: Vec<String>,
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
    let chain_id = match network.as_str() {
        "mainnet" => ChainId::MAINNET,
        "sepolia" => ChainId::SEPOLIA_TESTNET,
        _ => anyhow::bail!("Unsupported network: {}", network),
    };
    let validator_address = ValidatorAddress::from(Address(
        Felt::from_hex_str(&config.validator_address).context(format!(
            "Parsing validator address {}",
            config.validator_address
        ))?,
    ));
    anyhow::ensure!(!config.validators.is_empty(), "No validators provided");

    let validators = std::iter::once(validator_address)
        .chain(
            config
                .validators
                .iter()
                .map(|addr| {
                    Felt::from_hex_str(&addr).context(format!("Parsing validator address {addr}"))
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|addr| ValidatorAddress::from(Address(addr))),
        )
        .map(|address| {
            let sk = SigningKey::new(rand::rngs::OsRng);
            let vk = sk.verification_key();
            let public_key = PublicKey::from_bytes(vk.to_bytes());

            Validator {
                address,
                public_key,
                voting_power: 1,
            }
        })
        .collect::<Vec<Validator>>();
    tracing::debug!("validators: {:#?}", validators);
    // anyhow::bail!("test");

    let validator_set = ValidatorSet::new(validators);

    let config = P2PConsensusConfig::parse_or_exit(config.consensus);
    let (p2p_handle, client) = consensus::start(chain_id, config).await;
    let (mut p2p_event_rx, _p2p_client) = client.context("Starting P2P consensus client")?;
    // TODO figure out proposal part retention time
    const ONE_HOUR: u64 = 3600;
    let mut proposal_cache = TimedCache::<HeightAndRound, ProposalPart>::with_lifespan(ONE_HOUR);

    let consensus_handle = task::spawn(async move {
        let mut consensus = Consensus::new(Config::new(validator_address));
        consensus.handle_command(ConsensusCommand::StartHeight(Height::new(0), validator_set));
        // TODO not sure if this is needed
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        loop {
            if let Some(event) = consensus.next_event().await {
                match event {
                    ConsensusEvent::RequestProposal {
                        height: h,
                        round: r,
                        ..
                    } => {
                        tracing::info!(
                            "🔍 {validator_address} is proposing at height {h}, round {r:?}",
                        );

                        let proposal = Proposal {
                            height: h,
                            round: r,
                            proposer: validator_address,
                            pol_round: Round::from(0),
                            value_id: ConsensusValue::new(ValueId::new(Hash(
                                Felt::from_hex_str("0xabcdef").unwrap(),
                            ))),
                        };

                        consensus.handle_command(ConsensusCommand::Propose(proposal));
                    }

                    ConsensusEvent::Gossip(_msg) => {
                        // TODO
                        // gossip to network
                    }

                    ConsensusEvent::Decision { height: h, hash } => {
                        tracing::info!("✅ {validator_address} decided on {hash:?} at height {h}");
                        // TODO
                        // commit_block(height, hash);
                    }

                    ConsensusEvent::Error(error) => {
                        // TODO are all of these errors fatal or recoverable?
                        // What is the best way to handle them?
                        tracing::error!("❌ {validator_address} error: {error:?}");
                        // Bail out, stop the consensus
                        break;
                    }
                }
            }

            // Process inbound network messages
            while let Ok(event) = p2p_event_rx.try_recv() {
                tracing::info!("💌 {validator_address} received command: {event:?}");

                match event {
                    Event::Proposal(height_and_round, proposal_part) => {
                        proposal_cache.cache_set(height_and_round, proposal_part);
                    }
                    Event::Vote(vote) => {
                        let cmd = ConsensusCommand::Vote(SignedVote {
                            vote: vote.into(),
                            signature: Signature::test(), // TODO
                        });
                        consensus.handle_command(cmd);
                    }
                }

                // let cmd = match msg {
                //     NetworkMessage::Proposal(p) =>
                // ConsensusCommand::Proposal(p),
                //     NetworkMessage::Vote(v) => ConsensusCommand::Vote(v),
                // };
                // consensus.handle_command(cmd);
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    tokio::select! {
        result = p2p_handle => {
            tracing::info!("P2P consensus task finished with result: {:?}", result);
        }
        _ = consensus_handle => {
            tracing::info!("Consensus engine task finished unexpectedly");
        }
        _ = term_signal.recv() => {
            tracing::info!("TERM signal received");
        }
        _ = int_signal.recv() => {
            tracing::info!("INT signal received");
        }
    }

    tracing::info!("Shutdown started, waiting for tasks to finish...");
    util::task::tracker::close();
    // Force exit after a grace period
    match tokio::time::timeout(Duration::from_secs(10), util::task::tracker::wait()).await {
        Ok(_) => {
            tracing::info!("Shutdown finished successfully")
        }
        Err(_) => {
            tracing::error!("Some tasks failed to finish in time, forcing exit");
        }
    }

    Ok(())
}
