use std::time::Duration;

use anyhow::Context;
use cached::{Cached, TimedCache};
use clap::Parser;
use ed25519_consensus::SigningKey;
use malachite_signing_ed25519::PublicKey;
use p2p::consensus::{Event, HeightAndRound};
use p2p::libp2p::gossipsub::PublishError;
use p2p_proto::common::{Address, Hash, L1DataAvailabilityMode};
use p2p_proto::consensus::{BlockInfo, ProposalFin, ProposalInit, ProposalPart};
use pathfinder_common::{felt, ChainId};
use pathfinder_consensus::{
    Config,
    Consensus,
    ConsensusCommand,
    ConsensusEvent,
    ConsensusValue,
    Height,
    NetworkMessage,
    Proposal,
    Round,
    Signature,
    SignedProposal,
    SignedVote,
    // TimeoutValues,
    Validator,
    ValidatorAddress,
    ValidatorSet,
};
use pathfinder_crypto::Felt;
use pathfinder_lib::config::p2p::{P2PConsensusCli, P2PConsensusConfig};
use pathfinder_lib::p2p_network::consensus;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
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
        // .without_time()
        .try_init();
}

enum ConsensusTaskEvent {
    /// The consensus engine informs us about an event that it wants us to
    /// handle.
    Event(ConsensusEvent),
    /// We received an event from the P2P network which has impact on
    /// consensus, so we issue a command to the consensus engine.
    CommandFromP2P(ConsensusCommand),
}

enum P2PTaskEvent {
    /// An event coming from the P2P network (from the consensus P2P network
    /// main loop).
    P2PEvent(Event),
    /// The consensus engine requested that we produce a proposal, so we create
    /// it, feed it back to the consensus engine, and we must cache it for
    /// gossiping when the engine requests so.
    CacheProposal(HeightAndRound, Vec<ProposalPart>),
    /// Consensus requested that we gossip a message via the P2P network.
    GossipRequest(NetworkMessage),
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

    let validator_set = ValidatorSet::new(validators);

    let config = P2PConsensusConfig::parse_or_exit(config.consensus);
    let (p2p_main_loop_handle, client) = consensus::start(chain_id, config).await;
    let (mut p2p_event_rx, p2p_client) = client.context("Starting P2P consensus client")?;
    // TODO figure out proposal part retention time
    const ONE_HOUR: u64 = 3600;
    let mut cache = TimedCache::<HeightAndRound, Vec<ProposalPart>>::with_lifespan(ONE_HOUR);

    // Events that are produced by the P2p task consumed by the consensus task.
    // TODO channel size
    let (tx_to_consensus, mut rx_from_p2p) = mpsc::channel::<ConsensusTaskEvent>(10);
    // Events that are produced by the consensus task and consumed by the P2P task.
    // TODO channel size
    let (tx_to_p2p, mut rx_from_consensus) = mpsc::channel::<P2PTaskEvent>(10);

    let p2p_task_handle = task::spawn(async move {
        loop {
            let p2p_task_event = tokio::select! {
                p2p_event = p2p_event_rx.recv() => {
                    match p2p_event {
                        Some(event) => P2PTaskEvent::P2PEvent(event),
                        None => {
                            tracing::warn!("P2P event receiver was dropped, exiting P2P task");
                            return;
                        }
                    }
                }
                from_consensus = rx_from_consensus.recv() => {
                    from_consensus.expect("Receiver not to be dropped")
                }
            };

            match p2p_task_event {
                P2PTaskEvent::P2PEvent(event) => {
                    tracing::info!("🖧  💌 {validator_address} incoming p2p event: {event:?}");

                    match event {
                        Event::Proposal(height_and_round, proposal_part) => {
                            if let Ok(Some((proposal_commitment, proposer))) =
                                handle_proposal_part(height_and_round, proposal_part, &mut cache)
                            {
                                let proposal = Proposal {
                                    height: Height::try_from(height_and_round.height())
                                        .expect("Valid block number"),
                                    round: height_and_round.round().into(),
                                    value: proposal_commitment.into(),
                                    pol_round: Round::nil(),
                                    proposer: proposer.into(),
                                };

                                let cmd = ConsensusCommand::Proposal(SignedProposal {
                                    proposal,
                                    signature: Signature::test(), // TODO
                                });

                                tx_to_consensus
                                    .send(ConsensusTaskEvent::CommandFromP2P(cmd))
                                    .await
                                    .expect("Receiver not to be dropped");
                            }
                        }
                        Event::Vote(vote) => {
                            let vote = vote.into();
                            let cmd = ConsensusCommand::Vote(SignedVote {
                                vote,
                                signature: Signature::test(), // TODO
                            });

                            tx_to_consensus
                                .send(ConsensusTaskEvent::CommandFromP2P(cmd))
                                .await
                                .expect("Receiver not to be dropped");
                        }
                    }
                }
                P2PTaskEvent::CacheProposal(height_and_round, proposal_parts) => {
                    let ProposalPart::Fin(ProposalFin {
                        proposal_commitment,
                    }) = proposal_parts.last().expect("Valid proposal")
                    else {
                        unreachable!("Simulated proposal always ends with Fin");
                    };
                    let proposal_commitment = proposal_commitment.0;

                    tracing::info!(
                        "🖧  🗃️ {validator_address} caching our proposal for {height_and_round}, \
                         hash {proposal_commitment}"
                    );

                    cache.cache_set(height_and_round, proposal_parts);
                }
                P2PTaskEvent::GossipRequest(msg) => match msg {
                    NetworkMessage::Proposal(SignedProposal {
                        proposal,
                        signature: _, /* TODO */
                    }) => {
                        let height_and_round = HeightAndRound::new(
                            proposal.height.as_inner().get(),
                            // TODO What about Nil rounds?
                            proposal.round.as_u32().unwrap_or_default(),
                        );
                        let proposal = cache
                            .cache_remove(&height_and_round)
                            .expect("Proposal was inserted into the cache");

                        loop {
                            tracing::info!(
                                "🖧  🚀 {validator_address} Gossiping proposal for \
                                 {height_and_round}"
                            );
                            match p2p_client
                                .gossip_proposal(height_and_round, proposal.clone())
                                .await
                            {
                                Ok(()) => {
                                    tracing::info!(
                                        "🖧  🚀🎉 {validator_address} Gossiping proposal SUCCESS!"
                                    );
                                    break;
                                }
                                Err(PublishError::InsufficientPeers) => {
                                    tracing::warn!(
                                        "Insufficient peers to gossip proposal for \
                                         {height_and_round}, retrying..."
                                    );
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                }
                                Err(error) => {
                                    tracing::error!(
                                        "Error gossiping proposal for {height_and_round}: {error}"
                                    );
                                    // TODO Unrecoverable?
                                    return;
                                }
                            }
                        }
                    }
                    NetworkMessage::Vote(SignedVote {
                        vote,
                        signature: _, /* TODO */
                    }) => {
                        loop {
                            tracing::info!("🖧  ✋ {validator_address} Gossiping vote {vote:?}");
                            match p2p_client.gossip_vote(vote.clone().into()).await {
                                Ok(()) => {
                                    tracing::info!(
                                        "🖧  ✋🎉 {validator_address} Gossiping vote SUCCESS!"
                                    );
                                    break;
                                }
                                Err(PublishError::InsufficientPeers) => {
                                    tracing::warn!(
                                        "Insufficient peers to gossip {vote:?}, retrying..."
                                    );
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                }
                                Err(error) => {
                                    tracing::error!("Error gossiping {vote:?}: {error}");
                                    // TODO Unrecoverable?
                                    return;
                                }
                            }
                        }
                    }
                },
            }
        }
    });

    let consensus_task_handle = task::spawn(async move {
        let mut consensus = Consensus::new(Config::new(validator_address).with_timeout_values(
            // TimeoutValues {
            //     propose: Duration::from_secs(60),
            //     prevote: Duration::from_secs(60),
            //     precommit: Duration::from_secs(60),
            //     rebroadcast: Duration::from_secs(10),
            // },
            Default::default(),
        ));

        // Add grace time before others can join
        if validator_address == ValidatorAddress::from(Address(Felt::ONE)) {
            tracing::info!("🧠 ⏳  {validator_address} waiting before starting consensus...");
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }

        consensus.handle_command(ConsensusCommand::StartHeight(
            Height::try_from(0).expect("Valid block number"),
            validator_set,
        ));

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        loop {
            let consensus_task_event = tokio::select! {
                consensus_event = consensus.next_event() => {
                    match consensus_event {
                        Some(event) => ConsensusTaskEvent::Event(event),
                        None => {
                            continue;
                        }
                    }
                }
                from_p2p = rx_from_p2p.recv() => {
                    from_p2p.expect("Receiver not to be dropped")
                }
            };

            match consensus_task_event {
                ConsensusTaskEvent::Event(event) => {
                    tracing::info!("🧠 ℹ️  {validator_address} consensus event: {event:?}");

                    match event {
                        ConsensusEvent::RequestProposal { height, round, .. } => {
                            tracing::info!(
                                "🧠 🔍 {validator_address} is proposing at height {height}, round \
                                 {round}",
                            );

                            let wire_proposal =
                                sepolia_block_6_proposal(height, round, validator_address.into());

                            let ProposalPart::Fin(ProposalFin {
                                proposal_commitment,
                            }) = wire_proposal.last().expect("Valid proposal")
                            else {
                                unreachable!()
                            };
                            let proposal_commitment = *proposal_commitment;

                            tx_to_p2p
                                .send(P2PTaskEvent::CacheProposal(
                                    HeightAndRound::new(
                                        height.as_inner().get(),
                                        round.as_u32().unwrap_or_default(),
                                    ),
                                    wire_proposal,
                                ))
                                .await
                                .expect("Receiver not to be dropped");

                            let proposal = Proposal {
                                height,
                                round,
                                proposer: validator_address,
                                pol_round: Round::nil(),
                                value: ConsensusValue::new(proposal_commitment),
                            };

                            tracing::info!(
                                "🧠 ⚙️  {validator_address} handling command Propose({proposal:?})"
                            );

                            consensus.handle_command(ConsensusCommand::Propose(proposal));
                        }
                        ConsensusEvent::Gossip(msg) => {
                            tx_to_p2p
                                .send(P2PTaskEvent::GossipRequest(msg))
                                .await
                                .expect("Receiver not to be dropped");
                        }
                        ConsensusEvent::Decision { height, value } => {
                            tracing::info!(
                                "🧠 ✅ {validator_address} decided on {value:?} at height {height}"
                            );
                            // TODO
                            // commit_block(height, hash);
                        }
                        ConsensusEvent::Error(error) => {
                            // TODO are all of these errors fatal or recoverable?
                            // What is the best way to handle them?
                            tracing::error!("🧠 ❌ {validator_address} consensus error: {error:?}");
                            // Bail out, stop the consensus
                            break;
                        }
                    }
                }
                ConsensusTaskEvent::CommandFromP2P(cmd) => {
                    tracing::info!("🧠 ⚙️  {validator_address} handling command {cmd:?}");
                    consensus.handle_command(cmd);
                }
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    tokio::select! {
        result = p2p_main_loop_handle => {
            tracing::info!("P2P consensus main loop finished with result: {:?}", result);
        }
        _ = p2p_task_handle => {
            tracing::info!("P2P task finished unexpectedly");
        }
        _ = consensus_task_handle => {
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

fn handle_proposal_part(
    height_and_round: HeightAndRound,
    proposal_part: ProposalPart,
    cache: &mut TimedCache<HeightAndRound, Vec<ProposalPart>>,
) -> anyhow::Result<Option<(Hash, Address)>> {
    let parts = cache.cache_get_or_set_with(height_and_round, Vec::new);
    match proposal_part {
        ProposalPart::Init(_) => {
            if parts.is_empty() {
                parts.push(proposal_part);
                // TODO send for validation or validate in place
                Ok(None)
            } else {
                Err(anyhow::anyhow!(
                    "Unexpected proposal Init for height and round {} at posiotion {}",
                    height_and_round,
                    parts.len()
                ))
            }
        }
        ProposalPart::BlockInfo(_) => {
            if parts.len() == 1 {
                parts.push(proposal_part);
                // TODO send for validation or validate in place
                Ok(None)
            } else {
                Err(anyhow::anyhow!(
                    "Unexpected proposal BlockInfo for height and round {} at position {}",
                    height_and_round,
                    parts.len()
                ))
            }
        }
        ProposalPart::TransactionBatch(_) => {
            // TODO check if there a length limit for the batch at network
            // level?
            if parts.len() >= 2 {
                parts.push(proposal_part);
                // TODO send for execution
                Ok(None)
            } else {
                Err(anyhow::anyhow!(
                    "Unexpected proposal TransactionBatch for height and round {} at position {}",
                    height_and_round,
                    parts.len()
                ))
            }
        }
        ProposalPart::Fin(ProposalFin {
            proposal_commitment,
        }) => {
            parts.push(proposal_part);
            let ProposalPart::Init(ProposalInit { proposer, .. }) =
                parts.get(0).expect("Proposal Init")
            else {
                unreachable!("Proposal Init is inserted first");
            };

            // TODO validate commitment
            Ok(Some((proposal_commitment, *proposer)))
        }
    }
}

/// Based on Sepolia Block 6, however with adjustable height, round, and
/// proposer.
fn sepolia_block_6_proposal(height: Height, round: Round, proposer: Address) -> Vec<ProposalPart> {
    let round = round.as_u32().expect("Round not to be Nil???");
    vec![
        ProposalPart::Init(ProposalInit {
            height: height.into_inner().get(),
            round,
            // valid_round: Some(round), // TODO ???
            valid_round: None,
            proposer,
        }),
        ProposalPart::BlockInfo(BlockInfo {
            height: 0,
            timestamp: 1700483673,
            builder: proposer,
            l1_da_mode: L1DataAvailabilityMode::Calldata,
            l2_gas_price_fri: 1,
            l1_gas_price_wei: 1000000018,
            l1_data_gas_price_wei: 1,
            eth_to_fri_rate: 0,
        }),
        ProposalPart::TransactionBatch(vec![p2p_proto::consensus::Transaction {
            txn: p2p_proto::consensus::TransactionVariant::L1HandlerV0(
                p2p_proto::transaction::L1HandlerV0 {
                    nonce: Felt::ZERO,
                    address: Address(felt!(
                        "0x04C5772D1914FE6CE891B64EB35BF3522AEAE1315647314AAC58B01137607F3F"
                    )),
                    entry_point_selector: felt!(
                        "0x02D757788A8D8D6F21D1CD40BCE38A8222D70654214E96FF95D8086E684FBEE5"
                    ),
                    calldata: vec![
                        felt!("0x0000000000000000000000008453FC6CD1BCFE8D4DFC069C400B433054D47BDC"),
                        felt!("0x043ABAA073C768EBF039C0C4F46DB9ACC39E9EC165690418060A652AAB39E7D8"),
                        felt!("0x0000000000000000000000000000000000000000000000000DE0B6B3A7640000"),
                        Felt::ZERO,
                    ],
                },
            ),
            transaction_hash: Hash(felt!(
                "0x0785C2ADA3F53FBC66078D47715C27718F92E6E48B96372B36E5197DE69B82B5"
            )),
        }]),
        // ProposalPart::Fin(ProposalFin {
        //     proposal_commitment: Hash(felt!(
        //         "0x03BBA41E01A79A3BB776F2B5AB48EB3C5DF23717B558EEF04CC640E23153A743"
        //     )),
        // }),
        ProposalPart::Fin(ProposalFin {
            proposal_commitment: Hash(Felt::from_u64(height.as_inner().get())),
        }),
    ]
}
