use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
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
    NetworkMessage,
    Proposal,
    Round,
    Signature,
    SignedProposal,
    SignedVote,
    Validator,
    ValidatorSet,
};
use pathfinder_crypto::Felt;
use pathfinder_lib::config::p2p::{P2PConsensusCli, P2PConsensusConfig};
use pathfinder_lib::p2p_network::consensus;
use serde::{Deserialize, Serialize};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
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
    #[arg(
        long = "wal-directory",
        long_help = "Consensus WAL directory",
        value_name = "DIR",
        value_hint = clap::ValueHint::DirPath,
        default_value = "./wal"
    )]
    wal_directory: PathBuf,
    #[arg(
        long = "db-file",
        long_help = "Database file path",
        value_name = "FILE",
        value_hint = clap::ValueHint::FilePath,
        default_value = "./db"
    )]
    db_file: PathBuf,
    #[clap(flatten)]
    consensus: P2PConsensusCli,
}

fn setup_tracing_full() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("trace"));

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct ConsensusValue(p2p_proto::common::Hash);

impl std::fmt::Display for ConsensusValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct NodeAddress(p2p_proto::common::Address);

impl std::fmt::Display for NodeAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<NodeAddress> for Vec<u8> {
    fn from(value: NodeAddress) -> Self {
        value.0 .0.to_be_bytes().to_vec()
    }
}

enum ConsensusTaskEvent {
    /// The consensus engine informs us about an event that it wants us to
    /// handle.
    Event(ConsensusEvent<ConsensusValue, NodeAddress>),
    /// We received an event from the P2P network which has impact on
    /// consensus, so we issue a command to the consensus engine.
    CommandFromP2P(ConsensusCommand<ConsensusValue, NodeAddress>),
}

enum P2PTaskEvent {
    /// An event coming from the P2P network (from the consensus P2P network
    /// main loop).
    P2PEvent(Event),
    /// The consensus engine requested that we produce a proposal, so we create
    /// it, feed it back to the consensus engine, and we must cache it for
    /// gossiping when the engine requests so.
    CacheProposal(HeightAndRound, Vec<ProposalPart>),
    /// The consensus engine decided on the given height and we can finally
    /// removed the proposal that was cached for this height.
    RemoveProposal(u64),
    /// Consensus requested that we gossip a message via the P2P network.
    GossipRequest(NetworkMessage<ConsensusValue, NodeAddress>),
}

trait HeightExt {
    fn height(&self) -> u64;
}

impl HeightExt for NetworkMessage<ConsensusValue, NodeAddress> {
    fn height(&self) -> u64 {
        match self {
            NetworkMessage::Proposal(proposal) => proposal.proposal.height,
            NetworkMessage::Vote(vote) => vote.vote.height,
        }
    }
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
    let validator_address = NodeAddress(Address(
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
                    Felt::from_hex_str(addr).context(format!("Parsing validator address {addr}"))
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|addr| NodeAddress(Address(addr))),
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
        .collect::<Vec<Validator<NodeAddress>>>();
    tracing::trace!("Validators: {:#?}", validators);

    let validator_set = ValidatorSet::new(validators);

    let p2p_config = P2PConsensusConfig::parse_or_exit(config.consensus);
    let (p2p_main_loop_handle, client) = consensus::start(chain_id, p2p_config).await;
    let (mut p2p_event_rx, p2p_client) = client.context("Starting P2P consensus client")?;
    // Cache for proposals that we created and are waiting to be gossiped upon a
    // command from the consensus engine. Once the proposal is gossiped, it is
    // removed from the cache.
    let mut my_proposals_cache = HashMap::new();
    // Cache for proposals that we received from other validators and may need to be
    // proposed by us in another round at the same height. The proposals are removed
    // either when we gossip them or when decision is made at the same height.
    let mut incoming_proposals_cache = BTreeMap::new();
    // Events that are produced by the P2p task consumed by the consensus task.
    // TODO channel size
    let (tx_to_consensus, mut rx_from_p2p) = mpsc::channel::<ConsensusTaskEvent>(10);
    // Events that are produced by the consensus task and consumed by the P2P task.
    // TODO channel size
    let (tx_to_p2p, mut rx_from_consensus) = mpsc::channel::<P2PTaskEvent>(10);

    let p2p_task_handle = util::task::spawn(async move {
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
                                handle_incoming_proposal_part(
                                    height_and_round,
                                    proposal_part,
                                    &mut incoming_proposals_cache,
                                )
                            {
                                let proposal = Proposal {
                                    height: height_and_round.height(),
                                    round: height_and_round.round().into(),
                                    value: ConsensusValue(proposal_commitment),
                                    pol_round: Round::nil(),
                                    proposer: NodeAddress(proposer),
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
                            let vote = p2p_vote_to_consensus_vote(vote);
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
                    let ProposalFin {
                        proposal_commitment,
                    } = proposal_parts
                        .last()
                        .and_then(ProposalPart::as_fin)
                        .expect("Proposals produced by our node are always coherent and complete");

                    tracing::info!(
                        "🖧  🗃️  {validator_address} caching our proposal for {height_and_round}, \
                         hash {proposal_commitment}"
                    );

                    let duplicate_encountered = my_proposals_cache
                        .insert(height_and_round, proposal_parts)
                        .is_some();

                    if duplicate_encountered {
                        tracing::warn!("Duplicate proposal cache request for {height_and_round}!");
                    }
                }
                P2PTaskEvent::RemoveProposal(height) => {
                    tracing::info!(
                        "🖧  🗑️ {validator_address} removing incoming proposals from cache for \
                         height {height} ..."
                    );

                    let removed = incoming_proposals_cache.remove(&height).map(|x| {
                        x.into_keys()
                            .map(|k| k.as_u32().expect("Round not to be None"))
                            .collect::<Vec<_>>()
                    });

                    tracing::debug!(
                        "🖧  🗑️ {validator_address} removing incoming proposals from cache for \
                         height {height} DONE, removed rounds: {removed:?}",
                    );
                }
                P2PTaskEvent::GossipRequest(msg) => match msg {
                    NetworkMessage::Proposal(SignedProposal {
                        proposal,
                        signature: _, /* TODO */
                    }) => {
                        let height_and_round = HeightAndRound::new(
                            proposal.height,
                            proposal.round.as_u32().expect("Valid round"),
                        );

                        let proposal_parts = if let Some(proposal_parts) =
                            my_proposals_cache.remove(&height_and_round)
                        {
                            // TODO we're assuming that all proposals are valid and any failure to
                            // reach consensus in round 0 always yields reproposing the same
                            // proposal in following rounds. This will change once proposal
                            // validation is integrated.
                            proposal_parts
                        } else {
                            // TODO this is here to catch a very rare case which I'm almost
                            // sure occurred at least once during tests on my machine. Once I'm sure
                            // if it's a real concern or not the panic will be removed and
                            // the case handled correctly (if it really occurs).
                            tracing::warn!(
                                "Engine requested gossiping a proposal for {height_and_round} via \
                                 ConsensusEvent::Gossip but we did not create it due to missing \
                                 respective ConsensusEvent::RequestProposal. my_proposals_cache: \
                                 {my_proposals_cache:#?}, incoming_proposals_cache: \
                                 {incoming_proposals_cache:#?}",
                            );

                            // The engine chose us for this round as proposer and requested that we
                            // gossip a proposal from a previous round.
                            let mut prev_rounds_proposals = incoming_proposals_cache
                                .remove(&proposal.height)
                                .expect("Proposal was inserted into the cache");
                            // For now we just choose the proposal from the previous round, and the
                            // rest are kept for debugging purposes.
                            let (round, mut proposal_parts) = prev_rounds_proposals
                                .pop_last()
                                .expect("At least one proposal from a previous round");
                            assert_eq!(
                                round.as_u32().expect("Round not to be None") + 1,
                                proposal.round.as_u32().expect("Round not to be None")
                            );
                            let ProposalInit {
                                round, proposer, ..
                            } = proposal_parts
                                .first_mut()
                                .and_then(ProposalPart::as_init_mut)
                                .expect("First part to be Init");
                            // Since the proposal comes from some previous round we need to correct
                            // the round number and proposer address.
                            assert_ne!(
                                *round,
                                proposal.round.as_u32().expect("Round not to be None")
                            );
                            assert_ne!(*proposer, proposal.proposer.0);
                            *round = proposal.round.as_u32().expect("Round not to be None");
                            *proposer = proposal.proposer.0;
                            proposal_parts
                        };

                        loop {
                            tracing::info!(
                                "🖧  🚀 {validator_address} Gossiping proposal for \
                                 {height_and_round} ..."
                            );
                            match p2p_client
                                .gossip_proposal(height_and_round, proposal_parts.clone())
                                .await
                            {
                                Ok(()) => {
                                    tracing::info!(
                                        "🖧  🚀 {validator_address} Gossiping proposal for \
                                         {height_and_round} DONE"
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
                            tracing::info!("🖧  ✋ {validator_address} Gossiping vote {vote:?} ...");
                            match p2p_client
                                .gossip_vote(consensus_vote_to_p2p_vote(vote.clone()))
                                .await
                            {
                                Ok(()) => {
                                    tracing::info!(
                                        "🖧  ✋ {validator_address} Gossiping vote {vote:?} SUCCESS"
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

    let consensus_task_handle = util::task::spawn(async move {
        fn start_height(
            consensus: &mut Consensus<ConsensusValue, NodeAddress>,
            started_heights: &mut HashSet<u64>,
            height: u64,
            validator_set: ValidatorSet<NodeAddress>,
        ) {
            if !started_heights.contains(&height) {
                started_heights.insert(height);
                consensus.handle_command(ConsensusCommand::StartHeight(height, validator_set));
            }
        }

        let mut consensus = Consensus::new(
            Config::new(validator_address)
                .with_wal_dir(config.wal_directory)
                .with_history_depth(
                    // TODO: We don't support round certificates yet, and we want to limit
                    // rebroadcasting to a minimum. Rebroadcast timeouts will happen for historical
                    // engines which are finalized because the effect `CancelAllTimeouts` is only
                    // triggered upon a new round or a new height.
                    0,
                ),
        );

        // A validator that joins the consensus network and is lagging behind will vote
        // Nil for its current height, because the consensus network is already at a
        // higher height. This is a workaround for the missing sync/catch-up mechanism
        // that we'll have in pathfinder, once this tool is actually merged into
        // pathfinder.
        let mut last_nil_vote_height = None;

        let db_height = std::fs::read_to_string(&config.db_file)
            .unwrap_or_else(|e| {
                tracing::warn!("Failed to read db file {}: {e}", config.db_file.display());
                String::new()
            })
            .parse::<u64>()
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "Failed to parse db file {}: {e}, starting at height 0",
                    config.db_file.display()
                );
                0
            });

        let mut current_height = db_height;
        let mut started_heights = HashSet::new();

        start_height(
            &mut consensus,
            &mut started_heights,
            current_height,
            validator_set.clone(),
        );

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

                            let wire_proposal = sepolia_block_6_based_proposal(
                                height,
                                round.into(),
                                validator_address.0,
                            );

                            let ProposalFin {
                                proposal_commitment,
                            } = wire_proposal.last().and_then(ProposalPart::as_fin).expect(
                                "Proposals produced by our node are always coherent and complete",
                            );

                            let value = ConsensusValue(*proposal_commitment);

                            tx_to_p2p
                                .send(P2PTaskEvent::CacheProposal(
                                    HeightAndRound::new(height, round),
                                    wire_proposal,
                                ))
                                .await
                                .expect("Receiver not to be dropped");

                            let proposal = Proposal {
                                height,
                                round: round.into(),
                                proposer: validator_address,
                                pol_round: Round::nil(),
                                value,
                            };

                            tracing::info!(
                                "🧠 ⚙️  {validator_address} handling command Propose({proposal:?})"
                            );

                            consensus.handle_command(ConsensusCommand::Propose(proposal));
                        }
                        ConsensusEvent::Gossip(msg) => {
                            // TODO Sometimes the engine requests gossiping votes for heights that
                            // are a few steps behind the current height and have already been
                            // decided upon. This is due to the fact that `history_depth` in config
                            // is > 0 and we're not supporting round certificates yet. Setting
                            // history depth to a low value (or 0) should mitigate this issue for
                            // now.
                            if msg.height() >= current_height {
                                // Record the highest height at which we voted Nil as it may be an
                                // indication that we're lagging behind the consensus network.
                                if let NetworkMessage::Vote(SignedVote { vote, .. }) = &msg {
                                    if vote.is_nil() {
                                        last_nil_vote_height = Some(
                                            vote.height
                                                .max(last_nil_vote_height.unwrap_or_default()),
                                        );
                                    }
                                }

                                tx_to_p2p
                                    .send(P2PTaskEvent::GossipRequest(msg))
                                    .await
                                    .expect("Receiver not to be dropped");
                            } else {
                                tracing::debug!(
                                    "🧠 🤷 Ignoring gossip request for height {} < \
                                     {current_height}",
                                    msg.height()
                                );
                            }
                        }
                        ConsensusEvent::Decision { height, value } => {
                            tracing::info!(
                                "🧠 ✅ {validator_address} decided on {value:?} at height {height}"
                            );
                            // TODO commit the block to storage
                            // commit_block(height, hash);

                            let db_file = config.db_file.clone();
                            let _ = util::task::spawn_blocking(move |_| {
                                std::fs::write(db_file, current_height.to_string())
                            })
                            .await;

                            assert!(started_heights.remove(&height));

                            if height == current_height {
                                current_height = current_height
                                    .checked_add(1)
                                    .expect("Height never reaches i64::MAX");
                                start_height(
                                    &mut consensus,
                                    &mut started_heights,
                                    current_height,
                                    validator_set.clone(),
                                );
                            }

                            tx_to_p2p
                                .send(P2PTaskEvent::RemoveProposal(height))
                                .await
                                .expect("Receiver not to be dropped");
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

                    let cmd_height = cmd.height();
                    match &cmd {
                        // There were no p2p messages for a height higher than the current height,
                        // so we did start a new height upon successful decision, before any p2p
                        // messages for the new height were received.
                        ConsensusCommand::StartHeight(..) | ConsensusCommand::Propose(_) => {
                            assert!(cmd_height >= current_height);
                            assert!(started_heights.contains(&cmd_height));
                        }
                        // Sometimes messages for the next height are received before the engine
                        // decides upon the current height. In such case we need to ensure that a
                        // consensus engine is already started for this new height carried in those
                        // messages.
                        ConsensusCommand::Proposal(_) | ConsensusCommand::Vote(_) => {
                            // TODO catch up with the current height of the consensus network using
                            // sync, for the time being just observe the height in the rebroadcasted
                            // votes or in the proposals.
                            let last_nil = last_nil_vote_height.take();

                            if let Some(last_nil) = last_nil {
                                if cmd_height > current_height && cmd_height > last_nil {
                                    tracing::info!(
                                        "🧠 ⏩  {validator_address} catching up current height \
                                         {current_height} -> {cmd_height}",
                                    );
                                    current_height = cmd_height;
                                } else {
                                    last_nil_vote_height = Some(last_nil);
                                }
                            }

                            start_height(
                                &mut consensus,
                                &mut started_heights,
                                cmd_height,
                                validator_set.clone(),
                            );
                        }
                    }

                    consensus.handle_command(cmd);
                }
            }

            // Malachite is coroutine based, otherwise we starve other futures
            // in the outer select.
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

fn handle_incoming_proposal_part(
    height_and_round: HeightAndRound,
    proposal_part: ProposalPart,
    cache: &mut BTreeMap<u64, BTreeMap<Round, Vec<ProposalPart>>>,
) -> anyhow::Result<Option<(Hash, Address)>> {
    let height = height_and_round.height();
    let round = height_and_round.round().into();
    let proposals_at_height = cache.entry(height).or_default();
    let parts = proposals_at_height.entry(round).or_default();
    match proposal_part {
        ProposalPart::Init(_) => {
            if parts.is_empty() {
                parts.push(proposal_part);
                // TODO send for validation or validate in place
                Ok(None)
            } else {
                Err(anyhow::anyhow!(
                    "Unexpected proposal Init for height and round {} at position {}",
                    height,
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
                    height,
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
                    height,
                    parts.len()
                ))
            }
        }
        ProposalPart::Fin(ProposalFin {
            proposal_commitment,
        }) => {
            parts.push(proposal_part);
            let ProposalPart::Init(ProposalInit { proposer, .. }) =
                parts.first().expect("Proposal Init")
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
fn sepolia_block_6_based_proposal(
    height: u64,
    round: Round,
    proposer: Address,
) -> Vec<ProposalPart> {
    let round = round.as_u32().expect("Round not to be Nil???");
    vec![
        ProposalPart::Init(ProposalInit {
            height,
            round,
            valid_round: None, // TODO
            proposer,
        }),
        // Some "real" payload
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
        ProposalPart::Fin(ProposalFin {
            // For easy debugging
            proposal_commitment: Hash(Felt::from_u64(height)),
        }),
    ]
}

fn p2p_vote_to_consensus_vote(
    vote: p2p_proto::consensus::Vote,
) -> pathfinder_consensus::Vote<ConsensusValue, NodeAddress> {
    pathfinder_consensus::Vote {
        r#type: match vote.vote_type {
            p2p_proto::consensus::VoteType::Prevote => pathfinder_consensus::VoteType::Prevote,
            p2p_proto::consensus::VoteType::Precommit => pathfinder_consensus::VoteType::Precommit,
        },
        height: vote.height,
        round: vote.round.into(),
        value: vote.block_hash.map(ConsensusValue),
        validator_address: NodeAddress(vote.voter),
    }
}

fn consensus_vote_to_p2p_vote(
    vote: pathfinder_consensus::Vote<ConsensusValue, NodeAddress>,
) -> p2p_proto::consensus::Vote {
    p2p_proto::consensus::Vote {
        vote_type: match vote.r#type {
            pathfinder_consensus::VoteType::Prevote => p2p_proto::consensus::VoteType::Prevote,
            pathfinder_consensus::VoteType::Precommit => p2p_proto::consensus::VoteType::Precommit,
        },
        height: vote.height,
        round: vote.round.as_u32().expect("Round not to be Nil"),
        block_hash: vote.value.map(|v| v.0),
        voter: vote.validator_address.0,
        extension: None,
    }
}
