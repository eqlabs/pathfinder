use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use p2p::consensus::HeightAndRound;
use p2p_proto::common::{Address, Hash, L1DataAvailabilityMode};
use p2p_proto::consensus::{BlockInfo, ProposalFin, ProposalInit, ProposalPart};
use pathfinder_common::{felt, ContractAddress};
use pathfinder_consensus::{
    Config,
    Consensus,
    ConsensusCommand,
    ConsensusEvent,
    NetworkMessage,
    Proposal,
    PublicKey,
    Round,
    SignedVote,
    SigningKey,
    Validator,
    ValidatorSet,
};
use pathfinder_crypto::Felt;
use tokio::sync::mpsc;

use super::{ConsensusTaskEvent, ConsensusValue, HeightExt, P2PTaskEvent};
use crate::config::ConsensusConfig;

pub fn spawn(
    config: ConsensusConfig,
    wal_directory: PathBuf,
    tx_to_p2p: mpsc::Sender<P2PTaskEvent>,
    mut rx_from_p2p: mpsc::Receiver<ConsensusTaskEvent>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let mut current_height_file = wal_directory.clone();
    current_height_file.pop();
    current_height_file = current_height_file.join("current_height");

    let mut current_height = std::fs::read_to_string(&current_height_file)
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to read height file {}: {e}",
                current_height_file.display()
            );
            String::new()
        })
        .parse::<u64>()
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to parse height file {}: {e}, starting at height 0",
                current_height_file.display()
            );
            0
        });

    util::task::spawn(async move {
        let mut consensus = Consensus::new(
            Config::new(config.my_validator_address)
                .with_wal_dir(wal_directory)
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

        let validator_address = config.my_validator_address;

        let validators = std::iter::once(validator_address)
            .chain(config.validator_addresses)
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
            .collect::<Vec<Validator<_>>>();
        tracing::trace!("Validators: {:#?}", validators);

        let validator_set = ValidatorSet::new(validators);

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
                                validator_address,
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

                            let current_height_file = current_height_file.clone();
                            let _ = util::task::spawn_blocking(move |_| {
                                std::fs::write(current_height_file, current_height.to_string())
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

        Ok(())
    })
}

fn start_height(
    consensus: &mut Consensus<ConsensusValue, ContractAddress>,
    started_heights: &mut HashSet<u64>,
    height: u64,
    validator_set: ValidatorSet<ContractAddress>,
) {
    if !started_heights.contains(&height) {
        started_heights.insert(height);
        consensus.handle_command(ConsensusCommand::StartHeight(height, validator_set));
    }
}

/// Based on Sepolia Block 6, however with adjustable height, round, and
/// proposer.
fn sepolia_block_6_based_proposal(
    height: u64,
    round: Round,
    proposer: ContractAddress,
) -> Vec<ProposalPart> {
    let round = round.as_u32().expect("Round not to be Nil???");
    let proposer = Address(proposer.0);
    vec![
        ProposalPart::Init(ProposalInit {
            height,
            round,
            valid_round: None,
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
