//! Consensus behaviour and other related utilities for the consensus p2p
//! network.
mod behaviour;
mod client;
mod height_and_round;
mod stream;

use std::collections::HashMap;

pub use behaviour::Behaviour;
use height_and_round::HeightAndRound;
use p2p_proto::consensus::{ProposalPart, Vote};
use pathfinder_common::ContractAddress;
use smallvec::SmallVec;
use stream::{StreamMessage, StreamMessageBody, StreamState};
use tokio::sync::mpsc::Sender;

/// The topic for proposal messages in the consensus network.
pub const TOPIC_PROPOSALS: &str = "consensus_proposals";
/// The topic for vote messages in the consensus network.
pub const TOPIC_VOTES: &str = "consensus_votes";

/// The type of validator address in the consensus network.
pub type ValidatorAddress = ContractAddress;

/// Commands for the consensus behaviour.
#[derive(Debug, Clone)]
pub enum Command {
    /// A proposal (part) for a new block.
    Proposal {
        height_and_round: HeightAndRound,
        proposal: Vec<ProposalPart>,
        done_tx: Sender<anyhow::Result<()>>,
    },
    /// A vote for a proposal.
    Vote {
        vote: Vote,
        done_tx: Sender<anyhow::Result<()>>,
    },
    /// Test command to create a proposal stream.
    #[cfg(test)]
    TestProposalStream(HeightAndRound, Vec<ProposalPart>, bool),
}

/// Events emitted by the consensus behaviour.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// A proposal (part) for a new block.
    Proposal(HeightAndRound, ProposalPart),
    /// A vote for a proposal.
    Vote(Vote),
}

/// Configuration for the consensus P2P network.
#[derive(Default)]
pub struct Config {}

/// The state of the consensus P2P network.
#[derive(Default)]
pub struct State {
    /// The active streams of the consensus P2P network.
    active_streams: HashMap<HeightAndRound, StreamState<ProposalPart>>,
    // TODO: Implement cleanup of inactive streams
}

impl State {
    pub fn new() -> Self {
        Self {
            active_streams: HashMap::new(),
        }
    }
}

/// Create a new outgoing proposal stream message.
pub fn create_outgoing_proposal_message(
    state: &mut State,
    height_and_round: HeightAndRound,
    proposal: ProposalPart,
) -> SmallVec<[StreamMessage<ProposalPart>; 2]> {
    let mut messages = SmallVec::with_capacity(2);

    // Get or create stream state
    let stream_state = state
        .active_streams
        .entry(height_and_round)
        .or_insert_with(StreamState::new_outgoing);

    if let StreamState::Outgoing(state) = stream_state {
        let message_id = state.last_sent_message_id.map_or(0, |id| id + 1);

        // Track the sent message
        state.sent_messages.insert(message_id, proposal.clone());
        state.last_sent_message_id = Some(message_id);

        messages.push(StreamMessage {
            message: StreamMessageBody::Content(proposal.clone()),
            stream_id: height_and_round,
            message_id,
        });

        // If this is the last message, send the Fin signal
        if matches!(proposal, ProposalPart::Fin(_)) {
            let message_id = state.last_sent_message_id.unwrap();

            // Track the Fin message
            state.fin_sent = true;

            messages.push(StreamMessage {
                message: StreamMessageBody::Fin,
                stream_id: height_and_round,
                message_id: message_id + 1,
            });
        }
    } else {
        panic!("Expected Outgoing stream state")
    }

    messages
}

/// Handle an incoming proposal message.
pub fn handle_incoming_proposal_message(
    state: &mut State,
    message: StreamMessage<ProposalPart>,
) -> Vec<Event> {
    let stream_id = message.stream_id;

    // Get or create stream state for this (height, round)
    let stream_state = state
        .active_streams
        .entry(stream_id)
        .or_insert_with(StreamState::new_incoming);

    if let StreamState::Incoming(state) = stream_state {
        // Discard invalid messages
        if let Some(fin_id) = state.fin_message_id {
            if message.message_id >= fin_id {
                return vec![];
            }
        }

        // Handle "Fin" message
        if let StreamMessageBody::Fin = message.message {
            state.fin_message_id = Some(message.message_id);
            // Remove messages after the Fin message
            state
                .received_messages
                .retain(|id, _| id < &message.message_id);
            return vec![];
        }

        // Buffer out of order messages
        if message.message_id != state.next_message_id {
            state.received_messages.insert(message.message_id, message);
            return vec![];
        }

        // Process this message (it's in order)
        let mut events = Vec::new();
        if let StreamMessageBody::Content(content) = message.message {
            events.push(Event::Proposal(stream_id, content));
            state.next_message_id += 1;
        }

        // Process any buffered messages that are now in order
        while let Some(next_message) = state.received_messages.remove(&state.next_message_id) {
            if let StreamMessageBody::Content(content) = next_message.message {
                events.push(Event::Proposal(stream_id, content));
                state.next_message_id += 1;
            }
        }

        events
    } else {
        panic!("Expected Incoming stream state")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::time::Duration;

    use libp2p::identity::Keypair;
    use p2p_proto::common::{Address, Hash, L1DataAvailabilityMode};
    use p2p_proto::consensus::{
        BlockInfo,
        ProposalFin,
        ProposalInit,
        ProposalPart,
        Transaction,
        TransactionVariant,
        VoteType,
    };
    use p2p_proto::transaction::L1HandlerV0;
    use pathfinder_common::ChainId;
    use pathfinder_crypto::Felt;
    use tokio::sync::mpsc;

    use super::*;
    use crate::consensus::{Command, Event};
    use crate::core::{self, Config};
    use crate::libp2p::Multiaddr;
    use crate::{consensus, main_loop, new_consensus};

    /// Tests creating an outgoing proposal message and updating the state.
    #[test]
    fn test_create_outgoing_proposal_message_updates_state() {
        let mut state = State::new();
        let height_and_round: HeightAndRound = (1, 2).into();

        // Create a sample proposal
        let block_info = BlockInfo {
            height: 100,
            timestamp: 1234567890,
            builder: Address(Felt::from_hex_str("0x456").unwrap()),
            l1_da_mode: L1DataAvailabilityMode::Calldata,
            l2_gas_price_fri: 1000,
            l1_gas_price_wei: 2000,
            l1_data_gas_price_wei: 3000,
            eth_to_fri_rate: 4000,
        };
        let proposal = ProposalPart::BlockInfo(block_info);

        // Create messages
        let messages =
            create_outgoing_proposal_message(&mut state, height_and_round, proposal.clone());

        // Verify state was updated
        let stream_state = state.active_streams.get(&height_and_round).unwrap();
        if let StreamState::Outgoing(outgoing_state) = stream_state {
            assert_eq!(outgoing_state.last_sent_message_id, Some(0));
            assert_eq!(outgoing_state.sent_messages.len(), 1);
            assert_eq!(outgoing_state.sent_messages.get(&0).unwrap(), &proposal);
            assert!(!outgoing_state.fin_sent);
        } else {
            panic!("Expected Outgoing stream state");
        }

        // Verify messages
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id, 0);
        assert_eq!(messages[0].stream_id, height_and_round);
    }

    /// Tests handling an incoming proposal message and updating the state.
    #[test]
    fn test_handle_incoming_proposal_message_updates_state() {
        let mut state = State::new();
        let height_and_round: HeightAndRound = (1, 2).into();

        // Create a sample proposal
        let block_info = BlockInfo {
            height: 100,
            timestamp: 1234567890,
            builder: Address(Felt::from_hex_str("0x456").unwrap()),
            l1_da_mode: L1DataAvailabilityMode::Calldata,
            l2_gas_price_fri: 1000,
            l1_gas_price_wei: 2000,
            l1_data_gas_price_wei: 3000,
            eth_to_fri_rate: 4000,
        };
        let proposal = ProposalPart::BlockInfo(block_info);

        // Create a message
        let message = StreamMessage {
            stream_id: height_and_round,
            message_id: 0,
            message: StreamMessageBody::Content(proposal.clone()),
        };

        // Handle the message
        let events = handle_incoming_proposal_message(&mut state, message);

        // Verify state was updated
        let stream_state = state.active_streams.get(&height_and_round).unwrap();
        if let StreamState::Incoming(incoming_state) = stream_state {
            println!("Next message id: {}", incoming_state.next_message_id);
            assert_eq!(incoming_state.next_message_id, 1);
            assert!(incoming_state.received_messages.is_empty());
            assert_eq!(incoming_state.fin_message_id, None);
        } else {
            panic!("Expected Incoming stream state");
        }

        // Verify events
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], Event::Proposal(height_and_round, proposal));
    }

    /// Tests sending proposal streams between two nodes with message shuffling.
    ///
    /// This test creates two nodes, connects them, and sends multiple proposal
    /// streams from one node to another. The messages in each stream are
    /// shuffled before sending, simulating out-of-order network delivery.
    /// The test verifies that the receiving node correctly reassembles the
    /// streams and receives all proposals in the proper order.
    #[tokio::test]
    async fn test_proposal_stream() {
        // Create two nodes with different identities
        let (node1_client, _, node1_loop) = create_test_node().await;
        let (node2_client, mut node2_events, node2_loop) = create_test_node().await;

        // Start the main loops
        tokio::spawn(node1_loop.run());
        tokio::spawn(node2_loop.run());

        // Start listening on node1
        let node1_addr = "/ip4/127.0.0.1/tcp/50003".parse::<Multiaddr>().unwrap();
        node1_client
            .start_listening(node1_addr.clone())
            .await
            .unwrap();

        // Start listening on node2
        let node2_addr = "/ip4/127.0.0.1/tcp/50004".parse::<Multiaddr>().unwrap();
        node2_client
            .start_listening(node2_addr.clone())
            .await
            .unwrap();

        // Dial node1 from node2
        node2_client
            .dial(*node1_client.peer_id(), node1_addr.clone())
            .await
            .unwrap();

        // Wait for the nodes to connect
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Create a sequence of complete proposal streams
        let proposals = vec![
            create_proposal_stream(1, 1, 100),
            create_proposal_stream(1, 2, 101),
            create_proposal_stream(2, 1, 102),
        ];

        // Send proposals
        for (height_round, proposal_stream) in &proposals {
            // Send the entire proposal stream with shuffle flag
            node1_client
                .send(Command::TestProposalStream(
                    (*height_round).into(),
                    proposal_stream.clone(),
                    true, // shuffle enabled
                ))
                .await
                .unwrap();
        }

        // Node 2 should receive all proposal streams
        let mut received_proposals = HashMap::new();
        let mut completed_proposals = HashSet::new();

        while completed_proposals.len() < proposals.len() {
            if let Some(Event::Proposal(height_and_round, received_proposal)) =
                node2_events.recv().await
            {
                // Get or create the vector for this height/round
                let proposal_parts = received_proposals
                    .entry(height_and_round)
                    .or_insert_with(Vec::new);

                proposal_parts.push(received_proposal.clone());

                // If we received a Fin message, verify the complete proposal
                if let ProposalPart::Fin(_) = received_proposal {
                    // Find the matching proposal by height/round
                    let (_, expected_stream) = proposals
                        .iter()
                        .find(|((h, r), _)| {
                            *h == height_and_round.height() && *r == height_and_round.round()
                        })
                        .expect("Received unknown proposal stream");

                    // Verify we have all parts and they match in order
                    assert_eq!(
                        proposal_parts.len(),
                        expected_stream.len(),
                        "Received wrong number of proposal parts"
                    );

                    for (received, expected) in proposal_parts.iter().zip(expected_stream.iter()) {
                        assert_eq!(
                            received, expected,
                            "Proposal part content or order doesn't match"
                        );
                    }

                    completed_proposals.insert(height_and_round);
                }
            }
        }
    }

    /// Tests sending vote messages between two nodes.
    ///
    /// This test creates two nodes, connects them, and sends multiple vote
    /// messages from one node to another. The test verifies that the receiving
    /// node correctly receives all vote messages.
    #[tokio::test]
    async fn test_vote_messages() {
        // Create two nodes with different identities
        let (node1_client, _, node1_loop) = create_test_node().await;
        let (node2_client, mut node2_events, node2_loop) = create_test_node().await;

        // Start the main loops
        tokio::spawn(node1_loop.run());
        tokio::spawn(node2_loop.run());

        // Start listening on node1
        let node1_addr = "/ip4/127.0.0.1/tcp/50001".parse::<Multiaddr>().unwrap();
        node1_client
            .start_listening(node1_addr.clone())
            .await
            .unwrap();

        // Start listening on node2
        let node2_addr = "/ip4/127.0.0.1/tcp/50002".parse::<Multiaddr>().unwrap();
        node2_client
            .start_listening(node2_addr.clone())
            .await
            .unwrap();

        // Dial node1 from node2
        node2_client
            .dial(*node1_client.peer_id(), node1_addr.clone())
            .await
            .unwrap();

        // Wait for the nodes to connect
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Create a sequence of votes to send
        let votes = vec![
            Vote {
                vote_type: VoteType::Prevote,
                height: 100,
                round: 1,
                block_hash: Some(Hash(Felt::from_hex_str("0x123").unwrap())),
                voter: Address(Felt::from_hex_str("0x456").unwrap()),
                extension: None,
            },
            Vote {
                vote_type: VoteType::Precommit,
                height: 100,
                round: 1,
                block_hash: Some(Hash(Felt::from_hex_str("0x789").unwrap())),
                voter: Address(Felt::from_hex_str("0xabc").unwrap()),
                extension: None,
            },
            Vote {
                vote_type: VoteType::Prevote,
                height: 101,
                round: 2,
                block_hash: None, // NIL vote
                voter: Address(Felt::from_hex_str("0xdef").unwrap()),
                extension: None,
            },
        ];
        let mut rxs = Vec::new();
        // Send votes from node1
        for vote in &votes {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            rxs.push(rx);
            node1_client
                .send(Command::Vote {
                    vote: vote.clone(),
                    done_tx: tx,
                })
                .await
                .unwrap();
        }

        // Node 2 should receive all votes
        let mut received_votes = Vec::new();
        let mut expected_votes = votes.clone();

        while !expected_votes.is_empty() {
            if let Some(Event::Vote(received_vote)) = node2_events.recv().await {
                received_votes.push(received_vote.clone());

                // Find and remove the matching expected vote
                if let Some(pos) = expected_votes.iter().position(|v| v == &received_vote) {
                    expected_votes.remove(pos);
                }
            }
        }

        // Verify we received all votes
        assert_eq!(
            received_votes.len(),
            votes.len(),
            "Did not receive all votes"
        );
        assert!(
            expected_votes.is_empty(),
            "Some expected votes were not received"
        );
        assert!(
            rxs.iter_mut().all(|rx| { rx.try_recv().is_ok() }),
            "Not all confirmations were received"
        );
    }

    async fn create_test_node() -> (
        core::Client<consensus::Command>,
        mpsc::Receiver<consensus::Event>,
        main_loop::MainLoop<consensus::Behaviour>,
    ) {
        let keypair = Keypair::generate_ed25519();
        let core_config = Config::for_test();
        let consensus_config = consensus::Config::default();
        let chain_id = ChainId::MAINNET;

        new_consensus(keypair, core_config, consensus_config, chain_id)
    }

    fn create_proposal_stream(
        height: u64,
        round: u32,
        base: u64,
    ) -> ((u64, u32), Vec<ProposalPart>) {
        let mut stream = Vec::new();

        // ProposalInit
        stream.push(ProposalPart::Init(ProposalInit {
            height,
            round,
            proposer: p2p_proto::common::Address(Felt::from_hex_str("0x123").unwrap()),
            valid_round: None,
        }));

        // BlockInfo
        stream.push(ProposalPart::BlockInfo(BlockInfo {
            height,
            timestamp: 1234567890 + base,
            builder: p2p_proto::common::Address(Felt::from_hex_str("0x456").unwrap()),
            l1_da_mode: p2p_proto::common::L1DataAvailabilityMode::Calldata,
            l2_gas_price_fri: 1000 + base as u128,
            l1_gas_price_wei: 2000 + base as u128,
            l1_data_gas_price_wei: 3000 + base as u128,
            eth_to_fri_rate: 4000 + base as u128,
        }));

        // TransactionBatch (send a few)
        for i in 0..3 {
            stream.push(ProposalPart::TransactionBatch(vec![Transaction {
                transaction_hash: p2p_proto::common::Hash(
                    Felt::from_hex_str(&format!("0x123abc{i}")).unwrap(),
                ),
                txn: TransactionVariant::L1HandlerV0(L1HandlerV0 {
                    nonce: Felt::from_hex_str(&format!("0x{}", i + 1)).unwrap(),
                    address: p2p_proto::common::Address(
                        Felt::from_hex_str(&format!("0x789{i}")).unwrap(),
                    ),
                    entry_point_selector: Felt::from_hex_str(&format!("0x{}", i + 1)).unwrap(),
                    calldata: vec![Felt::from_hex_str(&format!("0x{}", i + 1)).unwrap()],
                }),
            }]));
        }

        // ProposalFin
        stream.push(ProposalPart::Fin(ProposalFin {
            proposal_commitment: p2p_proto::common::Hash(Felt::from_hex_str("0x69420abc").unwrap()),
        }));

        ((height, round), stream)
    }
}
