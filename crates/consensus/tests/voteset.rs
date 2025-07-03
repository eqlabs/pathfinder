use std::time::Duration;

use ed25519_consensus::SigningKey;
use malachite_signing_ed25519::PublicKey;
use malachite_types::{NilOrVal, VoteType};
use p2p_proto::common::{Address, Hash};
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
    SignedProposal,
    SignedVote,
    Validator,
    ValidatorAddress,
    ValidatorSet,
    ValueId,
    Vote,
};
use pathfinder_crypto::Felt;
use tokio::time::pause;

mod common;
use common::drive_until;

#[tokio::test]
async fn single_node_emits_request_vote_set_on_precommit_timeout() {
    //common::setup_tracing_full();

    // Pause time so we can control timeouts
    pause();

    let sk = SigningKey::new(rand::rngs::OsRng);
    let pk = sk.verification_key();
    let addr = ValidatorAddress::from(Address(Felt::from_hex_str("0x0000123").unwrap()));
    let pubkey = PublicKey::from_bytes(pk.to_bytes());
    let validator = Validator {
        address: addr,
        public_key: pubkey,
        voting_power: 1,
    };
    let validators = ValidatorSet::new(vec![validator.clone()]);

    // Create a (single) temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let temp_dir = temp_dir.path().to_path_buf();

    let config = Config::new(addr).with_wal_dir(temp_dir);
    let mut consensus = Consensus::new(config);
    let height = Height::new(1);
    consensus.handle_command(ConsensusCommand::StartHeight(height, validators));

    // Wait for the engine to request a proposal
    let _ = drive_until(
        &mut consensus,
        Duration::from_secs(1),
        5,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == Round::from(0)),
    ).await;

    // Send a proposal to enter Prevote
    let value_id = ValueId::new(Hash(Felt::from_hex_str("0xabc123").unwrap()));
    let proposal = Proposal {
        height,
        round: Round::from(0),
        value_id: ConsensusValue::new(value_id),
        pol_round: Round::from(0),
        proposer: addr,
    };
    let signed = SignedProposal {
        proposal,
        signature: Signature::from_bytes([0u8; 64]),
    };
    consensus.handle_command(ConsensusCommand::Proposal(signed));

    // Let time advance until the PrecommitTimeLimit is reached and RequestVoteSet
    // is triggered
    let request_voteset_event = drive_until(
        &mut consensus,
        Duration::from_secs(10),
        20,
        |evt| matches!(evt, ConsensusEvent::RequestVoteSet { height: h, round: r } if *h == height && *r == Round::from(0)),
    ).await;

    assert!(
        request_voteset_event.is_some(),
        "Did not emit RequestVoteSet after Precommit timeout"
    );
}

#[tokio::test]
async fn single_node_resumes_after_receiving_vote_set_response() {
    //common::setup_tracing_full();

    // Pause time so we can control timeouts
    pause();

    let sk = SigningKey::new(rand::rngs::OsRng);
    let pk = sk.verification_key();
    let addr = ValidatorAddress::from(Address(Felt::from_hex_str("0x0000123").unwrap()));
    let pubkey = PublicKey::from_bytes(pk.to_bytes());
    let validator = Validator {
        address: addr,
        public_key: pubkey,
        voting_power: 1,
    };
    let validators = ValidatorSet::new(vec![validator.clone()]);

    // Create a (single) temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let temp_dir = temp_dir.path().to_path_buf();

    let config = Config::new(addr).with_wal_dir(temp_dir);
    let mut consensus = Consensus::new(config);
    let height = Height::new(1);
    consensus.handle_command(ConsensusCommand::StartHeight(height, validators));

    // Drive to Propose step
    let _ = drive_until(
        &mut consensus,
        Duration::from_secs(1),
        5,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == Round::from(0)),
    ).await;

    // Send a proposal to move into Prevote step
    let value_id = ValueId::new(Hash(Felt::from_hex_str("0xabc123").unwrap()));
    let proposal = Proposal {
        height,
        round: Round::from(0),
        value_id: ConsensusValue::new(value_id),
        pol_round: Round::from(0),
        proposer: addr,
    };
    let signed = SignedProposal {
        proposal,
        signature: Signature::from_bytes([0u8; 64]),
    };
    consensus.handle_command(ConsensusCommand::Proposal(signed));

    // Wait for Precommit timeout and RequestVoteSet
    let _ = drive_until(
        &mut consensus,
        Duration::from_secs(10),
        20,
        |evt| matches!(evt, ConsensusEvent::RequestVoteSet { height: h, round: r } if *h == height && *r == Round::from(0)),
    ).await;

    // Send vote set response for the previous round
    let vote = Vote {
        r#type: VoteType::Precommit,
        height,
        round: Round::from(0),
        value: NilOrVal::Nil,
        validator_address: addr,
        extension: None,
    };
    let signed_vote = SignedVote {
        vote,
        signature: Signature::from_bytes([0u8; 64]),
    };

    consensus.handle_command(ConsensusCommand::VoteSet(
        height,
        Round::from(0),
        vec![signed_vote],
    ));

    // Verify that consensus resumes and emits a RequestProposal for round 1
    let resumed = drive_until(
        &mut consensus,
        Duration::from_secs(5),
        10,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == Round::from(1)),
    ).await;

    assert!(
        resumed.is_some(),
        "Consensus did not resume and progress to round 1 after VoteSetResponse"
    );
}

#[tokio::test]
async fn responds_with_vote_set_when_requested() {
    //common::setup_tracing_full();
    pause();

    let sk = SigningKey::new(rand::rngs::OsRng);
    let pk = sk.verification_key();
    let addr = ValidatorAddress::from(Address(Felt::from_hex_str("0x0000123").unwrap()));
    let pubkey = PublicKey::from_bytes(pk.to_bytes());
    let validator = Validator {
        address: addr,
        public_key: pubkey,
        voting_power: 1,
    };
    let validators = ValidatorSet::new(vec![validator.clone()]);

    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let temp_dir = temp_dir.path().to_path_buf();

    let config = Config::new(addr).with_wal_dir(temp_dir);
    let mut consensus = Consensus::new(config);
    let height = Height::new(1);
    consensus.handle_command(ConsensusCommand::StartHeight(height, validators));

    // Drive to Precommit step by feeding in a signed proposal
    let _ = drive_until(
        &mut consensus,
        Duration::from_secs(1),
        5,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == Round::from(0)),
    ).await;

    let value_id = ValueId::new(Hash(Felt::from_hex_str("0xabc123").unwrap()));
    let proposal = Proposal {
        height,
        round: Round::from(0),
        value_id: ConsensusValue::new(value_id),
        pol_round: Round::from(0),
        proposer: addr,
    };
    let signed = SignedProposal {
        proposal,
        signature: Signature::from_bytes([0u8; 64]),
    };
    consensus.handle_command(ConsensusCommand::Proposal(signed));

    // Let the engine reach precommit and timeout
    let _ = drive_until(
        &mut consensus,
        Duration::from_secs(10),
        20,
        |evt| matches!(evt, ConsensusEvent::RequestVoteSet { height: h, round: r } if *h == height && *r == Round::from(0)),
    ).await;

    // Now simulate a vote set request from a peer
    consensus.handle_command(ConsensusCommand::RequestVoteSet(
        addr,
        height,
        Round::from(0),
    ));

    // Expect a vote set response to be gossiped
    let response = drive_until(
        &mut consensus,
        Duration::from_secs(1),
        5,
        |evt| matches!(evt, ConsensusEvent::Gossip(msg) if matches!(msg, pathfinder_consensus::NetworkMessage::VoteSetResponse { requester, .. } if requester == &addr)),
    ).await;

    assert!(
        response.is_some(),
        "Expected VoteSetResponse gossip event after VoteSetRequest"
    );
}
