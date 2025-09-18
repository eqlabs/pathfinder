use std::time::Duration;

use pathfinder_consensus::{
    Config,
    Consensus,
    ConsensusCommand,
    ConsensusEvent,
    Proposal,
    PublicKey,
    Round,
    Signature,
    SignedProposal,
    SignedVote,
    SigningKey,
    Validator,
    ValidatorSet,
    Vote,
    VoteType,
};
use tokio::time::pause;

mod common;
use common::{drive_until, ConsensusValue, NodeAddress};

#[tokio::test]
async fn single_node_propose_timeout_advances_round() {
    //common::setup_tracing_full();
    pause();

    // Build a single-validator set
    let sk = SigningKey::new(rand::rngs::OsRng);
    let pk = sk.verification_key();
    let addr = NodeAddress("0x01".to_string());
    let pubkey = PublicKey::from_bytes(pk.to_bytes());
    let validator = Validator {
        address: addr.clone(),
        public_key: pubkey,
        voting_power: 1,
    };
    let validators = ValidatorSet::new(vec![validator]);

    // Create a (single) temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let temp_dir = temp_dir.path().to_path_buf();

    // Create consensus instance
    let config = Config::new(addr.clone()).with_wal_dir(temp_dir);
    let mut consensus: Consensus<ConsensusValue, NodeAddress> = Consensus::new(config);
    let height = 1;
    consensus.handle_command(ConsensusCommand::StartHeight(height, validators));

    // Expect initial RequestProposal at round 0
    let event = consensus.next_event().await;
    match event {
        Some(ConsensusEvent::RequestProposal {
            height: h,
            round: r,
            ..
        }) => {
            assert_eq!(h, height);
            assert_eq!(r, 0);
        }
        other => panic!("Expected RequestProposal for round 0, got: {other:?}"),
    }

    // Step time forward until round 1 proposal is requested
    let result = drive_until(
        &mut consensus,
        Duration::from_secs(5),
        10,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == 1),
    )
    .await;

    assert!(result.is_some(), "Timeout did not trigger expected round 1");
}

#[tokio::test]
async fn single_node_prevote_timeout_advances_round() {
    //common::setup_tracing_full();
    pause();

    // Build a single-validator set
    let sk = SigningKey::new(rand::rngs::OsRng);
    let pk = sk.verification_key();
    let addr = NodeAddress("0x0000123".to_string());
    let pubkey = PublicKey::from_bytes(pk.to_bytes());
    let validator = Validator {
        address: addr.clone(),
        public_key: pubkey,
        voting_power: 1,
    };
    let validators = ValidatorSet::new(vec![validator.clone()]);

    // Create a (single) temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let temp_dir = temp_dir.path().to_path_buf();

    // Create consensus instance
    let config = Config::new(addr.clone()).with_wal_dir(temp_dir);
    let mut consensus = Consensus::new(config);
    let height = 1;
    consensus.handle_command(ConsensusCommand::StartHeight(height, validators));

    // Wait for initial RequestProposal
    let _ = drive_until(
        &mut consensus,
        Duration::from_secs(1),
        5,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == 0),
    )
    .await;

    // Send a proposal (to enter prevote step)
    let value = ConsensusValue("Hello, world!".to_string());
    let proposal = Proposal {
        height,
        round: Round::new(0),
        value,
        pol_round: Round::new(0),
        proposer: addr,
    };
    let signature = Signature::from_bytes([0; 64]);
    let signed = SignedProposal {
        proposal,
        signature,
    };
    consensus.handle_command(ConsensusCommand::Proposal(signed));

    // Wait for round 1 (prevote timeout should have fired)
    let result = drive_until(
        &mut consensus,
        Duration::from_secs(5),
        10,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == 1),
    )
    .await;

    assert!(
        result.is_some(),
        "Prevote timeout did not advance to round 1"
    );
}

#[tokio::test]
async fn single_node_precommit_timeout_advances_round() {
    //common::setup_tracing_full();
    pause();

    // Build a single-validator set
    let sk = SigningKey::new(rand::rngs::OsRng);
    let pk = sk.verification_key();
    let addr = NodeAddress("0x0000456".to_string());
    let pubkey = PublicKey::from_bytes(pk.to_bytes());
    let validator = Validator {
        address: addr.clone(),
        public_key: pubkey,
        voting_power: 1,
    };
    let validators = ValidatorSet::new(vec![validator.clone()]);

    // Create a (single) temporary directory for WAL files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let temp_dir = temp_dir.path().to_path_buf();

    // Create consensus instance
    let config = Config::new(addr.clone()).with_wal_dir(temp_dir);
    let mut consensus = Consensus::new(config);
    let height = 1;
    consensus.handle_command(ConsensusCommand::StartHeight(height, validators));

    // Wait for initial RequestProposal
    let _ = drive_until(
        &mut consensus,
        Duration::from_secs(1),
        5,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == 0),
    )
    .await;

    // Send a proposal
    let value = ConsensusValue("Hello, world!".to_string());
    let proposal = Proposal {
        height,
        round: Round::new(0),
        value: value.clone(),
        pol_round: Round::new(0),
        proposer: addr.clone(),
    };
    let signature: Signature = Signature::from_bytes([0; 64]);
    let signed = SignedProposal {
        proposal: proposal.clone(),
        signature,
    };
    consensus.handle_command(ConsensusCommand::Proposal(signed));

    // Send prevote (this should move to Precommit step)
    let vote = Vote {
        r#type: VoteType::Prevote,
        height,
        round: Round::new(0),
        validator_address: addr,
        value: Some(value),
    };
    let vote_signature = Signature::from_bytes([0; 64]);
    let signed_vote = SignedVote {
        vote,
        signature: vote_signature,
    };
    consensus.handle_command(ConsensusCommand::Vote(signed_vote));

    // Do NOT send precommit; wait for precommit timeout to fire

    let result = drive_until(
        &mut consensus,
        Duration::from_secs(5),
        10,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == 1),
    )
    .await;

    assert!(
        result.is_some(),
        "Precommit timeout did not advance to round 1"
    );
}
