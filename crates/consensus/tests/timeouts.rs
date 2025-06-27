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
use tracing_subscriber::EnvFilter;

mod common;
use common::drive_until;

#[allow(dead_code)]
fn setup_tracing_full() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("trace"));

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_env_filter(filter)
        .with_target(true)
        .without_time()
        .try_init();
}

#[tokio::test]
async fn single_node_propose_timeout_advances_round() {
    //setup_tracing_full();
    pause();

    // Build a single-validator set
    let sk = SigningKey::new(rand::rngs::OsRng);
    let pk = sk.verification_key();
    let addr = ValidatorAddress::from(Address(Felt::from_hex_str("0x01").unwrap()));
    let pubkey = PublicKey::from_bytes(pk.to_bytes());
    let validator = Validator {
        address: addr,
        public_key: pubkey,
        voting_power: 1,
    };
    let validators = ValidatorSet::new(vec![validator]);

    // Create consensus instance
    let config = Config::new(addr);
    let mut consensus = Consensus::new(config);
    let height = Height::new(1);
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
            assert_eq!(r, Round::from(0));
        }
        other => panic!("Expected RequestProposal for round 0, got: {:?}", other),
    }

    // Step time forward until round 1 proposal is requested
    let result = drive_until(
        &mut consensus,
        Duration::from_secs(5),
        10,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == Round::from(1)),
    ).await;

    assert!(result.is_some(), "Timeout did not trigger expected round 1");
}

#[tokio::test]
async fn single_node_prevote_timeout_advances_round() {
    //setup_tracing_full();
    pause();

    // Build a single-validator set
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

    // Create consensus instance
    let config = Config::new(addr);
    let mut consensus = Consensus::new(config);
    let height = Height::new(1);
    consensus.handle_command(ConsensusCommand::StartHeight(height, validators));

    // Wait for initial RequestProposal
    let _ = drive_until(
        &mut consensus,
        Duration::from_secs(1),
        5,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == Round::from(0)),
    ).await;

    // Send a proposal (to enter prevote step)
    let value_id = ValueId::new(Hash(Felt::from_hex_str("0x123456789").unwrap()));
    let proposal = Proposal {
        height,
        round: Round::from(0),
        value_id: ConsensusValue::new(value_id),
        pol_round: Round::from(0),
        proposer: addr,
    };
    let signature: Signature = Signature::from_bytes([0; 64]);
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
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == Round::from(1)),
    ).await;

    assert!(
        result.is_some(),
        "Prevote timeout did not advance to round 1"
    );
}

#[tokio::test]
async fn single_node_precommit_timeout_advances_round() {
    //setup_tracing_full();
    pause();

    // Build a single-validator set
    let sk = SigningKey::new(rand::rngs::OsRng);
    let pk = sk.verification_key();
    let addr = ValidatorAddress::from(Address(Felt::from_hex_str("0x0000456").unwrap()));
    let pubkey = PublicKey::from_bytes(pk.to_bytes());
    let validator = Validator {
        address: addr,
        public_key: pubkey,
        voting_power: 1,
    };
    let validators = ValidatorSet::new(vec![validator.clone()]);

    // Create consensus instance
    let config = Config::new(addr);
    let mut consensus = Consensus::new(config);
    let height = Height::new(1);
    consensus.handle_command(ConsensusCommand::StartHeight(height, validators));

    // Wait for initial RequestProposal
    let _ = drive_until(
        &mut consensus,
        Duration::from_secs(1),
        5,
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == Round::from(0)),
    )
    .await;

    // Send a proposal
    let value_id = ValueId::new(Hash(Felt::from_hex_str("0x123456789").unwrap()));
    let proposal = Proposal {
        height,
        round: Round::from(0),
        value_id: ConsensusValue::new(value_id.clone()),
        pol_round: Round::from(0),
        proposer: addr,
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
        round: Round::from(0),
        validator_address: addr,
        value: NilOrVal::Val(value_id),
        extension: None,
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
        |evt| matches!(evt, ConsensusEvent::RequestProposal { round, .. } if *round == Round::from(1)),
    )
    .await;

    assert!(
        result.is_some(),
        "Precommit timeout did not advance to round 1"
    );
}
