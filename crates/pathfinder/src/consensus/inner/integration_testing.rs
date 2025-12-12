//! Integration testing helpers for the consensus task. These are only
//! active in debug builds when both the "p2p" and "consensus-integration-tests"
//! features are enabled.

use std::path::Path;

use p2p_proto::consensus::ProposalPart;

use crate::config::integration_testing::{InjectFailureConfig, InjectFailureTrigger};

/// ## Important
/// This function does nothing in production builds.
///
/// ## Integration testing
/// Exits the process with error code of value `1` if the current height
/// matches. This function is only active in debug builds when both the
/// "p2p" and "consensus-integration-tests" features are enabled. A marker file
/// is created in the data directory to indicate that the failure has been
/// triggered. If the file already exists, it is removed instead. This allows
/// for easy detection of whether the failure has been triggered or not.
/// The file is named `fail_on_{prefix}_{height}`.
///
/// ## Panics
/// The function will panic if it fails to create the marker file or fails to
/// remove it when the file exists.
pub fn debug_fail_on(
    _trigger_match_fn: impl FnOnce(InjectFailureTrigger) -> bool,
    _current_height: u64,
    _config: Option<InjectFailureConfig>,
    _data_directory: &Path,
) {
    #[cfg(all(
        feature = "p2p",
        feature = "consensus-integration-tests",
        debug_assertions
    ))]
    debug_fail_on_impl(_trigger_match_fn, _current_height, _config, _data_directory);
}

#[cfg(all(
    feature = "p2p",
    feature = "consensus-integration-tests",
    debug_assertions
))]
fn debug_fail_on_impl(
    trigger_match_fn: impl FnOnce(InjectFailureTrigger) -> bool,
    current_height: u64,
    config: Option<InjectFailureConfig>,
    data_directory: &Path,
) {
    let Some(config) = config else {
        return;
    };

    if current_height != config.height {
        return;
    }

    if !trigger_match_fn(config.trigger) {
        return;
    }

    let failure_height = config.height;
    let prefix = config.trigger.as_str();
    let path = data_directory.join(format!("fail_on_{prefix}_{failure_height}"));

    match std::fs::exists(&path) {
        Ok(true) => (),
        Ok(false) => {
            // Create the marker file to indicate that the failure has been
            // triggered.
            let file = std::fs::File::create(&path)
                .unwrap_or_else(|_| panic!("Failed to create marker file {}", path.display()));
            // Ensure the file is written to disk. We've seen cases of TOCTOU issues here
            // during test execution.
            file.sync_all()
                .unwrap_or_else(|_| panic!("Failed to sync marker file {}", path.display()));
            tracing::trace!(
                marker_file=%path.display(),
                "💥 ✅ Integration testing: created",
            );
            tracing::info!(
                "💥 💥 Integration testing: exiting process with error code 1 at height \
                 {failure_height} on {prefix}, as configured"
            );
            std::process::exit(1);
        }
        Err(e) => {
            panic!(
                "Failed to check existence of marker file {}, {}",
                path.display(),
                e
            );
        }
    }
}

pub fn debug_fail_on_proposal_part(
    proposal_part: &ProposalPart,
    height: u64,
    config: Option<InjectFailureConfig>,
    data_directory: &Path,
) {
    debug_fail_on(
        |trigger| {
            matches!(
                (proposal_part, trigger),
                (ProposalPart::Init(_), InjectFailureTrigger::ProposalInitRx)
                    | (
                        ProposalPart::BlockInfo(_),
                        InjectFailureTrigger::BlockInfoRx
                    )
                    | (
                        ProposalPart::TransactionBatch(_),
                        InjectFailureTrigger::TransactionBatchRx
                    )
                    | (
                        ProposalPart::ProposalCommitment(_),
                        InjectFailureTrigger::ProposalCommitmentRx
                    )
                    | (
                        ProposalPart::TransactionsFin(_),
                        InjectFailureTrigger::TransactionsFinRx
                    )
                    | (ProposalPart::Fin(_), InjectFailureTrigger::ProposalFinRx)
            )
        },
        height,
        config,
        data_directory,
    );
}

pub fn debug_fail_on_entire_proposal_rx(
    height: u64,
    inject_failure: Option<InjectFailureConfig>,
    data_directory: &Path,
) {
    debug_fail_on(
        |trigger| matches!(trigger, InjectFailureTrigger::EntireProposalRx),
        height,
        inject_failure,
        data_directory,
    );
}

pub fn debug_fail_on_entire_proposal_persisted(
    height: u64,
    inject_failure: Option<InjectFailureConfig>,
    data_directory: &Path,
) {
    debug_fail_on(
        |trigger| matches!(trigger, InjectFailureTrigger::EntireProposalPersisted),
        height,
        inject_failure,
        data_directory,
    );
}

pub fn debug_fail_on_proposal_committed(
    height: u64,
    inject_failure: Option<InjectFailureConfig>,
    data_directory: &Path,
) {
    debug_fail_on(
        |trigger| matches!(trigger, InjectFailureTrigger::ProposalCommitted),
        height,
        inject_failure,
        data_directory,
    );
}

pub fn debug_fail_on_vote(
    vote: &p2p_proto::consensus::Vote,
    inject_failure: Option<InjectFailureConfig>,
    data_directory: &Path,
) {
    debug_fail_on(
        |trigger| {
            matches!(
                (trigger, vote.vote_type),
                (
                    InjectFailureTrigger::PrevoteRx,
                    p2p_proto::consensus::VoteType::Prevote
                ) | (
                    InjectFailureTrigger::PrecommitRx,
                    p2p_proto::consensus::VoteType::Precommit
                )
            )
        },
        vote.block_number,
        inject_failure,
        data_directory,
    );
}

pub fn debug_fail_on_decided(
    height: u64,
    inject_failure: Option<InjectFailureConfig>,
    data_directory: &Path,
) {
    debug_fail_on(
        |trigger| trigger == InjectFailureTrigger::ProposalDecided,
        height,
        inject_failure,
        data_directory,
    );
}

#[cfg(all(
    feature = "p2p",
    feature = "consensus-integration-tests",
    debug_assertions
))]
pub fn send_outdated_vote(vote_height: u64, inject_failure: Option<InjectFailureConfig>) -> bool {
    matches!(inject_failure,
        Some(InjectFailureConfig {
            height,
            trigger: InjectFailureTrigger::OutdatedVote,
        }) if vote_height >= height
    )
}

#[cfg(not(all(
    feature = "p2p",
    feature = "consensus-integration-tests",
    debug_assertions
)))]
pub fn send_outdated_vote(
    _proposal_height: u64,
    _inject_failure: Option<InjectFailureConfig>,
) -> bool {
    false
}
