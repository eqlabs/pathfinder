use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use malachite_consensus::SignedConsensusMsg;
use malachite_types::{Timeout, Value};
use serde::{Deserialize, Serialize};

use crate::malachite::MalachiteContext;
use crate::{Height, Round, SignedProposal, SignedVote, ValidatorAddress, ValueId};

/// A trait for types that can append to a write-ahead log.
pub(crate) trait WalSink: Send {
    fn append(&mut self, entry: WalEntry);
}

/// A write-ahead log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum WalEntry {
    /// A signed proposal.
    SignedProposal(SignedProposal),
    /// A signed vote.
    SignedVote(SignedVote),
    /// A timeout.
    Timeout { kind: String, round: Round },
    /// A proposed value.
    ProposedValue {
        height: Height,
        round: Round,
        valid_round: Round,
        proposer: ValidatorAddress,
        value: ValueId,
        validity: bool,
    },
}

// This is necessary because unfortunately the malachite types are not
// serializable.
impl From<malachite_consensus::WalEntry<MalachiteContext>> for WalEntry {
    fn from(entry: malachite_consensus::WalEntry<MalachiteContext>) -> Self {
        use malachite_consensus::WalEntry as MalachiteWalEntry;
        match entry {
            MalachiteWalEntry::ConsensusMsg(msg) => {
                let signature = *msg.signature();
                match msg {
                    SignedConsensusMsg::Proposal(proposal) => {
                        let proposal = proposal.message;
                        WalEntry::SignedProposal(SignedProposal {
                            proposal,
                            signature,
                        })
                    }
                    SignedConsensusMsg::Vote(vote) => {
                        let vote = vote.message;
                        WalEntry::SignedVote(SignedVote { vote, signature })
                    }
                }
            }
            MalachiteWalEntry::Timeout(timeout) => {
                use malachite_types::TimeoutKind as Kind;
                WalEntry::Timeout {
                    kind: match timeout.kind {
                        Kind::Propose => "propose",
                        Kind::Prevote => "prevote",
                        Kind::PrevoteTimeLimit => "prevote-time-limit",
                        Kind::Precommit => "precommit",
                        Kind::PrecommitTimeLimit => "precommit-time-limit",
                        Kind::PrevoteRebroadcast => "prevote-rebroadcast",
                        Kind::PrecommitRebroadcast => "precommit-rebroadcast",
                    }
                    .to_string(),
                    round: timeout.round.into(),
                }
            }
            MalachiteWalEntry::ProposedValue(proposed_value) => WalEntry::ProposedValue {
                height: proposed_value.height,
                round: proposed_value.round.into(),
                valid_round: proposed_value.valid_round.into(),
                proposer: proposed_value.proposer,
                value: proposed_value.value.id(),
                validity: proposed_value.validity.is_valid(),
            },
        }
    }
}

impl From<Timeout> for WalEntry {
    fn from(timeout: Timeout) -> Self {
        use malachite_types::TimeoutKind as Kind;
        WalEntry::Timeout {
            kind: match timeout.kind {
                Kind::Propose => "propose",
                Kind::Prevote => "prevote",
                Kind::PrevoteTimeLimit => "prevote-time-limit",
                Kind::Precommit => "precommit",
                Kind::PrecommitTimeLimit => "precommit-time-limit",
                Kind::PrevoteRebroadcast => "prevote-rebroadcast",
                Kind::PrecommitRebroadcast => "precommit-rebroadcast",
            }
            .to_string(),
            round: timeout.round.into(),
        }
    }
}

/// A write-ahead log that writes to a file.
pub struct FileWalSink {
    file: std::fs::File,
    path: PathBuf,
}

impl FileWalSink {
    pub fn new(address: &ValidatorAddress, height: &Height) -> std::io::Result<Self> {
        let path = PathBuf::from(format!("wal-{address}-{height}.json"));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { file, path })
    }
}

impl Drop for FileWalSink {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_file(&self.path) {
            tracing::error!(
                path = %self.path.display(),
                error = %e,
                "Failed to delete WAL file"
            );
        } else {
            tracing::debug!(
                path = %self.path.display(),
                "Successfully deleted WAL file"
            );
        }
    }
}

impl WalSink for FileWalSink {
    fn append(&mut self, entry: WalEntry) {
        let line = serde_json::to_string(&entry).expect("WAL serialization failed");
        writeln!(self.file, "{line}").expect("WAL write failed");
    }
}

/// A write-ahead log that does nothing.
pub(crate) struct NoopWal;

impl WalSink for NoopWal {
    fn append(&mut self, entry: WalEntry) {
        tracing::debug!("NoopWal: Appending entry: {:?}", entry);
    }
}
