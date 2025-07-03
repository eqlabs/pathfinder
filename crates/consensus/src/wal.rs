use std::fs;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use malachite_consensus::{Input, PeerId, ProposedValue, SignedConsensusMsg};
use malachite_types::{Timeout, Value};
use serde::{Deserialize, Serialize};

use crate::malachite::MalachiteContext;
use crate::{ConsensusValue, Height, Round, SignedProposal, SignedVote, ValidatorAddress, ValueId};

/// The prefix of the write-ahead log file.
pub(crate) const WAL_FILE_PREFIX: &str = "wal-";

/// The extension of the write-ahead log file.
pub(crate) const WAL_FILE_EXTENSION: &str = "json";

/// The filename of the write-ahead log for a given validator and height.
pub(crate) fn filename(address: &ValidatorAddress, height: &Height) -> String {
    format!("{WAL_FILE_PREFIX}{address}-{height}.{WAL_FILE_EXTENSION}")
}

/// A trait for types that can append to a write-ahead log.
pub(crate) trait WalSink: Send {
    /// Append an entry to the write-ahead log.
    fn append(&mut self, entry: WalEntry);

    /// Check if this WAL has been finalized (a decision has been reached)
    fn is_finalized(&self) -> bool {
        false // Default impl. for WALs that don't track finalization
    }
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
    /// A decision was reached.
    Decision { height: Height, value: ValueId },
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
                        Kind::Precommit => "precommit",
                        Kind::Rebroadcast => "rebroadcast",
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
                Kind::Precommit => "precommit",
                Kind::Rebroadcast => "rebroadcast",
            }
            .to_string(),
            round: timeout.round.into(),
        }
    }
}

/// Convert a WAL entry to the corresponding malachite Input.
pub(crate) fn convert_wal_entry_to_input(entry: WalEntry) -> Input<MalachiteContext> {
    match entry {
        WalEntry::SignedProposal(proposal) => {
            tracing::debug!(
                value_id = ?proposal.proposal.value_id,
                from = %proposal.proposal.proposer,
                height = %proposal.proposal.height,
                round = %proposal.proposal.round,
                "Recovering proposal from WAL"
            );
            let signed_msg =
                malachite_types::SignedProposal::new(proposal.proposal, proposal.signature);
            Input::Proposal(signed_msg)
        }
        WalEntry::SignedVote(vote) => {
            tracing::debug!(
                vote_type = ?vote.vote.r#type,
                from = %vote.vote.validator_address,
                height = %vote.vote.height,
                round = %vote.vote.round,
                "Recovering vote from WAL"
            );
            let signed_vote = malachite_types::SignedVote::new(vote.vote, vote.signature);
            Input::Vote(signed_vote)
        }
        WalEntry::Timeout { kind, round } => {
            let timeout_kind = match kind.as_str() {
                "propose" => malachite_types::TimeoutKind::Propose,
                "prevote" => malachite_types::TimeoutKind::Prevote,
                "precommit" => malachite_types::TimeoutKind::Precommit,
                "rebroadcast" => malachite_types::TimeoutKind::Rebroadcast,
                _ => unreachable!(),
            };
            let timeout = Timeout::new(round.into_inner(), timeout_kind);
            tracing::debug!(
                timeout = ?timeout,
                "Recovering timeout from WAL"
            );
            Input::TimeoutElapsed(timeout)
        }
        WalEntry::ProposedValue {
            height,
            round,
            valid_round,
            proposer,
            value,
            validity,
        } => {
            tracing::debug!(
                height = %height,
                round = %round,
                value = ?value,
                "Recovering proposed value from WAL"
            );
            let proposed_value = ProposedValue {
                height,
                round: round.into_inner(),
                valid_round: valid_round.into_inner(),
                proposer,
                value: ConsensusValue::new(value),
                validity: if validity {
                    malachite_types::Validity::Valid
                } else {
                    malachite_types::Validity::Invalid
                },
            };
            let peer_id =
                PeerId::from_bytes(&proposer.to_be_bytes()).expect("Invalid proposer address");
            Input::ProposedValue(proposed_value, malachite_types::ValueOrigin::Sync(peer_id))
        }
        _ => unreachable!(),
    }
}

/// A write-ahead log that writes to a file.
pub struct FileWalSink {
    file: std::fs::File,
    path: PathBuf,
    has_decision: bool,
}

impl FileWalSink {
    pub fn new(
        address: &ValidatorAddress,
        height: &Height,
        wal_dir: &Path,
    ) -> std::io::Result<Self> {
        // Create the WAL directory if it doesn't exist
        std::fs::create_dir_all(wal_dir)?;

        let filename = filename(address, height);
        let path = wal_dir.join(filename);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            file,
            path,
            has_decision: false,
        })
    }
}

impl Drop for FileWalSink {
    fn drop(&mut self) {
        // Ensure all data is flushed to disk before we potentially delete the file
        if let Err(e) = self.file.flush() {
            tracing::error!(
                path = %self.path.display(),
                error = %e,
                "Failed to flush WAL file before drop"
            );
        }

        if self.has_decision {
            // Only delete the WAL file if we've reached a decision
            if let Err(e) = fs::remove_file(&self.path) {
                tracing::error!(
                    path = %self.path.display(),
                    error = %e,
                    "Failed to delete WAL file after decision"
                );
            } else {
                tracing::debug!(
                    path = %self.path.display(),
                    "Successfully deleted WAL file after decision"
                );
            }
        } else {
            // Keep the WAL file if no decision was reached
            tracing::debug!(
                path = %self.path.display(),
                "Keeping WAL file as no decision was reached"
            );
        }
    }
}

impl WalSink for FileWalSink {
    fn append(&mut self, entry: WalEntry) {
        // Check if this entry is a decision
        if matches!(entry, WalEntry::Decision { .. }) {
            self.has_decision = true;
            tracing::debug!(
                path = %self.path.display(),
                "Marking WAL as finalized - decision reached"
            );
        }

        let line = serde_json::to_string(&entry).expect("WAL serialization failed");
        writeln!(self.file, "{line}").expect("WAL write failed");
    }

    fn is_finalized(&self) -> bool {
        self.has_decision
    }
}

/// A write-ahead log that does nothing.
pub(crate) struct NoopWal;

impl WalSink for NoopWal {
    fn append(&mut self, entry: WalEntry) {
        tracing::debug!("NoopWal: Appending entry: {:?}", entry);
    }

    fn is_finalized(&self) -> bool {
        false // NoopWal is never finalized
    }
}

/// Recovery utilities for the write-ahead log.
pub(crate) mod recovery {

    use super::*;

    /// Extract the height from the filename of the write-ahead log file.
    pub(crate) fn extract_height_from_filename(path: &Path) -> Height {
        let filename = path.file_name().unwrap_or_default().to_string_lossy();

        // Expect format: "wal-{validator}-{height}.json"
        let height_str = filename
            .strip_prefix(WAL_FILE_PREFIX)
            .and_then(|s| s.strip_suffix(".json"))
            .and_then(|s| s.split('-').nth(1))
            .unwrap_or_default();

        let height = height_str.parse::<u64>().unwrap_or_else(|_| {
            tracing::warn!(
                filename = %filename,
                path = %path.display(),
                "Failed to parse height from filename, using 0"
            );
            0
        });

        Height::new(height)
    }

    /// Collect all the write-ahead log files in the given directory. The result
    /// is sorted by height.
    pub(crate) fn collect_wal_files(
        wal_dir: &Path,
    ) -> Result<Vec<(Height, PathBuf)>, std::io::Error> {
        let mut files = Vec::new();
        let dir = fs::read_dir(wal_dir).map_err(|e| {
            std::io::Error::other(format!(
                "Failed to read WAL directory {}: {}",
                wal_dir.display(),
                e
            ))
        })?;
        for entry in dir {
            let entry = entry?;
            let path = entry.path();
            if path.is_file()
                && path.extension().unwrap_or_default() == WAL_FILE_EXTENSION
                && path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .starts_with(WAL_FILE_PREFIX)
            {
                let height = extract_height_from_filename(&path);
                files.push((height, path));
            }
        }
        files.sort_by_key(|(height, _)| *height);
        Ok(files)
    }

    /// Read the entries from the write-ahead log file.
    pub(crate) fn read_entries(path: &Path) -> Result<Vec<WalEntry>, std::io::Error> {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            if !line.trim().is_empty() {
                let entry: WalEntry = serde_json::from_str(&line).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Failed to parse WAL entry at line {} in {}: {}",
                            line_num + 1,
                            path.display(),
                            e
                        ),
                    )
                })?;
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    /// Recover all incomplete heights from the write-ahead log.
    pub(crate) fn recover_incomplete_heights(
        wal_dir: &Path,
    ) -> Result<Vec<(Height, Vec<WalEntry>)>, std::io::Error> {
        // Check if the WAL directory exists
        if !wal_dir.exists() {
            tracing::info!(
                wal_dir = %wal_dir.display(),
                "WAL directory does not exist, no recovery needed"
            );
            return Ok(Vec::new());
        }

        let files = collect_wal_files(wal_dir)?;
        tracing::info!(
            files = ?files,
            "Recovering incomplete heights from WAL",
        );
        let mut result = Vec::new();
        // For each file, read the entries and add them to the result if the height is
        // not finalized.
        for (height, path) in files {
            let entries = read_entries(&path)?;
            let is_finalized = entries
                .iter()
                .any(|e| matches!(e, WalEntry::Decision { .. }));
            if is_finalized {
                tracing::debug!(
                    height = %height,
                    path = %path.display(),
                    "Skipping finalized height"
                );
                continue;
            }
            tracing::debug!(
                height = %height,
                path = %path.display(),
                entry_count = entries.len(),
                "Recovering incomplete height"
            );
            result.push((height, entries));
        }
        Ok(result)
    }
}
