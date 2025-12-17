use std::fmt::Debug;
use std::fs;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Round, SignedProposal, SignedVote};

/// The prefix of the write-ahead log file.
pub(crate) const WAL_FILE_PREFIX: &str = "wal-";

/// The extension of the write-ahead log file.
pub(crate) const WAL_FILE_EXTENSION: &str = "json";

/// The filename of the write-ahead log for a given validator and height.
pub(crate) fn filename(address: &impl ToString, height: u64) -> String {
    let address = address.to_string();
    format!("{WAL_FILE_PREFIX}{address}-{height}.{WAL_FILE_EXTENSION}")
}

/// Delete the WAL file for a given validator and height.
pub(crate) fn delete_wal_file(
    address: &impl ToString,
    height: u64,
    wal_dir: &Path,
) -> Result<(), std::io::Error> {
    let filename = filename(address, height);
    let path = wal_dir.join(&filename);

    if path.exists() {
        fs::remove_file(&path).map_err(|e| {
            std::io::Error::other(format!(
                "Failed to delete WAL file {}: {}",
                path.display(),
                e
            ))
        })?;
        tracing::debug!(
            path = %path.display(),
            "Deleted WAL file for pruned height"
        );
    }
    Ok(())
}

/// A trait for types that can append to a write-ahead log.
pub(crate) trait WalSink<V, A>: Send {
    /// Append an entry to the write-ahead log.
    fn append(&mut self, entry: WalEntry<V, A>);

    /// Check if this WAL has been finalized (a decision has been reached)
    fn is_finalized(&self) -> bool {
        false // Default impl. for WALs that don't track finalization
    }

    /// Mark this WAL as finalized. Used during recovery when we detect a
    /// Decision entry.
    fn mark_as_finalized(&mut self) {
        // Default impl does nothing
    }
}

/// A write-ahead log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum WalEntry<V, A> {
    /// A signed proposal.
    SignedProposal(SignedProposal<V, A>),
    /// A signed vote.
    SignedVote(SignedVote<V, A>),
    /// A timeout.
    Timeout { kind: String, round: Round },
    /// A proposed value.
    ProposedValue {
        height: u64,
        round: Round,
        valid_round: Round,
        proposer: A,
        value: V,
        validity: bool,
    },
    /// A decision was reached.
    Decision { height: u64, value: V },
}

/// A write-ahead log that writes to a file.
pub struct FileWalSink {
    file: std::fs::File,
    path: PathBuf,
    has_decision: bool,
}

impl FileWalSink {
    pub fn new(address: &impl ToString, height: u64, wal_dir: &Path) -> std::io::Result<Self> {
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
        // Ensure all data is flushed to disk before drop
        if let Err(e) = self.file.flush() {
            tracing::error!(
                path = %self.path.display(),
                error = %e,
                "Failed to flush WAL file before drop"
            );
        }

        // Note: We no longer delete WAL files here - we keep them for recovery
        // in case they're still within `history_depth`. WAL files for finalized
        // heights will be deleted during pruning (in `prune_old_engines`) when
        // they're actually removed from memory.
        tracing::debug!(
            path = %self.path.display(),
            "Keeping WAL file for potential recovery (will be deleted during pruning if outside `history_depth`)"
        );
    }
}

impl<V: Serialize, A: Serialize> WalSink<V, A> for FileWalSink {
    fn append(&mut self, entry: WalEntry<V, A>) {
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

    fn mark_as_finalized(&mut self) {
        self.has_decision = true;
    }
}

/// A write-ahead log that does nothing.
pub(crate) struct NoopWal;

impl<V: Debug, A: Debug> WalSink<V, A> for NoopWal {
    fn append(&mut self, entry: WalEntry<V, A>) {
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
    pub(crate) fn extract_height_from_filename(path: &Path) -> u64 {
        let filename = path.file_name().unwrap_or_default().to_string_lossy();

        // Expect format: "wal-{validator}-{height}.json"
        let height_str = filename
            .strip_prefix(WAL_FILE_PREFIX)
            .and_then(|s| s.strip_suffix(".json"))
            .and_then(|s| s.split('-').nth(1))
            .unwrap_or_default();

        height_str.parse::<u64>().unwrap_or_else(|_| {
            tracing::warn!(
                filename = %filename,
                path = %path.display(),
                "Failed to parse height from filename, using 0"
            );
            0
        })
    }

    /// Collect all the write-ahead log files in the given directory. The result
    /// is sorted by height.
    pub(crate) fn collect_wal_files(wal_dir: &Path) -> Result<Vec<(u64, PathBuf)>, std::io::Error> {
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
    pub(crate) fn read_entries<V, A>(path: &Path) -> Result<Vec<WalEntry<V, A>>, std::io::Error>
    where
        V: for<'de> Deserialize<'de>,
        A: for<'de> Deserialize<'de>,
    {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            if !line.trim().is_empty() {
                let entry: WalEntry<V, A> = serde_json::from_str(&line).map_err(|e| {
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
    ///
    /// Returns a tuple of:
    /// - Incomplete heights that need to be recovered
    /// - Finalized heights (for potential restoration within history_depth)
    /// - The highest Decision height found in the WAL (even if
    ///   finalized/skipped)
    #[allow(clippy::type_complexity)]
    pub(crate) fn recover_incomplete_heights<V, A>(
        wal_dir: &Path,
        highest_committed: Option<u64>,
    ) -> Result<
        (
            Vec<(u64, Vec<WalEntry<V, A>>)>,
            Vec<(u64, Vec<WalEntry<V, A>>)>,
            Option<u64>,
        ),
        std::io::Error,
    >
    where
        V: for<'de> Deserialize<'de>,
        A: for<'de> Deserialize<'de>,
    {
        // Check if the WAL directory exists
        if !wal_dir.exists() {
            tracing::info!(
                wal_dir = %wal_dir.display(),
                "WAL directory does not exist, no recovery needed"
            );
            return Ok((Vec::new(), Vec::new(), None));
        }

        let files = collect_wal_files(wal_dir)?;
        tracing::info!(
            files = ?files,
            "Recovering incomplete heights from WAL",
        );
        let mut incomplete = Vec::new();
        let mut finalized = Vec::new();
        let mut highest_decision: Option<u64> = None;

        // For each file, read the entries and categorize them as incomplete or
        // finalized. Also track the highest Decision height encountered.
        for (height, path) in files {
            let entries: Vec<WalEntry<V, A>> = read_entries(&path)?;

            // Track the highest Decision height we encounter (even for finalized heights).
            for entry in &entries {
                if let WalEntry::Decision {
                    height: decision_height,
                    ..
                } = entry
                {
                    let decision_height: u64 = *decision_height;
                    highest_decision = match highest_decision {
                        Some(current_max) => Some(std::cmp::max(current_max, decision_height)),
                        None => Some(decision_height),
                    };
                }
            }

            // `WalEntry::Decision` indicates that a decision has been reached at this
            // height by the consensus engine. But it's probable that the proposal itself
            // hasn't fully been executed and committed to the main storage locally yet, or
            // it has been executed but it just hasn't been committed to the main storage
            // yet. Any of these scenarios means that the consensus engine for
            // this height is not started but some work with the persisted
            // proposal is still required, outside of the WAL framework itself.
            //
            // The latter condition indicates that the executed proposal for this height has
            // indeed been executed, finalized, and committed to the main storage locally,
            // so there will be no additional work required for this height
            // outside of the WAL framework.
            let is_finalized = entries.iter().any(|e| {
                matches!(e, WalEntry::Decision { .. })
                    || highest_committed
                        .is_some_and(|highest_committed| height <= highest_committed)
            });
            if is_finalized {
                tracing::debug!(
                    height = %height,
                    path = %path.display(),
                    "\"Recovering\" finalized height (may be restored if within history_depth)"
                );
                finalized.push((height, entries));
            } else {
                tracing::debug!(
                    height = %height,
                    path = %path.display(),
                    entry_count = entries.len(),
                    "Recovering incomplete height"
                );
                incomplete.push((height, entries));
            }
        }
        Ok((incomplete, finalized, highest_decision))
    }
}
