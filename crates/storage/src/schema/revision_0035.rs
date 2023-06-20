/// This migration originally replaced all trie null ref counts with 1. However this migration took long with no actual benefit
/// so we removed it again. Whether or not this migration was run does not matter as the ref counts are already corrupt.
pub(crate) fn migrate(_tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    Ok(())
}
