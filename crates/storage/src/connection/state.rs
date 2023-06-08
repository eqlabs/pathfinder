use pathfinder_common::{ClassHash, ContractNonce, ContractRoot, ContractStateHash};

use crate::prelude::*;

pub(super) fn contract_state(
    tx: &Transaction<'_>,
    state_hash: ContractStateHash,
) -> anyhow::Result<Option<(ContractRoot, ClassHash, ContractNonce)>> {
    tx.query_row(
        "SELECT root, hash, nonce FROM contract_states WHERE state_hash = :state_hash",
        named_params! {
            ":state_hash": &state_hash
        },
        |row| {
            let root = row.get_contract_root("root")?;
            let hash = row.get_class_hash("hash")?;
            let nonce = row.get_contract_nonce("nonce")?;

            Ok((root, hash, nonce))
        },
    )
    .optional()
    .map_err(|e| e.into())
}

pub(super) fn insert_contract_state(
    tx: &Transaction<'_>,
    state_hash: ContractStateHash,
    class_hash: ClassHash,
    root: ContractRoot,
    nonce: ContractNonce,
) -> anyhow::Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO contract_states (state_hash, hash, root, nonce) VALUES (:state_hash, :hash, :root, :nonce)",
        named_params! {
            ":state_hash": &state_hash,
            ":hash": &class_hash,
            ":root": &root,
            ":nonce": &nonce,
        },
    )?;
    Ok(())
}
