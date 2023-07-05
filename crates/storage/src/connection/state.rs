use pathfinder_common::{ClassHash, ContractNonce, ContractRoot, ContractStateHash};

use crate::prelude::*;

pub(super) fn contract_state(
    tx: &Transaction<'_>,
    state_hash: ContractStateHash,
) -> anyhow::Result<Option<(ContractRoot, ClassHash, ContractNonce)>> {
    tx.inner()
        .query_row(
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
    tx.inner().execute(
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

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;

    use super::*;

    #[test]
    fn contract_state() {
        let mut db = crate::Storage::in_memory().unwrap().connection().unwrap();
        let tx = db.transaction().unwrap();

        let state_hash = contract_state_hash_bytes!(b"state hash");
        let class_hash = class_hash_bytes!(b"class hash");
        let contract_root = contract_root_bytes!(b"contract root");
        let contract_nonce = contract_nonce_bytes!(b"contract nonce");

        insert_contract_state(&tx, state_hash, class_hash, contract_root, contract_nonce).unwrap();

        let result = super::contract_state(&tx, state_hash).unwrap().unwrap();
        assert_eq!(result.0, contract_root);
        assert_eq!(result.1, class_hash);
        assert_eq!(result.2, contract_nonce);

        let invalid =
            super::contract_state(&tx, contract_state_hash_bytes!(b"invalid state hash")).unwrap();
        assert_eq!(invalid, None);
    }
}
