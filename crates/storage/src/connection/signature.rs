use anyhow::Context;
use pathfinder_common::{BlockCommitmentSignature, BlockNumber};

use crate::prelude::*;

pub(super) fn insert_signature(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    signature: &BlockCommitmentSignature,
) -> anyhow::Result<()> {
    tx.inner()
        .execute(
            r"INSERT INTO block_signatures
               ( block_number,  signature_r,  signature_s)
        VALUES (:block_number, :signature_r, :signature_s)",
            named_params! {
                ":block_number": &block_number,
                ":signature_r": &signature.r,
                ":signature_s": &signature.s,
            },
        )
        .context("Inserting signature")?;

    Ok(())
}
