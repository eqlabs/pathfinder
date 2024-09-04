use anyhow::Context;
use pathfinder_common::{BlockCommitmentSignature, BlockNumber};

use crate::prelude::*;
use crate::BlockId;

impl Transaction<'_> {
    pub fn insert_signature(
        &self,
        block_number: BlockNumber,
        signature: &BlockCommitmentSignature,
    ) -> anyhow::Result<()> {
        self.inner()
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

    pub fn signature(&self, block: BlockId) -> anyhow::Result<Option<BlockCommitmentSignature>> {
        match block {
            BlockId::Latest => self.inner().query_row(
                "SELECT signature_r, signature_s FROM block_signatures ORDER BY block_number DESC \
                 LIMIT 1",
                [],
                |row| {
                    let r = row.get_block_commitment_signature_elem(0)?;
                    let s = row.get_block_commitment_signature_elem(1)?;
                    Ok(BlockCommitmentSignature { r, s })
                },
            ),
            BlockId::Number(number) => self.inner().query_row(
                "SELECT signature_r, signature_s FROM block_signatures WHERE block_number = ?",
                params![&number],
                |row| {
                    let r = row.get_block_commitment_signature_elem(0)?;
                    let s = row.get_block_commitment_signature_elem(1)?;
                    Ok(BlockCommitmentSignature { r, s })
                },
            ),
            BlockId::Hash(hash) => self.inner().query_row(
                r"SELECT signature_r, signature_s
                FROM block_signatures
                JOIN block_headers ON block_signatures.block_number = block_headers.number
                WHERE block_headers.hash = ?",
                params![&hash],
                |row| {
                    let r = row.get_block_commitment_signature_elem(0)?;
                    let s = row.get_block_commitment_signature_elem(1)?;
                    Ok(BlockCommitmentSignature { r, s })
                },
            ),
        }
        .optional()
        .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::prelude::*;

    use super::*;
    use crate::Connection;

    fn setup() -> (Connection, Vec<BlockHeader>, Vec<BlockCommitmentSignature>) {
        let storage = crate::StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let genesis = BlockHeader::builder()
            .number(BlockNumber::new_or_panic(0))
            .finalize_with_hash(block_hash_bytes!(b"genesis"));
        let genesis_signature = BlockCommitmentSignature {
            r: block_commitment_signature_elem_bytes!(b"genesis r"),
            s: block_commitment_signature_elem_bytes!(b"genesis s"),
        };

        let block1 = genesis
            .child_builder()
            .finalize_with_hash(block_hash_bytes!(b"block 1 hash"));
        let block1_signature = BlockCommitmentSignature {
            r: block_commitment_signature_elem_bytes!(b"block 1 r"),
            s: block_commitment_signature_elem_bytes!(b"block 1 s"),
        };

        let headers = vec![genesis, block1];
        let signatures = vec![genesis_signature, block1_signature];
        for (header, signature) in headers.iter().zip(&signatures) {
            tx.insert_block_header(header).unwrap();
            tx.insert_signature(header.number, signature).unwrap();
        }
        tx.commit().unwrap();

        (connection, headers, signatures)
    }

    #[test]
    fn get_latest() {
        let (mut connection, _headers, signatures) = setup();
        let tx = connection.transaction().unwrap();

        let result = tx.signature(BlockId::Latest).unwrap().unwrap();
        let expected = signatures.last().unwrap();

        assert_eq!(&result, expected);
    }

    #[test]
    fn get_by_number() {
        let (mut connection, headers, signatures) = setup();
        let tx = connection.transaction().unwrap();

        for (header, signature) in headers.iter().zip(&signatures) {
            let result = tx.signature(header.number.into()).unwrap().unwrap();

            assert_eq!(&result, signature);
        }

        let past_head = headers.last().unwrap().number + 1;
        let result = tx.signature(past_head.into()).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn get_by_hash() {
        let (mut connection, headers, signatures) = setup();
        let tx = connection.transaction().unwrap();

        for (header, signature) in headers.iter().zip(&signatures) {
            let result = tx.signature(header.hash.into()).unwrap().unwrap();

            assert_eq!(&result, signature);
        }

        let past_head = headers.last().unwrap().number + 1;
        let result = tx.signature(past_head.into()).unwrap();
        assert_eq!(result, None);
    }
}
