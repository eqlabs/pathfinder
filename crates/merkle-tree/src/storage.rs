use anyhow::Context;
use bitvec::prelude::Msb0;
use stark_hash::Felt;

use crate::Node;

/// Read-only storage used by the [Merkle tree](crate::tree::MerkleTree).
pub trait Storage {
    type Error: std::error::Error + Send + Sync + 'static;

    fn get(&self, node: &Felt) -> Result<Option<Node>, Self::Error>;
}

/// Wrapper around [anyhow::Error].
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct AnyhowError(#[from] anyhow::Error);

/// Database serialization for [Node].
impl rusqlite::types::FromSql for Node {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let data = value.as_blob()?;

        use rusqlite::types::FromSqlError;
        match data.len() {
            64 => {
                // unwraps and indexing are safe due to length check == 64.
                let left: [u8; 32] = data[..32].try_into().unwrap();
                let right: [u8; 32] = data[32..].try_into().unwrap();

                let left = Felt::from_be_bytes(left)
                    .context("Binary node's left hash is corrupt")
                    .map_err(|e| FromSqlError::Other(e.into()))?;
                let right = Felt::from_be_bytes(right)
                    .context("Binary node's right hash is corrupt")
                    .map_err(|e| FromSqlError::Other(e.into()))?;

                Ok(Node::Binary { left, right })
            }
            65 => {
                // unwraps and indexing are safe due to length check == 65.
                let child: [u8; 32] = data[..32].try_into().unwrap();
                let path = data[32..64].to_vec();
                let length = data[64] as usize;

                // Grab the __last__ `length` bits. Path is stored in MSB format, which means LSB
                // is always stored in the last bit. Since the path may vary in length we must take
                // the last bits.
                use bitvec::view::BitView;
                let path = path.view_bits::<Msb0>()[256 - length..].to_bitvec();

                let child = Felt::from_be_bytes(child)
                    .context("Edge node's child hash is corrupt.")
                    .map_err(|e| FromSqlError::Other(e.into()))?;

                anyhow::Result::Ok(Node::Edge { path, child })
            }
            other => Err(FromSqlError::Other(
                anyhow::anyhow!("Bad node length: {other}").into(),
            )),
        }
    }
}

/// Database deserialization for [Node].
impl rusqlite::types::ToSql for Node {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        use bitvec::view::BitView;
        use rusqlite::types::{ToSqlOutput, Value};

        let mut buffer = Vec::with_capacity(65);

        match self {
            Node::Binary { left, right } => {
                buffer.extend_from_slice(left.as_be_bytes());
                buffer.extend_from_slice(right.as_be_bytes());
            }
            Node::Edge { child, path } => {
                buffer.extend_from_slice(child.as_be_bytes());
                // Bit path must be written in MSB format. This means that the LSB
                // must be in the last bit position. Since we write a fixed number of
                // bytes (32) but the path length may vary, we have to ensure we are writing
                // to the end of the slice.
                buffer.resize(65, 0);
                buffer[32..][..32].view_bits_mut::<Msb0>()[256 - path.len()..]
                    .copy_from_bitslice(path);

                buffer[64] = path.len() as u8;
            }
        }

        Ok(ToSqlOutput::Owned(Value::Blob(buffer)))
    }
}

/// This macro defines a [Storage] adapter for a Sqlite table.
///
/// The table schema is expected to already be created and should match:
/// ```sql
/// hash: BLOB,
/// data: BLOB,
/// ```
///
/// Usage:
/// ```
/// define_sqlite_storage!(AdapterStructName, "table_name");
/// ````
#[macro_export]
macro_rules! define_sqlite_storage {
    ($name: ident, $table: literal) => {
        pub struct $name<'tx>(&'tx rusqlite::Transaction<'tx>);

        impl<'tx> $name<'tx> {
            #[allow(dead_code)]
            pub fn new(tx: &'tx rusqlite::Transaction<'tx>) -> Self {
                Self(tx)
            }

            #[allow(dead_code)]
            fn insert(&self, hash: &stark_hash::Felt, node: &$crate::Node) -> anyhow::Result<()> {
                self.0
                    .execute(
                        concat!(
                            "INSERT OR IGNORE INTO ",
                            $table,
                            " (hash, data) VALUES (?, ?)"
                        ),
                        rusqlite::params![hash.as_be_bytes(), node],
                    )
                    .context("Inserting node into tree_class table")?;

                Ok(())
            }
        }

        impl<'tx> $crate::storage::Storage for $name<'tx> {
            type Error = $crate::storage::AnyhowError;

            fn get(&self, node: &stark_hash::Felt) -> Result<Option<$crate::Node>, Self::Error> {
                use rusqlite::OptionalExtension;

                self.0
                    .query_row(
                        concat!("SELECT data FROM ", $table, " WHERE hash = ?"),
                        rusqlite::params![node.as_be_bytes()],
                        |row| row.get::<_, $crate::Node>(0),
                    )
                    .optional()
                    .context("Fetching node data from $table in database")
                    .map_err($crate::storage::AnyhowError::from)
            }
        }
    };
}
