//! Contains the Sqlite persistent storage abstraction for a Starknet Binary Merkle Patricia Tree.
//!
//! For more information on the structure of the tree, see
//! [`MerkleTree`](crate::state::merkle_tree::MerkleTree).
//!
//! ## Overview
//!
//! This storage functions similarly to a key-value store with the addition of automatic
//! reference counting. A [node's](PersistedNode) key is its [hash](StarkHash), and it is
//! stored as bytes (although from an API perspective they get deserialized).
//!
//! Reference counting is performed automatically for all nodes i.e. when a node is inserted,
//! its children's reference count get incremented. Upon deletion, the children's reference
//! count get decremented. If a child's reference count reaches zero, it is automatically
//! deleted as well.
//!
//! ## Database format
//!
//! The data is stored as a single table with three columns:
//!
//! - `key`: BLOB (PK)
//! - `data`: BLOB
//! - `ref_count`: INTEGER
//!
//! ## Serialization format
//!
//! There are three node types, which get serialized as follows.
//!
//! #### [PersistedNode::Leaf]
//!
//! This is stored as an empty vector i.e. `Vec::<u8>::new()`. This is possible since
//! a leaf's value is also it's hash.
//!
//! #### [PersistedNode::Binary]
//!
//! This is stored as 64 bytes: [left child (32), right child (32)].
//!
//! #### [PersistedNode::Edge]
//!
//! This is stored as 65 bytes: [child (32), path (32), path length (1)]

use std::borrow::Cow;

use anyhow::Context;
use bitvec::{order::Msb0, prelude::BitVec, view::BitView};
use rusqlite::{named_params, OptionalExtension, Transaction};

use stark_hash::StarkHash;

/// Provides a reference counted storage backend for the
/// nodes of a Starknet Binary Merkle Patricia Tree.
///
/// This storage will automatically provide reference counting
/// for nodes upon insertion and deletion.
///
/// ### Warning
///
/// None of the [RcNodeStorage] functions rollback on failure. This means that if any error
/// is encountered, the transaction should be rolled back to prevent database corruption.
pub struct RcNodeStorage<'tx, 'queries> {
    transaction: &'tx Transaction<'tx>,
    queries: Queries<'queries>,
}

impl std::fmt::Debug for RcNodeStorage<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // this is practically useless
        f.debug_struct("RcNodeStorage")
            .field("transaction", &self.transaction)
            .finish()
    }
}

/// Queries used by the [`RcNodeStorage`].
///
/// We have `static ref` for the two table names pathfinder really uses. For other tables (in
/// tests) new queries are built at initialization.
struct Queries<'a> {
    create: Cow<'a, str>,
    insert: Cow<'a, str>,
    get: Cow<'a, str>,
    #[cfg(test)]
    delete_node: Cow<'a, str>,
    #[cfg(test)]
    set_ref_count: Cow<'a, str>,
    increment_ref_count: Cow<'a, str>,
    #[cfg(test)]
    get_ref_count: Cow<'a, str>,
}

lazy_static::lazy_static! {
    static ref GLOBAL: Queries<'static> = Queries::format("tree_global");
    static ref CONTRACTS: Queries<'static> = Queries::format("tree_contracts");
}

impl Queries<'static> {
    fn format(table: &str) -> Queries<'static> {
        Queries {
            create: format!(
                r"CREATE TABLE IF NOT EXISTS {}(
                hash        BLOB PRIMARY KEY,
                data        BLOB,
                ref_count   INTEGER
            )",
                table
            )
            .into(),
            insert: format!(
                // You may be tempted to increment the reference count ON CONFLICT, but that is incorrect.
                //
                // Reference counts only get incremented for the children of a node. So even though this node
                // already exists, and someone is trying to insert it again, this node's reference count increment
                // will occur when that someone inserts the new parent node.
                "INSERT INTO {} (hash, data, ref_count) VALUES (:hash, :data, :ref_count) ON CONFLICT DO NOTHING",
                table
            ).into(),
            get: format!("SELECT data FROM {} WHERE hash = :hash", table).into(),
            #[cfg(test)]
            delete_node: format!("DELETE FROM {} WHERE hash = :hash", table).into(),
            #[cfg(test)]
            set_ref_count: format!("UPDATE {} SET ref_count = :count WHERE hash = :hash", table).into(),
            increment_ref_count: format!("UPDATE {} SET ref_count = ref_count + 1 WHERE hash = :hash", table).into(),
            #[cfg(test)]
            get_ref_count: format!("SELECT ref_count FROM {} WHERE hash = :hash", table).into(),
        }
    }

    /// Re-borrow static self with a smaller lifetime.
    ///
    /// This is used with the `static ref` kind of `Queries`. Using `Clone` would not work here,
    /// because of how it cannot be defined for `Cow` properly.
    fn borrow<'a>(&'static self) -> Queries<'a> {
        macro_rules! borrow_cow {
            ($e:expr) => {
                match &$e {
                    std::borrow::Cow::Borrowed(s) => std::borrow::Cow::Borrowed(s),
                    std::borrow::Cow::Owned(o) => std::borrow::Cow::Borrowed(&o),
                }
            };
        }

        Queries {
            create: borrow_cow!(self.create),
            insert: borrow_cow!(self.insert),
            get: borrow_cow!(self.get),
            #[cfg(test)]
            delete_node: borrow_cow!(self.delete_node),
            #[cfg(test)]
            set_ref_count: borrow_cow!(self.set_ref_count),
            increment_ref_count: borrow_cow!(self.increment_ref_count),
            #[cfg(test)]
            get_ref_count: borrow_cow!(self.get_ref_count),
        }
    }
}

impl<'a, 'queries> crate::state::merkle_tree::NodeStorage for RcNodeStorage<'a, 'queries> {
    fn get(&self, key: StarkHash) -> anyhow::Result<Option<PersistedNode>> {
        self.get(key)
    }

    fn upsert(&self, key: StarkHash, node: PersistedNode) -> anyhow::Result<()> {
        self.upsert(key, node)
    }

    #[cfg(test)]
    fn decrement_ref_count(&self, key: StarkHash) -> anyhow::Result<()> {
        RcNodeStorage::decrement_ref_count(self, key)
    }

    fn increment_ref_count(&self, key: StarkHash) -> anyhow::Result<()> {
        self.increment_ref_count(key)
    }
}

/// A binary node which can be read / written from an [RcNodeStorage].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedBinaryNode {
    pub left: StarkHash,
    pub right: StarkHash,
}

/// An edge node which can be read / written from an [RcNodeStorage].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedEdgeNode {
    pub path: BitVec<Msb0, u8>,
    pub child: StarkHash,
}

/// A node which can be read / written from an [RcNodeStorage].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedNode {
    Binary(PersistedBinaryNode),
    Edge(PersistedEdgeNode),
    Leaf,
}

impl PersistedNode {
    fn serialize(&self, buffer: &mut [u8]) -> usize {
        match self {
            PersistedNode::Binary(binary) => {
                buffer[..32].copy_from_slice(&binary.left.to_be_bytes());
                buffer[32..][..32].copy_from_slice(&binary.right.to_be_bytes());
                64
            }
            PersistedNode::Edge(edge) => {
                let length = edge.path.len() as u8;

                buffer[..32].copy_from_slice(&edge.child.to_be_bytes());

                // Bit path must be written in MSB format. This means that the LSB
                // must be in the last bit position. Since we write a fixed number of
                // bytes (32) but the path length may vary, we have to ensure we are writing
                // to the end of the slice.
                buffer[32..][..32].view_bits_mut::<Msb0>()[256 - edge.path.len()..]
                    .copy_from_bitslice(&edge.path);

                buffer[64] = length;

                65
            }
            PersistedNode::Leaf => 0,
        }
    }

    fn deserialize(bytes: &[u8]) -> anyhow::Result<PersistedNode> {
        match bytes.len() {
            0 => Ok(PersistedNode::Leaf),
            64 => {
                // unwraps and indexing are safe due to length check == 64.
                let left: [u8; 32] = bytes[..32].try_into().unwrap();
                let right: [u8; 32] = bytes[32..].try_into().unwrap();

                let left = StarkHash::from_be_bytes(left)
                    .context("Binary node's left hash is corrupt.")?;
                let right = StarkHash::from_be_bytes(right)
                    .context("Binary node's right hash is corrupt.")?;

                Ok(PersistedNode::Binary(PersistedBinaryNode { left, right }))
            }
            65 => {
                // unwraps and indexing are safe due to length check == 65.
                let child: [u8; 32] = bytes[..32].try_into().unwrap();
                let path = bytes[32..64].to_vec();
                let length = bytes[64] as usize;

                anyhow::ensure!(length <= 251, "Edge node's length is too big: {}.", length);
                // Grab the __last__ `length` bits. Path is stored in MSB format, which means LSB
                // is always stored in the last bit. Since the path may vary in length we must take
                // the last bits.
                let path = path.view_bits::<Msb0>()[256 - length..].to_bitvec();

                let child = StarkHash::from_be_bytes(child)
                    .context("Edge node's child hash is corrupt.")?;

                Ok(PersistedNode::Edge(PersistedEdgeNode { path, child }))
            }
            other => anyhow::bail!(
                "Failed to deserialize node, data size is incorrect: {} bytes.",
                other
            ),
        }
    }
}

impl<'tx, 'queries> RcNodeStorage<'tx, 'queries> {
    /// Opens the Sqlite table as an [RcNodeStorage]. If the table does not exist, it will
    /// be created.
    ///
    /// The given transaction will be used to perform all database interactions,
    /// which can be committed once the storage session is complete.
    ///
    /// ### Warning
    ///
    /// None of the [RcNodeStorage] functions rollback on failure. This means that if any error
    /// is encountered, the transaction should be rolled back to prevent database corruption.
    pub fn open(table: &str, transaction: &'tx Transaction<'tx>) -> anyhow::Result<Self> {
        let queries = if table == "tree_global" {
            let q = GLOBAL.borrow();
            // this assertion exists to prove that the reborrowing works.
            debug_assert!(matches!(q.create, Cow::Borrowed(_)));
            q
        } else if table == "tree_contracts" {
            CONTRACTS.borrow()
        } else {
            Queries::format(table)
        };

        transaction.execute(&queries.create, [])?;

        Ok(Self {
            transaction,
            queries,
        })
    }

    /// Inserts the node into storage, and increments the reference count of the node's
    /// children (if any). Does nothing if the node already exists.
    ///
    /// A newly inserted node will have a reference count of zero.
    ///
    /// ### Warning
    ///
    /// Does not perform rollback on failure. This implies that you should rollback the [RcNodeStorage's](RcNodeStorage) transaction
    /// if this call returns an error to prevent database corruption.
    pub fn upsert(&self, key: StarkHash, node: PersistedNode) -> anyhow::Result<()> {
        let hash = key.to_be_bytes();

        let mut data = [0u8; 65];

        // Insert the node itself
        let written = node.serialize(&mut data);

        if written == 0 {
            return Ok(());
        }

        let count = self.transaction.execute(
            &self.queries.insert,
            named_params! {
                ":hash": &hash[..],
                ":data": &data[..written],
                ":ref_count": 0
            },
        )?;

        // Increment children reference counts ONLY IF the node was inserted.
        if count != 0 {
            match node {
                PersistedNode::Binary(binary) => {
                    self.increment_ref_count(binary.left)
                        .context("Failed to increment left child's reference count.")?;
                    self.increment_ref_count(binary.right)
                        .context("Failed to increment right child's reference count.")?;
                }
                PersistedNode::Edge(edge) => {
                    self.increment_ref_count(edge.child)
                        .context("Failed to increment child's reference count.")?;
                }
                PersistedNode::Leaf => unreachable!("leaves are no longer inserted"),
            }
        }

        Ok(())
    }

    /// Returns the node given by `key`, or [None] if it doesn't exist.
    pub fn get(&self, key: StarkHash) -> anyhow::Result<Option<PersistedNode>> {
        let hash = key.to_be_bytes();

        let node = self
            .transaction
            .query_row(
                &self.queries.get,
                named_params! {
                    ":hash": &hash[..],
                },
                |row| {
                    let data = row.get_ref_unwrap("data").as_blob()?;
                    Ok(PersistedNode::deserialize(data))
                },
            )
            .optional()?;

        node.transpose()
    }

    /// Deletes the given node from storage, and decrements the reference count of the node's
    /// children (if any).
    ///
    /// If a child's reference count reaches 0 as a result of this operation,
    /// it will get deleted in turn. A single deletion may therefore result in a daisy-chain of
    /// deletions.
    ///
    /// ### Warning
    ///
    /// Does not perform rollback on failure. This implies that you should rollback the [RcNodeStorage's](RcNodeStorage) transaction
    /// if this call returns an error to prevent database corruption.
    #[cfg(test)]
    fn delete_node(&self, key: StarkHash) -> anyhow::Result<()> {
        let hash = key.to_be_bytes();

        let node = match self.get(key)? {
            Some(node) => node,
            None => return Ok(()),
        };

        self.transaction.execute(
            &self.queries.delete_node,
            named_params! {
               ":hash": &hash[..],
            },
        )?;

        match node {
            PersistedNode::Binary(binary) => {
                self.decrement_ref_count(binary.left)?;
                self.decrement_ref_count(binary.right)?;
            }
            PersistedNode::Edge(edge) => self.decrement_ref_count(edge.child)?,
            PersistedNode::Leaf => {}
        }

        Ok(())
    }

    /// Decrements the reference count of the node and automatically deletes it
    /// if the count becomes zero.
    #[cfg(test)]
    pub fn decrement_ref_count(&self, key: StarkHash) -> anyhow::Result<()> {
        let hash = key.to_be_bytes();

        let ref_count = self
            .transaction
            .query_row(
                &self.queries.get_ref_count,
                named_params! {
                    ":hash": &hash[..],
                },
                |row| {
                    let ref_count: u16 = row.get("ref_count")?;

                    Ok(ref_count)
                },
            )
            .optional()?;

        match ref_count {
            Some(0 | 1) => self.delete_node(key)?,
            Some(count) => {
                self.transaction.execute(
                    &self.queries.set_ref_count,
                    named_params! {
                    ":count": count - 1,
                    ":hash": &hash[..]},
                )?;
            }
            None => {}
        }

        Ok(())
    }

    /// Increments the reference count of the node.
    pub fn increment_ref_count(&self, key: StarkHash) -> anyhow::Result<()> {
        let hash = key.to_be_bytes();
        self.transaction.execute(
            &self.queries.increment_ref_count,
            named_params! {
               ":hash": &hash[..],
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::bitvec;

    /// Test helper function to query a node's current reference count from the database.
    fn get_ref_count(storage: &RcNodeStorage<'_, '_>, key: StarkHash) -> Option<u64> {
        let hash = key.to_be_bytes();
        storage
            .transaction
            .query_row(
                &storage.queries.get_ref_count,
                named_params! {
                   ":hash": &hash[..],
                },
                |row| {
                    let ref_count = row.get("ref_count")?;

                    Ok(ref_count)
                },
            )
            .optional()
            .unwrap()
    }

    mod serde {
        use super::*;
        use crate::starkhash;

        #[test]
        fn edge() {
            // Tests all different possible path lengths. This is an area of concern as we are serializing
            // and deserializing big endian bit paths to a fixed size big endian array.
            let child = starkhash!("123abc");
            // 251 randomly generated bits.
            let bits251 = bitvec![Msb0, u8; 1,0,0,1,1,0,1,1,0,0,1,1,1,1,0,0,1,1,1,0,1,0,0,1,0,1,0,1,1,0,0,0,
                                                           1,1,1,1,1,1,1,0,1,1,0,1,0,0,1,1,1,0,0,1,0,1,1,1,0,0,0,1,0,1,0,0,
                                                           0,1,0,0,1,1,0,0,1,0,1,1,0,0,1,1,0,0,1,0,0,0,0,0,0,0,1,1,0,0,1,0,
                                                           0,0,1,1,1,0,0,0,0,1,0,1,0,1,0,0,0,0,1,1,1,1,0,0,1,0,0,1,0,1,0,1,
                                                           1,0,1,1,0,0,1,1,0,0,1,0,1,0,1,1,0,1,1,0,0,0,0,0,1,0,0,0,1,1,1,1,
                                                           1,0,1,0,1,0,1,1,1,0,1,1,1,0,1,0,1,0,0,0,1,1,1,0,1,0,0,0,0,1,0,0,
                                                           1,1,0,1,1,0,1,0,0,0,1,0,0,1,0,0,0,1,0,0,0,1,1,1,1,1,1,1,1,1,0,1,
                                                           0,0,0,0,0,0,1,0,1,0,0,1,0,1,0,0,1,0,0,0,1,0,1,0,1,1,1];

            let mut scratch = [0u8; 65];

            for i in 0..251 {
                let path = bits251[i..].to_bitvec();

                let original = PersistedNode::Edge(PersistedEdgeNode { path, child });

                let written = original.serialize(&mut scratch);
                let deserialized = PersistedNode::deserialize(&scratch[..written]).unwrap();

                assert_eq!(deserialized, original, "iteration {i}");
            }
        }

        #[test]
        fn binary() {
            let original = PersistedNode::Binary(PersistedBinaryNode {
                left: starkhash!("0123"),
                right: starkhash!("0abc"),
            });

            let mut data = [0u8; 65];

            let written = original.serialize(&mut data);
            let deserialized = PersistedNode::deserialize(&data[..written]).unwrap();

            assert_eq!(deserialized, original);
        }
    }

    mod reference_count {
        use super::*;
        use crate::starkhash;

        #[test]
        fn increment() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = RcNodeStorage::open("test", &transaction).unwrap();

            let key = starkhash!("123abc");
            let node = PersistedNode::Binary(PersistedBinaryNode {
                left: starkhash!("0321"),
                right: starkhash!("0abc"),
            });

            uut.upsert(key, node).unwrap();
            assert_eq!(get_ref_count(&uut, key), Some(0));

            uut.increment_ref_count(key).unwrap();
            assert_eq!(get_ref_count(&uut, key), Some(1));

            uut.increment_ref_count(key).unwrap();
            uut.increment_ref_count(key).unwrap();
            assert_eq!(get_ref_count(&uut, key), Some(3));
        }

        #[test]
        fn decrement() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = RcNodeStorage::open("test", &transaction).unwrap();

            let key = starkhash!("123abc");
            let node = PersistedNode::Binary(PersistedBinaryNode {
                left: starkhash!("0321"),
                right: starkhash!("0abc"),
            });

            uut.upsert(key, node).unwrap();
            assert_eq!(get_ref_count(&uut, key), Some(0));

            uut.increment_ref_count(key).unwrap();
            uut.increment_ref_count(key).unwrap();
            assert_eq!(get_ref_count(&uut, key), Some(2));

            uut.decrement_ref_count(key).unwrap();
            assert_eq!(get_ref_count(&uut, key), Some(1));
            // Node should get deleted once the reference count hits 0.
            uut.decrement_ref_count(key).unwrap();
            assert_eq!(uut.get(key).unwrap(), None);
        }

        #[test]
        fn repeat_insert() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = RcNodeStorage::open("test", &transaction).unwrap();

            let key = starkhash!("123abc");
            let node = PersistedNode::Binary(PersistedBinaryNode {
                left: starkhash!("0321"),
                right: starkhash!("0abc"),
            });

            uut.upsert(key, node.clone()).unwrap();
            uut.upsert(key, node.clone()).unwrap();
            uut.upsert(key, node).unwrap();
            assert_eq!(get_ref_count(&uut, key), Some(0));
        }
    }

    mod insert_get {
        use super::*;
        use crate::starkhash;

        #[test]
        fn missing() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = RcNodeStorage::open("test", &transaction).unwrap();

            let key = starkhash!("123abc");
            assert_eq!(uut.get(key).unwrap(), None);
        }

        #[test]
        fn binary() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = RcNodeStorage::open("test", &transaction).unwrap();

            let left_child_key = starkhash!("123abc");
            let left_child = PersistedNode::Leaf;

            let right_child_key = starkhash!("ddd111");
            let right_child = PersistedNode::Leaf;

            let parent_key = starkhash!("def123");
            let parent = PersistedNode::Binary(PersistedBinaryNode {
                left: left_child_key,
                right: right_child_key,
            });

            uut.upsert(left_child_key, left_child).unwrap();
            assert_eq!(get_ref_count(&uut, left_child_key), None);

            uut.upsert(right_child_key, right_child).unwrap();
            assert_eq!(get_ref_count(&uut, right_child_key), None);

            uut.upsert(parent_key, parent.clone()).unwrap();
            assert_eq!(get_ref_count(&uut, left_child_key), None);
            assert_eq!(get_ref_count(&uut, right_child_key), None);

            assert_eq!(uut.get(parent_key).unwrap(), Some(parent));
        }

        #[test]
        fn edge() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = RcNodeStorage::open("test", &transaction).unwrap();

            let child_key = starkhash!("123abc");
            let child = PersistedNode::Leaf;

            let parent_key = starkhash!("def123");
            let parent = PersistedNode::Edge(PersistedEdgeNode {
                path: bitvec![Msb0, u8; 1, 0, 0],
                child: child_key,
            });

            uut.upsert(child_key, child).unwrap();
            assert_eq!(get_ref_count(&uut, child_key), None);

            uut.upsert(parent_key, parent.clone()).unwrap();
            assert_eq!(get_ref_count(&uut, child_key), None);

            assert_eq!(uut.get(parent_key).unwrap(), Some(parent));
        }

        #[test]
        fn leaf() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = RcNodeStorage::open("test", &transaction).unwrap();

            let key = starkhash!("123abc");
            let node = PersistedNode::Leaf;

            uut.upsert(key, node).unwrap();
            assert_eq!(
                uut.get(key).unwrap(),
                None,
                "leaves should no longer be persisted"
            );
        }
    }

    mod delete {
        use super::*;
        use crate::starkhash;

        #[test]
        fn binary() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = RcNodeStorage::open("test", &transaction).unwrap();

            let left_child_key = starkhash!("123abc");
            let left_child = PersistedNode::Leaf;

            let right_child_key = starkhash!("ddd111");
            let right_child = PersistedNode::Leaf;

            let parent_key = starkhash!("def123");
            let parent = PersistedNode::Binary(PersistedBinaryNode {
                left: left_child_key,
                right: right_child_key,
            });

            uut.upsert(left_child_key, left_child).unwrap();
            uut.upsert(right_child_key, right_child).unwrap();
            uut.upsert(parent_key, parent).unwrap();
            uut.delete_node(parent_key).unwrap();

            assert_eq!(uut.get(left_child_key).unwrap(), None);
            assert_eq!(uut.get(right_child_key).unwrap(), None);
            assert_eq!(uut.get(parent_key).unwrap(), None);
        }

        #[test]
        fn edge() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = RcNodeStorage::open("test", &transaction).unwrap();

            let child_key = starkhash!("123abc");
            let child = PersistedNode::Leaf;

            let parent_key = starkhash!("def123");
            let parent = PersistedNode::Edge(PersistedEdgeNode {
                path: bitvec![Msb0, u8; 1, 0, 0],
                child: child_key,
            });

            uut.upsert(child_key, child).unwrap();
            uut.upsert(parent_key, parent).unwrap();
            uut.delete_node(parent_key).unwrap();

            assert_eq!(uut.get(child_key).unwrap(), None);
            assert_eq!(uut.get(parent_key).unwrap(), None);
        }

        #[test]
        fn decrement_ref_count() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = RcNodeStorage::open("test", &transaction).unwrap();

            let leaf_key = starkhash!("123abc");
            let leaf_node = PersistedNode::Leaf;

            let parent_key_1 = starkhash!("0111");
            let parent_key_2 = starkhash!("0222");

            let parent_node_1 = PersistedNode::Edge(PersistedEdgeNode {
                path: bitvec![Msb0, u8; 1, 0, 0],
                child: leaf_key,
            });
            let parent_node_2 = PersistedNode::Edge(PersistedEdgeNode {
                path: bitvec![Msb0, u8; 1, 1, 1],
                child: leaf_key,
            });

            uut.upsert(leaf_key, leaf_node).unwrap();
            uut.upsert(parent_key_1, parent_node_1).unwrap();
            uut.upsert(parent_key_2, parent_node_2).unwrap();

            // This test case is a bit more trickier since after removal of leaf insertions, this
            // is a bit more trickier to test, and it is not obvious what should be the next tier
            // edges.
            //
            // originally this case allowed testing that leaf lives as long as either of it's
            // parents.
            uut.delete_node(parent_key_1).unwrap();
            uut.delete_node(parent_key_2).unwrap();
        }
    }
}
