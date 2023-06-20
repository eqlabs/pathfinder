use std::collections::HashMap;

use anyhow::Context;
use pathfinder_common::trie::TrieNode;
use stark_hash::Felt;

use crate::prelude::*;

insert_trie!(insert_class_trie, tree_class, ClassTrieReader);
insert_trie!(insert_contract_trie, tree_contracts, ContractTrieReader);
insert_trie!(insert_storage_trie, tree_global, StorageTrieReader);

/// Creates the sql for inserting a node or incrementing its reference count if it already exists, returning
/// the final reference count.
macro_rules! insert_trie {
    ($fn_name: ident, $table: ident, $reader_struct: ident) => {
        /// Stores the node data for this trie in the `$table` table and returns the number of
        /// new nodes that were added i.e. the nodes not already present in the database.
        ///
        /// Inserts nodes starting from the root.
        ///
        /// **NOTE**: since [TrieNode] does not identify leaf nodes explicitly, this function assumes that
        /// any node definition not present in the hash map is in fact a leaf node. This means we recurse through
        /// child nodes until the child node already exists in the database, or the child definition is not present
        /// in the hash map (indicating it is a leaf node, and should not be inserted).
        pub(super) fn $fn_name(
            tx: &rusqlite::Transaction<'_>,
            root: Felt,
            nodes: &HashMap<Felt, TrieNode>,
        ) -> anyhow::Result<usize> {
            let mut to_insert = Vec::new();
            to_insert.push(root);

            let mut stmt = tx
                .prepare_cached(concat!(
                    "INSERT OR IGNORE INTO ",
                    stringify!($table),
                    "(hash, data) VALUES(?, ?) ",
                ))
                .context("Creating insert statement")?;

            let mut count = 0;

            // cargo fmt misbehaves on the let some else expression.
            #[cfg_attr(rustfmt, rustfmt_skip)]
            while let Some(hash) = to_insert.pop() {
                let Some(node) = nodes.get(&hash) else {
                    continue;
                };
                let inserted = stmt
                    .execute(params![&hash.as_be_bytes().as_slice(), node])
                    .context("Inserting node")?;

                if inserted == 1 {
                    count += 1;

                    match node {
                        TrieNode::Binary { left, right } => {
                            to_insert.push(*left);
                            to_insert.push(*right);
                        }
                        TrieNode::Edge { child, .. } => to_insert.push(*child),
                    }
                }
            }

            Ok(count)
        }

        pub struct $reader_struct<'tx>(&'tx Transaction<'tx>);

        impl<'tx> $reader_struct<'tx> {
            pub(super) fn new(tx: &'tx Transaction<'tx>) -> Self {
                Self(tx)
            }

            pub fn get(&self, node: &stark_hash::Felt) -> anyhow::Result<Option<TrieNode>> {
                // We rely on sqlite caching the statement here. Storing the statement would be nice,
                // however that leads to &mut requirements or interior mutable work-arounds.
                let mut stmt = self
                    .0
                    .inner()
                    .prepare_cached(concat!(
                        "SELECT data FROM ",
                        stringify!($table),
                        " WHERE hash = ?",
                    ))
                    .context("Creating get statement")?;

                let node: Option<TrieNode> = stmt
                    .query_row(params![&node.as_be_bytes().as_slice()], |row| {
                        row.get_trie_node(0)
                    })
                    .optional()?;

                Ok(node)
            }
        }
    };
}
use insert_trie;

#[cfg(test)]
mod tests {
    use bitvec::prelude::Msb0;
    use pathfinder_common::felt_bytes;

    use super::*;

    #[test]
    fn trie() {
        // Since graph testing and traversal is quite annoying, we use a
        // single large test which checks several things at once.
        //
        // The graph created is unrealistic, but does include two key things:
        //  1. edge, binary and leaf node variants
        //  2. a node can appear multiple times in the same graph (duplicate)
        //
        //                       root
        //                    /       \
        //          left child         right child
        //                |               |
        //                \              edge
        //                 \           /
        //                   duplicate
        //                  /         \
        //            leaf 1           leaf 2

        insert_trie!(insert_test, tree_test, TestTrieReader);

        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let tx = db.transaction().unwrap();
        tx.execute(
            "CREATE TABLE tree_test(hash BLOB PRIMARY KEY, data BLOB, ref_count INTEGER)",
            [],
        )
        .unwrap();

        let root = felt_bytes!(b"root node");
        let l_child = felt_bytes!(b"left child");
        let r_child = felt_bytes!(b"right child");
        let edge = felt_bytes!(b"edge node");
        let duplicate = felt_bytes!(b"duplicate");
        // These must not get inserted.
        let leaf_1 = felt_bytes!(b"leaf 1");
        let leaf_2 = felt_bytes!(b"leaf 2");

        let root_node = TrieNode::Binary {
            left: l_child,
            right: r_child,
        };
        let l_node = TrieNode::Edge {
            child: duplicate,
            path: bitvec::bitvec![Msb0, u8; 1, 0, 1, 1, 1],
        };
        let r_node = TrieNode::Edge {
            child: edge,
            path: bitvec::bitvec![Msb0, u8; 1, 0, 1, 1],
        };
        let edge_node = TrieNode::Edge {
            child: duplicate,
            path: bitvec::bitvec![Msb0, u8; 1, 0, 1, 1, 1, 1, 1],
        };
        let duplicate_node = TrieNode::Binary {
            left: leaf_1,
            right: leaf_2,
        };

        let mut nodes = HashMap::new();
        nodes.insert(root, root_node.clone());
        nodes.insert(l_child, l_node.clone());
        nodes.insert(r_child, r_node.clone());
        nodes.insert(edge, edge_node.clone());
        nodes.insert(duplicate, duplicate_node.clone());

        let count = insert_test(&tx, root, &nodes).unwrap();
        let db_count: usize = tx
            .query_row("SELECT COUNT(1) FROM tree_test", [], |row| row.get(0))
            .unwrap();

        // We expect inserts for the root, left and right children, edge and duplicate node.
        assert_eq!(count, 5);
        assert_eq!(count, db_count);

        // Inserting the same trie again should do nothing
        let count = insert_test(&tx, root, &nodes).unwrap();
        assert_eq!(count, 0);

        let tx = Transaction::from_inner(tx);

        let reader = TestTrieReader::new(&tx);

        let root = reader.get(&root).unwrap().unwrap();
        assert_eq!(root, root_node);
        let l_child = reader.get(&l_child).unwrap().unwrap();
        assert_eq!(l_child, l_node);
        let r_child = reader.get(&r_child).unwrap().unwrap();
        assert_eq!(r_child, r_node);
        let edge = reader.get(&edge).unwrap().unwrap();
        assert_eq!(edge, edge_node);
        let duplicate = reader.get(&duplicate).unwrap().unwrap();
        assert_eq!(duplicate, duplicate_node);

        let leaf_1 = reader.get(&leaf_1).unwrap();
        assert!(leaf_1.is_none());
        let leaf_2 = reader.get(&leaf_2).unwrap();
        assert!(leaf_2.is_none());
    }
}
