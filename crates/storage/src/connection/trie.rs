use std::collections::HashMap;

use anyhow::Context;
use pathfinder_common::trie::TrieNode;
use stark_hash::Felt;

use crate::prelude::*;

generate_trie_methods!(
    insert_class_trie,
    delete_class_trie,
    tree_class,
    ClassTrieReader,
    251
);
generate_trie_methods!(
    insert_contract_trie,
    delete_contract_trie,
    tree_contracts,
    ContractTrieReader,
    251
);
generate_trie_methods!(
    insert_storage_trie,
    delete_storage_trie,
    tree_global,
    StorageTrieReader,
    251
);

/// Generates methods for inserting and deleting a tree from storage, as well as reading node data.
macro_rules! generate_trie_methods {
    ($insert_fn: ident, $delete_fn: ident, $table: ident, $reader_struct: ident, $height: literal) => {
        /// Stores the node data for this trie in the `$table` table and returns the number of
        /// new nodes that were added i.e. the nodes not already present in the database.
        ///
        /// Uses reference counting to track the number of references to a specific node. This allows us
        /// to delete trees.
        pub(super) fn $insert_fn(
            tx: &rusqlite::Transaction<'_>,
            root: Felt,
            nodes: &HashMap<Felt, TrieNode>,
        ) -> anyhow::Result<usize> {
            // Insert a node with reference count of one, or increment the count if node already exists.
            // Returns the new reference count so we can identify if this was a new insert or an update.
            let mut insert_or_update = tx
                .prepare_cached(concat!(
                    "INSERT INTO ",
                    stringify!($table),
                    "(hash, data, ref_count) VALUES(?, ?, 1) ",
                    "ON CONFLICT DO UPDATE SET ref_count=ref_count+1 ",
                    "RETURNING ref_count",
                ))
                .context("Creating insert or update statement")?;

            // Increment's a node's reference count.
            let mut increment_count = tx
                .prepare_cached(concat!(
                    "UPDATE OR ABORT ",
                    stringify!($table),
                    " SET ref_count=ref_count+1",
                    " WHERE hash = ?",
                ))
                .context("Creating increment reference count statement")?;

            // Track the number of new nodes inserted.
            let mut count = 0;

            // Tracks which nodes we need to process instead of using a recursive approach.
            let mut to_process = Vec::new();
            to_process.push((0, root));

            while let Some((height, hash)) = to_process.pop() {
                match nodes.get(&hash) {
                    Some(node) => {
                        // If the node exists in the hashmap then it is possible it is new. This is not a
                        // guarantee though, as it is possible the tree mutations resulted in a node not present
                        // in the current mutated tree but is in the database from another tree, or even elsewhere
                        // within the same tree but from a path that was not opened during mutation.
                        //
                        // This means we need to insert if not present, or else increment its reference count.
                        let ref_count: u32 = insert_or_update
                            .query_row(params![&hash.as_be_bytes().as_slice(), node], |row| {
                                row.get(0)
                            })
                            .context("Inserting node")?;

                        // Only process its children if it was a new node, which it is if its reference count is one.
                        if ref_count == 1 {
                            count += 1;

                            match node {
                                TrieNode::Binary { left, right } => {
                                    let child_height = height + 1;
                                    // Don't process leaves as these are not stored at all.
                                    if child_height < $height {
                                        to_process.push((child_height, *left));
                                        to_process.push((child_height, *right));
                                    }
                                }
                                TrieNode::Edge { child, path } => {
                                    let child_height = height + path.len();
                                    // Don't process leaves as these are not stored at all.
                                    if child_height < $height {
                                        to_process.push((child_height, *child));
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        // If the node was not in the hashmap then we are guaranteed that the node is already
                        // in the database. All nodes must be in the database or hashmap.
                        //
                        // Since we know the node already exists we can simply increment its reference count.
                        increment_count
                            .execute(params![&hash.as_be_bytes().as_slice()])
                            .context("Incrementing reference count")?;
                    }
                }
            }

            Ok(count)
        }

        /// Deletes a tree from storage using reference counting.
        pub(super) fn $delete_fn(
            tx: &rusqlite::Transaction<'_>,
            root: Felt,
        ) -> anyhow::Result<Vec<Felt>> {
            // Decrement the node's reference count. Returns the node's
            // rowid so that subsequent lookups don't require searching by hash.
            let mut decrement_count = tx
                .prepare_cached(concat!(
                    "UPDATE ",
                    stringify!($table),
                    " SET ref_count=ref_count-1 ",
                    "WHERE hash = ? ",
                    "RETURNING ref_count, rowid"
                ))
                .context("Creating decrement reference count statement")?;

            let mut delete_node = tx
                .prepare_cached(concat!(
                    "DELETE FROM ",
                    stringify!($table),
                    " WHERE rowid = ? ",
                    "RETURNING data"
                ))
                .context("Creating delete statement")?;

            let mut dead_leaves = Vec::new();

            // Tracks which nodes we need to process instead of using a recursive approach.
            let mut to_process = Vec::new();
            to_process.push((0, root));

            while let Some((height, hash)) = to_process.pop() {
                // Decrement this node's reference count.
                let (count, rowid): (u32, u32) = decrement_count
                    .query_row(params![&hash.as_be_bytes().as_slice()], |row| {
                        let count = row.get(0)?;
                        let rowid = row.get(1)?;

                        Ok((count, rowid))
                    })
                    .context("Decrementing reference count")?;

                // Delete this node and process its children if reference count has reached zero.
                if count == 0 {
                    let node = delete_node
                        .query_row(params![&rowid], |row| row.get_trie_node(0))
                        .context("Deleting node")?;

                    match node {
                        TrieNode::Binary { left, right } => {
                            // Only process children if they are not leaves.
                            let child_height = height + 1;
                            if child_height < $height {
                                to_process.push((child_height, left));
                                to_process.push((child_height, right));
                            } else {
                                dead_leaves.push(left);
                                dead_leaves.push(right);
                            }
                        }
                        TrieNode::Edge { child, path } => {
                            // Only process children if they are not leaves.
                            let child_height = height + path.len();
                            if child_height < $height {
                                to_process.push((child_height, child));
                            } else {
                                dead_leaves.push(child);
                            }
                        }
                    }
                }
            }

            Ok(dead_leaves)
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

            #[cfg(test)]
            #[allow(dead_code)]
            /// Returns the entire trie's nodes.
            fn get_all(&self, root: stark_hash::Felt) -> anyhow::Result<HashMap<Felt, TrieNode>> {
                let mut nodes = HashMap::new();
                let mut to_get = vec![(0, root)];
                while let Some((height, hash)) = to_get.pop() {
                    let node = self.get(&hash)?.context("Node missing")?;

                    match &node {
                        TrieNode::Binary { left, right } => {
                            let child_height = height + 1;
                            if child_height < $height {
                                to_get.push((child_height, *left));
                                to_get.push((child_height, *right));
                            }
                        }
                        TrieNode::Edge { child, path } => {
                            let child_height = height + path.len();
                            if child_height < $height {
                                to_get.push((child_height, *child));
                            }
                        }
                    }

                    nodes.insert(hash, node);
                }

                Ok(nodes)
            }
        }
    };
}
use generate_trie_methods;

#[cfg(test)]
mod tests {
    use bitvec::prelude::Msb0;
    use pathfinder_common::felt_bytes;

    use super::*;

    #[rstest::fixture]
    /// Generates a simple set of tree nodes with a height of 10.
    ///
    /// The graph created is unrealistic, but does include two key things:
    ///  1. edge, binary and leaf node variants
    ///  2. a node can appear multiple times in the same graph (duplicate)
    ///
    ///                       root
    ///                    /       \
    ///          left child         right child
    ///                |               |
    ///                \              edge
    ///                 \           /
    ///                   duplicate
    ///                  /         \
    ///            leaf 1           leaf 2
    fn simple_tree() -> (Felt, HashMap<Felt, TrieNode>) {
        let root_hash = felt_bytes!(b"root node");
        let l_child = felt_bytes!(b"left child");
        let r_child = felt_bytes!(b"right child");
        let edge = felt_bytes!(b"edge node");
        let duplicate = felt_bytes!(b"duplicate");
        // These should not get inserted.
        let leaf_1_hash = felt_bytes!(b"leaf 1");
        let leaf_2_hash = felt_bytes!(b"leaf 2");

        let root_node = TrieNode::Binary {
            left: l_child,
            right: r_child,
        };
        let l_node = TrieNode::Edge {
            child: duplicate,
            path: bitvec::bitvec![u8, Msb0; 1, 0, 1, 1, 1, 0, 0, 1],
        };
        let r_node = TrieNode::Edge {
            child: edge,
            path: bitvec::bitvec![u8, Msb0; 1, 0, 1, 1],
        };
        let edge_node = TrieNode::Edge {
            child: duplicate,
            path: bitvec::bitvec![u8, Msb0; 1, 1, 1, 1],
        };
        let duplicate_node = TrieNode::Binary {
            left: leaf_1_hash,
            right: leaf_2_hash,
        };

        let mut nodes = HashMap::new();
        nodes.insert(root_hash, root_node);
        nodes.insert(l_child, l_node);
        nodes.insert(r_child, r_node);
        nodes.insert(edge, edge_node);
        nodes.insert(duplicate, duplicate_node);

        (root_hash, nodes)
    }

    #[rstest::fixture]
    /// Returns another tree which partially overlaps with `simple_tree`.
    ///
    ///                      simple                     second root
    ///                    /       \                    /         \
    ///          left child         right child        /          |
    ///                |               |              /          |
    ///                \              edge -----------        edge 2
    ///                 \           /                          /
    ///                   duplicate                           /
    ///                  /         \                         /
    ///            leaf 1           leaf 2                leaf 3     
    fn second_tree() -> (Felt, HashMap<Felt, TrieNode>) {
        let root_hash = felt_bytes!(b"second root");
        let edge = felt_bytes!(b"edge node");
        let edge2 = felt_bytes!(b"another edge");
        let leaf_3_hash = felt_bytes!(b"leaf 3");

        let root_node = TrieNode::Binary {
            left: edge,
            right: edge2,
        };
        let edge2_node = TrieNode::Edge {
            child: leaf_3_hash,
            path: bitvec::bitvec![u8, Msb0; 1, 0, 0, 1, 0, 1, 0, 1, 0],
        };

        let mut nodes = HashMap::new();
        nodes.insert(root_hash, root_node);
        nodes.insert(edge2, edge2_node);

        (root_hash, nodes)
    }

    #[rstest::rstest]
    fn all_nodes_are_inserted(simple_tree: (Felt, HashMap<Felt, TrieNode>)) {
        generate_trie_methods!(insert_test, _delete_test, tree_test, TestTrieReader, 10);

        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let tx = db.transaction().unwrap();
        tx.execute(
            "CREATE TABLE tree_test(hash BLOB PRIMARY KEY, data BLOB, ref_count INTEGER)",
            [],
        )
        .unwrap();

        let (root, nodes) = simple_tree;
        let count = insert_test(&tx, root, &nodes).unwrap();

        let tx = Transaction::from_inner(tx);
        let reader = TestTrieReader::new(&tx);
        let db_nodes = reader.get_all(root).unwrap();

        assert_eq!(nodes, db_nodes);
        assert_eq!(count, nodes.len());
    }

    #[rstest::rstest]
    fn inserting_twice_adds_no_new_nodes(simple_tree: (Felt, HashMap<Felt, TrieNode>)) {
        generate_trie_methods!(insert_test, _delete_test, tree_test, TestTrieReader, 10);

        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let tx = db.transaction().unwrap();
        tx.execute(
            "CREATE TABLE tree_test(hash BLOB PRIMARY KEY, data BLOB, ref_count INTEGER)",
            [],
        )
        .unwrap();

        let (root, nodes) = simple_tree;
        let count = insert_test(&tx, root, &nodes).unwrap();
        let count2 = insert_test(&tx, root, &nodes).unwrap();

        let tx = Transaction::from_inner(tx);
        let reader = TestTrieReader::new(&tx);
        let db_nodes = reader.get_all(root).unwrap();

        assert_eq!(nodes, db_nodes);
        assert_eq!(count, nodes.len());
        assert_eq!(count2, 0);
    }

    #[rstest::rstest]
    fn get(simple_tree: (Felt, HashMap<Felt, TrieNode>)) {
        generate_trie_methods!(insert_test, _delete_test, tree_test, TestTrieReader, 10);

        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let tx = db.transaction().unwrap();
        tx.execute(
            "CREATE TABLE tree_test(hash BLOB PRIMARY KEY, data BLOB, ref_count INTEGER)",
            [],
        )
        .unwrap();

        let (root, nodes) = simple_tree;
        insert_test(&tx, root, &nodes).unwrap();

        let tx = Transaction::from_inner(tx);
        let reader = TestTrieReader::new(&tx);
        for (hash, node) in &nodes {
            let result = reader.get(hash).unwrap().unwrap();

            assert_eq!(&result, node);
        }
    }

    #[rstest::rstest]
    fn delete(
        simple_tree: (Felt, HashMap<Felt, TrieNode>),
        second_tree: (Felt, HashMap<Felt, TrieNode>),
    ) {
        generate_trie_methods!(insert_test, delete_test, tree_test, TestTrieReader, 10);

        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let tx = db.transaction().unwrap();
        tx.execute(
            "CREATE TABLE tree_test(hash BLOB PRIMARY KEY, data BLOB, ref_count INTEGER)",
            [],
        )
        .unwrap();

        let (root, nodes) = simple_tree;
        insert_test(&tx, root, &nodes).unwrap();
        insert_test(&tx, root, &nodes).unwrap();

        let (root2, nodes2) = second_tree;
        insert_test(&tx, root2, &nodes2).unwrap();

        // We should now have all nodes that are the union of simple and second tree.
        let tx = Transaction::from_inner(tx);
        let db_count: usize = tx
            .inner()
            .query_row("SELECT COUNT(1) FROM tree_test", [], |row| row.get(0))
            .unwrap();

        let mut tree_union = nodes.clone();
        tree_union.extend(nodes2.clone().into_iter());
        assert_eq!(tree_union.len(), db_count);

        // Deleting second tree should leave only simple tree nodes behind.
        let reader = TestTrieReader::new(&tx);
        let dangling_leaves = delete_test(tx.inner(), root2).unwrap();
        assert_eq!(dangling_leaves.len(), 1);
        let db_nodes = reader.get_all(root).unwrap();
        assert_eq!(nodes, db_nodes);

        // First simple delete should do nothing except decrement reference count because
        // we inserted simple twice.
        let dangling_leaves = delete_test(tx.inner(), root).unwrap();
        assert!(dangling_leaves.is_empty());

        let db_nodes = reader.get_all(root).unwrap();
        assert_eq!(nodes, db_nodes);

        // Second delete should delete everything.
        let dangling_leaves = delete_test(&tx.inner(), root).unwrap();
        assert_eq!(dangling_leaves.len(), 2);

        let db_root = reader.get(&root).unwrap();
        assert_eq!(db_root, None);

        // Count manually to ensure the table is truely empty.
        let db_count: usize = tx
            .inner()
            .query_row("SELECT COUNT(1) FROM tree_test", [], |row| row.get(0))
            .unwrap();

        assert_eq!(db_count, 0);
    }
}
