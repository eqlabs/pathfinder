//! Starknet utilises a custom Binary Merkle-Patrica Tree to store and organise its state.
//!
//! From an external perspective the tree is similar to a key-value store, where both key
//! and value are [StarkHashes](StarkHash). The difference is that each tree is immutable,
//! and any mutations result in a new tree with a new root. This mutated variant can then
//! be accessed via the new root, and the old variant via the old root.
//!
//! Trees share common nodes to be efficient. These nodes perform reference counting and
//! will get deleted once all references are gone. State can therefore be tracked over time
//! by mutating the current state, and storing the new root. Old states can be dropped by
//! deleting old roots which are no longer required.
//!
//! #### Tree definition
//!
//! It is important to understand that since all keys are [StarkHashes](StarkHash), this means
//! all paths to a key are equally long - 251 bits.
//!
//! Starknet defines three node types for a tree.
//!
//! [Leaf nodes](Node::Leaf) which represent an actual value stored.
//!
//! [Edge nodes](Node::Edge) which connect two nodes, and __must be__ a maximal subtree (i.e. be as
//! long as possible). This latter condition is important as it strictly defines a tree (i.e. all
//! trees with the same leaves must have the same nodes). The path of an edge node can therefore
//! be many bits long.
//!
//! [Binary nodes](Node::Binary) is a branch node with two children, left and right. This represents
//! only a single bit on the path to a leaf.
//!
//! A tree storing a single key-value would consist of two nodes. The root node would be an edge node
//! with a path equal to the key. This edge node is connected to a leaf node storing the value.
//!
//! #### Implementation details
//!
//! We've defined an additional node type, an [Unresolved node](Node::Unresolved). This is used to
//! represent a node who's hash is known, but has not yet been retrieved from storage (and we therefore
//! have no further details about it).
//!
//! Our implementation is a mix of nodes from persistent storage and any mutations are kept in-memory. It is
//! done this way to allow many mutations to a tree before committing only the final result to storage. This
//! may be confusing since we just said trees are immutable -- but since we are only changing the in-memory
//! tree, the immutable tree still exists in storage. One can therefore think of the in-memory tree as containing
//! the state changes between tree `N` and `N + 1`.
//!
//! The in-memory tree is built using a graph of [Rc<RefCell<Node>>] which is a bit painful.

mod node;
mod storage;

use anyhow::Context;
use bitvec::prelude::BitVec;
use rusqlite::Transaction;
use std::{cell::RefCell, rc::Rc};

use crate::merkle_tree::{
    node::{BinaryNode, Direction, EdgeNode, Node},
    storage::{PersistedBinaryNode, PersistedEdgeNode, PersistedNode, RcNodeStorage},
};

use pedersen::StarkHash;

pub const ZERO_HASH: StarkHash = StarkHash::zero();

/// A Starknet binary Merkle-Patricia tree with a specific root entry-point and storage.
///
/// This is used to update, mutate and access global Starknet state as well as individual contract states.
///
/// For more information on how this functions internally, see [here](super::merkle_tree).
#[derive(Debug, Clone)]
pub struct MerkleTree<'a> {
    storage: RcNodeStorage<'a>,
    root: Rc<RefCell<Node>>,
}

impl<'a> MerkleTree<'a> {
    /// Removes one instance of the tree and its root from persistent storage.
    ///
    /// This implies decrementing the root's reference count. The root will
    /// only get deleted if the reference count reaches zero. This will in turn
    /// delete all internal nodes and leaves which no longer have a root to connect to.
    ///
    /// This allows for multiple instances of the same tree state to be committed,
    /// without deleting all of them in a single call.
    pub fn delete(self) -> anyhow::Result<()> {
        match self.root.borrow().hash() {
            Some(hash) if hash != ZERO_HASH => self
                .storage
                .decrement_ref_count(hash)
                .context("Failed to delete tree root"),
            _ => Ok(()),
        }
    }

    /// Loads an existing tree or creates a new one if it does not yet exist.
    ///
    /// Use the [ZERO_HASH] as root if the tree does not yet exist, will otherwise
    /// error if the given hash does not exist.
    ///
    /// The transaction is used for all storage interactions. The transaction
    /// should therefore be committed after all tree mutations are completed.
    ///
    /// Uses an [RcNodeStorage] as backing storage.
    ///
    /// ### Warning
    ///
    /// None of the [RcNodeStorage] functions rollback on failure. This means that if any error
    /// is encountered, the transaction should be rolled back to prevent database corruption.
    pub fn load(
        table: String,
        transaction: &'a Transaction,
        root: StarkHash,
    ) -> anyhow::Result<Self> {
        let storage = RcNodeStorage::open(table, transaction)?;

        // Create a tree with root node unresolved, so we can use the resolve function.
        // Bit clumsy, but oh well.
        let root_node = Rc::new(RefCell::new(Node::Unresolved(root)));
        let mut tree = Self {
            storage,
            root: root_node,
        };

        if root != ZERO_HASH {
            // Resolve non-zero root node to check that it does exist.
            let root_node = tree
                .resolve(root, 0)
                .context("Failed to resolve root node")?;
            tree.root = Rc::new(RefCell::new(root_node));
        }

        Ok(tree)
    }

    /// Persists all changes to storage and returns the new root hash.
    ///
    /// Note that the root is reference counted in storage. Committing the
    /// same tree again will therefore increment the count again.
    pub fn commit(self) -> anyhow::Result<StarkHash> {
        // Go through tree, collect dirty nodes, calculate their hashes and
        // persist them. Take care to increment ref counts of child nodes. So in order
        // to do this correctly, will have to start back-to-front.
        self.commit_subtree(&mut *self.root.borrow_mut())?;
        // unwrap is safe as `commit_subtree` will set the hash.
        let root = self.root.borrow().hash().unwrap();
        self.storage.increment_ref_count(root)?;
        Ok(root)
    }

    /// Persists any changes in this subtree to storage.
    ///
    /// This necessitates recursively calculating the hash of, and
    /// in turn persisting, any changed child nodes. This is necessary
    /// as the parent node's hash relies on its childrens hashes.
    ///
    /// In effect, the entire subtree gets persisted.
    fn commit_subtree(&self, node: &mut Node) -> anyhow::Result<()> {
        use Node::*;
        match node {
            // Unresolved nodes are already persisted.
            Unresolved(_) => {}
            Leaf(hash) => {
                self.storage
                    .upsert(*hash, PersistedNode::Leaf)
                    .context("Failed to insert leaf node")?;
            }
            Binary(binary) if binary.hash.is_some() => {}
            Edge(edge) if edge.hash.is_some() => {}
            Binary(binary) => {
                self.commit_subtree(&mut *binary.left.borrow_mut())?;
                self.commit_subtree(&mut *binary.right.borrow_mut())?;
                // This will succeed as `commit_subtree` will set the child hashes.
                binary.calculate_hash();
                // unwrap is safe as `commit_subtree` will set the hashes.
                let left = binary.left.borrow().hash().unwrap();
                let right = binary.right.borrow().hash().unwrap();
                let persisted_node = PersistedNode::Binary(PersistedBinaryNode { left, right });
                // unwrap is safe as we just set the hash.
                self.storage
                    .upsert(binary.hash.unwrap(), persisted_node)
                    .context("Failed to insert binary node")?;
            }
            Edge(edge) => {
                self.commit_subtree(&mut *edge.child.borrow_mut())?;
                // This will succeed as `commit_subtree` will set the child's hash.
                edge.calculate_hash();

                // unwrap is safe as `commit_subtree` will set the hash.
                let child = edge.child.borrow().hash().unwrap();
                let persisted_node = PersistedNode::Edge(PersistedEdgeNode {
                    path: edge.path.clone(),
                    child,
                });
                // unwrap is safe as we just set the hash.
                self.storage
                    .upsert(edge.hash.unwrap(), persisted_node)
                    .context("Failed to insert edge node")?;
            }
        }

        Ok(())
    }

    /// Sets the value of a key. To delete a key, set the value to [ZERO_HASH].
    pub fn set(&mut self, key: StarkHash, value: StarkHash) -> anyhow::Result<()> {
        if value == ZERO_HASH {
            return self.delete_leaf(key);
        }

        // Changing or inserting a new leaf into the tree will change the hashes
        // of all nodes along the path to the leaf.
        let path = self.traverse(key)?;
        for node in &path {
            node.borrow_mut().mark_dirty();
        }

        // There are three possibilities.
        //
        // 1. The leaf exists, in which case we simply change its value.
        //
        // 2. The tree is empty, we insert the new leaf and the root becomes an edge node connecting to it.
        //
        // 3. The leaf does not exist, and the tree is not empty. The final node in the traversal will
        //    be an edge node who's path diverges from our new leaf node's.
        //
        //    This edge must be split into a new subtree containing both the existing edge's child and the
        //    new leaf. This requires an edge followed by a binary node and then further edges to both the
        //    current child and the new leaf. Any of these new edges may also end with an empty path in
        //    which case they should be elided. It depends on the common path length of the current edge
        //    and the new leaf i.e. the split may be at the first bit (in which case there is no leading
        //    edge), or the split may be in the middle (requires both leading and post edges), or the
        //    split may be the final bit (no post edge).
        use Node::*;
        match path.last() {
            Some(node) => {
                let updated = match &*node.borrow() {
                    Edge(edge) => {
                        let common = edge.common_path(key);

                        // Height of the binary node
                        let branch_height = edge.height + common.len();
                        // Height of the binary node's children
                        let child_height = branch_height + 1;

                        // Path from binary node to new leaf
                        let new_path = key.view_bits()[child_height..].to_bitvec();
                        // Path from binary node to existing child
                        let old_path = edge.path[common.len() + 1..].to_bitvec();

                        // The new leaf branch of the binary node.
                        // (this may be edge -> leaf, or just leaf depending).
                        let new_leaf = Node::Leaf(value);
                        let new = match new_path.is_empty() {
                            true => Rc::new(RefCell::new(new_leaf)),
                            false => {
                                let new_edge = Node::Edge(EdgeNode {
                                    hash: None,
                                    height: child_height,
                                    path: new_path,
                                    child: Rc::new(RefCell::new(new_leaf)),
                                });
                                Rc::new(RefCell::new(new_edge))
                            }
                        };

                        // The existing child branch of the binary node.
                        let old = match old_path.is_empty() {
                            true => edge.child.clone(),
                            false => {
                                let old_edge = Node::Edge(EdgeNode {
                                    hash: None,
                                    height: child_height,
                                    path: old_path,
                                    child: edge.child.clone(),
                                });
                                Rc::new(RefCell::new(old_edge))
                            }
                        };

                        let new_direction = Direction::from(key.view_bits()[branch_height]);
                        let (left, right) = match new_direction {
                            Direction::Left => (new, old),
                            Direction::Right => (old, new),
                        };

                        let branch = Node::Binary(BinaryNode {
                            hash: None,
                            height: branch_height,
                            left,
                            right,
                        });

                        // We may require an edge leading to the binary node.
                        match common.is_empty() {
                            true => branch,
                            false => Node::Edge(EdgeNode {
                                hash: None,
                                height: edge.height,
                                path: common.to_bitvec(),
                                child: Rc::new(RefCell::new(branch)),
                            }),
                        }
                    }
                    // Leaf exists, we replace its value.
                    Leaf(_) => Node::Leaf(value),
                    Unresolved(_) | Binary(_) => {
                        unreachable!("The end of a traversion cannot be unresolved or binary")
                    }
                };

                node.swap(&RefCell::new(updated));
            }
            None => {
                // Getting no travel nodes implies that the tree is empty.
                //
                // Create a new leaf node with the value, and the root becomes
                // an edge node connecting to the leaf.
                let leaf = Node::Leaf(value);
                let edge = Node::Edge(EdgeNode {
                    hash: None,
                    height: 0,
                    path: key.view_bits().to_bitvec(),
                    child: Rc::new(RefCell::new(leaf)),
                });

                self.root = Rc::new(RefCell::new(edge));
            }
        }

        Ok(())
    }

    /// Deletes a leaf node from the tree.
    ///
    /// This is not an external facing API; the functionality is instead
    /// accessed by calling [Mpt::set] with value set to [ZERO_HASH].
    fn delete_leaf(&mut self, key: StarkHash) -> anyhow::Result<()> {
        // Algorithm explanation:
        //
        // The leaf's parent node is either an edge, or a binary node.
        // If it's an edge node, then it must also be deleted. And its parent
        // must be a binary node. In either case we end up with a binary node
        // who's one child is deleted. This changes the binary to an edge node.
        //
        // Note that its possible that there is no binary node -- if the resulting tree would be empty.
        //
        // This new edge node may need to merge with the old binary node's parent node
        // and other remaining child node -- if they're also edges.
        //
        // Then we are done.
        let path = self.traverse(key)?;

        // Do nothing if the leaf does not exist.
        match path.last() {
            Some(node) => match &*node.borrow() {
                Node::Leaf(_) => {}
                _ => return Ok(()),
            },
            None => return Ok(()),
        }

        // All hashes along the path will become invalid (if they aren't deleted).
        for node in &path {
            node.borrow_mut().mark_dirty();
        }

        // Go backwards until we hit a branch node.
        let mut node_iter = path
            .into_iter()
            .rev()
            .skip_while(|node| !node.borrow().is_binary());

        match node_iter.next() {
            Some(node) => {
                let new_edge = {
                    // This node must be a binary node due to the iteration condition.
                    let binary = node.borrow().as_binary().cloned().unwrap();
                    // Create an edge node to replace the old binary node
                    // i.e. with the remaining child (note the direction invert),
                    //      and a path of just a single bit.
                    let direction = binary.direction(key).invert();
                    let child = binary.get_child(direction);
                    let path = std::iter::once(bool::from(direction)).collect::<BitVec<_, _>>();
                    let mut edge = EdgeNode {
                        hash: None,
                        height: binary.height,
                        path,
                        child,
                    };

                    // Merge the remaining child if it's an edge.
                    edge.merge_child_edge();

                    edge
                };
                // Replace the old binary node with the new edge node.
                node.swap(&RefCell::new(Node::Edge(new_edge)));
            }
            None => {
                // We reached the root without a hitting binary node. The new tree
                // must therefore be empty.
                self.root = Rc::new(RefCell::new(Node::Unresolved(ZERO_HASH)));
                return Ok(());
            }
        };

        // Check the parent of the new edge. If it is also an edge, then they must merge.
        if let Some(node) = node_iter.next() {
            if let Node::Edge(edge) = &mut *node.borrow_mut() {
                edge.merge_child_edge();
            }
        }

        Ok(())
    }

    /// Returns the value stored at key, or [ZERO_HASH] if it does not exist.
    pub fn get(&self, key: StarkHash) -> anyhow::Result<StarkHash> {
        let val = match self.traverse(key)?.last() {
            Some(node) => match &*node.borrow() {
                Node::Leaf(value) => *value,
                _ => StarkHash::zero(),
            },
            None => StarkHash::zero(),
        };
        Ok(val)
    }

    /// Traverses from the current root towards the destination [Leaf](Node::Leaf) node.
    /// Returns the list of nodes along the path.
    ///
    /// If the destination node exists, it will be the final node in the list.
    ///
    /// This means that the final node will always be either a the destination [Leaf](Node::Leaf) node,
    /// or an [Edge](Node::Edge) node who's path suffix does not match the leaf's path.
    ///
    /// The final node can __not__ be a [Binary](Node::Binary) node since it would always be possible to continue
    /// on towards the destination. Nor can it be an [Unresolved](Node::Unresolved) node since this would be
    /// resolved to check if we can travel further.
    fn traverse(&self, dst: StarkHash) -> anyhow::Result<Vec<Rc<RefCell<Node>>>> {
        if self.root.borrow().is_empty() {
            return Ok(Vec::new());
        }

        let mut current = self.root.clone();
        let mut height = 0;
        let mut nodes = Vec::new();
        loop {
            use Node::*;

            let current_tmp = current.borrow().clone();

            let next = match current_tmp {
                Unresolved(hash) => {
                    let node = self.resolve(hash, height)?;
                    current.swap(&RefCell::new(node));
                    current
                }
                Binary(binary) => {
                    nodes.push(current.clone());
                    let next = binary.direction(dst);
                    let next = binary.get_child(next);
                    height += 1;
                    next
                }
                Edge(edge) if edge.path_matches(dst) => {
                    nodes.push(current.clone());
                    height += edge.path.len();
                    edge.child.clone()
                }
                Leaf(_) | Edge(_) => {
                    nodes.push(current);
                    return Ok(nodes);
                }
            };

            current = next;
        }
    }

    /// Retrieves the requested node from storage.
    ///
    /// Result will be either a [Binary](Node::Binary), [Edge](Node::Edge) or [Leaf](Node::Leaf) node.
    fn resolve(&self, hash: StarkHash, height: usize) -> anyhow::Result<Node> {
        let node = self.storage.get(hash)?.context("Node does not exists")?;

        let node = match node {
            PersistedNode::Binary(binary) => Node::Binary(BinaryNode {
                hash: Some(hash),
                height,
                left: Rc::new(RefCell::new(Node::Unresolved(binary.left))),
                right: Rc::new(RefCell::new(Node::Unresolved(binary.right))),
            }),
            PersistedNode::Edge(edge) => Node::Edge(EdgeNode {
                hash: Some(hash),
                height,
                path: edge.path,
                child: Rc::new(RefCell::new(Node::Unresolved(edge.child))),
            }),
            PersistedNode::Leaf => Node::Leaf(hash),
        };

        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::prelude::*;

    fn starkhash_from_bits(bits: &BitSlice<Msb0, u8>) -> StarkHash {
        assert!(bits.len() <= 251);

        let mut b2 = bitvec![Msb0, u8; 0; 256 - bits.len()];
        b2.extend_from_bitslice(bits);
        let bytes = b2.into_vec().try_into().unwrap();

        StarkHash::from_be_bytes(bytes).unwrap()
    }

    #[test]
    fn get_empty() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();
        let uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

        let key = StarkHash::from_hex_str("99cadc82").unwrap();
        assert_eq!(uut.get(key).unwrap(), ZERO_HASH);
    }

    #[test]
    fn load_bad_root() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        let non_root = StarkHash::from_hex_str("99cadc82").unwrap();
        MerkleTree::load("test".to_string(), &transaction, non_root).unwrap_err();
    }

    mod set {
        use super::*;

        #[test]
        fn set_get() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            let key0 = StarkHash::from_hex_str("99cadc82").unwrap();
            let key1 = StarkHash::from_hex_str("901823").unwrap();
            let key2 = StarkHash::from_hex_str("8975").unwrap();

            let val0 = StarkHash::from_hex_str("891127cbaf").unwrap();
            let val1 = StarkHash::from_hex_str("82233127cbaf").unwrap();
            let val2 = StarkHash::from_hex_str("891124667aacde7cbaf").unwrap();

            uut.set(key0, val0).unwrap();
            uut.set(key1, val1).unwrap();
            uut.set(key2, val2).unwrap();

            assert_eq!(uut.get(key0).unwrap(), val0);
            assert_eq!(uut.get(key1).unwrap(), val1);
            assert_eq!(uut.get(key2).unwrap(), val2);
        }

        #[test]
        fn overwrite() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            let key = StarkHash::from_hex_str("123").unwrap();
            let old_value = StarkHash::from_hex_str("abc").unwrap();
            let new_value = StarkHash::from_hex_str("def").unwrap();

            uut.set(key, old_value).unwrap();
            uut.set(key, new_value).unwrap();

            assert_eq!(uut.get(key).unwrap(), new_value);
        }
    }

    mod tree_state {
        use super::*;

        #[test]
        fn single_leaf() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            let key = StarkHash::from_hex_str("123").unwrap();
            let value = StarkHash::from_hex_str("abc").unwrap();

            uut.set(key, value).unwrap();

            // The tree should consist of an edge node (root) leading to a leaf node.
            // The edge node path should match the key, and the leaf node the value.
            let expected_path = key.view_bits().to_bitvec();

            let edge = uut
                .root
                .borrow()
                .as_edge()
                .cloned()
                .expect("root should be an edge");
            assert_eq!(edge.path, expected_path);
            assert_eq!(edge.height, 0);

            let leaf = edge.child.borrow().to_owned();
            assert_eq!(leaf, Node::Leaf(value));
        }

        #[test]
        fn binary_middle() {
            let key0 = bitvec![Msb0, u8; 0; 251];
            let key0 = starkhash_from_bits(&key0);

            let mut key1 = bitvec![Msb0, u8; 0; 251];
            key1.set(50, true);
            let key1 = starkhash_from_bits(&key1);

            let value0 = StarkHash::from_hex_str("abc").unwrap();
            let value1 = StarkHash::from_hex_str("def").unwrap();

            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            uut.set(key0, value0).unwrap();
            uut.set(key1, value1).unwrap();

            let edge = uut
                .root
                .borrow()
                .as_edge()
                .cloned()
                .expect("root should be an edge");

            let expected_path = bitvec![Msb0, u8; 0; 50];
            assert_eq!(edge.path, expected_path);
            assert_eq!(edge.height, 0);

            let binary = edge
                .child
                .borrow()
                .as_binary()
                .cloned()
                .expect("should be a binary node");

            assert_eq!(binary.height, 50);

            let direction0 = Direction::from(false);
            let direction1 = Direction::from(true);

            let child0 = binary
                .get_child(direction0)
                .borrow()
                .as_edge()
                .cloned()
                .expect("child should be an edge");
            let child1 = binary
                .get_child(direction1)
                .borrow()
                .as_edge()
                .cloned()
                .expect("child should be an edge");

            assert_eq!(child0.height, 51);
            assert_eq!(child1.height, 51);

            let leaf0 = child0.child.borrow().to_owned();
            let leaf1 = child1.child.borrow().to_owned();

            assert_eq!(leaf0, Node::Leaf(value0));
            assert_eq!(leaf1, Node::Leaf(value1));
        }

        #[test]
        fn binary_root() {
            let key0 = bitvec![Msb0, u8; 0; 251];
            let key0 = starkhash_from_bits(&key0);

            let mut key1 = bitvec![Msb0, u8; 0; 251];
            key1.set(0, true);
            let key1 = starkhash_from_bits(&key1);

            let value0 = StarkHash::from_hex_str("abc").unwrap();
            let value1 = StarkHash::from_hex_str("def").unwrap();

            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            uut.set(key0, value0).unwrap();
            uut.set(key1, value1).unwrap();

            let binary = uut
                .root
                .borrow()
                .as_binary()
                .cloned()
                .expect("root should be a binary node");

            assert_eq!(binary.height, 0);

            let direction0 = Direction::from(false);
            let direction1 = Direction::from(true);

            let child0 = binary
                .get_child(direction0)
                .borrow()
                .as_edge()
                .cloned()
                .expect("child should be an edge");
            let child1 = binary
                .get_child(direction1)
                .borrow()
                .as_edge()
                .cloned()
                .expect("child should be an edge");

            assert_eq!(child0.height, 1);
            assert_eq!(child1.height, 1);

            let leaf0 = child0.child.borrow().to_owned();
            let leaf1 = child1.child.borrow().to_owned();

            assert_eq!(leaf0, Node::Leaf(value0));
            assert_eq!(leaf1, Node::Leaf(value1));
        }

        #[test]
        fn binary_leaves() {
            let key0 = StarkHash::from_hex_str("0").unwrap();
            let key1 = StarkHash::from_hex_str("1").unwrap();
            let value0 = StarkHash::from_hex_str("abc").unwrap();
            let value1 = StarkHash::from_hex_str("def").unwrap();

            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            uut.set(key0, value0).unwrap();
            uut.set(key1, value1).unwrap();

            // The tree should consist of an edge node, terminating in a binary node connecting to
            // the two leaf nodes.
            let edge = uut
                .root
                .borrow()
                .as_edge()
                .cloned()
                .expect("root should be an edge");
            // The edge's path will be the full key path excluding the final bit.
            // The final bit is represented by the following binary node.
            let mut expected_path = key0.view_bits().to_bitvec();
            expected_path.pop();

            assert_eq!(edge.path, expected_path);
            assert_eq!(edge.height, 0);

            let binary = edge
                .child
                .borrow()
                .as_binary()
                .cloned()
                .expect("should be a binary node");
            assert_eq!(binary.height, 250);

            // The binary children should be the leaf nodes.
            let direction0 = Direction::from(false);
            let direction1 = Direction::from(true);
            let child0 = binary.get_child(direction0).borrow().to_owned();
            let child1 = binary.get_child(direction1).borrow().to_owned();
            assert_eq!(child0, Node::Leaf(value0));
            assert_eq!(child1, Node::Leaf(value1));
        }

        #[test]
        fn empty() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            assert_eq!(*uut.root.borrow(), Node::Unresolved(ZERO_HASH));
        }
    }

    mod delete_leaf {
        use super::*;

        #[test]
        fn empty() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            let key = StarkHash::from_hex_str("123abc").unwrap();
            uut.delete_leaf(key).unwrap();

            assert_eq!(*uut.root.borrow(), Node::Unresolved(ZERO_HASH));
        }

        #[test]
        fn single_insert_and_removal() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            let key = StarkHash::from_hex_str("123").unwrap();
            let value = StarkHash::from_hex_str("abc").unwrap();

            uut.set(key, value).unwrap();
            uut.delete_leaf(key).unwrap();

            assert_eq!(uut.get(key).unwrap(), ZERO_HASH);
            assert_eq!(*uut.root.borrow(), Node::Unresolved(ZERO_HASH));
        }

        #[test]
        fn three_leaves_and_one_removal() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            let key0 = StarkHash::from_hex_str("99cadc82").unwrap();
            let key1 = StarkHash::from_hex_str("901823").unwrap();
            let key2 = StarkHash::from_hex_str("8975").unwrap();

            let val0 = StarkHash::from_hex_str("1").unwrap();
            let val1 = StarkHash::from_hex_str("2").unwrap();
            let val2 = StarkHash::from_hex_str("3").unwrap();

            uut.set(key0, val0).unwrap();
            uut.set(key1, val1).unwrap();
            uut.set(key2, val2).unwrap();

            uut.delete_leaf(key1).unwrap();

            assert_eq!(uut.get(key0).unwrap(), val0);
            assert_eq!(uut.get(key1).unwrap(), ZERO_HASH);
            assert_eq!(uut.get(key2).unwrap(), val2);
        }
    }

    mod persistence {
        use super::*;

        #[test]
        fn set() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            let key0 = StarkHash::from_hex_str("99cadc82").unwrap();
            let key1 = StarkHash::from_hex_str("901823").unwrap();
            let key2 = StarkHash::from_hex_str("8975").unwrap();

            let val0 = StarkHash::from_hex_str("1").unwrap();
            let val1 = StarkHash::from_hex_str("2").unwrap();
            let val2 = StarkHash::from_hex_str("3").unwrap();

            uut.set(key0, val0).unwrap();
            uut.set(key1, val1).unwrap();
            uut.set(key2, val2).unwrap();

            let root = uut.commit().unwrap();

            let uut = MerkleTree::load("test".to_string(), &transaction, root).unwrap();

            assert_eq!(uut.get(key0).unwrap(), val0);
            assert_eq!(uut.get(key1).unwrap(), val1);
            assert_eq!(uut.get(key2).unwrap(), val2);
        }

        mod consecutive_roots {
            use super::*;

            #[test]
            fn set_get() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();

                let key0 = StarkHash::from_hex_str("99cadc82").unwrap();
                let key1 = StarkHash::from_hex_str("901823").unwrap();
                let key2 = StarkHash::from_hex_str("8975").unwrap();

                let val0 = StarkHash::from_hex_str("1").unwrap();
                let val1 = StarkHash::from_hex_str("2").unwrap();
                let val2 = StarkHash::from_hex_str("3").unwrap();

                let mut uut =
                    MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();
                uut.set(key0, val0).unwrap();
                let root0 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
                uut.set(key1, val1).unwrap();
                let root1 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test".to_string(), &transaction, root1).unwrap();
                uut.set(key2, val2).unwrap();
                let root2 = uut.commit().unwrap();

                let uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
                assert_eq!(uut.get(key0).unwrap(), val0);
                assert_eq!(uut.get(key1).unwrap(), ZERO_HASH);
                assert_eq!(uut.get(key2).unwrap(), ZERO_HASH);

                let uut = MerkleTree::load("test".to_string(), &transaction, root1).unwrap();
                assert_eq!(uut.get(key0).unwrap(), val0);
                assert_eq!(uut.get(key1).unwrap(), val1);
                assert_eq!(uut.get(key2).unwrap(), ZERO_HASH);

                let uut = MerkleTree::load("test".to_string(), &transaction, root2).unwrap();
                assert_eq!(uut.get(key0).unwrap(), val0);
                assert_eq!(uut.get(key1).unwrap(), val1);
                assert_eq!(uut.get(key2).unwrap(), val2);
            }

            #[test]
            fn delete() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();

                let key0 = StarkHash::from_hex_str("99cadc82").unwrap();
                let key1 = StarkHash::from_hex_str("901823").unwrap();
                let key2 = StarkHash::from_hex_str("8975").unwrap();

                let val0 = StarkHash::from_hex_str("1").unwrap();
                let val1 = StarkHash::from_hex_str("2").unwrap();
                let val2 = StarkHash::from_hex_str("3").unwrap();

                let mut uut =
                    MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();
                uut.set(key0, val0).unwrap();
                let root0 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
                uut.set(key1, val1).unwrap();
                let root1 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test".to_string(), &transaction, root1).unwrap();
                uut.set(key2, val2).unwrap();
                let root2 = uut.commit().unwrap();

                let uut = MerkleTree::load("test".to_string(), &transaction, root1).unwrap();
                uut.delete().unwrap();

                let uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
                assert_eq!(uut.get(key0).unwrap(), val0);
                assert_eq!(uut.get(key1).unwrap(), ZERO_HASH);
                assert_eq!(uut.get(key2).unwrap(), ZERO_HASH);

                MerkleTree::load("test".to_string(), &transaction, root1).unwrap_err();

                let uut = MerkleTree::load("test".to_string(), &transaction, root2).unwrap();
                assert_eq!(uut.get(key0).unwrap(), val0);
                assert_eq!(uut.get(key1).unwrap(), val1);
                assert_eq!(uut.get(key2).unwrap(), val2);
            }
        }

        mod parallel_roots {
            use super::*;

            #[test]
            fn set_get() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();

                let key0 = StarkHash::from_hex_str("99cadc82").unwrap();
                let key1 = StarkHash::from_hex_str("901823").unwrap();
                let key2 = StarkHash::from_hex_str("8975").unwrap();

                let val0 = StarkHash::from_hex_str("1").unwrap();
                let val1 = StarkHash::from_hex_str("2").unwrap();
                let val2 = StarkHash::from_hex_str("3").unwrap();

                let mut uut =
                    MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();
                uut.set(key0, val0).unwrap();
                let root0 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
                uut.set(key1, val1).unwrap();
                let root1 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
                uut.set(key2, val2).unwrap();
                let root2 = uut.commit().unwrap();

                let uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
                assert_eq!(uut.get(key0).unwrap(), val0);
                assert_eq!(uut.get(key1).unwrap(), ZERO_HASH);
                assert_eq!(uut.get(key2).unwrap(), ZERO_HASH);

                let uut = MerkleTree::load("test".to_string(), &transaction, root1).unwrap();
                assert_eq!(uut.get(key0).unwrap(), val0);
                assert_eq!(uut.get(key1).unwrap(), val1);
                assert_eq!(uut.get(key2).unwrap(), ZERO_HASH);

                let uut = MerkleTree::load("test".to_string(), &transaction, root2).unwrap();
                assert_eq!(uut.get(key0).unwrap(), val0);
                assert_eq!(uut.get(key1).unwrap(), ZERO_HASH);
                assert_eq!(uut.get(key2).unwrap(), val2);
            }

            #[test]
            fn delete() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();

                let key0 = StarkHash::from_hex_str("99cadc82").unwrap();
                let key1 = StarkHash::from_hex_str("901823").unwrap();
                let key2 = StarkHash::from_hex_str("8975").unwrap();

                let val0 = StarkHash::from_hex_str("1").unwrap();
                let val1 = StarkHash::from_hex_str("2").unwrap();
                let val2 = StarkHash::from_hex_str("3").unwrap();

                let mut uut =
                    MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();
                uut.set(key0, val0).unwrap();
                let root0 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
                uut.set(key1, val1).unwrap();
                let root1 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
                uut.set(key2, val2).unwrap();
                let root2 = uut.commit().unwrap();

                let uut = MerkleTree::load("test".to_string(), &transaction, root1).unwrap();
                uut.delete().unwrap();

                let uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
                assert_eq!(uut.get(key0).unwrap(), val0);
                assert_eq!(uut.get(key1).unwrap(), ZERO_HASH);
                assert_eq!(uut.get(key2).unwrap(), ZERO_HASH);

                MerkleTree::load("test".to_string(), &transaction, root1).unwrap_err();

                let uut = MerkleTree::load("test".to_string(), &transaction, root2).unwrap();
                assert_eq!(uut.get(key0).unwrap(), val0);
                assert_eq!(uut.get(key1).unwrap(), ZERO_HASH);
                assert_eq!(uut.get(key2).unwrap(), val2);
            }
        }

        #[test]
        fn mulitple_identical_roots() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            let key = StarkHash::from_hex_str("99cadc82").unwrap();
            let val = StarkHash::from_hex_str("12345678").unwrap();
            uut.set(key, val).unwrap();

            let root0 = uut.commit().unwrap();

            let uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
            let root1 = uut.commit().unwrap();

            let uut = MerkleTree::load("test".to_string(), &transaction, root1).unwrap();
            let root2 = uut.commit().unwrap();

            assert_eq!(root0, root1);
            assert_eq!(root0, root2);

            let uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
            uut.delete().unwrap();

            let uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
            assert_eq!(uut.get(key).unwrap(), val);

            let uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
            uut.delete().unwrap();

            let uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
            assert_eq!(uut.get(key).unwrap(), val);

            let uut = MerkleTree::load("test".to_string(), &transaction, root0).unwrap();
            uut.delete().unwrap();

            // This should fail since the root has been deleted.
            MerkleTree::load("test".to_string(), &transaction, root0).unwrap_err();
        }
    }

    mod real_world {
        use super::*;

        #[ignore = "Root data is incorrect"]
        #[test]
        fn simple() {
            // Test data created from Starknet cairo wrangling.

            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            uut.set(
                StarkHash::from_hex_str("1").unwrap(),
                StarkHash::from_hex_str("0").unwrap(),
            )
            .unwrap();

            uut.set(
                StarkHash::from_hex_str("134").unwrap(),
                StarkHash::from_hex_str("1").unwrap(),
            )
            .unwrap();

            uut.set(
                StarkHash::from_hex_str("135").unwrap(),
                StarkHash::from_hex_str("2").unwrap(),
            )
            .unwrap();

            let root = uut.commit().unwrap();

            assert_eq!(
                root,
                StarkHash::from_hex_str(
                    "05bb9440e27889a364bcb678b1f679ecd1347acdedcbf36e83494f857cc58026"
                )
                .unwrap()
            );
        }

        #[test]
        fn contract_edge_branches_correctly_on_insert() {
            // This emulates the contract update which exposed a bug in `set`.
            //
            // This was discovered by comparing the global state tree for the
            // gensis block on goerli testnet (alpha 4.0).
            //
            // The bug was identified by comparing root and nodes against the python
            // utility in `root/py/src/test_generate_test_storage_tree.py`.
            let leaves = vec![
                ("0x5", "0x66"),
                (
                    "0x1BF95D4B58F0741FEA29F94EE5A118D0847C8B7AE0173C2A570C9F74CCA9EA1",
                    "0x7E5",
                ),
                (
                    "0x3C75C20765D020B0EC41B48BB8C5338AC4B619FC950D59994E844E1E1B9D2A9",
                    "0x7C7",
                ),
                (
                    "0x4065B936C56F5908A981084DAFA66DC17600937DC80C52EEB834693BB811792",
                    "0x7970C532B764BB36FAF5696B8BC1317505B8A4DC9EEE5DF4994671757975E4D",
                ),
                (
                    "0x4B5FBB4904167E2E8195C35F7D4E78501A3FE95896794367C85B60B39AEFFC2",
                    "0x232C969EAFC5B30C20648759D7FA1E2F4256AC6604E1921578101DCE4DFDF48",
                ),
            ];

            // create test database
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();

            let mut tree = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

            for (key, val) in leaves {
                let key = StarkHash::from_hex_str(key).unwrap();
                let val = StarkHash::from_hex_str(val).unwrap();
                tree.set(key, val).unwrap();
            }

            let root = tree.commit().unwrap();

            let expected = StarkHash::from_hex_str(
                "0x06ee9a8202b40f3f76f1a132f953faa2df78b3b33ccb2b4406431abdc99c2dfe",
            )
            .unwrap();

            assert_eq!(root, expected);
        }
    }
}
