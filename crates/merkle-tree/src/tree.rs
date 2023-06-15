//! Starknet utilises a custom Binary Merkle-Patricia Tree to store and organise its state.
//!
//! From an external perspective the tree is similar to a key-value store, where both key
//! and value are [Felts](Felt). The difference is that each tree is immutable,
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
//! It is important to understand that since all keys are [Felts](Felt), this means
//! all paths to a key are equally long - 251 bits.
//!
//! Starknet defines three node types for a tree.
//!
//! `Leaf nodes` which represent an actual value stored.
//!
//! `Edge nodes` which connect two nodes, and __must be__ a maximal subtree (i.e. be as
//! long as possible). This latter condition is important as it strictly defines a tree (i.e. all
//! trees with the same leaves must have the same nodes). The path of an edge node can therefore
//! be many bits long.
//!
//! `Binary nodes` is a branch node with two children, left and right. This represents
//! only a single bit on the path to a leaf.
//!
//! A tree storing a single key-value would consist of two nodes. The root node would be an edge node
//! with a path equal to the key. This edge node is connected to a leaf node storing the value.
//!
//! #### Implementation details
//!
//! We've defined an additional node type, an `Unresolved node`. This is used to
//! represent a node who's hash is known, but has not yet been retrieved from storage (and we therefore
//! have no further details about it).
//!
//! Our implementation is a mix of nodes from persistent storage and any mutations are kept in-memory. It is
//! done this way to allow many mutations to a tree before committing only the final result to storage. This
//! may be confusing since we just said trees are immutable -- but since we are only changing the in-memory
//! tree, the immutable tree still exists in storage. One can therefore think of the in-memory tree as containing
//! the state changes between tree `N` and `N + 1`.
//!
//! The in-memory tree is built using a graph of `Rc<RefCell<Node>>` which is a bit painful.

use crate::merkle_node::{BinaryNode, Direction, EdgeNode, InternalNode};
use crate::storage::Storage;
use anyhow::Context;
use bitvec::{prelude::BitSlice, prelude::BitVec, prelude::Msb0};
use pathfinder_common::hash::FeltHash;
use pathfinder_common::trie::TrieNode;
use stark_hash::Felt;
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::{cell::RefCell, rc::Rc};

/// A Starknet binary Merkle-Patricia tree.
#[derive(Debug, Clone)]
pub struct MerkleTree<H: FeltHash, const HEIGHT: usize> {
    root: Rc<RefCell<InternalNode>>,
    _hasher: std::marker::PhantomData<H>,
}

/// The result of committing a [MerkleTree]. Contains the new root and any
/// new nodes added in this update.
pub struct TrieUpdate {
    pub root: Felt,
    /// New nodes added. Note that these may contain false positives if the
    /// mutations resulted in removing and then re-adding the same nodes within the tree.
    pub nodes: HashMap<Felt, TrieNode>,
}

impl<H: FeltHash, const HEIGHT: usize> MerkleTree<H, HEIGHT> {
    pub fn new(root: Felt) -> Self {
        let root_node = Rc::new(RefCell::new(InternalNode::Unresolved(root)));
        Self {
            root: root_node,
            _hasher: std::marker::PhantomData,
        }
    }

    pub fn empty() -> Self {
        Self::new(Felt::ZERO)
    }

    /// Commits all tree mutations and returns the [changes](TrieUpdate) to the tree.
    pub fn commit(mut self) -> anyhow::Result<TrieUpdate> {
        self.commit_mut()
    }

    pub fn commit_mut(&mut self) -> anyhow::Result<TrieUpdate> {
        // Go through tree, collect mutated nodes and calculate their hashes.
        let mut added = HashMap::new();
        Self::commit_subtree(&mut self.root.borrow_mut(), &mut added)?;
        // unwrap is safe as `commit_subtree` will set the hash.
        let root = self.root.borrow().hash().unwrap();

        Ok(TrieUpdate { root, nodes: added })
    }

    /// Persists any changes in this subtree to storage.
    ///
    /// This necessitates recursively calculating the hash of, and
    /// in turn persisting, any changed child nodes. This is necessary
    /// as the parent node's hash relies on its childrens hashes.
    ///
    /// In effect, the entire subtree gets persisted.
    fn commit_subtree(
        node: &mut InternalNode,
        added: &mut HashMap<Felt, TrieNode>,
    ) -> anyhow::Result<()> {
        use InternalNode::*;
        match node {
            Unresolved(_) => { /* Unresolved nodes are already persisted. */ }
            Leaf(_) => { /* storage wouldn't persist these even if we asked. */ }
            Binary(binary) if binary.hash.is_some() => { /* not dirty, already persisted */ }
            Edge(edge) if edge.hash.is_some() => { /* not dirty, already persisted */ }

            Binary(binary) => {
                Self::commit_subtree(&mut binary.left.borrow_mut(), added)?;
                Self::commit_subtree(&mut binary.right.borrow_mut(), added)?;
                // This will succeed as `commit_subtree` will set the child hashes.
                binary.calculate_hash::<H>();
                // unwrap is safe as `commit_subtree` will set the hashes.
                let left = binary.left.borrow().hash().unwrap();
                let right = binary.right.borrow().hash().unwrap();
                let persisted_node = TrieNode::Binary { left, right };
                // unwrap is safe as we just set the hash.
                added.insert(binary.hash.unwrap(), persisted_node);
            }

            Edge(edge) => {
                Self::commit_subtree(&mut edge.child.borrow_mut(), added)?;
                // This will succeed as `commit_subtree` will set the child's hash.
                edge.calculate_hash::<H>();

                // unwrap is safe as `commit_subtree` will set the hash.
                let child = edge.child.borrow().hash().unwrap();
                let persisted_node = TrieNode::Edge {
                    path: edge.path.clone(),
                    child,
                };
                // unwrap is safe as we just set the hash.
                added.insert(edge.hash.unwrap(), persisted_node);
            }
        }

        Ok(())
    }

    /// Sets the value of a key. To delete a key, set the value to [Felt::ZERO].
    pub fn set(
        &mut self,
        storage: &impl Storage,
        key: &BitSlice<Msb0, u8>,
        value: Felt,
    ) -> anyhow::Result<()> {
        if value == Felt::ZERO {
            return self.delete_leaf(storage, key);
        }

        // Changing or inserting a new leaf into the tree will change the hashes
        // of all nodes along the path to the leaf.
        let path = self.traverse(storage, key)?;
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
        use InternalNode::*;
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
                        let new_path = key[child_height..].to_bitvec();
                        // Path from binary node to existing child
                        let old_path = edge.path[common.len() + 1..].to_bitvec();

                        // The new leaf branch of the binary node.
                        // (this may be edge -> leaf, or just leaf depending).
                        let new_leaf = InternalNode::Leaf(value);
                        let new = match new_path.is_empty() {
                            true => Rc::new(RefCell::new(new_leaf)),
                            false => {
                                let new_edge = InternalNode::Edge(EdgeNode {
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
                                let old_edge = InternalNode::Edge(EdgeNode {
                                    hash: None,
                                    height: child_height,
                                    path: old_path,
                                    child: edge.child.clone(),
                                });
                                Rc::new(RefCell::new(old_edge))
                            }
                        };

                        let new_direction = Direction::from(key[branch_height]);
                        let (left, right) = match new_direction {
                            Direction::Left => (new, old),
                            Direction::Right => (old, new),
                        };

                        let branch = InternalNode::Binary(BinaryNode {
                            hash: None,
                            height: branch_height,
                            left,
                            right,
                        });

                        // We may require an edge leading to the binary node.
                        match common.is_empty() {
                            true => branch,
                            false => InternalNode::Edge(EdgeNode {
                                hash: None,
                                height: edge.height,
                                path: common.to_bitvec(),
                                child: Rc::new(RefCell::new(branch)),
                            }),
                        }
                    }
                    // Leaf exists, we replace its value.
                    Leaf(_) => InternalNode::Leaf(value),
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
                let leaf = InternalNode::Leaf(value);
                let edge = InternalNode::Edge(EdgeNode {
                    hash: None,
                    height: 0,
                    path: key.to_bitvec(),
                    child: Rc::new(RefCell::new(leaf)),
                });

                self.root = Rc::new(RefCell::new(edge));
            }
        }

        Ok(())
    }

    /// Deletes a leaf node from the tree.
    ///
    /// This is not an external facing API; the functionality is instead accessed by calling
    /// [`MerkleTree::set`] with value set to [`Felt::ZERO`].
    fn delete_leaf(
        &mut self,
        storage: &impl Storage,
        key: &BitSlice<Msb0, u8>,
    ) -> anyhow::Result<()> {
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
        let path = self.traverse(storage, key)?;

        // Do nothing if the leaf does not exist.
        match path.last() {
            Some(node) => match &*node.borrow() {
                InternalNode::Leaf(_) => {}
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
                    self.merge_edges(storage, &mut edge)?;

                    edge
                };
                // Replace the old binary node with the new edge node.
                node.swap(&RefCell::new(InternalNode::Edge(new_edge)));
            }
            None => {
                // We reached the root without a hitting binary node. The new tree
                // must therefore be empty.
                self.root = Rc::new(RefCell::new(InternalNode::Unresolved(Felt::ZERO)));
                return Ok(());
            }
        };

        // Check the parent of the new edge. If it is also an edge, then they must merge.
        if let Some(node) = node_iter.next() {
            if let InternalNode::Edge(edge) = &mut *node.borrow_mut() {
                self.merge_edges(storage, edge)?;
            }
        }

        Ok(())
    }

    /// Returns the value stored at key, or `None` if it does not exist.
    pub fn get(
        &self,
        storage: &impl Storage,
        key: &BitSlice<Msb0, u8>,
    ) -> anyhow::Result<Option<Felt>> {
        let result = self
            .traverse(storage, key)?
            .last()
            .and_then(|node| match &*node.borrow() {
                InternalNode::Leaf(value) if !value.is_zero() => Some(*value),
                _ => None,
            });
        Ok(result)
    }

    /// Generates a merkle-proof for a given `key`.
    ///
    /// Returns vector of [`TrieNode`] which form a chain from the root to the key,
    /// if it exists, or down to the node which proves that the key does not exist.
    ///
    /// The nodes are returned in order, root first.
    ///
    /// Verification is performed by confirming that:
    ///   1. the chain follows the path of `key`, and
    ///   2. the hashes are correct, and
    ///   3. the root hash matches the known root
    pub fn get_proof(
        &self,
        storage: &impl Storage,
        key: &BitSlice<Msb0, u8>,
    ) -> anyhow::Result<Vec<TrieNode>> {
        let mut nodes = self.traverse(storage, key)?;

        // Return an empty list if tree is empty.
        let node = match nodes.last() {
            Some(node) => node,
            None => return Ok(Vec::new()),
        };

        // A leaf node is redudant data as the information for it is already contained in the previous node.
        if matches!(&*node.borrow(), InternalNode::Leaf(_)) {
            nodes.pop();
        }

        Ok(nodes
            .iter()
            .map(|node| match &*node.borrow() {
                InternalNode::Binary(bin) => TrieNode::Binary {
                    left: bin.left.borrow().hash().expect("Node should be committed"),
                    right: bin.right.borrow().hash().expect("Node should be committed"),
                },
                InternalNode::Edge(edge) => TrieNode::Edge {
                    child: edge
                        .child
                        .borrow()
                        .hash()
                        .expect("Node should be committed"),
                    path: edge.path.clone(),
                },
                _ => unreachable!(),
            })
            .collect())
    }

    /// Traverses from the current root towards destination node.
    /// Returns the list of nodes along the path.
    ///
    /// If the destination node exists, it will be the final node in the list.
    ///
    /// This means that the final node will always be either a the destination [Leaf](InternalNode::Leaf) node,
    /// or an [Edge](InternalNode::Edge) node who's path suffix does not match the leaf's path.
    ///
    /// The final node can __not__ be a [Binary](InternalNode::Binary) node since it would always be possible to continue
    /// on towards the destination. Nor can it be an [Unresolved](InternalNode::Unresolved) node since this would be
    /// resolved to check if we can travel further.
    fn traverse(
        &self,
        storage: &impl Storage,
        dst: &BitSlice<Msb0, u8>,
    ) -> anyhow::Result<Vec<Rc<RefCell<InternalNode>>>> {
        if self.root.borrow().is_empty() {
            return Ok(Vec::new());
        }

        let mut current = self.root.clone();
        let mut height = 0;
        let mut nodes = Vec::new();
        loop {
            use InternalNode::*;

            let current_tmp = current.borrow().clone();

            let next = match current_tmp {
                Unresolved(hash) => {
                    let node = self.resolve(storage, hash, height)?;
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
    /// Result will be either a [Binary](InternalNode::Binary), [Edge](InternalNode::Edge) or [Leaf](InternalNode::Leaf) node.
    fn resolve(
        &self,
        storage: &impl Storage,
        hash: Felt,
        height: usize,
    ) -> anyhow::Result<InternalNode> {
        if height == HEIGHT {
            #[cfg(debug_assertions)]
            match storage.get(&hash)? {
                Some(TrieNode::Edge { .. } | TrieNode::Binary { .. }) | None => {
                    // some cases are because of collisions, none is the common outcome
                }
            }
            return Ok(InternalNode::Leaf(hash));
        }

        let node = storage
            .get(&hash)?
            .with_context(|| format!("Node at height {height} does not exist: {hash}"))?;

        let node = match node {
            TrieNode::Binary { left, right } => InternalNode::Binary(BinaryNode {
                hash: Some(hash),
                height,
                left: Rc::new(RefCell::new(InternalNode::Unresolved(left))),
                right: Rc::new(RefCell::new(InternalNode::Unresolved(right))),
            }),
            TrieNode::Edge { child, path } => InternalNode::Edge(EdgeNode {
                hash: Some(hash),
                height,
                path,
                child: Rc::new(RefCell::new(InternalNode::Unresolved(child))),
            }),
        };

        Ok(node)
    }

    /// This is a convenience function which merges the edge node with its child __iff__ it is also an edge.
    ///
    /// Does nothing if the child is not also an edge node.
    ///
    /// This can occur when mutating the tree (e.g. deleting a child of a binary node), and is an illegal state
    /// (since edge nodes __must be__ maximal subtrees).
    fn merge_edges(&self, storage: &impl Storage, parent: &mut EdgeNode) -> anyhow::Result<()> {
        let resolved_child = match &*parent.child.borrow() {
            InternalNode::Unresolved(hash) => {
                self.resolve(storage, *hash, parent.height + parent.path.len())?
            }
            other => other.clone(),
        };

        if let Some(child_edge) = resolved_child.as_edge().cloned() {
            parent.path.extend_from_bitslice(&child_edge.path);
            parent.child = child_edge.child;
        }

        Ok(())
    }

    /// Visits all of the nodes in the tree in pre-order using the given visitor function.
    ///
    /// For each node, there will first be a visit for `InternalNode::Unresolved(hash)` followed by visit
    /// at the loaded node when [`Visit::ContinueDeeper`] is returned. At any time the visitor
    /// function can also return `ControlFlow::Break` to stop the visit with the given return
    /// value, which will be returned as `Some(value))` to the caller.
    ///
    /// The visitor function receives the node being visited, as well as the full path to that node.
    ///
    /// Upon successful non-breaking visit of the tree, `None` will be returned.
    #[allow(dead_code)]
    pub fn dfs<X, VisitorFn>(
        &self,
        storage: &impl Storage,
        visitor_fn: &mut VisitorFn,
    ) -> anyhow::Result<Option<X>>
    where
        VisitorFn: FnMut(&InternalNode, &BitSlice<Msb0, u8>) -> ControlFlow<X, Visit>,
    {
        use bitvec::prelude::bitvec;

        #[allow(dead_code)]
        struct VisitedNode {
            node: Rc<RefCell<InternalNode>>,
            path: BitVec<Msb0, u8>,
        }

        let mut visiting = vec![VisitedNode {
            node: self.root.clone(),
            path: bitvec![Msb0, u8;],
        }];

        loop {
            match visiting.pop() {
                None => break,
                Some(VisitedNode { node, path }) => {
                    let current_node = &*node.borrow();
                    if !matches!(current_node, InternalNode::Unresolved(Felt::ZERO)) {
                        match visitor_fn(current_node, &path) {
                            ControlFlow::Continue(Visit::ContinueDeeper) => {
                                // the default, no action, just continue deeper
                            }
                            ControlFlow::Continue(Visit::StopSubtree) => {
                                // make sure we don't add any more to `visiting` on this subtree
                                continue;
                            }
                            ControlFlow::Break(x) => {
                                // early exit
                                return Ok(Some(x));
                            }
                        }
                    }
                    match current_node {
                        InternalNode::Binary(b) => {
                            visiting.push(VisitedNode {
                                node: b.right.clone(),
                                path: {
                                    let mut path_right = path.clone();
                                    path_right.push(Direction::Right.into());
                                    path_right
                                },
                            });
                            visiting.push(VisitedNode {
                                node: b.left.clone(),
                                path: {
                                    let mut path_left = path.clone();
                                    path_left.push(Direction::Left.into());
                                    path_left
                                },
                            });
                        }
                        InternalNode::Edge(e) => {
                            visiting.push(VisitedNode {
                                node: e.child.clone(),
                                path: {
                                    let mut extended_path = path.clone();
                                    extended_path.extend_from_bitslice(&e.path);
                                    extended_path
                                },
                            });
                        }
                        InternalNode::Leaf(_) => {}
                        InternalNode::Unresolved(hash) => {
                            // Zero means empty tree, so nothing to resolve
                            if hash != &Felt::ZERO {
                                visiting.push(VisitedNode {
                                    node: Rc::new(RefCell::new(self.resolve(
                                        storage,
                                        *hash,
                                        path.len(),
                                    )?)),
                                    path,
                                });
                            }
                        }
                    };
                }
            }
        }

        Ok(None)
    }
}

/// Direction for the [`MerkleTree::dfs`] as the return value of the visitor function.
#[derive(Default)]
pub enum Visit {
    /// Instructs that the visit should visit any subtrees of the current node. This is a no-op for
    /// [`InternalNode::Leaf`].
    #[default]
    ContinueDeeper,
    /// Returning this value for [`InternalNode::Binary`] or [`InternalNode::Edge`] will ignore all of the children
    /// of the node for the rest of the iteration. This is useful because two trees often share a
    /// number of subtrees with earlier blocks. Returning this for [`InternalNode::Leaf`] is a no-op.
    StopSubtree,
}

#[cfg(test)]
mod tests {
    use pathfinder_common::hash::PedersenHash;

    use super::*;
    use bitvec::prelude::*;
    use pathfinder_common::felt;

    type TestTree = MerkleTree<PedersenHash, 251>;

    #[derive(Default)]
    struct TestStorage(HashMap<Felt, TrieNode>);

    impl Storage for TestStorage {
        fn get(&self, node: &Felt) -> anyhow::Result<Option<TrieNode>> {
            Ok(self.0.get(node).cloned())
        }
    }

    /// Commits the tree changes and persists them to storage.
    fn commit_and_persist<H: FeltHash, const HEIGHT: usize>(
        tree: MerkleTree<H, HEIGHT>,
        storage: &mut TestStorage,
    ) -> Felt {
        let update = tree.commit().unwrap();

        for (hash, node) in update.nodes {
            storage.0.insert(hash, node);
        }

        update.root
    }

    #[test]
    fn get_empty() {
        let uut = TestTree::empty();
        let storage = TestStorage::default();

        let key = felt!("0x99cadc82").view_bits().to_bitvec();
        assert_eq!(uut.get(&storage, &key).unwrap(), None);
    }

    mod set {
        use super::*;

        #[test]
        fn set_get() {
            let mut uut = TestTree::empty();
            let storage = TestStorage::default();

            let key0 = felt!("0x99cadc82").view_bits().to_bitvec();
            let key1 = felt!("0x901823").view_bits().to_bitvec();
            let key2 = felt!("0x8975").view_bits().to_bitvec();

            let val0 = felt!("0x891127cbaf");
            let val1 = felt!("0x82233127cbaf");
            let val2 = felt!("0x891124667aacde7cbaf");

            uut.set(&storage, &key0, val0).unwrap();
            uut.set(&storage, &key1, val1).unwrap();
            uut.set(&storage, &key2, val2).unwrap();

            assert_eq!(uut.get(&storage, &key0).unwrap(), Some(val0));
            assert_eq!(uut.get(&storage, &key1).unwrap(), Some(val1));
            assert_eq!(uut.get(&storage, &key2).unwrap(), Some(val2));
        }

        #[test]
        fn overwrite() {
            let mut uut = TestTree::empty();
            let storage = TestStorage::default();

            let key = felt!("0x123").view_bits().to_bitvec();
            let old_value = felt!("0xabc");
            let new_value = felt!("0xdef");

            uut.set(&storage, &key, old_value).unwrap();
            uut.set(&storage, &key, new_value).unwrap();

            assert_eq!(uut.get(&storage, &key).unwrap(), Some(new_value));
        }
    }

    mod tree_state {
        use super::*;

        #[test]
        fn single_leaf() {
            let mut uut = TestTree::empty();
            let storage = TestStorage::default();

            let key = felt!("0x123").view_bits().to_bitvec();
            let value = felt!("0xabc");

            uut.set(&storage, &key, value).unwrap();

            // The tree should consist of an edge node (root) leading to a leaf node.
            // The edge node path should match the key, and the leaf node the value.
            let expected_path = key.clone();

            let edge = uut
                .root
                .borrow()
                .as_edge()
                .cloned()
                .expect("root should be an edge");
            assert_eq!(edge.path, expected_path);
            assert_eq!(edge.height, 0);

            let leaf = edge.child.borrow().to_owned();
            assert_eq!(leaf, InternalNode::Leaf(value));
        }

        #[test]
        fn binary_middle() {
            let key0 = bitvec![Msb0, u8; 0; 251];

            let mut key1 = bitvec![Msb0, u8; 0; 251];
            key1.set(50, true);

            let value0 = felt!("0xabc");
            let value1 = felt!("0xdef");

            let mut uut = TestTree::empty();
            let storage = TestStorage::default();

            uut.set(&storage, &key0, value0).unwrap();
            uut.set(&storage, &key1, value1).unwrap();

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

            assert_eq!(leaf0, InternalNode::Leaf(value0));
            assert_eq!(leaf1, InternalNode::Leaf(value1));
        }

        #[test]
        fn binary_root() {
            let key0 = bitvec![Msb0, u8; 0; 251];

            let mut key1 = bitvec![Msb0, u8; 0; 251];
            key1.set(0, true);

            let value0 = felt!("0xabc");
            let value1 = felt!("0xdef");

            let mut uut = TestTree::empty();
            let storage = TestStorage::default();

            uut.set(&storage, &key0, value0).unwrap();
            uut.set(&storage, &key1, value1).unwrap();

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

            assert_eq!(leaf0, InternalNode::Leaf(value0));
            assert_eq!(leaf1, InternalNode::Leaf(value1));
        }

        #[test]
        fn binary_leaves() {
            let key0 = felt!("0x0").view_bits().to_bitvec();
            let key1 = felt!("0x1").view_bits().to_bitvec();
            let value0 = felt!("0xabc");
            let value1 = felt!("0xdef");

            let mut uut = TestTree::empty();
            let storage = TestStorage::default();

            uut.set(&storage, &key0, value0).unwrap();
            uut.set(&storage, &key1, value1).unwrap();

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
            let mut expected_path = key0.to_bitvec();
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
            assert_eq!(child0, InternalNode::Leaf(value0));
            assert_eq!(child1, InternalNode::Leaf(value1));
        }

        #[test]
        fn empty() {
            let uut = TestTree::empty();
            assert_eq!(*uut.root.borrow(), InternalNode::Unresolved(Felt::ZERO));
        }
    }

    mod delete_leaf {
        use super::*;

        #[test]
        fn empty() {
            let mut uut = TestTree::empty();
            let storage = TestStorage::default();

            let key = felt!("0x123abc").view_bits().to_bitvec();
            uut.delete_leaf(&storage, &key).unwrap();

            assert_eq!(*uut.root.borrow(), InternalNode::Unresolved(Felt::ZERO));
        }

        #[test]
        fn single_insert_and_removal() {
            let mut uut = TestTree::empty();
            let storage = TestStorage::default();

            let key = felt!("0x123").view_bits().to_bitvec();
            let value = felt!("0xabc");

            uut.set(&storage, &key, value).unwrap();
            uut.delete_leaf(&storage, &key).unwrap();

            assert_eq!(uut.get(&storage, &key).unwrap(), None);
            assert_eq!(*uut.root.borrow(), InternalNode::Unresolved(Felt::ZERO));
        }

        #[test]
        fn three_leaves_and_one_removal() {
            let mut uut = TestTree::empty();
            let storage = TestStorage::default();

            let key0 = felt!("0x99cadc82").view_bits().to_bitvec();
            let key1 = felt!("0x901823").view_bits().to_bitvec();
            let key2 = felt!("0x8975").view_bits().to_bitvec();

            let val0 = felt!("0x1");
            let val1 = felt!("0x2");
            let val2 = felt!("0x3");

            uut.set(&storage, &key0, val0).unwrap();
            uut.set(&storage, &key1, val1).unwrap();
            uut.set(&storage, &key2, val2).unwrap();

            uut.delete_leaf(&storage, &key1).unwrap();

            assert_eq!(uut.get(&storage, &key0).unwrap(), Some(val0));
            assert_eq!(uut.get(&storage, &key1).unwrap(), None);
            assert_eq!(uut.get(&storage, &key2).unwrap(), Some(val2));
        }
    }

    mod persistence {
        use super::*;

        #[test]
        fn set() {
            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();

            let key0 = felt!("0x99cadc82").view_bits().to_bitvec();
            let key1 = felt!("0x901823").view_bits().to_bitvec();
            let key2 = felt!("0x8975").view_bits().to_bitvec();

            let val0 = felt!("0x1");
            let val1 = felt!("0x2");
            let val2 = felt!("0x3");

            uut.set(&storage, &key0, val0).unwrap();
            uut.set(&storage, &key1, val1).unwrap();
            uut.set(&storage, &key2, val2).unwrap();

            let root = commit_and_persist(uut, &mut storage);

            let uut = TestTree::new(root);

            assert_eq!(uut.get(&storage, &key0).unwrap(), Some(val0));
            assert_eq!(uut.get(&storage, &key1).unwrap(), Some(val1));
            assert_eq!(uut.get(&storage, &key2).unwrap(), Some(val2));
        }

        #[test]
        fn delete_leaf_regression() {
            // This test exercises a bug in the merging of edge nodes. It was caused
            // by the merge code not resolving unresolved nodes. This meant that
            // unresolved edge nodes would not get merged with the parent edge node
            // causing a malformed tree.
            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();

            let leaves = [
                (
                    felt!("0x1A2FD9B06EAB5BCA4D3885EE4C42736E835A57399FF8B7F6083A92FD2A20095"),
                    felt!("0x215AA555E0CE3E462423D18B7216378D3CCD5D94D724AC7897FBC83FAAA4ED4"),
                ),
                (
                    felt!("0x7AC69285B869DC3E8B305C748A0B867B2DE3027AECEBA51158ECA3B7354D76F"),
                    felt!("0x65C85592F29501D97A2EA1CCF2BA867E6A838D602F4E7A7391EFCBF66958386"),
                ),
                (
                    felt!("0x5C71AB5EF6A5E9DBC7EFD5C61554AB36039F60E5BA076833102E24344524566"),
                    felt!("0x60970DF8E8A19AF3F41B78E93B845EC074A0AED4E96D18C6633580722B93A28"),
                ),
                (
                    felt!("0x000000000000000000000000000000000000000000000000000000000000005"),
                    felt!("0x00000000000000000000000000000000000000000000000000000000000022B"),
                ),
                (
                    felt!("0x000000000000000000000000000000000000000000000000000000000000005"),
                    felt!("0x000000000000000000000000000000000000000000000000000000000000000"),
                ),
            ];

            // Add the first four leaves and commit them to storage.
            for (key, val) in &leaves[..4] {
                let key = key.view_bits();
                uut.set(&storage, key, *val).unwrap();
            }
            let root = commit_and_persist(uut, &mut storage);

            // Delete the final leaf; this exercises the bug as the nodes are all in storage (unresolved).
            let mut uut = TestTree::new(root);
            let key = leaves[4].0.view_bits().to_bitvec();
            let val = leaves[4].1;
            uut.set(&storage, &key, val).unwrap();
            let root = commit_and_persist(uut, &mut storage);
            let expect = felt!("0x5f3b2b98faef39c60dbbb459dbe63d1d10f1688af47fbc032f2cab025def896");
            assert_eq!(root, expect);
        }

        #[test]
        fn consecutive_roots() {
            let key0 = felt!("0x99cadc82").view_bits().to_bitvec();
            let key1 = felt!("0x901823").view_bits().to_bitvec();
            let key2 = felt!("0x8975").view_bits().to_bitvec();

            let val0 = felt!("0x1");
            let val1 = felt!("0x2");
            let val2 = felt!("0x3");

            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();
            uut.set(&storage, &key0, val0).unwrap();
            let root0 = commit_and_persist(uut, &mut storage);

            let mut uut = TestTree::new(root0);
            uut.set(&storage, &key1, val1).unwrap();
            let root1 = commit_and_persist(uut, &mut storage);

            let mut uut = TestTree::new(root1);
            uut.set(&storage, &key2, val2).unwrap();
            let root2 = commit_and_persist(uut, &mut storage);

            let uut = TestTree::new(root0);
            assert_eq!(uut.get(&storage, &key0).unwrap(), Some(val0));
            assert_eq!(uut.get(&storage, &key1).unwrap(), None);
            assert_eq!(uut.get(&storage, &key2).unwrap(), None);

            let uut = TestTree::new(root1);
            assert_eq!(uut.get(&storage, &key0).unwrap(), Some(val0));
            assert_eq!(uut.get(&storage, &key1).unwrap(), Some(val1));
            assert_eq!(uut.get(&storage, &key2).unwrap(), None);

            let uut = TestTree::new(root2);
            assert_eq!(uut.get(&storage, &key0).unwrap(), Some(val0));
            assert_eq!(uut.get(&storage, &key1).unwrap(), Some(val1));
            assert_eq!(uut.get(&storage, &key2).unwrap(), Some(val2));
        }

        #[test]
        fn parallel_roots() {
            let key0 = felt!("0x99cadc82").view_bits().to_bitvec();
            let key1 = felt!("0x901823").view_bits().to_bitvec();
            let key2 = felt!("0x8975").view_bits().to_bitvec();

            let val0 = felt!("0x1");
            let val1 = felt!("0x2");
            let val2 = felt!("0x3");

            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();
            uut.set(&storage, &key0, val0).unwrap();
            let root0 = commit_and_persist(uut, &mut storage);

            let mut uut = TestTree::new(root0);
            uut.set(&storage, &key1, val1).unwrap();
            let root1 = commit_and_persist(uut, &mut storage);

            let mut uut = TestTree::new(root0);
            uut.set(&storage, &key2, val2).unwrap();
            let root2 = commit_and_persist(uut, &mut storage);

            let uut = TestTree::new(root0);
            assert_eq!(uut.get(&storage, &key0).unwrap(), Some(val0));
            assert_eq!(uut.get(&storage, &key1).unwrap(), None);
            assert_eq!(uut.get(&storage, &key2).unwrap(), None);

            let uut = TestTree::new(root1);
            assert_eq!(uut.get(&storage, &key0).unwrap(), Some(val0));
            assert_eq!(uut.get(&storage, &key1).unwrap(), Some(val1));
            assert_eq!(uut.get(&storage, &key2).unwrap(), None);

            let uut = TestTree::new(root2);
            assert_eq!(uut.get(&storage, &key0).unwrap(), Some(val0));
            assert_eq!(uut.get(&storage, &key1).unwrap(), None);
            assert_eq!(uut.get(&storage, &key2).unwrap(), Some(val2));
        }

        #[test]
        fn multiple_identical_roots() {
            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();

            let key = felt!("0x99cadc82").view_bits().to_bitvec();
            let val = felt!("0x12345678");
            uut.set(&storage, &key, val).unwrap();

            let root0 = commit_and_persist(uut, &mut storage);

            let uut = TestTree::new(root0);
            let root1 = commit_and_persist(uut, &mut storage);

            let uut = TestTree::new(root1);
            let root2 = commit_and_persist(uut, &mut storage);

            assert_eq!(root0, root1);
            assert_eq!(root0, root2);
        }
    }

    mod real_world {
        use super::*;
        use pathfinder_common::felt;

        #[test]
        fn simple() {
            // Test data created from Starknet cairo wrangling.

            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();

            uut.set(&storage, felt!("0x1").view_bits(), felt!("0x0"))
                .unwrap();

            uut.set(&storage, felt!("0x86").view_bits(), felt!("0x1"))
                .unwrap();

            uut.set(&storage, felt!("0x87").view_bits(), felt!("0x2"))
                .unwrap();

            let root = commit_and_persist(uut, &mut storage);

            assert_eq!(
                root,
                felt!("0x5458b9f8491e7c845bffa4cd36cdb3a7c29dcdf75f2809bd6f4ce65386facfc")
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
            let leaves = [
                (felt!("0x5"), felt!("0x66")),
                (
                    felt!("0x1BF95D4B58F0741FEA29F94EE5A118D0847C8B7AE0173C2A570C9F74CCA9EA1"),
                    felt!("0x7E5"),
                ),
                (
                    felt!("0x3C75C20765D020B0EC41B48BB8C5338AC4B619FC950D59994E844E1E1B9D2A9"),
                    felt!("0x7C7"),
                ),
                (
                    felt!("0x4065B936C56F5908A981084DAFA66DC17600937DC80C52EEB834693BB811792"),
                    felt!("0x7970C532B764BB36FAF5696B8BC1317505B8A4DC9EEE5DF4994671757975E4D"),
                ),
                (
                    felt!("0x4B5FBB4904167E2E8195C35F7D4E78501A3FE95896794367C85B60B39AEFFC2"),
                    felt!("0x232C969EAFC5B30C20648759D7FA1E2F4256AC6604E1921578101DCE4DFDF48"),
                ),
            ];

            // create test database

            let mut tree = TestTree::empty();
            let storage = TestStorage::default();

            for (key, val) in leaves {
                let key = key.view_bits();
                tree.set(&storage, key, val).unwrap();
            }

            let root = tree.commit().unwrap().root;

            let expected =
                felt!("0x6ee9a8202b40f3f76f1a132f953faa2df78b3b33ccb2b4406431abdc99c2dfe");

            assert_eq!(root, expected);
        }
    }

    mod dfs {
        use super::{BinaryNode, EdgeNode, InternalNode, TestStorage, TestTree, Visit};
        use bitvec::slice::BitSlice;
        use bitvec::{bitvec, prelude::Msb0};
        use pathfinder_common::felt;
        use std::cell::RefCell;
        use std::ops::ControlFlow;
        use std::rc::Rc;

        #[test]
        fn empty_tree() {
            let uut = TestTree::empty();
            let storage = TestStorage::default();

            let mut visited = vec![];
            let mut visitor_fn = |node: &InternalNode, path: &BitSlice<Msb0, u8>| {
                visited.push((node.clone(), path.to_bitvec()));
                ControlFlow::Continue::<(), Visit>(Default::default())
            };
            uut.dfs(&storage, &mut visitor_fn).unwrap();
            assert!(visited.is_empty());
        }

        #[test]
        fn one_leaf() {
            let mut uut = TestTree::empty();
            let storage = TestStorage::default();

            let key = felt!("0x1");
            let value = felt!("0x2");

            uut.set(&storage, key.view_bits(), value).unwrap();

            let mut visited = vec![];
            let mut visitor_fn = |node: &InternalNode, path: &BitSlice<Msb0, u8>| {
                visited.push((node.clone(), path.to_bitvec()));
                ControlFlow::Continue::<(), Visit>(Default::default())
            };
            uut.dfs(&storage, &mut visitor_fn).unwrap();

            assert_eq!(
                visited,
                vec![
                    (
                        InternalNode::Edge(EdgeNode {
                            hash: None,
                            height: 0,
                            path: key.view_bits().into(),
                            child: Rc::new(RefCell::new(InternalNode::Leaf(value)))
                        }),
                        bitvec![Msb0, u8;]
                    ),
                    (InternalNode::Leaf(value), key.view_bits().into())
                ],
            );
        }

        #[test]
        fn two_leaves() {
            let mut uut = TestTree::empty();
            let storage = TestStorage::default();

            let key_left = felt!("0x0");
            let value_left = felt!("0x2");
            let key_right = felt!("0x1");
            let value_right = felt!("0x3");

            uut.set(&storage, key_right.view_bits(), value_right)
                .unwrap();
            uut.set(&storage, key_left.view_bits(), value_left).unwrap();

            let mut visited = vec![];
            let mut visitor_fn = |node: &InternalNode, path: &BitSlice<Msb0, u8>| {
                visited.push((node.clone(), path.to_bitvec()));
                ControlFlow::Continue::<(), Visit>(Default::default())
            };
            uut.dfs(&storage, &mut visitor_fn).unwrap();

            let expected_3 = (
                InternalNode::Leaf(value_right),
                key_right.view_bits().into(),
            );
            let expected_2 = (InternalNode::Leaf(value_left), key_left.view_bits().into());
            let expected_1 = (
                InternalNode::Binary(BinaryNode {
                    hash: None,
                    height: 250,
                    left: Rc::new(RefCell::new(expected_2.0.clone())),
                    right: Rc::new(RefCell::new(expected_3.0.clone())),
                }),
                bitvec![Msb0, u8; 0; 250],
            );
            let expected_0 = (
                InternalNode::Edge(EdgeNode {
                    hash: None,
                    height: 0,
                    path: bitvec![Msb0, u8; 0; 250],
                    child: Rc::new(RefCell::new(expected_1.0.clone())),
                }),
                bitvec![Msb0, u8;],
            );

            pretty_assertions::assert_eq!(
                visited,
                vec![expected_0, expected_1, expected_2, expected_3]
            );
        }

        #[test]
        fn three_leaves() {
            let mut uut = TestTree::empty();
            let storage = TestStorage::default();

            let key_a = felt!("0x10");
            let value_a = felt!("0xa");
            let key_b = felt!("0x11");
            let value_b = felt!("0xb");
            let key_c = felt!("0x13");
            let value_c = felt!("0xc");

            uut.set(&storage, key_c.view_bits(), value_c).unwrap();
            uut.set(&storage, key_a.view_bits(), value_a).unwrap();
            uut.set(&storage, key_b.view_bits(), value_b).unwrap();

            let mut visited = vec![];
            let mut visitor_fn = |node: &InternalNode, path: &BitSlice<Msb0, u8>| {
                visited.push((node.clone(), path.to_bitvec()));
                ControlFlow::Continue::<(), Visit>(Default::default())
            };
            uut.dfs(&storage, &mut visitor_fn).unwrap();

            // 0
            // |
            // 1
            // |\
            // 2 5
            // |\ \
            // 3 4 6
            // a b c

            let path_to_0 = bitvec![Msb0, u8;];
            let path_to_1 = {
                let mut p = bitvec![Msb0, u8; 0; 249];
                *p.get_mut(246).unwrap() = true;
                p
            };
            let mut path_to_2 = path_to_1.clone();
            path_to_2.push(false);
            let mut path_to_5 = path_to_1.clone();
            path_to_5.push(true);

            let expected_6 = (InternalNode::Leaf(value_c), key_c.view_bits().into());
            let expected_5 = (
                InternalNode::Edge(EdgeNode {
                    hash: None,
                    height: 250,
                    path: bitvec![Msb0, u8; 1; 1],
                    child: Rc::new(RefCell::new(expected_6.0.clone())),
                }),
                path_to_5,
            );
            let expected_4 = (InternalNode::Leaf(value_b), key_b.view_bits().into());
            let expected_3 = (InternalNode::Leaf(value_a), key_a.view_bits().into());
            let expected_2 = (
                InternalNode::Binary(BinaryNode {
                    hash: None,
                    height: 250,
                    left: Rc::new(RefCell::new(expected_3.0.clone())),
                    right: Rc::new(RefCell::new(expected_4.0.clone())),
                }),
                path_to_2,
            );
            let expected_1 = (
                InternalNode::Binary(BinaryNode {
                    hash: None,
                    height: 249,
                    left: Rc::new(RefCell::new(expected_2.0.clone())),
                    right: Rc::new(RefCell::new(expected_5.0.clone())),
                }),
                path_to_1.clone(),
            );
            let expected_0 = (
                InternalNode::Edge(EdgeNode {
                    hash: None,
                    height: 0,
                    path: path_to_1,
                    child: Rc::new(RefCell::new(expected_1.0.clone())),
                }),
                path_to_0,
            );

            pretty_assertions::assert_eq!(
                visited,
                vec![
                    expected_0, expected_1, expected_2, expected_3, expected_4, expected_5,
                    expected_6
                ]
            );
        }
    }

    mod proofs {
        use crate::storage::Storage;
        use crate::tree::tests::commit_and_persist;
        use pathfinder_common::hash::{FeltHash, PedersenHash};
        use pathfinder_common::trie::TrieNode;

        use super::{Direction, MerkleTree, TestStorage, TestTree};
        use bitvec::prelude::Msb0;
        use bitvec::slice::BitSlice;
        use pathfinder_common::felt;
        use stark_hash::Felt;

        #[derive(Debug, PartialEq, Eq)]
        pub enum Membership {
            Member,
            NonMember,
        }

        /// Verifies that the key `key` with value `value` is indeed part of the MPT that has root
        /// `root`, given `proofs`.
        /// Supports proofs of non-membership as well as proof of membership: this function returns
        /// an enum corresponding to the membership of `value`, or returns `None` in case of a hash mismatch.
        /// The algorithm follows this logic:
        /// 1. init expected_hash <- root hash
        /// 2. loop over nodes: current <- nodes[i]
        ///    1. verify the current node's hash matches expected_hash (if not then we have a bad proof)
        ///    2. move towards the target - if current is:
        ///       1. binary node then choose the child that moves towards the target, else if
        ///       2. edge node then check the path against the target bits
        ///          1. If it matches then proceed with the child, else
        ///          2. if it does not match then we now have a proof that the target does not exist
        ///    3. nibble off target bits according to which child you got in (2). If all bits are gone then you
        ///       have reached the target and the child hash is the value you wanted and the proof is complete.
        ///    4. set expected_hash <- to the child hash
        /// 3. check that the expected_hash is `value` (we should've reached the leaf)
        fn verify_proof(
            root: Felt,
            key: &BitSlice<Msb0, u8>,
            value: Felt,
            proofs: &[TrieNode],
        ) -> Option<Membership> {
            // Protect from ill-formed keys
            if key.len() != 251 {
                return None;
            }

            let mut expected_hash = root;
            let mut remaining_path: &BitSlice<Msb0, u8> = key;

            for proof_node in proofs.iter() {
                // Hash mismatch? Return None.
                if proof_node.hash::<PedersenHash>() != expected_hash {
                    return None;
                }
                match proof_node {
                    TrieNode::Binary { left, right } => {
                        // Direction will always correspond to the 0th index
                        // because we're removing bits on every iteration.
                        let direction = Direction::from(remaining_path[0]);

                        // Set the next hash to be the left or right hash,
                        // depending on the direction
                        expected_hash = match direction {
                            Direction::Left => *left,
                            Direction::Right => *right,
                        };

                        // Advance by a single bit
                        remaining_path = &remaining_path[1..];
                    }
                    TrieNode::Edge { child, path } => {
                        if path != &remaining_path[..path.len()] {
                            // If paths don't match, we've found a proof of non membership because we:
                            // 1. Correctly moved towards the target insofar as is possible, and
                            // 2. hashing all the nodes along the path does result in the root hash, which means
                            // 3. the target definitely does not exist in this tree
                            return Some(Membership::NonMember);
                        }

                        // Set the next hash to the child's hash
                        expected_hash = *child;

                        // Advance by the whole edge path
                        remaining_path = &remaining_path[path.len()..];
                    }
                }
            }

            // At this point, we should reach `value` !
            if expected_hash == value {
                Some(Membership::Member)
            } else {
                // Hash mismatch. Return `None`.
                None
            }
        }

        /// Structure representing a randomly generated tree.
        struct RandomTree {
            keys: Vec<Felt>,
            values: Vec<Felt>,
            root: Felt,
            tree: MerkleTree<PedersenHash, 251>,
            storage: TestStorage,
        }

        impl RandomTree {
            /// Creates a new random tree with `len` key / value pairs.
            fn new(len: usize) -> Self {
                let mut uut = TestTree::empty();
                let mut storage = TestStorage::default();

                // Create random keys
                let keys: Vec<Felt> = gen_random_hashes(len);

                // Create random values
                let values: Vec<Felt> = gen_random_hashes(len);

                // Insert them
                keys.iter()
                    .zip(values.iter())
                    .for_each(|(k, v)| uut.set(&storage, k.view_bits(), *v).unwrap());

                let root = commit_and_persist(uut, &mut storage);
                let tree = TestTree::new(root);

                Self {
                    keys,
                    values,
                    root,
                    tree,
                    storage,
                }
            }

            /// Calls `get_proof` and `verify_proof` on every key/value pair in the random_tree.
            fn verify(&mut self) {
                let keys_bits: Vec<&BitSlice<Msb0, u8>> =
                    self.keys.iter().map(|k| k.view_bits()).collect();
                let proofs = get_proofs(&keys_bits, &self.tree, &self.storage).unwrap();
                keys_bits
                    .iter()
                    .zip(self.values.iter())
                    .enumerate()
                    .for_each(|(i, (k, v))| {
                        let verified = verify_proof(self.root, k, *v, &proofs[i]).unwrap();
                        assert_eq!(verified, Membership::Member, "Failed to prove key");
                    });
            }
        }

        /// Generates a storage proof for each `key` in `keys` and returns the result in the form of an array.
        fn get_proofs<H: FeltHash, const HEIGHT: usize>(
            keys: &'_ [&BitSlice<Msb0, u8>],
            tree: &MerkleTree<H, HEIGHT>,
            storage: &impl Storage,
        ) -> anyhow::Result<Vec<Vec<TrieNode>>> {
            keys.iter().map(|k| tree.get_proof(storage, k)).collect()
        }

        #[test]
        fn simple_binary() {
            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();

            //   (250, 0, x1)
            //        |
            //     (0,0,x1)
            //      /    \
            //     (2)  (3)

            let key_1 = felt!("0x0"); // 0b01
            let key_2 = felt!("0x1"); // 0b01

            let key1 = key_1.view_bits();
            let key2 = key_2.view_bits();
            let keys = [key1, key2];

            let value_1 = felt!("0x2");
            let value_2 = felt!("0x3");

            uut.set(&storage, key1, value_1).unwrap();
            uut.set(&storage, key2, value_2).unwrap();
            let root = commit_and_persist(uut, &mut storage);

            let uut = TestTree::new(root);

            let proofs = get_proofs(&keys, &uut, &storage).unwrap();

            let verified_key1 = verify_proof(root, key1, value_1, &proofs[0]).unwrap();

            assert_eq!(verified_key1, Membership::Member);
        }

        #[test]
        fn double_binary() {
            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();

            //           (249,0,x3)
            //               |
            //           (0, 0, x3)
            //         /            \
            //     (0,0,x1)       (1, 1, 5)
            //      /    \             |
            //     (2)  (3)           (5)

            let key_1 = felt!("0x0"); // 0b01
            let key_2 = felt!("0x1"); // 0b01
            let key_3 = felt!("0x3"); // 0b11

            let key1 = key_1.view_bits();
            let key2 = key_2.view_bits();
            let key3 = key_3.view_bits();
            let keys = [key1, key2, key3];

            let value_1 = felt!("0x2");
            let value_2 = felt!("0x3");
            let value_3 = felt!("0x5");

            uut.set(&storage, key1, value_1).unwrap();
            uut.set(&storage, key2, value_2).unwrap();
            uut.set(&storage, key3, value_3).unwrap();

            let root = commit_and_persist(uut, &mut storage);
            let uut = TestTree::new(root);

            let proofs = get_proofs(&keys, &uut, &storage).unwrap();
            let verified_1 = verify_proof(root, key1, value_1, &proofs[0]).unwrap();
            assert_eq!(verified_1, Membership::Member, "Failed to prove key1");

            let verified_2 = verify_proof(root, key2, value_2, &proofs[1]).unwrap();
            assert_eq!(verified_2, Membership::Member, "Failed to prove key2");

            let verified_key3 = verify_proof(root, key3, value_3, &proofs[2]).unwrap();
            assert_eq!(verified_key3, Membership::Member, "Failed to prove key3");
        }

        #[test]
        fn left_edge() {
            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();

            //  (251,0x00,0x99)
            //       /
            //      /
            //   (0x99)

            let key_1 = felt!("0x0"); // 0b00

            let key1 = key_1.view_bits();
            let keys = [key1];

            let value_1 = felt!("0xaa");

            uut.set(&storage, key1, value_1).unwrap();

            let root = commit_and_persist(uut, &mut storage);
            let uut = TestTree::new(root);

            let proofs = get_proofs(&keys, &uut, &storage).unwrap();
            let verified_1 = verify_proof(root, key1, value_1, &proofs[0]).unwrap();
            assert_eq!(verified_1, Membership::Member, "Failed to prove key1");
        }

        #[test]
        fn left_right_edge() {
            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();

            //  (251,0xff,0xaa)
            //     /
            //     \
            //   (0xaa)

            let key_1 = felt!("0xff"); // 0b11111111

            let key1 = key_1.view_bits();
            let keys = [key1];

            let value_1 = felt!("0xaa");

            uut.set(&storage, key1, value_1).unwrap();

            let root = commit_and_persist(uut, &mut storage);
            let uut = TestTree::new(root);

            let proofs = get_proofs(&keys, &uut, &storage).unwrap();
            let verified_1 = verify_proof(root, key1, value_1, &proofs[0]).unwrap();
            assert_eq!(verified_1, Membership::Member, "Failed to prove key1");
        }

        #[test]
        fn right_most_edge() {
            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();

            //  (251,0x7fff...,0xbb)
            //          \
            //           \
            //          (0xbb)

            let key_1 = felt!("0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 0b111...

            let key1 = key_1.view_bits();
            let keys = [key1];

            let value_1 = felt!("0xbb");

            uut.set(&storage, key1, value_1).unwrap();

            let root = commit_and_persist(uut, &mut storage);
            let uut = TestTree::new(root);

            let proofs = get_proofs(&keys, &uut, &storage).unwrap();
            let verified_1 = verify_proof(root, key1, value_1, &proofs[0]).unwrap();
            assert_eq!(verified_1, Membership::Member, "Failed to prove key1");
        }

        #[test]
        fn binary_root() {
            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();

            //           (0, 0, x)
            //    /                    \
            // (250, 0, cc)     (250, 11111.., dd)
            //    |                     |
            //   (cc)                  (dd)

            let key_1 = felt!("0x0");
            let key_2 = felt!("0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 0b111...

            let key1 = key_1.view_bits();
            let key2 = key_2.view_bits();
            let keys = [key1, key2];

            let value_1 = felt!("0xcc");
            let value_2 = felt!("0xdd");

            uut.set(&storage, key1, value_1).unwrap();
            uut.set(&storage, key2, value_2).unwrap();

            let root = commit_and_persist(uut, &mut storage);
            let uut = TestTree::new(root);

            let proofs = get_proofs(&keys, &uut, &storage).unwrap();
            let verified_1 = verify_proof(root, key1, value_1, &proofs[0]).unwrap();
            assert_eq!(verified_1, Membership::Member, "Failed to prove key1");

            let verified_2 = verify_proof(root, key2, value_2, &proofs[1]).unwrap();
            assert_eq!(verified_2, Membership::Member, "Failed to prove key2");
        }

        /// Generates `n` random [Felt]
        fn gen_random_hashes(n: usize) -> Vec<Felt> {
            let mut out = Vec::with_capacity(n);
            let mut rng = rand::rngs::ThreadRng::default();

            while out.len() < n {
                let sh = Felt::random(&mut rng);
                if sh.has_more_than_251_bits() {
                    continue;
                }
                out.push(sh);
            }

            out
        }

        #[test]
        fn random_tree() {
            const LEN: usize = 256;
            RandomTree::new(LEN).verify();
        }

        #[test]
        fn non_membership() {
            const LEN: usize = 256;

            let random_tree = RandomTree::new(LEN);

            // 1337 code to be able to filter out duplicates in O(n) instead of O(n^2)
            let keys_set: std::collections::HashSet<&Felt> = random_tree.keys.iter().collect();

            let inexistent_keys: Vec<Felt> = gen_random_hashes(LEN)
                .into_iter()
                .filter(|key| !keys_set.contains(key)) // Filter out duplicates if there are any
                .collect();

            let keys_bits: Vec<&BitSlice<Msb0, u8>> =
                inexistent_keys.iter().map(|k| k.view_bits()).collect();
            let proofs = get_proofs(&keys_bits, &random_tree.tree, &random_tree.storage).unwrap();
            keys_bits
                .iter()
                .zip(random_tree.values.iter())
                .enumerate()
                .for_each(|(i, (k, v))| {
                    let verified = verify_proof(random_tree.root, k, *v, &proofs[i]).unwrap();
                    assert_eq!(verified, Membership::NonMember);
                });
        }

        #[test]
        fn invalid_values() {
            const LEN: usize = 256;

            let random_tree = RandomTree::new(LEN);

            // 1337 code to be able to filter out duplicates in O(n) instead of O(n^2)
            let values_set: std::collections::HashSet<&Felt> = random_tree.values.iter().collect();

            let inexistent_values: Vec<Felt> = gen_random_hashes(LEN)
                .into_iter()
                .filter(|value| !values_set.contains(value)) // Filter out duplicates if there are any
                .collect();

            let keys_bits: Vec<&BitSlice<Msb0, u8>> =
                random_tree.keys.iter().map(|k| k.view_bits()).collect();
            let proofs =
                get_proofs(&keys_bits[..], &random_tree.tree, &random_tree.storage).unwrap();

            keys_bits
                .iter()
                .zip(inexistent_values.iter())
                .enumerate()
                .for_each(|(i, (k, v))| {
                    let verified = verify_proof(random_tree.root, k, *v, &proofs[i]);
                    assert!(verified.is_none());
                });
        }

        #[test]
        fn modified_binary_left() {
            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();

            //           (0, 0, x)
            //    /                    \
            // (250, 0, cc)     (250, 11111.., dd)
            //    |                     |
            //   (cc)                  (dd)

            let key_1 = felt!("0x0");
            let key_2 = felt!("0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 0b111...

            let key1 = key_1.view_bits();
            let key2 = key_2.view_bits();
            let keys = [key1, key2];

            let value_1 = felt!("0xcc");
            let value_2 = felt!("0xdd");

            uut.set(&storage, key1, value_1).unwrap();
            uut.set(&storage, key2, value_2).unwrap();

            let root = commit_and_persist(uut, &mut storage);
            let uut = TestTree::new(root);

            let mut proofs = get_proofs(&keys, &uut, &storage).unwrap();

            // Modify the left hash
            let new_node = match &proofs[0][0] {
                TrieNode::Binary { right, .. } => TrieNode::Binary {
                    left: felt!("0x42"),
                    right: *right,
                },
                _ => unreachable!(),
            };
            proofs[0][0] = new_node;

            let verified = verify_proof(root, key1, value_1, &proofs[0]);
            assert!(verified.is_none());
        }

        #[test]
        fn modified_edge_child() {
            let mut uut = TestTree::empty();
            let mut storage = TestStorage::default();

            //           (0, 0, x)
            //    /                    \
            // (250, 0, cc)     (250, 11111.., dd)
            //    |                     |
            //   (cc)                  (dd)

            let key_1 = felt!("0x0");
            let key_2 = felt!("0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 0b111...

            let key1 = key_1.view_bits();
            let key2 = key_2.view_bits();
            let keys = [key1, key2];

            let value_1 = felt!("0xcc");
            let value_2 = felt!("0xdd");

            uut.set(&storage, key1, value_1).unwrap();
            uut.set(&storage, key2, value_2).unwrap();

            let root = commit_and_persist(uut, &mut storage);
            let uut = TestTree::new(root);

            let mut proofs = get_proofs(&keys, &uut, &storage).unwrap();

            // Modify the child hash
            let new_node = match &proofs[0][1] {
                TrieNode::Edge { path, .. } => TrieNode::Edge {
                    child: felt!("0x42"),
                    path: path.clone(),
                },
                _ => unreachable!(),
            };
            proofs[0][1] = new_node;

            let verified = verify_proof(root, key1, value_1, &proofs[0]);
            assert!(verified.is_none());
        }
    }

    #[test]
    fn dfs_on_leaf_to_binary_collision_tree() {
        let mut uut = TestTree::empty();
        let mut storage = TestStorage::default();

        let value = felt!("0x1");
        let key0 = felt!("0xee00").view_bits().to_bitvec();
        let key1 = felt!("0xee01").view_bits().to_bitvec();

        let key2 = felt!("0xffff").view_bits().to_bitvec();
        let hash_of_values = stark_hash::stark_hash(value, value);
        uut.set(&storage, &key2, hash_of_values).unwrap();

        uut.set(&storage, &key0, value).unwrap();
        uut.set(&storage, &key1, value).unwrap();

        let root = commit_and_persist(uut, &mut storage);

        let uut = TestTree::new(root);
        // this used to panic because it did find the binary on dev profile with the leaf hash
        let mut visited = Vec::new();
        uut.dfs(&storage, &mut |n: &_, p: &_| -> ControlFlow<(), Visit> {
            if let InternalNode::Leaf(h) = n {
                visited.push((Felt::from_bits(p).unwrap(), *h));
            }
            std::ops::ControlFlow::Continue(Default::default())
        })
        .unwrap();
        assert_eq!(uut.get(&storage, &key0).unwrap(), Some(value));
        assert_eq!(uut.get(&storage, &key1).unwrap(), Some(value));
        assert_eq!(uut.get(&storage, &key2).unwrap(), Some(hash_of_values));

        assert_eq!(
            visited,
            &[
                (felt!("0xEE00"), felt!("0x1")),
                (felt!("0xEE01"), felt!("0x1")),
                (
                    felt!("0xFFFF"),
                    felt!("0x2EBBD6878F81E49560AE863BD4EF327A417037BF57B63A016130AD0A94C8EAC")
                )
            ]
        );
    }
}
