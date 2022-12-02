//! Starknet utilises a custom Binary Merkle-Patricia Tree to store and organise its state.
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

use anyhow::Context;
use bitvec::{prelude::BitSlice, prelude::BitVec, prelude::Msb0};
use rusqlite::Transaction;
use serde::Serialize;
use std::ops::ControlFlow;
use std::{cell::RefCell, rc::Rc};

use crate::state::merkle_node::{BinaryNode, Direction, EdgeNode, Node};

use crate::storage::merkle_tree::{
    PersistedBinaryNode, PersistedEdgeNode, PersistedNode, RcNodeStorage,
};

use stark_hash::StarkHash;

/// Backing storage for [`MerkleTree`].
///
/// Default implementation and persistent implementation is the `RcNodeStorage`. Testing/future
/// implementations include [`HashMap`](std::collections::HashMap) and `()` based implementations
/// where the backing storage is not persistent, or doesn't exist at all. The nodes will still be
/// visitable in-memory.
pub trait NodeStorage {
    /// Find a persistent node during a traversal from the storage.
    fn get(&self, key: StarkHash) -> anyhow::Result<Option<PersistedNode>>;

    /// Insert or ignore if already exists `node` to storage under the given `key`.
    ///
    /// This does not imply incrementing the nodes ref count.
    fn upsert(&self, key: StarkHash, node: PersistedNode) -> anyhow::Result<()>;

    /// Decrement previously stored `key`'s reference count. This shouldn't fail for key not found.
    #[cfg(test)]
    fn decrement_ref_count(&self, key: StarkHash) -> anyhow::Result<()>;

    /// Increment previously stored `key`'s reference count. This shouldn't fail for key not found.
    fn increment_ref_count(&self, key: StarkHash) -> anyhow::Result<()>;
}

/// Lightweight representation of [BinaryNode]. Only holds left and right hashes.
#[derive(Debug, PartialEq, Serialize)]
pub struct BinaryProofNode {
    pub left_hash: StarkHash,
    pub right_hash: StarkHash,
}

impl From<&BinaryNode> for ProofNode {
    fn from(bin: &BinaryNode) -> Self {
        Self::Binary(BinaryProofNode {
            left_hash: bin.left.borrow().hash().expect("Node should be committed"),
            right_hash: bin.right.borrow().hash().expect("Node should be committed"),
        })
    }
}

/// Ligthtweight representation of [EdgeNode]. Only holds its path and its child's hash.
#[derive(Debug, PartialEq)]
pub struct EdgeProofNode {
    pub path: BitVec<Msb0, u8>,
    pub child_hash: StarkHash,
}

impl From<&EdgeNode> for ProofNode {
    fn from(edge: &EdgeNode) -> Self {
        Self::Edge(EdgeProofNode {
            path: edge.path.clone(),
            child_hash: edge
                .child
                .borrow()
                .hash()
                .expect("Node should be committed"),
        })
    }
}

/// [ProofNode] s are lightweight versions of their `Node` counterpart.
/// They only consist of [BinaryProofNode] and [EdgeProofNode] because `Leaf`
/// and `Unresolved` nodes should not appear in a proof.
#[derive(Debug, PartialEq)]
pub enum ProofNode {
    Binary(BinaryProofNode),
    Edge(EdgeProofNode),
}

/// A Starknet binary Merkle-Patricia tree with a specific root entry-point and storage.
///
/// This is used to update, mutate and access global Starknet state as well as individual contract states.
///
/// For more information on how this functions internally, see [here](super::merkle_tree).
#[derive(Debug, Clone)]
pub struct MerkleTree<T> {
    storage: T,
    root: Rc<RefCell<Node>>,
    max_height: u8,
}

impl<'tx, 'queries> MerkleTree<RcNodeStorage<'tx, 'queries>> {
    /// Loads an existing tree or creates a new one if it does not yet exist.
    ///
    /// Use the [StarkHash::ZERO] as root if the tree does not yet exist, will otherwise
    /// error if the given hash does not exist.
    ///
    /// The transaction is used for all storage interactions. The transaction
    /// should therefore be committed after all tree mutations are completed.
    ///
    /// Uses an `RcNodeStorage` as backing storage. Tree will be 251 max height; there's no method
    /// currently for loading a non-251 height tree of the storage, as there is none such.
    ///
    /// ### Warning
    ///
    /// None of the `RcNodeStorage` functions rollback on failure. This means that if any error
    /// is encountered, the transaction should be rolled back to prevent database corruption.
    pub fn load(
        table: &str,
        transaction: &'tx Transaction<'tx>,
        root: StarkHash,
    ) -> anyhow::Result<Self> {
        let storage = RcNodeStorage::open(table, transaction)?;
        Self::new(storage, root, 251)
    }
}

impl<T: NodeStorage> MerkleTree<T> {
    /// Removes one instance of the tree and its root from persistent storage.
    ///
    /// This implies decrementing the root's reference count. The root will
    /// only get deleted if the reference count reaches zero. This will in turn
    /// delete all internal nodes and leaves which no longer have a root to connect to.
    ///
    /// This allows for multiple instances of the same tree state to be committed,
    /// without deleting all of them in a single call.
    #[cfg(test)]
    pub fn delete(self) -> anyhow::Result<()> {
        match self.root.borrow().hash() {
            Some(hash) if hash != StarkHash::ZERO => self
                .storage
                .decrement_ref_count(hash)
                .context("Failed to delete tree root"),
            _ => Ok(()),
        }
    }

    /// Less visible initialization for `MerkleTree<T>` as the main entry points should be
    /// [`MerkleTree::<RcNodeStorage>::load`] for persistent trees and [`MerkleTree::empty`] for
    /// transient ones.
    fn new(storage: T, root: StarkHash, max_height: u8) -> anyhow::Result<Self> {
        let root_node = Rc::new(RefCell::new(Node::Unresolved(root)));
        let mut tree = Self {
            storage,
            root: root_node,
            max_height,
        };
        if root != StarkHash::ZERO {
            // Resolve non-zero root node to check that it does exist.
            let root_node = tree
                .resolve(root, 0)
                .context("Failed to resolve root node")?;
            tree.root = Rc::new(RefCell::new(root_node));
        }
        Ok(tree)
    }

    pub fn empty(storage: T, max_height: u8) -> Self {
        Self::new(storage, StarkHash::ZERO, max_height).expect(
            "Since called with ZERO as root, there should not have been a query, and therefore no error",
        )
    }

    /// Persists all changes to storage and returns the new root hash.
    ///
    /// Note that the root is reference counted in storage. Committing the
    /// same tree again will therefore increment the count again.
    pub fn commit(mut self) -> anyhow::Result<StarkHash> {
        self.commit_mut()
    }

    pub fn commit_mut(&mut self) -> anyhow::Result<StarkHash> {
        // Go through tree, collect dirty nodes, calculate their hashes and
        // persist them. Take care to increment ref counts of child nodes. So in order
        // to do this correctly, will have to start back-to-front.
        self.commit_subtree(&mut self.root.borrow_mut())?;
        // unwrap is safe as `commit_subtree` will set the hash.
        let root = self.root.borrow().hash().unwrap();
        self.storage.increment_ref_count(root)?;

        // TODO: (debug only) expand tree assert that no edge node has edge node as child

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
            Unresolved(_) => { /* Unresolved nodes are already persisted. */ }
            Leaf(_) => { /* storage wouldn't persist these even if we asked. */ }
            Binary(binary) if binary.hash.is_some() => { /* not dirty, already persisted */ }
            Edge(edge) if edge.hash.is_some() => { /* not dirty, already persisted */ }

            Binary(binary) => {
                self.commit_subtree(&mut binary.left.borrow_mut())?;
                self.commit_subtree(&mut binary.right.borrow_mut())?;
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
                self.commit_subtree(&mut edge.child.borrow_mut())?;
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

    /// Sets the value of a key. To delete a key, set the value to [StarkHash::ZERO].
    pub fn set(&mut self, key: &BitSlice<Msb0, u8>, value: StarkHash) -> anyhow::Result<()> {
        if value == StarkHash::ZERO {
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
                        let new_path = key[child_height..].to_bitvec();
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

                        let new_direction = Direction::from(key[branch_height]);
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
    /// [`MerkleTree::set`] with value set to [`StarkHash::ZERO`].
    fn delete_leaf(&mut self, key: &BitSlice<Msb0, u8>) -> anyhow::Result<()> {
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
                    self.merge_edges(&mut edge)?;

                    edge
                };
                // Replace the old binary node with the new edge node.
                node.swap(&RefCell::new(Node::Edge(new_edge)));
            }
            None => {
                // We reached the root without a hitting binary node. The new tree
                // must therefore be empty.
                self.root = Rc::new(RefCell::new(Node::Unresolved(StarkHash::ZERO)));
                return Ok(());
            }
        };

        // Check the parent of the new edge. If it is also an edge, then they must merge.
        if let Some(node) = node_iter.next() {
            if let Node::Edge(edge) = &mut *node.borrow_mut() {
                self.merge_edges(edge)?;
            }
        }

        Ok(())
    }

    /// Returns the value stored at key, or `None` if it does not exist.
    pub fn get(&self, key: &BitSlice<Msb0, u8>) -> anyhow::Result<Option<StarkHash>> {
        let result = self
            .traverse(key)?
            .last()
            .and_then(|node| match &*node.borrow() {
                Node::Leaf(value) if !value.is_zero() => Some(*value),
                _ => None,
            });
        Ok(result)
    }

    /// Generates a merkle-proof a given `key`.
    ///
    /// Returns vector of [`ProofNode`] which form a chain from the root to the key,
    /// if it exists, or upto the node which proves that the key does not exist.
    ///
    /// The nodes are returned in order, root first.
    ///
    /// Verification is performed by confirming that:
    ///   1. the chain follows the path of `key`, and
    ///   2. the hashes are correct, and
    ///   3. the root hash matches the known root
    pub fn get_proof(&self, key: &BitSlice<Msb0, u8>) -> anyhow::Result<Vec<ProofNode>> {
        let mut nodes = self.traverse(key)?;

        // Return an empty list if tree is empty.
        let node = match nodes.last() {
            Some(node) => node,
            None => return Ok(Vec::new()),
        };

        // A leaf node is redudant data as the information for it is already contained in the previous node.
        if matches!(&*node.borrow(), Node::Leaf(_)) {
            nodes.pop();
        }

        Ok(nodes
            .iter()
            .map(|node| match &*node.borrow() {
                Node::Binary(bin) => ProofNode::from(bin),
                Node::Edge(edge) => ProofNode::from(edge),
                _ => unreachable!(),
            })
            .collect())
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
    fn traverse(&self, dst: &BitSlice<Msb0, u8>) -> anyhow::Result<Vec<Rc<RefCell<Node>>>> {
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
        if height == self.max_height as usize {
            #[cfg(debug_assertions)]
            match self.storage.get(hash)? {
                Some(PersistedNode::Edge(_) | PersistedNode::Binary(_)) | None => {
                    // some cases are because of collisions, none is the common outcome
                }
                Some(PersistedNode::Leaf) => {
                    // they exist in some databases, but in general we run only release builds
                    // against real databases
                    unreachable!("leaf nodes should no longer exist");
                }
            }
            return Ok(Node::Leaf(hash));
        }

        let node = self
            .storage
            .get(hash)?
            .with_context(|| format!("Node at height {height} does not exist: {hash}"))?;

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
            PersistedNode::Leaf => anyhow::bail!(
                "Retrieved node {hash} is a leaf at {height} out of {}",
                self.max_height
            ),
        };

        Ok(node)
    }

    /// This is a convenience function which merges the edge node with its child __iff__ it is also an edge.
    ///
    /// Does nothing if the child is not also an edge node.
    ///
    /// This can occur when mutating the tree (e.g. deleting a child of a binary node), and is an illegal state
    /// (since edge nodes __must be__ maximal subtrees).
    fn merge_edges(&self, parent: &mut EdgeNode) -> anyhow::Result<()> {
        let resolved_child = match &*parent.child.borrow() {
            Node::Unresolved(hash) => self.resolve(*hash, parent.height + parent.path.len())?,
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
    /// For each node, there will first be a visit for `Node::Unresolved(hash)` followed by visit
    /// at the loaded node when [`Visit::ContinueDeeper`] is returned. At any time the visitor
    /// function can also return `ControlFlow::Break` to stop the visit with the given return
    /// value, which will be returned as `Some(value))` to the caller.
    ///
    /// The visitor function receives the node being visited, as well as the full path to that node.
    ///
    /// Upon successful non-breaking visit of the tree, `None` will be returned.
    #[allow(dead_code)]
    pub fn dfs<X, VisitorFn>(&self, visitor_fn: &mut VisitorFn) -> anyhow::Result<Option<X>>
    where
        VisitorFn: FnMut(&Node, &BitSlice<Msb0, u8>) -> ControlFlow<X, Visit>,
    {
        use bitvec::prelude::bitvec;

        #[allow(dead_code)]
        struct VisitedNode {
            node: Rc<RefCell<Node>>,
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
                    if !matches!(current_node, Node::Unresolved(StarkHash::ZERO)) {
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
                        Node::Binary(b) => {
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
                        Node::Edge(e) => {
                            visiting.push(VisitedNode {
                                node: e.child.clone(),
                                path: {
                                    let mut extended_path = path.clone();
                                    extended_path.extend_from_bitslice(&e.path);
                                    extended_path
                                },
                            });
                        }
                        Node::Leaf(_) => {}
                        Node::Unresolved(hash) => {
                            // Zero means empty tree, so nothing to resolve
                            if hash != &StarkHash::ZERO {
                                visiting.push(VisitedNode {
                                    node: Rc::new(RefCell::new(self.resolve(*hash, path.len())?)),
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

    pub fn into_storage(self) -> T {
        self.storage
    }
}

/// Direction for the [`MerkleTree::dfs`] as the return value of the visitor function.
#[derive(Default)]
pub enum Visit {
    /// Instructs that the visit should visit any subtrees of the current node. This is a no-op for
    /// [`Node::Leaf`].
    #[default]
    ContinueDeeper,
    /// Returning this value for [`Node::Binary`] or [`Node::Edge`] will ignore all of the children
    /// of the node for the rest of the iteration. This is useful because two trees often share a
    /// number of subtrees with earlier blocks. Returning this for [`Node::Leaf`] is a no-op.
    StopSubtree,
}

impl NodeStorage for () {
    fn get(&self, _key: StarkHash) -> anyhow::Result<Option<PersistedNode>> {
        // the rc<refcell> impl will do just fine by without any backing for transaction tree
        // building
        Ok(None)
    }

    fn upsert(&self, _key: StarkHash, _node: PersistedNode) -> anyhow::Result<()> {
        Ok(())
    }

    #[cfg(test)]
    fn decrement_ref_count(&self, _key: StarkHash) -> anyhow::Result<()> {
        Ok(())
    }

    fn increment_ref_count(&self, _key: StarkHash) -> anyhow::Result<()> {
        Ok(())
    }
}

impl NodeStorage for std::cell::RefCell<std::collections::HashMap<StarkHash, PersistedNode>> {
    fn get(&self, key: StarkHash) -> anyhow::Result<Option<PersistedNode>> {
        Ok(self.borrow().get(&key).cloned())
    }

    fn upsert(&self, key: StarkHash, node: PersistedNode) -> anyhow::Result<()> {
        use std::collections::hash_map::Entry::*;
        if !matches!(node, PersistedNode::Leaf) {
            match self.borrow_mut().entry(key) {
                Vacant(ve) => {
                    ve.insert(node);
                }
                Occupied(oe) => {
                    let existing = oe.get();
                    anyhow::ensure!(
                        existing == &node,
                        "trying to upsert a different node over existing? {existing:?} != {node:?}"
                    );
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn decrement_ref_count(&self, _key: StarkHash) -> anyhow::Result<()> {
        Ok(())
    }

    fn increment_ref_count(&self, _key: StarkHash) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::prelude::*;
    use pathfinder_common::starkhash;

    #[test]
    fn get_empty() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();
        let uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

        let key = starkhash!("99cadc82").view_bits().to_bitvec();
        assert_eq!(uut.get(&key).unwrap(), None);
    }

    #[test]
    fn load_bad_root() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        let non_root = starkhash!("99cadc82");
        MerkleTree::load("test", &transaction, non_root).unwrap_err();
    }

    mod set {
        use super::*;

        #[test]
        fn set_get() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let key0 = starkhash!("99cadc82").view_bits().to_bitvec();
            let key1 = starkhash!("901823").view_bits().to_bitvec();
            let key2 = starkhash!("8975").view_bits().to_bitvec();

            let val0 = starkhash!("891127cbaf");
            let val1 = starkhash!("82233127cbaf");
            let val2 = starkhash!("0891124667aacde7cbaf");

            uut.set(&key0, val0).unwrap();
            uut.set(&key1, val1).unwrap();
            uut.set(&key2, val2).unwrap();

            assert_eq!(uut.get(&key0).unwrap(), Some(val0));
            assert_eq!(uut.get(&key1).unwrap(), Some(val1));
            assert_eq!(uut.get(&key2).unwrap(), Some(val2));
        }

        #[test]
        fn overwrite() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let key = starkhash!("0123").view_bits().to_bitvec();
            let old_value = starkhash!("0abc");
            let new_value = starkhash!("0def");

            uut.set(&key, old_value).unwrap();
            uut.set(&key, new_value).unwrap();

            assert_eq!(uut.get(&key).unwrap(), Some(new_value));
        }
    }

    mod tree_state {
        use super::*;

        #[test]
        fn single_leaf() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let key = starkhash!("0123").view_bits().to_bitvec();
            let value = starkhash!("0abc");

            uut.set(&key, value).unwrap();

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
            assert_eq!(leaf, Node::Leaf(value));
        }

        #[test]
        fn binary_middle() {
            let key0 = bitvec![Msb0, u8; 0; 251];

            let mut key1 = bitvec![Msb0, u8; 0; 251];
            key1.set(50, true);

            let value0 = starkhash!("0abc");
            let value1 = starkhash!("0def");

            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            uut.set(&key0, value0).unwrap();
            uut.set(&key1, value1).unwrap();

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

            let mut key1 = bitvec![Msb0, u8; 0; 251];
            key1.set(0, true);

            let value0 = starkhash!("0abc");
            let value1 = starkhash!("0def");

            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            uut.set(&key0, value0).unwrap();
            uut.set(&key1, value1).unwrap();

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
            let key0 = starkhash!("00").view_bits().to_bitvec();
            let key1 = starkhash!("01").view_bits().to_bitvec();
            let value0 = starkhash!("0abc");
            let value1 = starkhash!("0def");

            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            uut.set(&key0, value0).unwrap();
            uut.set(&key1, value1).unwrap();

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
            assert_eq!(child0, Node::Leaf(value0));
            assert_eq!(child1, Node::Leaf(value1));
        }

        #[test]
        fn empty() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            assert_eq!(*uut.root.borrow(), Node::Unresolved(StarkHash::ZERO));
        }
    }

    mod delete_leaf {
        use super::*;

        #[test]
        fn empty() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let key = starkhash!("123abc").view_bits().to_bitvec();
            uut.delete_leaf(&key).unwrap();

            assert_eq!(*uut.root.borrow(), Node::Unresolved(StarkHash::ZERO));
        }

        #[test]
        fn single_insert_and_removal() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let key = starkhash!("0123").view_bits().to_bitvec();
            let value = starkhash!("0abc");

            uut.set(&key, value).unwrap();
            uut.delete_leaf(&key).unwrap();

            assert_eq!(uut.get(&key).unwrap(), None);
            assert_eq!(*uut.root.borrow(), Node::Unresolved(StarkHash::ZERO));
        }

        #[test]
        fn three_leaves_and_one_removal() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let key0 = starkhash!("99cadc82").view_bits().to_bitvec();
            let key1 = starkhash!("901823").view_bits().to_bitvec();
            let key2 = starkhash!("8975").view_bits().to_bitvec();

            let val0 = starkhash!("01");
            let val1 = starkhash!("02");
            let val2 = starkhash!("03");

            uut.set(&key0, val0).unwrap();
            uut.set(&key1, val1).unwrap();
            uut.set(&key2, val2).unwrap();

            uut.delete_leaf(&key1).unwrap();

            assert_eq!(uut.get(&key0).unwrap(), Some(val0));
            assert_eq!(uut.get(&key1).unwrap(), None);
            assert_eq!(uut.get(&key2).unwrap(), Some(val2));
        }
    }

    mod persistence {
        use super::*;

        #[test]
        fn set() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let key0 = starkhash!("99cadc82").view_bits().to_bitvec();
            let key1 = starkhash!("901823").view_bits().to_bitvec();
            let key2 = starkhash!("8975").view_bits().to_bitvec();

            let val0 = starkhash!("01");
            let val1 = starkhash!("02");
            let val2 = starkhash!("03");

            uut.set(&key0, val0).unwrap();
            uut.set(&key1, val1).unwrap();
            uut.set(&key2, val2).unwrap();

            let root = uut.commit().unwrap();

            let uut = MerkleTree::load("test", &transaction, root).unwrap();

            assert_eq!(uut.get(&key0).unwrap(), Some(val0));
            assert_eq!(uut.get(&key1).unwrap(), Some(val1));
            assert_eq!(uut.get(&key2).unwrap(), Some(val2));
        }

        #[test]
        fn delete_leaf_regression() {
            // This test exercises a bug in the merging of edge nodes. It was caused
            // by the merge code not resolving unresolved nodes. This meant that
            // unresolved edge nodes would not get merged with the parent edge node
            // causing a malformed tree.
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let leaves = [
                (
                    starkhash!("01A2FD9B06EAB5BCA4D3885EE4C42736E835A57399FF8B7F6083A92FD2A20095"),
                    starkhash!("0215AA555E0CE3E462423D18B7216378D3CCD5D94D724AC7897FBC83FAAA4ED4"),
                ),
                (
                    starkhash!("07AC69285B869DC3E8B305C748A0B867B2DE3027AECEBA51158ECA3B7354D76F"),
                    starkhash!("065C85592F29501D97A2EA1CCF2BA867E6A838D602F4E7A7391EFCBF66958386"),
                ),
                (
                    starkhash!("05C71AB5EF6A5E9DBC7EFD5C61554AB36039F60E5BA076833102E24344524566"),
                    starkhash!("060970DF8E8A19AF3F41B78E93B845EC074A0AED4E96D18C6633580722B93A28"),
                ),
                (
                    starkhash!("0000000000000000000000000000000000000000000000000000000000000005"),
                    starkhash!("000000000000000000000000000000000000000000000000000000000000022B"),
                ),
                (
                    starkhash!("0000000000000000000000000000000000000000000000000000000000000005"),
                    starkhash!("0000000000000000000000000000000000000000000000000000000000000000"),
                ),
            ];

            // Add the first four leaves and commit them to storage.
            for (key, val) in &leaves[..4] {
                let key = key.view_bits();
                uut.set(key, *val).unwrap();
            }
            let root = uut.commit().unwrap();

            // Delete the final leaf; this exercises the bug as the nodes are all in storage (unresolved).
            let mut uut = MerkleTree::load("test", &transaction, root).unwrap();
            let key = leaves[4].0.view_bits().to_bitvec();
            let val = leaves[4].1;
            uut.set(&key, val).unwrap();
            let root = uut.commit().unwrap();
            let expect =
                starkhash!("05f3b2b98faef39c60dbbb459dbe63d1d10f1688af47fbc032f2cab025def896");
            assert_eq!(root, expect);
        }

        mod consecutive_roots {
            use super::*;

            #[test]
            fn set_get() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();

                let key0 = starkhash!("99cadc82").view_bits().to_bitvec();
                let key1 = starkhash!("901823").view_bits().to_bitvec();
                let key2 = starkhash!("8975").view_bits().to_bitvec();

                let val0 = starkhash!("01");
                let val1 = starkhash!("02");
                let val2 = starkhash!("03");

                let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();
                uut.set(&key0, val0).unwrap();
                let root0 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test", &transaction, root0).unwrap();
                uut.set(&key1, val1).unwrap();
                let root1 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test", &transaction, root1).unwrap();
                uut.set(&key2, val2).unwrap();
                let root2 = uut.commit().unwrap();

                let uut = MerkleTree::load("test", &transaction, root0).unwrap();
                assert_eq!(uut.get(&key0).unwrap(), Some(val0));
                assert_eq!(uut.get(&key1).unwrap(), None);
                assert_eq!(uut.get(&key2).unwrap(), None);

                let uut = MerkleTree::load("test", &transaction, root1).unwrap();
                assert_eq!(uut.get(&key0).unwrap(), Some(val0));
                assert_eq!(uut.get(&key1).unwrap(), Some(val1));
                assert_eq!(uut.get(&key2).unwrap(), None);

                let uut = MerkleTree::load("test", &transaction, root2).unwrap();
                assert_eq!(uut.get(&key0).unwrap(), Some(val0));
                assert_eq!(uut.get(&key1).unwrap(), Some(val1));
                assert_eq!(uut.get(&key2).unwrap(), Some(val2));
            }

            #[test]
            fn delete() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();

                let key0 = starkhash!("99cadc82").view_bits().to_bitvec();
                let key1 = starkhash!("901823").view_bits().to_bitvec();
                let key2 = starkhash!("8975").view_bits().to_bitvec();

                let val0 = starkhash!("01");
                let val1 = starkhash!("02");
                let val2 = starkhash!("03");

                let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();
                uut.set(&key0, val0).unwrap();
                let root0 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test", &transaction, root0).unwrap();
                uut.set(&key1, val1).unwrap();
                let root1 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test", &transaction, root1).unwrap();
                uut.set(&key2, val2).unwrap();
                let root2 = uut.commit().unwrap();

                let uut = MerkleTree::load("test", &transaction, root1).unwrap();
                uut.delete().unwrap();

                let uut = MerkleTree::load("test", &transaction, root0).unwrap();
                assert_eq!(uut.get(&key0).unwrap(), Some(val0));
                assert_eq!(uut.get(&key1).unwrap(), None);
                assert_eq!(uut.get(&key2).unwrap(), None);

                MerkleTree::load("test", &transaction, root1).unwrap_err();

                let uut = MerkleTree::load("test", &transaction, root2).unwrap();
                assert_eq!(uut.get(&key0).unwrap(), Some(val0));
                assert_eq!(uut.get(&key1).unwrap(), Some(val1));
                assert_eq!(uut.get(&key2).unwrap(), Some(val2));
            }
        }

        mod parallel_roots {
            use super::*;

            #[test]
            fn set_get() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();

                let key0 = starkhash!("99cadc82").view_bits().to_bitvec();
                let key1 = starkhash!("901823").view_bits().to_bitvec();
                let key2 = starkhash!("8975").view_bits().to_bitvec();

                let val0 = starkhash!("01");
                let val1 = starkhash!("02");
                let val2 = starkhash!("03");

                let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();
                uut.set(&key0, val0).unwrap();
                let root0 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test", &transaction, root0).unwrap();
                uut.set(&key1, val1).unwrap();
                let root1 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test", &transaction, root0).unwrap();
                uut.set(&key2, val2).unwrap();
                let root2 = uut.commit().unwrap();

                let uut = MerkleTree::load("test", &transaction, root0).unwrap();
                assert_eq!(uut.get(&key0).unwrap(), Some(val0));
                assert_eq!(uut.get(&key1).unwrap(), None);
                assert_eq!(uut.get(&key2).unwrap(), None);

                let uut = MerkleTree::load("test", &transaction, root1).unwrap();
                assert_eq!(uut.get(&key0).unwrap(), Some(val0));
                assert_eq!(uut.get(&key1).unwrap(), Some(val1));
                assert_eq!(uut.get(&key2).unwrap(), None);

                let uut = MerkleTree::load("test", &transaction, root2).unwrap();
                assert_eq!(uut.get(&key0).unwrap(), Some(val0));
                assert_eq!(uut.get(&key1).unwrap(), None);
                assert_eq!(uut.get(&key2).unwrap(), Some(val2));
            }

            #[test]
            fn delete() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();

                let key0 = starkhash!("99cadc82").view_bits().to_bitvec();
                let key1 = starkhash!("901823").view_bits().to_bitvec();
                let key2 = starkhash!("8975").view_bits().to_bitvec();

                let val0 = starkhash!("01");
                let val1 = starkhash!("02");
                let val2 = starkhash!("03");

                let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();
                uut.set(&key0, val0).unwrap();
                let root0 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test", &transaction, root0).unwrap();
                uut.set(&key1, val1).unwrap();
                let root1 = uut.commit().unwrap();

                let mut uut = MerkleTree::load("test", &transaction, root0).unwrap();
                uut.set(&key2, val2).unwrap();
                let root2 = uut.commit().unwrap();

                let uut = MerkleTree::load("test", &transaction, root1).unwrap();
                uut.delete().unwrap();

                let uut = MerkleTree::load("test", &transaction, root0).unwrap();
                assert_eq!(uut.get(&key0).unwrap(), Some(val0));
                assert_eq!(uut.get(&key1).unwrap(), None);
                assert_eq!(uut.get(&key2).unwrap(), None);

                MerkleTree::load("test", &transaction, root1).unwrap_err();

                let uut = MerkleTree::load("test", &transaction, root2).unwrap();
                assert_eq!(uut.get(&key0).unwrap(), Some(val0));
                assert_eq!(uut.get(&key1).unwrap(), None);
                assert_eq!(uut.get(&key2).unwrap(), Some(val2));
            }
        }

        #[test]
        fn multiple_identical_roots() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let key = starkhash!("99cadc82").view_bits().to_bitvec();
            let val = starkhash!("12345678");
            uut.set(&key, val).unwrap();

            let root0 = uut.commit().unwrap();

            let uut = MerkleTree::load("test", &transaction, root0).unwrap();
            let root1 = uut.commit().unwrap();

            let uut = MerkleTree::load("test", &transaction, root1).unwrap();
            let root2 = uut.commit().unwrap();

            assert_eq!(root0, root1);
            assert_eq!(root0, root2);

            let uut = MerkleTree::load("test", &transaction, root0).unwrap();
            uut.delete().unwrap();

            let uut = MerkleTree::load("test", &transaction, root0).unwrap();
            assert_eq!(uut.get(&key).unwrap(), Some(val));

            let uut = MerkleTree::load("test", &transaction, root0).unwrap();
            uut.delete().unwrap();

            let uut = MerkleTree::load("test", &transaction, root0).unwrap();
            assert_eq!(uut.get(&key).unwrap(), Some(val));

            let uut = MerkleTree::load("test", &transaction, root0).unwrap();
            uut.delete().unwrap();

            // This should fail since the root has been deleted.
            MerkleTree::load("test", &transaction, root0).unwrap_err();
        }
    }

    mod real_world {
        use super::*;
        use pathfinder_common::starkhash;

        #[test]
        fn simple() {
            // Test data created from Starknet cairo wrangling.

            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            uut.set(starkhash!("01").view_bits(), starkhash!("00"))
                .unwrap();

            uut.set(starkhash!("86").view_bits(), starkhash!("01"))
                .unwrap();

            uut.set(starkhash!("87").view_bits(), starkhash!("02"))
                .unwrap();

            let root = uut.commit().unwrap();

            assert_eq!(
                root,
                starkhash!("05458b9f8491e7c845bffa4cd36cdb3a7c29dcdf75f2809bd6f4ce65386facfc")
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
                (starkhash!("05"), starkhash!("66")),
                (
                    starkhash!("01BF95D4B58F0741FEA29F94EE5A118D0847C8B7AE0173C2A570C9F74CCA9EA1"),
                    starkhash!("07E5"),
                ),
                (
                    starkhash!("03C75C20765D020B0EC41B48BB8C5338AC4B619FC950D59994E844E1E1B9D2A9"),
                    starkhash!("07C7"),
                ),
                (
                    starkhash!("04065B936C56F5908A981084DAFA66DC17600937DC80C52EEB834693BB811792"),
                    starkhash!("07970C532B764BB36FAF5696B8BC1317505B8A4DC9EEE5DF4994671757975E4D"),
                ),
                (
                    starkhash!("04B5FBB4904167E2E8195C35F7D4E78501A3FE95896794367C85B60B39AEFFC2"),
                    starkhash!("0232C969EAFC5B30C20648759D7FA1E2F4256AC6604E1921578101DCE4DFDF48"),
                ),
            ];

            // create test database
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();

            let mut tree = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            for (key, val) in leaves {
                let key = key.view_bits();
                tree.set(key, val).unwrap();
            }

            let root = tree.commit().unwrap();

            let expected =
                starkhash!("06ee9a8202b40f3f76f1a132f953faa2df78b3b33ccb2b4406431abdc99c2dfe");

            assert_eq!(root, expected);
        }
    }

    mod dfs {
        use super::{BinaryNode, EdgeNode, MerkleTree, Node, Visit};
        use bitvec::slice::BitSlice;
        use bitvec::{bitvec, prelude::Msb0};
        use pathfinder_common::starkhash;
        use stark_hash::StarkHash;
        use std::cell::RefCell;
        use std::ops::ControlFlow;
        use std::rc::Rc;

        #[test]
        fn empty_tree() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let mut visited = vec![];
            let mut visitor_fn = |node: &Node, path: &BitSlice<Msb0, u8>| {
                visited.push((node.clone(), path.to_bitvec()));
                ControlFlow::Continue::<(), Visit>(Default::default())
            };
            uut.dfs(&mut visitor_fn).unwrap();
            assert!(visited.is_empty());
        }

        #[test]
        fn one_leaf() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let key = starkhash!("01");
            let value = starkhash!("02");

            uut.set(key.view_bits(), value).unwrap();

            let mut visited = vec![];
            let mut visitor_fn = |node: &Node, path: &BitSlice<Msb0, u8>| {
                visited.push((node.clone(), path.to_bitvec()));
                ControlFlow::Continue::<(), Visit>(Default::default())
            };
            uut.dfs(&mut visitor_fn).unwrap();

            assert_eq!(
                visited,
                vec![
                    (
                        Node::Edge(EdgeNode {
                            hash: None,
                            height: 0,
                            path: key.view_bits().into(),
                            child: Rc::new(RefCell::new(Node::Leaf(value)))
                        }),
                        bitvec![Msb0, u8;]
                    ),
                    (Node::Leaf(value), key.view_bits().into())
                ],
            );
        }

        #[test]
        fn two_leaves() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let key_left = starkhash!("00");
            let value_left = starkhash!("02");
            let key_right = starkhash!("01");
            let value_right = starkhash!("03");

            uut.set(key_right.view_bits(), value_right).unwrap();
            uut.set(key_left.view_bits(), value_left).unwrap();

            let mut visited = vec![];
            let mut visitor_fn = |node: &Node, path: &BitSlice<Msb0, u8>| {
                visited.push((node.clone(), path.to_bitvec()));
                ControlFlow::Continue::<(), Visit>(Default::default())
            };
            uut.dfs(&mut visitor_fn).unwrap();

            let expected_3 = (Node::Leaf(value_right), key_right.view_bits().into());
            let expected_2 = (Node::Leaf(value_left), key_left.view_bits().into());
            let expected_1 = (
                Node::Binary(BinaryNode {
                    hash: None,
                    height: 250,
                    left: Rc::new(RefCell::new(expected_2.0.clone())),
                    right: Rc::new(RefCell::new(expected_3.0.clone())),
                }),
                bitvec![Msb0, u8; 0; 250],
            );
            let expected_0 = (
                Node::Edge(EdgeNode {
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
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            let key_a = starkhash!("10");
            let value_a = starkhash!("0a");
            let key_b = starkhash!("11");
            let value_b = starkhash!("0b");
            let key_c = starkhash!("13");
            let value_c = starkhash!("0c");

            uut.set(key_c.view_bits(), value_c).unwrap();
            uut.set(key_a.view_bits(), value_a).unwrap();
            uut.set(key_b.view_bits(), value_b).unwrap();

            let mut visited = vec![];
            let mut visitor_fn = |node: &Node, path: &BitSlice<Msb0, u8>| {
                visited.push((node.clone(), path.to_bitvec()));
                ControlFlow::Continue::<(), Visit>(Default::default())
            };
            uut.dfs(&mut visitor_fn).unwrap();

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

            let expected_6 = (Node::Leaf(value_c), key_c.view_bits().into());
            let expected_5 = (
                Node::Edge(EdgeNode {
                    hash: None,
                    height: 250,
                    path: bitvec![Msb0, u8; 1; 1],
                    child: Rc::new(RefCell::new(expected_6.0.clone())),
                }),
                path_to_5,
            );
            let expected_4 = (Node::Leaf(value_b), key_b.view_bits().into());
            let expected_3 = (Node::Leaf(value_a), key_a.view_bits().into());
            let expected_2 = (
                Node::Binary(BinaryNode {
                    hash: None,
                    height: 250,
                    left: Rc::new(RefCell::new(expected_3.0.clone())),
                    right: Rc::new(RefCell::new(expected_4.0.clone())),
                }),
                path_to_2,
            );
            let expected_1 = (
                Node::Binary(BinaryNode {
                    hash: None,
                    height: 249,
                    left: Rc::new(RefCell::new(expected_2.0.clone())),
                    right: Rc::new(RefCell::new(expected_5.0.clone())),
                }),
                path_to_1.clone(),
            );
            let expected_0 = (
                Node::Edge(EdgeNode {
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
        use super::{
            BinaryProofNode, Direction, EdgeProofNode, MerkleTree, ProofNode, RcNodeStorage,
        };
        use bitvec::prelude::Msb0;
        use bitvec::slice::BitSlice;
        use pathfinder_common::starkhash;
        use rusqlite::Transaction;
        use stark_hash::StarkHash;

        impl EdgeProofNode {
            fn hash(&self) -> StarkHash {
                // Code taken from [merkle_node::EdgeNode::calculate_hash]
                let child_hash = self.child_hash;

                // Path should be valid, so `unwrap()` is safe to use here.
                let path = StarkHash::from_bits(&self.path).unwrap();
                let mut length = [0; 32];
                // Safe as len() is guaranteed to be <= 251
                length[31] = self.path.len() as u8;

                // Length should be smaller than the maximum size of a stark hash.
                let length = StarkHash::from_be_bytes(length).unwrap();

                stark_hash::stark_hash(child_hash, path) + length
            }
        }

        impl BinaryProofNode {
            fn hash(&self) -> StarkHash {
                // Code taken from [merkle_node::EdgeNode::calculate_hash]
                stark_hash::stark_hash(self.left_hash, self.right_hash)
            }
        }

        impl ProofNode {
            fn hash(&self) -> StarkHash {
                match self {
                    ProofNode::Binary(bin) => bin.hash(),
                    ProofNode::Edge(edge) => edge.hash(),
                }
            }
        }

        #[derive(Debug, PartialEq)]
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
        /// 1. verify the current node's hash matches expected_hash (if not then we have a bad proof)
        /// 2. move towards the target - if current is:
        ///    1. binary node then choose the child that moves towards the target, else if
        ///    2. edge node then check the path against the target bits
        ///       1. If it matches then proceed with the child, else
        ///       2. if it does not match then we now have a proof that the target does not exist
        /// 3. nibble off target bits according to which child you got in (2). If all bits are gone then you have reached the target and the child hash is the value you wanted and the proof is complete.
        /// 4. set expected_hash <- to the child hash
        fn verify_proof(
            root: StarkHash,
            key: &BitSlice<Msb0, u8>,
            value: StarkHash,
            proofs: &Vec<ProofNode>,
        ) -> Option<Membership> {
            // Protect from ill-formed keys
            if key.len() != 251 {
                return None;
            }

            let mut expected_hash = root;
            let mut remaining_path: &BitSlice<Msb0, u8> = key;

            for proof_node in proofs.iter() {
                // Hash mismatch? Return None.
                if proof_node.hash() != expected_hash {
                    return None;
                }
                match proof_node {
                    ProofNode::Binary(bin) => {
                        // Direction will always correspond to the 0th index
                        // because we're removing bits on every iteration.
                        let direction = Direction::from(remaining_path[0]);

                        // Set the next hash to be the left or right hash,
                        // depending on the direction
                        expected_hash = match direction {
                            Direction::Left => bin.left_hash,
                            Direction::Right => bin.right_hash,
                        };

                        // Advance by a single bit
                        remaining_path = &remaining_path[1..];
                    }
                    ProofNode::Edge(edge) => {
                        let path_matches = edge.path == remaining_path[..edge.path.len()];
                        if !path_matches {
                            // If paths don't match, we've found a proof of non membership because we:
                            // 1. Correctly moved towards the target insofar as is possible, and
                            // 2. hashing all the nodes along the path does result in the root hash, which means
                            // 3. the target definitely does not exist in this tree
                            return Some(Membership::NonMember);
                        }

                        // Set the next hash to the child's hash
                        expected_hash = edge.child_hash;

                        // Advance by the whole edge path
                        remaining_path = &remaining_path[edge.path.len()..];
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
        struct RandomTree<'tx, 'queries> {
            keys: Vec<StarkHash>,
            values: Vec<StarkHash>,
            root: StarkHash,
            tree: MerkleTree<RcNodeStorage<'tx, 'queries>>,
        }

        impl<'tx> RandomTree<'tx, '_> {
            /// Creates a new random tree with `len` key / value pairs.
            fn new(len: usize, transaction: &'tx Transaction<'tx>) -> Self {
                let mut uut = MerkleTree::load("test", transaction, StarkHash::ZERO).unwrap();

                // Create random keys
                let keys: Vec<StarkHash> = gen_random_hashes(len);

                // Create random values
                let values: Vec<StarkHash> = gen_random_hashes(len);

                // Insert them
                keys.iter()
                    .zip(values.iter())
                    .for_each(|(k, v)| uut.set(k.view_bits(), *v).unwrap());

                let root = uut.commit().unwrap();
                let tree = MerkleTree::load("test", &transaction, root).unwrap();

                Self {
                    keys,
                    values,
                    root,
                    tree,
                }
            }

            /// Calls `get_proof` and `verify_proof` on every key/value pair in the random_tree.
            fn verify(&self) {
                let keys_bits: Vec<&BitSlice<Msb0, u8>> =
                    self.keys.iter().map(|k| k.view_bits()).collect();
                let proofs = get_proofs(&keys_bits, &self.tree).unwrap();
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
        fn get_proofs<'a, 'tx>(
            keys: &'a [&BitSlice<Msb0, u8>],
            tree: &MerkleTree<RcNodeStorage<'tx, '_>>,
        ) -> anyhow::Result<Vec<Vec<ProofNode>>> {
            keys.iter().map(|k| tree.get_proof(k)).collect()
        }

        #[test]
        fn simple_binary() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            //   (250, 0, x1)
            //        |
            //     (0,0,x1)
            //      /    \
            //     (2)  (3)

            let key_1 = starkhash!("00"); // 0b01
            let key_2 = starkhash!("01"); // 0b01

            let key1 = key_1.view_bits();
            let key2 = key_2.view_bits();
            let keys = [key1, key2];

            let value_1 = starkhash!("02");
            let value_2 = starkhash!("03");

            uut.set(key1, value_1).unwrap();
            uut.set(key2, value_2).unwrap();
            let root = uut.commit().unwrap();

            let uut = MerkleTree::load("test", &transaction, root).unwrap();

            let proofs = get_proofs(&keys, &uut).unwrap();

            let verified_key1 = verify_proof(root, key1, value_1, &proofs[0]).unwrap();

            assert_eq!(verified_key1, Membership::Member);
        }

        #[test]
        fn double_binary() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            //           (249,0,x3)
            //               |
            //           (0, 0, x3)
            //         /            \
            //     (0,0,x1)       (1, 1, 5)
            //      /    \          /     \
            //     (2)  (3)       (0)    (5)

            let key_1 = starkhash!("00"); // 0b01
            let key_2 = starkhash!("01"); // 0b01
            let key_3 = starkhash!("03"); // 0b11

            let key1 = key_1.view_bits();
            let key2 = key_2.view_bits();
            let key3 = key_3.view_bits();
            let keys = [key1, key2, key3];

            let value_1 = starkhash!("02");
            let value_2 = starkhash!("03");
            let value_3 = starkhash!("05");

            uut.set(key1, value_1).unwrap();
            uut.set(key2, value_2).unwrap();
            uut.set(key3, value_3).unwrap();

            let root = uut.commit().unwrap();
            let uut = MerkleTree::load("test", &transaction, root).unwrap();

            let proofs = get_proofs(&keys, &uut).unwrap();
            let verified_1 = verify_proof(root, key1, value_1, &proofs[0]).unwrap();
            assert_eq!(verified_1, Membership::Member, "Failed to prove key1");

            let verified_2 = verify_proof(root, key2, value_2, &proofs[1]).unwrap();
            assert_eq!(verified_2, Membership::Member, "Failed to prove key2");

            let verified_key3 = verify_proof(root, key3, value_3, &proofs[2]).unwrap();
            assert_eq!(verified_key3, Membership::Member, "Failed to prove key3");
        }

        #[test]
        fn left_edge() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            //  (251,0x00,0x99)
            //       /
            //      /
            //   (0x99)

            let key_1 = starkhash!("00"); // 0b00

            let key1 = key_1.view_bits();
            let keys = [key1];

            let value_1 = starkhash!("aa");

            uut.set(key1, value_1).unwrap();

            let root = uut.commit().unwrap();
            let uut = MerkleTree::load("test", &transaction, root).unwrap();

            let proofs = get_proofs(&keys, &uut).unwrap();
            let verified_1 = verify_proof(root, key1, value_1, &proofs[0]).unwrap();
            assert_eq!(verified_1, Membership::Member, "Failed to prove key1");
        }

        #[test]
        fn left_right_edge() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            //  (251,0xff,0xaa)
            //     /
            //     \
            //   (0xaa)

            let key_1 = starkhash!("ff"); // 0b11111111

            let key1 = key_1.view_bits();
            let keys = [key1];

            let value_1 = starkhash!("aa");

            uut.set(key1, value_1).unwrap();

            let root = uut.commit().unwrap();
            let uut = MerkleTree::load("test", &transaction, root).unwrap();

            let proofs = get_proofs(&keys, &uut).unwrap();
            let verified_1 = verify_proof(root, key1, value_1, &proofs[0]).unwrap();
            assert_eq!(verified_1, Membership::Member, "Failed to prove key1");
        }

        #[test]
        fn right_most_edge() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            //  (251,0x7fff...,0xbb)
            //          \
            //           \
            //          (0xbb)

            let key_1 =
                starkhash!("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 0b111...

            let key1 = key_1.view_bits();
            let keys = [key1];

            let value_1 = starkhash!("bb");

            uut.set(key1, value_1).unwrap();

            let root = uut.commit().unwrap();
            let uut = MerkleTree::load("test", &transaction, root).unwrap();

            let proofs = get_proofs(&keys, &uut).unwrap();
            let verified_1 = verify_proof(root, key1, value_1, &proofs[0]).unwrap();
            assert_eq!(verified_1, Membership::Member, "Failed to prove key1");
        }

        #[test]
        fn binary_root() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            //           (0, 0, x)
            //    /                    \
            // (250, 0, cc)     (250, 11111.., dd)
            //    |                     |
            //   (cc)                  (dd)

            let key_1 = starkhash!("00");
            let key_2 =
                starkhash!("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 0b111...

            let key1 = key_1.view_bits();
            let key2 = key_2.view_bits();
            let keys = [key1, key2];

            let value_1 = starkhash!("cc");
            let value_2 = starkhash!("dd");

            uut.set(key1, value_1).unwrap();
            uut.set(key2, value_2).unwrap();

            let root = uut.commit().unwrap();
            let uut = MerkleTree::load("test", &transaction, root).unwrap();

            let proofs = get_proofs(&keys, &uut).unwrap();
            let verified_1 = verify_proof(root, key1, value_1, &proofs[0]).unwrap();
            assert_eq!(verified_1, Membership::Member, "Failed to prove key1");

            let verified_2 = verify_proof(root, key2, value_2, &proofs[1]).unwrap();
            assert_eq!(verified_2, Membership::Member, "Failed to prove key2");
        }

        /// Generates `n` random [StarkHash]
        fn gen_random_hashes(n: usize) -> Vec<StarkHash> {
            let mut out = Vec::with_capacity(n);
            let mut rng = rand::rngs::ThreadRng::default();

            while out.len() < n {
                let sh = StarkHash::random(&mut rng);
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
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let random_tree = RandomTree::new(LEN, &transaction);

            random_tree.verify();
        }

        #[test]
        fn non_membership() {
            const LEN: usize = 256;
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();

            let random_tree = RandomTree::new(LEN, &transaction);

            // 1337 code to be able to filter out duplicates in O(n) instead of O(n^2)
            let keys_set: std::collections::HashSet<&StarkHash> = random_tree.keys.iter().collect();

            let inexistent_keys: Vec<StarkHash> = gen_random_hashes(LEN)
                .into_iter()
                .filter(|key| !keys_set.contains(key)) // Filter out duplicates if there are any
                .collect();

            let keys_bits: Vec<&BitSlice<Msb0, u8>> =
                inexistent_keys.iter().map(|k| k.view_bits()).collect();
            let proofs = get_proofs(&keys_bits, &random_tree.tree).unwrap();
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
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();

            let random_tree = RandomTree::new(LEN, &transaction);

            // 1337 code to be able to filter out duplicates in O(n) instead of O(n^2)
            let values_set: std::collections::HashSet<&StarkHash> =
                random_tree.values.iter().collect();

            let inexistent_values: Vec<StarkHash> = gen_random_hashes(LEN)
                .into_iter()
                .filter(|value| !values_set.contains(value)) // Filter out duplicates if there are any
                .collect();

            let keys_bits: Vec<&BitSlice<Msb0, u8>> =
                random_tree.keys.iter().map(|k| k.view_bits()).collect();
            let proofs = get_proofs(&keys_bits[..], &random_tree.tree).unwrap();

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
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            //           (0, 0, x)
            //    /                    \
            // (250, 0, cc)     (250, 11111.., dd)
            //    |                     |
            //   (cc)                  (dd)

            let key_1 = starkhash!("00");
            let key_2 =
                starkhash!("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 0b111...

            let key1 = key_1.view_bits();
            let key2 = key_2.view_bits();
            let keys = [key1, key2];

            let value_1 = starkhash!("cc");
            let value_2 = starkhash!("dd");

            uut.set(key1, value_1).unwrap();
            uut.set(key2, value_2).unwrap();

            let root = uut.commit().unwrap();
            let uut = MerkleTree::load("test", &transaction, root).unwrap();

            let mut proofs = get_proofs(&keys, &uut).unwrap();

            // Modify the left hash
            let to_change = proofs[0].get_mut(0).unwrap();
            match to_change {
                ProofNode::Binary(bin) => bin.left_hash = starkhash!("42"),
                _ => unreachable!(),
            };

            let verified = verify_proof(root, key1, value_1, &proofs[0]);
            assert!(verified.is_none());
        }

        #[test]
        fn modified_edge_child() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();
            let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

            //           (0, 0, x)
            //    /                    \
            // (250, 0, cc)     (250, 11111.., dd)
            //    |                     |
            //   (cc)                  (dd)

            let key_1 = starkhash!("00");
            let key_2 =
                starkhash!("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 0b111...

            let key1 = key_1.view_bits();
            let key2 = key_2.view_bits();
            let keys = [key1, key2];

            let value_1 = starkhash!("cc");
            let value_2 = starkhash!("dd");

            uut.set(key1, value_1).unwrap();
            uut.set(key2, value_2).unwrap();

            let root = uut.commit().unwrap();
            let uut = MerkleTree::load("test", &transaction, root).unwrap();

            let mut proofs = get_proofs(&keys, &uut).unwrap();

            // Modify the child hash
            let to_change = proofs[0].get_mut(1).unwrap();
            match to_change {
                ProofNode::Edge(edge) => edge.child_hash = starkhash!("42"),
                _ => unreachable!(),
            };

            let verified = verify_proof(root, key1, value_1, &proofs[0]);
            assert!(verified.is_none());
        }
    }

    #[test]
    fn dfs_on_leaf_to_binary_collision_tree() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();
        let mut uut = MerkleTree::load("test", &transaction, StarkHash::ZERO).unwrap();

        let value = starkhash!("01");
        let key0 = starkhash!("ee00").view_bits().to_bitvec();
        let key1 = starkhash!("ee01").view_bits().to_bitvec();

        let key2 = starkhash!("ffff").view_bits().to_bitvec();
        let hash_of_values = stark_hash::stark_hash(value, value);
        uut.set(&key2, hash_of_values).unwrap();

        uut.set(&key0, value).unwrap();
        uut.set(&key1, value).unwrap();

        let root = uut.commit().unwrap();

        let uut = MerkleTree::load("test", &transaction, root).unwrap();
        // this used to panic because it did find the binary on dev profile with the leaf hash
        let mut visited = Vec::new();
        uut.dfs(&mut |n: &_, p: &_| -> ControlFlow<(), Visit> {
            if let Node::Leaf(h) = n {
                visited.push((StarkHash::from_bits(p).unwrap(), *h));
            }
            std::ops::ControlFlow::Continue(Default::default())
        })
        .unwrap();
        assert_eq!(uut.get(&key0).unwrap(), Some(value));
        assert_eq!(uut.get(&key1).unwrap(), Some(value));
        assert_eq!(uut.get(&key2).unwrap(), Some(hash_of_values));

        assert_eq!(
            visited,
            &[
                (starkhash!("EE00"), starkhash!("01")),
                (starkhash!("EE01"), starkhash!("01")),
                (
                    starkhash!("FFFF"),
                    starkhash!("02EBBD6878F81E49560AE863BD4EF327A417037BF57B63A016130AD0A94C8EAC")
                )
            ]
        );
    }
}
