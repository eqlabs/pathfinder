//! Contains constructs for describing the nodes in a Binary Merkle Patricia Tree
//! used by Starknet.
//!
//! For more information about how these Starknet trees are structured, see [MerkleTree](super::MerkleTree).

use std::{cell::RefCell, rc::Rc};

use bitvec::{order::Msb0, prelude::BitVec, slice::BitSlice};
use pedersen::StarkHash;

use crate::merkle_tree::ZERO_HASH;

/// A node in a Binary Merkle-Patricia Tree graph.
#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    /// A node that has not been fetched from storage yet.
    ///
    /// As such, all we know is its hash.
    Unresolved(StarkHash),
    /// A branch node with exactly two children.
    Binary(BinaryNode),
    /// Describes a path connecting two other nodes.
    Edge(EdgeNode),
    /// A leaf node that contains a value.
    Leaf(StarkHash),
}

/// Describes the [Node::Binary] variant.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryNode {
    /// The hash of this node. Is [None] if the node
    /// has not yet been committed.
    pub hash: Option<StarkHash>,
    /// The height of this node in the tree.
    pub height: usize,
    /// [Left](Direction::Left) child.
    pub left: Rc<RefCell<Node>>,
    /// [Right](Direction::Right) child.
    pub right: Rc<RefCell<Node>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EdgeNode {
    /// The hash of this node. Is [None] if the node
    /// has not yet been committed.
    pub hash: Option<StarkHash>,
    /// The starting height of this node in the tree.
    pub height: usize,
    /// The path this edge takes.
    pub path: BitVec<Msb0, u8>,
    /// The child of this node.
    pub child: Rc<RefCell<Node>>,
}

/// Describes the direction a child of a [BinaryNode] may have.
///
/// Binary nodes have two children, one left and one right.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Left,
    Right,
}

impl Direction {
    /// Inverts the [Direction].
    ///
    /// [Left] becomes [Right], and [Right] becomes [Left].
    ///
    /// [Left]: Direction::Left
    /// [Right]: Direction::Right
    pub fn invert(self) -> Direction {
        match self {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        }
    }
}

impl From<bool> for Direction {
    fn from(tf: bool) -> Self {
        match tf {
            true => Direction::Right,
            false => Direction::Left,
        }
    }
}

impl From<Direction> for bool {
    fn from(direction: Direction) -> Self {
        match direction {
            Direction::Left => false,
            Direction::Right => true,
        }
    }
}

impl BinaryNode {
    /// Maps the key's bit at the binary node's height to a [Direction].
    ///
    /// This can be used to check which direction the key descibes in the context
    /// of this binary node i.e. which direction the child along the key's path would
    /// take.
    pub fn direction(&self, key: StarkHash) -> Direction {
        key.view_bits()[self.height].into()
    }

    /// Returns the [Left] or [Right] child.
    ///
    /// [Left]: Direction::Left
    /// [Right]: Direction::Right
    pub fn get_child(&self, direction: Direction) -> Rc<RefCell<Node>> {
        match direction {
            Direction::Left => self.left.clone(),
            Direction::Right => self.right.clone(),
        }
    }
}

impl Node {
    /// Convenience function which sets the inner node's hash to [None], if
    /// applicable.
    ///
    /// Used to indicate that this node has been mutated.
    pub fn mark_dirty(&mut self) {
        match self {
            Node::Binary(inner) => inner.hash = None,
            Node::Edge(inner) => inner.hash = None,
            _ => {}
        }
    }

    /// Returns true if the node represents an empty node -- this is defined as a node
    /// with the [ZERO_HASH].
    ///
    /// This can occur for the root node in an empty graph.
    pub fn is_empty(&self) -> bool {
        match self {
            Node::Unresolved(hash) => hash == &ZERO_HASH,
            _ => false,
        }
    }

    pub fn is_binary(&self) -> bool {
        matches!(self, Node::Binary(..))
    }

    pub fn as_binary(&self) -> Option<&BinaryNode> {
        match self {
            Node::Binary(binary) => Some(binary),
            _ => None,
        }
    }

    pub fn as_edge(&self) -> Option<&EdgeNode> {
        match self {
            Node::Edge(edge) => Some(edge),
            _ => None,
        }
    }

    pub fn hash(&self) -> Option<StarkHash> {
        match self {
            Node::Unresolved(hash) => Some(*hash),
            Node::Binary(binary) => binary.hash,
            Node::Edge(edge) => edge.hash,
            Node::Leaf(value) => Some(*value),
        }
    }
}

impl EdgeNode {
    /// Returns true if the edge node's path matches the same path given by the key.
    pub fn path_matches(&self, key: StarkHash) -> bool {
        let key = key.view_bits();
        self.path == key[self.height..self.height + self.path.len()]
    }

    /// Returns the common bit prefix between the edge node's path and the given key.
    ///
    /// This is calculated with the edge's height taken into account.
    pub fn common_path(&self, key: StarkHash) -> &BitSlice<Msb0, u8> {
        let key_path = key.view_bits().iter().skip(self.height);
        let common_length = key_path
            .zip(self.path.iter())
            .take_while(|(a, b)| a == b)
            .count();

        &self.path[..common_length]
    }

    /// This is a convenience function which merges the edge node with its child __iff__ it is also an edge.
    ///
    /// Does nothing if the child is not also an edge node.
    ///
    /// This can occur when mutating the tree (e.g. deleting a child of a binary node), and is an illegal state
    /// (since edge nodes __must be__ maximal subtrees).
    pub fn merge_child_edge(&mut self) {
        // Cannot merge the borrow into the if let as this results in a double borrow
        // when swapping the child's child in.
        let child_edge = self.child.borrow().as_edge().cloned();
        if let Some(child_edge) = child_edge {
            self.path.extend_from_bitslice(&child_edge.path);
            self.child.swap(&child_edge.child.clone());
        }
    }
}
