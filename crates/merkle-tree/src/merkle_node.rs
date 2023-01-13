//! Contains constructs for describing the nodes in a Binary Merkle Patricia Tree
//! used by Starknet.
//!
//! For more information about how these Starknet trees are structured, see
//! [`MerkleTree`](super::merkle_tree::MerkleTree).

use std::{cell::RefCell, rc::Rc};

use bitvec::{order::Msb0, prelude::BitVec, slice::BitSlice};
use stark_hash::Felt;

use crate::Hash;

/// A node in a Binary Merkle-Patricia Tree graph.
#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    /// A node that has not been fetched from storage yet.
    ///
    /// As such, all we know is its hash.
    Unresolved(Felt),
    /// A branch node with exactly two children.
    Binary(BinaryNode),
    /// Describes a path connecting two other nodes.
    Edge(EdgeNode),
    /// A leaf node that contains a value.
    Leaf(Felt),
}

/// Describes the [Node::Binary] variant.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryNode {
    /// The hash of this node. Is [None] if the node
    /// has not yet been committed.
    pub hash: Option<Felt>,
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
    pub hash: Option<Felt>,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub fn direction(&self, key: &BitSlice<Msb0, u8>) -> Direction {
        key[self.height].into()
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

    /// If possible, calculates and sets its own hash value.
    ///
    /// Does nothing if the hash is already [Some].
    ///
    /// If either childs hash is [None], then the hash cannot
    /// be calculated and it will remain [None].
    pub(crate) fn calculate_hash<H: Hash>(&mut self) {
        if self.hash.is_some() {
            return;
        }

        let left = match self.left.borrow().hash() {
            Some(hash) => hash,
            None => unreachable!("subtrees have to be commited first"),
        };

        let right = match self.right.borrow().hash() {
            Some(hash) => hash,
            None => unreachable!("subtrees have to be commited first"),
        };

        self.hash = Some(H::hash(left, right));
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
    /// with the [Felt::ZERO].
    ///
    /// This can occur for the root node in an empty graph.
    pub fn is_empty(&self) -> bool {
        match self {
            Node::Unresolved(hash) => hash == &Felt::ZERO,
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

    pub fn hash(&self) -> Option<Felt> {
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
    pub fn path_matches(&self, key: &BitSlice<Msb0, u8>) -> bool {
        self.path == key[self.height..self.height + self.path.len()]
    }

    /// Returns the common bit prefix between the edge node's path and the given key.
    ///
    /// This is calculated with the edge's height taken into account.
    pub fn common_path(&self, key: &BitSlice<Msb0, u8>) -> &BitSlice<Msb0, u8> {
        let key_path = key.iter().skip(self.height);
        let common_length = key_path
            .zip(self.path.iter())
            .take_while(|(a, b)| a == b)
            .count();

        &self.path[..common_length]
    }

    /// If possible, calculates and sets its own hash value.
    ///
    /// Does nothing if the hash is already [Some].
    ///
    /// If the child's hash is [None], then the hash cannot
    /// be calculated and it will remain [None].
    pub(crate) fn calculate_hash<H: Hash>(&mut self) {
        if self.hash.is_some() {
            return;
        }

        let child = match self.child.borrow().hash() {
            Some(hash) => hash,
            None => unreachable!("subtree has to be commited before"),
        };

        let path = Felt::from_bits(&self.path).unwrap();
        let mut length = [0; 32];
        // Safe as len() is guaranteed to be <= 251
        length[31] = self.path.len() as u8;

        let length = Felt::from_be_bytes(length).unwrap();
        let hash = H::hash(child, path) + length;
        self.hash = Some(hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PedersenHash;

    mod direction {
        use super::*;
        use Direction::*;

        #[test]
        fn invert() {
            assert_eq!(Left.invert(), Right);
            assert_eq!(Right.invert(), Left);
        }

        #[test]
        fn bool_round_trip() {
            assert_eq!(Direction::from(bool::from(Left)), Left);
            assert_eq!(Direction::from(bool::from(Right)), Right);
        }

        #[test]
        fn right_is_true() {
            assert!(bool::from(Right));
        }

        #[test]
        fn left_is_false() {
            assert!(!bool::from(Left));
        }
    }

    mod binary {
        use super::*;
        use bitvec::bitvec;
        use pathfinder_common::felt;

        #[test]
        fn direction() {
            let uut = BinaryNode {
                hash: None,
                height: 1,
                left: Rc::new(RefCell::new(Node::Leaf(felt!("0xabc")))),
                right: Rc::new(RefCell::new(Node::Leaf(felt!("0xdef")))),
            };

            let mut zero_key = bitvec![Msb0, u8; 1; 251];
            zero_key.set(1, false);

            let mut one_key = bitvec![Msb0, u8; 0; 251];
            one_key.set(1, true);

            let zero_direction = uut.direction(&zero_key);
            let one_direction = uut.direction(&one_key);

            assert_eq!(zero_direction, Direction::from(false));
            assert_eq!(one_direction, Direction::from(true));
        }

        #[test]
        fn get_child() {
            let left = Rc::new(RefCell::new(Node::Leaf(felt!("0xabc"))));
            let right = Rc::new(RefCell::new(Node::Leaf(felt!("0xdef"))));

            let uut = BinaryNode {
                hash: None,
                height: 1,
                left: left.clone(),
                right: right.clone(),
            };

            use Direction::*;
            assert_eq!(uut.get_child(Left), left);
            assert_eq!(uut.get_child(Right), right);
        }

        #[test]
        fn hash() {
            // Test data taken from starkware cairo-lang repo:
            // https://github.com/starkware-libs/cairo-lang/blob/fc97bdd8322a7df043c87c371634b26c15ed6cee/src/starkware/starkware_utils/commitment_tree/patricia_tree/nodes_test.py#L14
            //
            // Note that the hash function must be exchanged for `async_stark_hash_func`, otherwise it just uses some other test hash function.
            let expected = Felt::from_hex_str(
                "0615bb8d47888d2987ad0c63fc06e9e771930986a4dd8adc55617febfcf3639e",
            )
            .unwrap();
            let left = felt!("0x1234");
            let right = felt!("0xabcd");

            let left = Rc::new(RefCell::new(Node::Unresolved(left)));
            let right = Rc::new(RefCell::new(Node::Unresolved(right)));

            let mut uut = BinaryNode {
                hash: None,
                height: 0,
                left,
                right,
            };

            uut.calculate_hash::<PedersenHash>();

            assert_eq!(uut.hash, Some(expected));
        }
    }

    mod edge {
        use super::*;
        use bitvec::bitvec;
        use pathfinder_common::felt;

        #[test]
        fn hash() {
            // Test data taken from starkware cairo-lang repo:
            // https://github.com/starkware-libs/cairo-lang/blob/fc97bdd8322a7df043c87c371634b26c15ed6cee/src/starkware/starkware_utils/commitment_tree/patricia_tree/nodes_test.py#L38
            //
            // Note that the hash function must be exchanged for `async_stark_hash_func`, otherwise it just uses some other test hash function.
            let expected = Felt::from_hex_str(
                "1d937094c09b5f8e26a662d21911871e3cbc6858d55cc49af9848ea6fed4e9",
            )
            .unwrap();
            let child = felt!("0x1234ABCD");
            let child = Rc::new(RefCell::new(Node::Unresolved(child)));
            // Path = 42 in binary.
            let path = bitvec![Msb0, u8; 1, 0, 1, 0, 1, 0];

            let mut uut = EdgeNode {
                hash: None,
                height: 0,
                path,
                child,
            };

            uut.calculate_hash::<PedersenHash>();

            assert_eq!(uut.hash, Some(expected));
        }

        mod path_matches {
            use super::*;
            use pathfinder_common::felt;

            #[test]
            fn full() {
                let key = felt!("0x123456789abcdef");
                let child = Rc::new(RefCell::new(Node::Leaf(felt!("0xabc"))));

                let uut = EdgeNode {
                    hash: None,
                    height: 0,
                    path: key.view_bits().to_bitvec(),
                    child,
                };

                assert!(uut.path_matches(key.view_bits()));
            }

            #[test]
            fn prefix() {
                let key = felt!("0x123456789abcdef");
                let child = Rc::new(RefCell::new(Node::Leaf(felt!("0xabc"))));

                let path = key.view_bits()[..45].to_bitvec();

                let uut = EdgeNode {
                    hash: None,
                    height: 0,
                    path,
                    child,
                };

                assert!(uut.path_matches(key.view_bits()));
            }

            #[test]
            fn suffix() {
                let key = felt!("0x123456789abcdef");
                let child = Rc::new(RefCell::new(Node::Leaf(felt!("0xabc"))));

                let path = key.view_bits()[50..].to_bitvec();

                let uut = EdgeNode {
                    hash: None,
                    height: 50,
                    path,
                    child,
                };

                assert!(uut.path_matches(key.view_bits()));
            }

            #[test]
            fn middle_slice() {
                let key = felt!("0x123456789abcdef");
                let child = Rc::new(RefCell::new(Node::Leaf(felt!("0xabc"))));

                let path = key.view_bits()[230..235].to_bitvec();

                let uut = EdgeNode {
                    hash: None,
                    height: 230,
                    path,
                    child,
                };

                assert!(uut.path_matches(key.view_bits()));
            }
        }
    }
}
