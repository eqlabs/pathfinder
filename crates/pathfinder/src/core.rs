//! Contains core functions and types that are widely used but have no real
//! home of their own.
//!
//! This includes many trivial wrappers around [StarkHash] which help by providing additional type safety.
use pedersen::StarkHash;

/// The address of a StarkNet contract.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ContractAddress(pub StarkHash);

/// The hash of a StarkNet contract.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ContractHash(pub StarkHash);

/// The hash of StarkNet contract's state. This is the value stored
/// in the global state tree.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ContractStateHash(pub StarkHash);

/// The commitment root of a StarkNet contract. This is the entry-point
/// for a contract's state at a specific point in time via the contract
/// state tree.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ContractRoot(pub StarkHash);

/// The address of a storage element for a StarkNet contract.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct StorageAddress(pub StarkHash);

/// The value of a storage element for a StarkNet contract.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct StorageValue(pub StarkHash);

/// The commitment root of the global StarkNet state. This is the entry-point
/// for the global state at a specific point in time via the global state tree.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct GlobalRoot(pub StarkHash);
