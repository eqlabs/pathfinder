//! Contains core functions and types that are widely used but have no real
//! home of their own.
//!
//! This includes many trivial wrappers around [StarkHash] which help by providing additional type safety.
use pedersen::StarkHash;
use web3::types::H256;

/// The address of a StarkNet contract.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ContractAddress(pub StarkHash);

/// A StarkNet contract's hash. This is a hash over a contract's
/// deployment properties e.g. code and ABI.
///
/// Not to be confused with [ContractStateHash].
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ContractHash(pub StarkHash);

/// A StarkNet contract's state hash. This is the value stored
/// in the global state tree.
///
/// Not to be confused with [ContractHash].
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ContractStateHash(pub StarkHash);

/// A commitment root of a StarkNet contract. This is the entry-point
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

/// A commitment root of the global StarkNet state. This is the entry-point
/// for the global state at a specific point in time via the global state tree.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct GlobalRoot(pub StarkHash);

/// A StarkNet block hash.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct StarknetBlockHash(pub StarkHash);

/// A StarkNet block number.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct StarknetBlockNumber(pub u64);

/// The timestamp of a Starknet block.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct StarknetBlockTimestamp(pub u64);

/// An Ethereum block hash.
#[derive(Debug, Copy, Clone, PartialEq, Hash, Eq)]
pub struct EthereumBlockHash(pub H256);

/// An Ethereum block number.
#[derive(Debug, Copy, Clone, PartialEq, Hash, Eq)]
pub struct EthereumBlockNumber(pub u64);

/// An Ethereum transaction hash.
#[derive(Debug, Copy, Clone, PartialEq, Hash, Eq)]
pub struct EthereumTransactionHash(pub H256);

/// An Ethereum transaction's index within a block.
#[derive(Debug, Copy, Clone, PartialEq, Hash, Eq)]
pub struct EthereumTransactionIndex(pub u64);

/// An Ethereum log's index within a block.
#[derive(Debug, Copy, Clone, PartialEq, Hash, Eq)]
pub struct EthereumLogIndex(pub u64);
