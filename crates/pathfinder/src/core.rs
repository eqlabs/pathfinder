//! Contains core functions and types that are widely used but have no real
//! home of their own.
//!
//! This includes many trivial wrappers around [StarkHash] which help by providing additional type safety.
use pedersen::StarkHash;
use serde::{Deserialize, Serialize};
use web3::types::{H160, H256};

/// The address of a StarkNet contract.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct ContractAddress(pub StarkHash);

/// The salt of a StarkNet contract address.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct ContractAddressSalt(pub StarkHash);

/// A StarkNet contract's hash. This is a hash over a contract's
/// deployment properties e.g. code and ABI.
///
/// Not to be confused with [ContractStateHash].
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractHash(pub StarkHash);

/// A StarkNet contract's state hash. This is the value stored
/// in the global state tree.
///
/// Not to be confused with [ContractHash].
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractStateHash(pub StarkHash);

/// A commitment root of a StarkNet contract. This is the entry-point
/// for a contract's state at a specific point in time via the contract
/// state tree.
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractRoot(pub StarkHash);

/// Entry point of a StarkNet `call`.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct EntryPoint(pub StarkHash);

/// A single parameter passed to a StarkNet `call`.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct CallParam(pub StarkHash);

/// A single parameter passed to a StarkNet contract constructor.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct ConstructorParam(pub StarkHash);

/// A single result value of a StarkNet `call`.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct CallResultValue(pub StarkHash);

/// A single element of a signature used to secure a StarkNet `call`.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct CallSignatureElem(pub StarkHash);

/// A word from a StarkNet contract bytecode.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct ByecodeWord(pub StarkHash);

/// The address of a storage element for a StarkNet contract.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StorageAddress(pub StarkHash);

/// The value of a storage element for a StarkNet contract.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StorageValue(pub StarkHash);

/// A commitment root of the global StarkNet state. This is the entry-point
/// for the global state at a specific point in time via the global state tree.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct GlobalRoot(pub StarkHash);

/// A StarkNet block hash.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetBlockHash(pub StarkHash);

/// A StarkNet block number.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetBlockNumber(pub u64);

/// The timestamp of a Starknet block.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct StarknetBlockTimestamp(pub u64);

/// A StarkNet transaction hash.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetTransactionHash(pub StarkHash);

/// A StarkNet transaction hash.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetTransactionIndex(pub u64);

/// A single element of a signature used to secure a StarkNet transaction.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct TransactionSignatureElem(pub StarkHash);

/// A nonce that is added to an L1 to L2 message in a StarkNet transaction.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct L1ToL2MessageNonce(pub StarkHash);

/// A single element of the payload of an L1 to L2 message in a StarkNet transaction.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct L1ToL2MessagePayloadElem(pub StarkHash);

/// A single element of the payload of an L2 to L1 message in a StarkNet transaction.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct L2ToL1MessagePayloadElem(pub StarkHash);

/// StarkNet transaction event data.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct EventData(pub StarkHash);

/// StarkNet transaction event key.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct EventKey(pub StarkHash);

/// StarkNet chain id.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetChainId(pub H256);

/// StarkNet protocol version.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetProtocolVersion(pub H256);

/// An Ethereum address.
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct EthereumAddress(pub H160);

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
