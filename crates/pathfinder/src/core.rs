//! Contains core functions and types that are widely used but have no real
//! home of their own.
//!
//! This includes many trivial wrappers around [StarkHash] which help by providing additional type safety.
use serde::{Deserialize, Serialize};
use stark_hash::StarkHash;
use web3::types::{H128, H160, H256};

/// The address of a StarkNet contract.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
pub struct ContractAddress(pub StarkHash);

/// The salt of a StarkNet contract address.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord)]
pub struct ContractAddressSalt(pub StarkHash);

/// The hash of a StarkNet contract. This is a hash over a class'
/// deployment properties e.g. code and ABI.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ClassHash(pub StarkHash);

/// A StarkNet contract's state hash. This is the value stored
/// in the global state tree.
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractStateHash(pub StarkHash);

/// A commitment root of a StarkNet contract. This is the entry-point
/// for a contract's state at a specific point in time via the contract
/// state tree.
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractRoot(pub StarkHash);

/// A Starknet contract's bytecode and ABI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractCode {
    pub bytecode: Vec<ByteCodeWord>,
    pub abi: String,
}

// Bytecode and entry point list of a class
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractClass {
    pub program: Vec<ByteCodeWord>,
    // A JSON representation of the entry points
    // We don't actually process this value, just serialize/deserialize
    // from an already validated JSON.
    // This is kept as a Value to avoid dependency on sequencer API types.
    pub entry_points_by_type: serde_json::Value,
}

/// Entry point of a StarkNet `call`.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct EntryPoint(pub StarkHash);

impl EntryPoint {
    /// Returns a new EntryPoint which has been truncated to fit from Keccak256 digest of input.
    ///
    /// See: <https://starknet.io/documentation/contracts/#function_selector>
    pub fn hashed(input: &[u8]) -> Self {
        use sha3::Digest;
        EntryPoint(crate::state::class_hash::truncated_keccak(
            <[u8; 32]>::from(sha3::Keccak256::digest(input)),
        ))
    }
}

/// Offset of an entry point into the bytecode of a StarkNet contract.
///
/// This is a StarkHash because we use it directly for computing the
/// class hashes.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct ByteCodeOffset(pub StarkHash);

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
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct CallSignatureElem(pub StarkHash);

/// A word from a StarkNet contract bytecode.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct ByteCodeWord(pub StarkHash);

/// The address of a storage element for a StarkNet contract.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord)]
pub struct StorageAddress(pub StarkHash);

/// The value of a storage element for a StarkNet contract.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord)]
pub struct StorageValue(pub StarkHash);

/// A commitment root of the global StarkNet state. This is the entry-point
/// for the global state at a specific point in time via the global state tree.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct GlobalRoot(pub StarkHash);

/// A StarkNet block hash.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetBlockHash(pub StarkHash);

/// A StarkNet block number.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StarknetBlockNumber(pub u64);

/// The timestamp of a Starknet block.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetBlockTimestamp(pub u64);

/// A StarkNet transaction hash.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetTransactionHash(pub StarkHash);

/// A StarkNet transaction index.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetTransactionIndex(pub u64);

/// A single element of a signature used to secure a StarkNet transaction.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct TransactionSignatureElem(pub StarkHash);

/// A nonce that is added to an L1 to L2 message in a StarkNet transaction.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct L1ToL2MessageNonce(pub StarkHash);

/// A single element of the payload of an L1 to L2 message in a StarkNet transaction.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct L1ToL2MessagePayloadElem(pub StarkHash);

/// A single element of the payload of an L2 to L1 message in a StarkNet transaction.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct L2ToL1MessagePayloadElem(pub StarkHash);

/// StarkNet transaction event data.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct EventData(pub StarkHash);

/// StarkNet transaction event key.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct EventKey(pub StarkHash);

/// StarkNet sequencer address.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct SequencerAddress(pub StarkHash);

/// StarkNet protocol version.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetProtocolVersion(pub H256);

/// StarkNet fee value.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct Fee(pub H128);

/// StarkNet gas price.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct GasPrice(pub u128);

// Starknet transaction nonce.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct TransactionNonce(pub StarkHash);

/// StarkNet transaction version.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct TransactionVersion(pub H256);

/// An Ethereum address.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
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

/// A way of identifying a specific block.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum BlockId {
    Number(StarknetBlockNumber),
    Hash(StarknetBlockHash),
    Latest,
    Pending,
}

impl StarknetBlockNumber {
    pub const GENESIS: StarknetBlockNumber = StarknetBlockNumber(0);
}

impl std::cmp::PartialOrd for StarknetBlockNumber {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl std::ops::Add<u64> for StarknetBlockNumber {
    type Output = StarknetBlockNumber;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl std::ops::AddAssign<u64> for StarknetBlockNumber {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl std::ops::Sub<u64> for StarknetBlockNumber {
    type Output = StarknetBlockNumber;

    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl std::ops::SubAssign<u64> for StarknetBlockNumber {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

impl std::fmt::Display for StarknetBlockNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Debug for StarknetBlockNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StarknetBlockNumber({})", self.0)
    }
}

impl From<EthereumBlockNumber> for web3::types::BlockId {
    fn from(number: EthereumBlockNumber) -> Self {
        web3::types::BlockId::Number(web3::types::BlockNumber::Number(number.0.into()))
    }
}

impl From<StarknetBlockNumber> for crate::rpc::types::BlockNumberOrTag {
    fn from(number: StarknetBlockNumber) -> Self {
        crate::rpc::types::BlockNumberOrTag::Number(number)
    }
}

impl From<StarknetBlockHash> for crate::rpc::types::BlockHashOrTag {
    fn from(hash: StarknetBlockHash) -> Self {
        crate::rpc::types::BlockHashOrTag::Hash(hash)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("expected slice length of 16 or less, got {0}")]
pub struct FromSliceError(usize);

impl GasPrice {
    pub const ZERO: GasPrice = GasPrice(0u128);

    /// Returns the big-endian representation of this [GasPrice].
    pub fn to_be_bytes(&self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    /// Constructs [GasPrice] from an array of bytes. Big endian byte order is assumed.
    pub fn from_be_bytes(src: [u8; 16]) -> Self {
        Self(u128::from_be_bytes(src))
    }

    /// Constructs [GasPrice] from a slice of bytes. Big endian byte order is assumed.
    pub fn from_be_slice(src: &[u8]) -> Result<Self, FromSliceError> {
        if src.len() > 16 {
            return Err(FromSliceError(src.len()));
        }

        let mut buf = [0u8; 16];
        buf[16 - src.len()..].copy_from_slice(src);

        Ok(Self::from_be_bytes(buf))
    }
}

impl From<u64> for GasPrice {
    fn from(src: u64) -> Self {
        Self(u128::from(src))
    }
}

impl From<crate::rpc::types::BlockNumberOrTag> for BlockId {
    fn from(block: crate::rpc::types::BlockNumberOrTag) -> Self {
        use crate::rpc::types::BlockNumberOrTag::*;
        use crate::rpc::types::Tag::*;

        match block {
            Number(number) => Self::Number(number),
            Tag(Latest) => Self::Latest,
            Tag(Pending) => Self::Pending,
        }
    }
}

impl From<crate::rpc::types::BlockHashOrTag> for BlockId {
    fn from(block: crate::rpc::types::BlockHashOrTag) -> Self {
        use crate::rpc::types::BlockHashOrTag::*;
        use crate::rpc::types::Tag::*;

        match block {
            Hash(hash) => Self::Hash(hash),
            Tag(Latest) => Self::Latest,
            Tag(Pending) => Self::Pending,
        }
    }
}

impl From<StarknetBlockNumber> for BlockId {
    fn from(number: StarknetBlockNumber) -> Self {
        Self::Number(number)
    }
}

impl From<StarknetBlockHash> for BlockId {
    fn from(hash: StarknetBlockHash) -> Self {
        Self::Hash(hash)
    }
}
