//! Contains core functions and types that are widely used but have no real
//! home of their own.
//!
//! This includes many trivial wrappers around [StarkHash] which help by providing additional type safety.
use serde::{Deserialize, Serialize};
use stark_hash::StarkHash;
use web3::types::{H128, H160, H256};

mod macros;

/// The address of a StarkNet contract.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
pub struct ContractAddress(StarkHash);

macros::starkhash251::newtype!(ContractAddress);
macros::starkhash251::deserialization!(ContractAddress);

/// A nonce that is associated with a particular deployed StarkNet contract
/// distinguishing it from other contracts that use the same contract class.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ContractNonce(pub StarkHash);

impl ContractNonce {
    pub const ZERO: Self = Self(StarkHash::ZERO);
}

/// The salt of a StarkNet contract address.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord)]
pub struct ContractAddressSalt(pub StarkHash);

/// The hash of a StarkNet contract. This is a hash over a class'
/// deployment properties e.g. code and ABI.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ClassHash(pub StarkHash);

/// A StarkNet contract's state hash. This is the value stored
/// in the global state tree.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractStateHash(pub StarkHash);

/// A commitment root of a StarkNet contract. This is the entry-point
/// for a contract's state at a specific point in time via the contract
/// state tree.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRoot(pub StarkHash);

impl ContractRoot {
    pub const ZERO: Self = Self(StarkHash::ZERO);
}

// Bytecode and entry point list of a class
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractClass {
    // A base64 encoding of the gzip-compressed JSON representation of program.
    pub program: String,
    // A JSON representation of the entry points
    // We don't actually process this value, just serialize/deserialize
    // from an already validated JSON.
    // This is kept as a Value to avoid dependency on sequencer API types.
    pub entry_points_by_type: serde_json::Value,
}

/// Entry point of a StarkNet `call`.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ByteCodeOffset(pub StarkHash);

/// A single parameter passed to a StarkNet `call`.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CallParam(pub StarkHash);

/// A single parameter passed to a StarkNet contract constructor.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConstructorParam(pub StarkHash);

/// A single result value of a StarkNet `call`.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CallResultValue(pub StarkHash);

/// A single element of a signature used to secure a StarkNet `call`.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CallSignatureElem(pub StarkHash);

/// A word from a StarkNet contract bytecode.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ByteCodeWord(pub StarkHash);

/// The address of a storage element for a StarkNet contract.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, PartialOrd, Ord)]
pub struct StorageAddress(StarkHash);

macros::starkhash251::newtype!(StorageAddress);
macros::starkhash251::deserialization!(StorageAddress);

/// The value of a storage element for a StarkNet contract.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord)]
pub struct StorageValue(pub StarkHash);

/// A commitment root of the global StarkNet state. This is the entry-point
/// for the global state at a specific point in time via the global state tree.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GlobalRoot(pub StarkHash);

/// A StarkNet block hash.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StarknetBlockHash(pub StarkHash);

/// A StarkNet block number.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct StarknetBlockNumber(u64);

macros::i64_backed_u64::to_from_sql!(StarknetBlockNumber);
macros::i64_backed_u64::new_get_partialeq!(StarknetBlockNumber);
macros::i64_backed_u64::serdes!(StarknetBlockNumber);

impl From<StarknetBlockNumber> for StarkHash {
    fn from(x: StarknetBlockNumber) -> Self {
        StarkHash::from(x.0)
    }
}

/// The timestamp of a Starknet block.
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub struct StarknetBlockTimestamp(u64);

macros::i64_backed_u64::to_from_sql!(StarknetBlockTimestamp);
macros::i64_backed_u64::new_get_partialeq!(StarknetBlockTimestamp);
macros::i64_backed_u64::serdes!(StarknetBlockTimestamp);

/// A StarkNet transaction hash.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StarknetTransactionHash(pub StarkHash);

/// A StarkNet transaction index.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct StarknetTransactionIndex(u64);

macros::i64_backed_u64::to_from_sql!(StarknetTransactionIndex);
macros::i64_backed_u64::new_get_partialeq!(StarknetTransactionIndex);
macros::i64_backed_u64::serdes!(StarknetTransactionIndex);

/// A single element of a signature used to secure a StarkNet transaction.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionSignatureElem(pub StarkHash);

/// A nonce that is added to an L1 to L2 message in a StarkNet transaction.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct L1ToL2MessageNonce(pub StarkHash);

/// A single element of the payload of an L1 to L2 message in a StarkNet transaction.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct L1ToL2MessagePayloadElem(pub StarkHash);

/// A single element of the payload of an L2 to L1 message in a StarkNet transaction.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct L2ToL1MessagePayloadElem(pub StarkHash);

/// StarkNet transaction event data.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EventData(pub StarkHash);

/// StarkNet transaction event key.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Hash)]
pub struct EventKey(pub StarkHash);

/// StarkNet sequencer address.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SequencerAddress(pub StarkHash);

/// StarkNet fee value.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Fee(pub H128);

/// StarkNet gas price.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GasPrice(pub u128);

// Starknet transaction nonce.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionNonce(pub StarkHash);

/// StarkNet transaction version.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionVersion(pub H256);

/// An Ethereum address.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EthereumAddress(pub H160);

/// An Ethereum block hash.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct EthereumBlockHash(pub H256);

/// An Ethereum block number.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct EthereumBlockNumber(pub u64);

/// An Ethereum transaction hash.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct EthereumTransactionHash(pub H256);

/// An Ethereum transaction's index within a block.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct EthereumTransactionIndex(pub u64);

/// An Ethereum log's index within a block.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct EthereumLogIndex(pub u64);

/// A way of identifying a specific block.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "rpc-full-serde"), derive(Serialize))]
#[serde(deny_unknown_fields)]
pub enum BlockId {
    #[serde(rename = "block_number")]
    Number(StarknetBlockNumber),
    #[serde(rename = "block_hash")]
    Hash(StarknetBlockHash),
    #[serde(rename = "latest")]
    Latest,
    #[serde(rename = "pending")]
    Pending,
}

impl StarknetBlockNumber {
    pub const GENESIS: StarknetBlockNumber = StarknetBlockNumber::new_or_panic(0);
    /// The maximum [StarknetBlockNumber] we can support. Restricted to `u64::MAX/2` to
    /// match Sqlite's maximum integer value.
    pub const MAX: StarknetBlockNumber = StarknetBlockNumber::new_or_panic(i64::MAX as u64);
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

impl From<EthereumBlockNumber> for web3::types::BlockId {
    fn from(number: EthereumBlockNumber) -> Self {
        web3::types::BlockId::Number(web3::types::BlockNumber::Number(number.0.into()))
    }
}

impl From<StarknetBlockNumber> for crate::rpc::v01::types::BlockNumberOrTag {
    fn from(number: StarknetBlockNumber) -> Self {
        crate::rpc::v01::types::BlockNumberOrTag::Number(number)
    }
}

impl From<StarknetBlockHash> for crate::rpc::v01::types::BlockHashOrTag {
    fn from(hash: StarknetBlockHash) -> Self {
        crate::rpc::v01::types::BlockHashOrTag::Hash(hash)
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

impl From<crate::rpc::v01::types::BlockNumberOrTag> for BlockId {
    fn from(block: crate::rpc::v01::types::BlockNumberOrTag) -> Self {
        use crate::rpc::v01::types::BlockNumberOrTag::*;
        use crate::rpc::v01::types::Tag::*;

        match block {
            Number(number) => Self::Number(number),
            Tag(Latest) => Self::Latest,
            Tag(Pending) => Self::Pending,
        }
    }
}

impl From<crate::rpc::v01::types::BlockHashOrTag> for BlockId {
    fn from(block: crate::rpc::v01::types::BlockHashOrTag) -> Self {
        use crate::rpc::v01::types::BlockHashOrTag::*;
        use crate::rpc::v01::types::Tag::*;

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

/// Ethereum network chains running Starknet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthereumChain {
    Mainnet,
    Goerli,
}

/// Starknet chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Mainnet,
    Testnet,
    Integration,
}

impl Chain {
    pub const fn starknet_chain_id(&self) -> StarkHash {
        match self {
            // SN_MAIN
            Chain::Mainnet => StarkHash::from_u128(0x534e5f4d41494eu128),
            // SN_GOERLI
            Chain::Testnet => StarkHash::from_u128(0x534e5f474f45524c49u128),
            // SN_INTEGRATION
            Chain::Integration => StarkHash::from_u128(0x534E5F494E544547524154494F4E),
        }
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Mainnet => f.write_str("Mainnet"),
            Chain::Testnet => f.write_str("Görli"),
            Chain::Integration => f.write_str("Integration"),
        }
    }
}

// these types are used in sequencer tests, which require special fixed width representation
// FIXME: it'd be better if these had normal varlen display and lenient parsing.
macros::fmt::thin_debug!(ContractAddress);
macros::starkhash::to_from_sql!(ContractAddress);

macros::fmt::thin_debug!(StarknetTransactionHash);
macros::starkhash::to_from_sql!(StarknetTransactionHash);

macros::fmt::thin_debug!(ClassHash);
macros::starkhash::to_from_sql!(ClassHash);

macros::starkhash::common_newtype!(
    ContractAddressSalt,
    ContractNonce,
    ContractStateHash,
    ContractRoot,
    EntryPoint,
    ByteCodeOffset,
    CallParam,
    ConstructorParam,
    CallResultValue,
    CallSignatureElem,
    ByteCodeWord,
    StorageAddress,
    StorageValue,
    GlobalRoot,
    StarknetBlockHash,
    TransactionSignatureElem,
    L1ToL2MessageNonce,
    L1ToL2MessagePayloadElem,
    L2ToL1MessagePayloadElem,
    EventData,
    EventKey,
    SequencerAddress,
    TransactionNonce,
);

macros::fmt::thin_display!(StarknetBlockNumber);
macros::fmt::thin_display!(StarknetBlockTimestamp);

#[cfg(test)]
mod tests {
    mod block_id_serde {
        use super::super::BlockId;

        #[test]
        fn latest() {
            let result = serde_json::from_str::<BlockId>(r#""latest""#).unwrap();
            assert_eq!(result, BlockId::Latest);
        }

        #[test]
        fn pending() {
            let result = serde_json::from_str::<BlockId>(r#""pending""#).unwrap();
            assert_eq!(result, BlockId::Pending);
        }

        #[test]
        fn number() {
            use crate::core::StarknetBlockNumber;
            let result = serde_json::from_str::<BlockId>(r#"{"block_number": 123456}"#).unwrap();
            assert_eq!(result, BlockId::Number(StarknetBlockNumber(123456)));
        }

        #[test]
        fn hash() {
            use crate::core::StarknetBlockHash;
            use crate::starkhash;
            let result =
                serde_json::from_str::<BlockId>(r#"{"block_hash": "0xdeadbeef"}"#).unwrap();
            assert_eq!(
                result,
                BlockId::Hash(StarknetBlockHash(starkhash!("deadbeef")))
            );
        }
    }
}
