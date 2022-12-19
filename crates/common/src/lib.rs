//! Contains core functions and types that are widely used but have no real
//! home of their own.
//!
//! This includes many trivial wrappers around [Felt] which help by providing additional type safety.
use ethers::types::{H128, H160, H256};
use serde::{Deserialize, Serialize};
use stark_hash::Felt;

pub mod consts;
mod macros;
#[cfg(feature = "test-utils")]
pub mod test_utils;

/// The address of a StarkNet contract.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
pub struct ContractAddress(Felt);

macros::starkhash251::newtype!(ContractAddress);
macros::starkhash251::deserialization!(ContractAddress);

/// A nonce that is associated with a particular deployed StarkNet contract
/// distinguishing it from other contracts that use the same contract class.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ContractNonce(pub Felt);

impl ContractNonce {
    pub const ZERO: Self = Self(Felt::ZERO);
}

/// The salt of a StarkNet contract address.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord)]
pub struct ContractAddressSalt(pub Felt);

/// The hash of a StarkNet contract. This is a hash over a class'
/// deployment properties e.g. code and ABI.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ClassHash(pub Felt);

/// A StarkNet contract's state hash. This is the value stored
/// in the global state tree.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractStateHash(pub Felt);

/// A commitment root of a StarkNet contract. This is the entry-point
/// for a contract's state at a specific point in time via the contract
/// state tree.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRoot(pub Felt);

impl ContractRoot {
    pub const ZERO: Self = Self(Felt::ZERO);
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
pub struct EntryPoint(pub Felt);

impl EntryPoint {
    /// Returns a new EntryPoint which has been truncated to fit from Keccak256 digest of input.
    ///
    /// See: <https://starknet.io/documentation/contracts/#function_selector>
    pub fn hashed(input: &[u8]) -> Self {
        use sha3::Digest;
        EntryPoint(truncated_keccak(<[u8; 32]>::from(sha3::Keccak256::digest(
            input,
        ))))
    }
}

/// Offset of an entry point into the bytecode of a StarkNet contract.
///
/// This is a StarkHash because we use it directly for computing the
/// class hashes.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ByteCodeOffset(pub Felt);

/// A single parameter passed to a StarkNet `call`.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CallParam(pub Felt);

/// A single parameter passed to a StarkNet contract constructor.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConstructorParam(pub Felt);

/// A single result value of a StarkNet `call`.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CallResultValue(pub Felt);

/// A word from a StarkNet contract bytecode.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ByteCodeWord(pub Felt);

/// The address of a storage element for a StarkNet contract.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, PartialOrd, Ord)]
pub struct StorageAddress(Felt);

macros::starkhash251::newtype!(StorageAddress);
macros::starkhash251::deserialization!(StorageAddress);

/// The value of a storage element for a StarkNet contract.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord)]
pub struct StorageValue(pub Felt);

/// A commitment root of the global StarkNet state. This is the entry-point
/// for the global state at a specific point in time via the global state tree.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GlobalRoot(pub Felt);

/// A StarkNet block hash.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StarknetBlockHash(pub Felt);

/// A StarkNet block number.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct StarknetBlockNumber(u64);

macros::i64_backed_u64::to_from_sql!(StarknetBlockNumber);
macros::i64_backed_u64::new_get_partialeq!(StarknetBlockNumber);
macros::i64_backed_u64::serdes!(StarknetBlockNumber);

impl From<StarknetBlockNumber> for Felt {
    fn from(x: StarknetBlockNumber) -> Self {
        Felt::from(x.0)
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
pub struct StarknetTransactionHash(pub Felt);

/// A StarkNet transaction index.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct StarknetTransactionIndex(u64);

macros::i64_backed_u64::to_from_sql!(StarknetTransactionIndex);
macros::i64_backed_u64::new_get_partialeq!(StarknetTransactionIndex);
macros::i64_backed_u64::serdes!(StarknetTransactionIndex);

/// A single element of a signature used to secure a StarkNet transaction.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionSignatureElem(pub Felt);

/// A nonce that is added to an L1 to L2 message in a StarkNet transaction.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct L1ToL2MessageNonce(pub Felt);

/// A single element of the payload of an L1 to L2 message in a StarkNet transaction.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct L1ToL2MessagePayloadElem(pub Felt);

/// A single element of the payload of an L2 to L1 message in a StarkNet transaction.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct L2ToL1MessagePayloadElem(pub Felt);

/// StarkNet transaction event data.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EventData(pub Felt);

/// StarkNet transaction event key.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Hash)]
pub struct EventKey(pub Felt);

/// StarkNet sequencer address.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SequencerAddress(pub Felt);

/// StarkNet fee value.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Fee(pub H128);

/// StarkNet gas price.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GasPrice(pub u128);

// Starknet transaction nonce.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionNonce(pub Felt);

impl TransactionNonce {
    pub const ZERO: Self = Self(Felt::ZERO);
}

/// StarkNet transaction version.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionVersion(pub H256);

impl TransactionVersion {
    /// Checks if version is zero, handling QUERY_VERSION_BASE.
    pub fn is_zero(&self) -> bool {
        self.without_query_version() == 0
    }

    /// Returns the transaction versin without QUERY_VERSION_BASE.
    ///
    /// QUERY_VERSION_BASE (2**128) is a large constant that gets
    /// added to the real version to make sure transactions constructed for
    /// call or estimateFee cannot be submitted for inclusion on the chain.
    pub fn without_query_version(&self) -> u128 {
        let lower = &self.0.as_bytes()[16..];
        u128::from_be_bytes(lower.try_into().expect("slice should be the right length"))
    }

    pub const ZERO: Self = Self(H256::zero());
    pub const ONE: Self = Self(H256(hex_literal::hex!(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )));
    pub const ZERO_WITH_QUERY_VERSION: Self = Self(H256(hex_literal::hex!(
        "0000000000000000000000000000000100000000000000000000000000000000"
    )));
    pub const ONE_WITH_QUERY_VERSION: Self = Self(H256(hex_literal::hex!(
        "0000000000000000000000000000000100000000000000000000000000000001"
    )));
}

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
#[cfg_attr(any(test, feature = "full-serde"), derive(Serialize))]
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

impl From<EthereumBlockNumber> for ethers::types::BlockId {
    fn from(number: EthereumBlockNumber) -> Self {
        ethers::types::BlockId::Number(ethers::types::BlockNumber::Number(number.0.into()))
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
    Other(ethers::types::U256),
}

/// Starknet chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Mainnet,
    Testnet,
    Integration,
    Testnet2,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct ChainId(pub Felt);

impl ChainId {
    /// Convenience function for the constants because unwrap() is not const.
    const fn from_slice_unwrap(slice: &[u8]) -> Self {
        Self(match Felt::from_be_slice(slice) {
            Ok(v) => v,
            Err(_) => panic!("Bad value"),
        })
    }

    pub fn to_hex_str(&self) -> std::borrow::Cow<'static, str> {
        self.0.to_hex_str()
    }

    pub const MAINNET: Self = Self::from_slice_unwrap(b"SN_MAIN");
    pub const TESTNET: Self = Self::from_slice_unwrap(b"SN_GOERLI");
    pub const TESTNET2: Self = Self::from_slice_unwrap(b"SN_GOERLI2");
    pub const INTEGRATION: Self = Self::from_slice_unwrap(b"SN_GOERLI");
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Mainnet => f.write_str("Mainnet"),
            Chain::Testnet => f.write_str("Görli"),
            Chain::Testnet2 => f.write_str("Görli2"),
            Chain::Integration => f.write_str("Integration"),
            Chain::Custom => f.write_str("Custom"),
        }
    }
}

// these types are used in sequencer tests, which require special fixed width representation
// FIXME: it'd be better if these had normal varlen display and lenient parsing.
macros::fmt::thin_debug!(ContractAddress);
macros::fmt::thin_display!(ContractAddress);
macros::starkhash::to_from_sql!(ContractAddress);

macros::fmt::thin_debug!(StarknetTransactionHash);
macros::fmt::thin_display!(StarknetTransactionHash);
macros::starkhash::to_from_sql!(StarknetTransactionHash);

macros::fmt::thin_debug!(ClassHash);
macros::fmt::thin_display!(ClassHash);
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

/// See:
/// <https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/public/abi.py#L21-L26>
pub fn truncated_keccak(mut plain: [u8; 32]) -> Felt {
    // python code masks with (2**250 - 1) which starts 0x03 and is followed by 31 0xff in be
    // truncation is needed not to overflow the field element.
    plain[0] &= 0x03;
    Felt::from_be_bytes(plain).expect("cannot overflow: smaller than modulus")
}

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
            use crate::StarknetBlockNumber;
            let result = serde_json::from_str::<BlockId>(r#"{"block_number": 123456}"#).unwrap();
            assert_eq!(result, BlockId::Number(StarknetBlockNumber(123456)));
        }

        #[test]
        fn hash() {
            use crate::felt;
            use crate::StarknetBlockHash;
            let result =
                serde_json::from_str::<BlockId>(r#"{"block_hash": "0xdeadbeef"}"#).unwrap();
            assert_eq!(
                result,
                BlockId::Hash(StarknetBlockHash(felt!("0xdeadbeef")))
            );
        }
    }
}
