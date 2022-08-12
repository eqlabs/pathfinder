//! Contains core functions and types that are widely used but have no real
//! home of their own.
//!
//! This includes many trivial wrappers around [StarkHash] which help by providing additional type safety.
use serde::{Deserialize, Serialize};
use stark_hash::StarkHash;
use web3::types::{H128, H160, H256};

/// The address of a StarkNet contract.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
pub struct ContractAddress(
    #[serde(deserialize_with = "deserialize_starkhash_251_bits")] pub StarkHash,
);

/// A nonce that is associated with a particular deployed StarkNet contract
/// distinguishing it from other contracts that use the same contract class.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ContractNonce(pub StarkHash);

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
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord)]
pub struct StorageAddress(
    #[serde(deserialize_with = "deserialize_starkhash_251_bits")] pub StarkHash,
);

/// Deserializes a [StarkHash] and in addition enforces that it has at most 251 bits
/// used. This is slightly less than the maximum [StarkHash] value, but 251 bit limit are
/// required by types which are keys of the state trees.
fn deserialize_starkhash_251_bits<'de, D>(de: D) -> Result<StarkHash, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct StarkHash251;

    impl<'de> serde::de::Visitor<'de> for StarkHash251 {
        type Value = StarkHash;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("A hex string with at most 251 bits set.")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let hash = StarkHash::from_hex_str(v).map_err(serde::de::Error::custom)?;

            match hash.has_more_than_251_bits() {
                true => Err(serde::de::Error::custom("more than 251 bits set")),
                false => Ok(hash),
            }
        }
    }

    de.deserialize_str(StarkHash251)
}

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

macro_rules! i64_backed_newtype_new_get_partialeq {
    ($target:ty) => {
        impl $target {
            pub const fn new(val: u64) -> Option<Self> {
                let max = i64::MAX as u64;
                // Range::contains is not const
                if val <= max {
                    Some(Self(val))
                } else {
                    None
                }
            }

            pub const fn new_or_panic(val: u64) -> Self {
                match Self::new(val) {
                    Some(x) => x,
                    None => panic!("Invalid constant"),
                }
            }

            pub const fn get(&self) -> u64 {
                self.0
            }
        }

        impl PartialEq<u64> for $target {
            fn eq(&self, other: &u64) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<i64> for $target {
            fn eq(&self, other: &i64) -> bool {
                u64::try_from(*other).map(|x| self == &x).unwrap_or(false)
            }
        }
    };
}

macro_rules! i64_masquerading_as_u64_newtype_to_from_sql {
    ($target:ty) => {
        impl rusqlite::ToSql for $target {
            fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
                // this uses i64::try_from(u64_value) thus limiting our u64 to 0..=i64::MAX
                self.0.to_sql()
            }
        }

        impl rusqlite::types::FromSql for $target {
            fn column_result(
                value: rusqlite::types::ValueRef<'_>,
            ) -> rusqlite::types::FromSqlResult<Self> {
                Ok(Self(value.as_i64()? as u64))
            }
        }
    };
}

macro_rules! i64_backed_newtype_serde {
    ($target:ty) => {
        impl serde::Serialize for $target {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_u64(self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $target {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let raw = u64::deserialize(deserializer)?;
                <$target>::deserialize_value::<D::Error>(raw)
            }
        }

        impl $target {
            pub fn deserialize_value<E>(raw: u64) -> Result<Self, E>
            where
                E: serde::de::Error,
            {
                <$target>::new(raw).ok_or_else(|| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Unsigned(raw),
                        &"i64::MAX unsigned integer",
                    )
                })
            }
        }
    };
}

/// A StarkNet block number.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct StarknetBlockNumber(u64);

i64_masquerading_as_u64_newtype_to_from_sql!(StarknetBlockNumber);
i64_backed_newtype_new_get_partialeq!(StarknetBlockNumber);
i64_backed_newtype_serde!(StarknetBlockNumber);

impl From<StarknetBlockNumber> for StarkHash {
    fn from(x: StarknetBlockNumber) -> Self {
        StarkHash::from(x.0)
    }
}

/// The timestamp of a Starknet block.
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub struct StarknetBlockTimestamp(u64);

i64_masquerading_as_u64_newtype_to_from_sql!(StarknetBlockTimestamp);
i64_backed_newtype_new_get_partialeq!(StarknetBlockTimestamp);
i64_backed_newtype_serde!(StarknetBlockTimestamp);

/// A StarkNet transaction hash.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StarknetTransactionHash(pub StarkHash);

/// A StarkNet transaction index.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct StarknetTransactionIndex(u64);

i64_masquerading_as_u64_newtype_to_from_sql!(StarknetTransactionIndex);
i64_backed_newtype_new_get_partialeq!(StarknetTransactionIndex);
i64_backed_newtype_serde!(StarknetTransactionIndex);

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

/// Ethereum network chains running Starknet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    /// The Ethereum mainnet chain.
    Mainnet,
    /// The Ethereum Goerli test network chain.
    Goerli,
}

const MAINNET_CHAIN_ID: StarkHash = StarkHash::from_u128(0x534e5f4d41494eu128);
const GOERLI_CHAIN_ID: StarkHash = StarkHash::from_u128(0x534e5f474f45524c49u128);

impl Chain {
    pub const fn starknet_chain_id(&self) -> StarkHash {
        match self {
            // SN_MAIN
            Chain::Mainnet => MAINNET_CHAIN_ID,
            // SN_GOERLI
            Chain::Goerli => GOERLI_CHAIN_ID,
        }
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Mainnet => f.write_str("Mainnet"),
            Chain::Goerli => f.write_str("Görli"),
        }
    }
}

/// Common trait implementations for *[StarkHash]* newtypes, meaning tuple structs with single
/// field.
macro_rules! starkhash_common_newtype {
    ($target:ty) => {
        starkhash_to_from_sql!($target);
        thin_starkhash_debug!($target);
        thin_newtype_display!($target);
    };

    ($head:ty, $($tail:ty),+ $(,)?) => {
        starkhash_common_newtype!($head);
        starkhash_common_newtype!($($tail),+);
    };
}

/// Adds the common ToSql and FromSql implementations for the type.
///
/// This avoids having to implement the traits over at `stark_hash` which would require a
/// dependency to `rusqlite` over at `stark_hash`.
///
/// This allows direct use of the values as sql parameters or reading them from the rows. It should
/// be noted that `Option<_>` must be used to when reading a nullable column, as this
/// implementation will error at `as_blob()?`.
macro_rules! starkhash_to_from_sql {
    ($target:ty) => {
        impl rusqlite::ToSql for $target {
            fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
                use rusqlite::types::{ToSqlOutput, ValueRef};
                Ok(ToSqlOutput::Borrowed(ValueRef::Blob(self.0.as_be_bytes())))
            }
        }

        impl rusqlite::types::FromSql for $target {
            fn column_result(
                value: rusqlite::types::ValueRef<'_>,
            ) -> rusqlite::types::FromSqlResult<Self> {
                let blob = value.as_blob()?;
                let sh = stark_hash::StarkHash::from_be_slice(blob)
                    .map_err(|e| rusqlite::types::FromSqlError::Other(e.into()))?;
                Ok(Self(sh))
            }
        }
    };
}

/// Adds a thin display implementation which skips the type name.
macro_rules! thin_newtype_display {
    ($target:ty) => {
        impl std::fmt::Display for $target {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

/// Adds a thin Debug implementation, which skips `X(StarkHash(debug))` as `X(debug)`.
///
/// The implementation uses Display of the wrapped value to produce smallest possible string, but
/// still wraps it in a default Debug derive style `TypeName(hash)`.
macro_rules! thin_starkhash_debug {
    ($target:ty) => {
        impl std::fmt::Debug for $target {
            fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(fmt, "{}({})", stringify!($target), self.0)
            }
        }
    };

    ($head:ty, $($tail:ty),+ $(,)?) => {
        thin_starkhash_debug!($head);
        thin_starkhash_debug!($($tail),+);
    };
}

// these types are used in sequencer tests, which require special fixed width representation
// FIXME: it'd be better if these had normal varlen display and lenient parsing.
thin_starkhash_debug!(ContractAddress, StarknetTransactionHash, ClassHash,);

starkhash_to_from_sql!(ContractAddress);
starkhash_to_from_sql!(StarknetTransactionHash);
starkhash_to_from_sql!(ClassHash);

starkhash_common_newtype!(
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

thin_newtype_display!(StarknetBlockNumber);
thin_newtype_display!(StarknetBlockTimestamp);

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
