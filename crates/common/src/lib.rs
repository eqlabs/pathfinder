//! Contains core functions and types that are widely used but have no real
//! home of their own.
//!
//! This includes many trivial wrappers around [Felt] which help by providing additional type safety.
use anyhow::Context;
use primitive_types::{H160, H256};
use serde::{Deserialize, Serialize};
use stark_hash::Felt;

pub mod consts;
pub mod event;
pub mod hash;
mod header;
mod macros;
pub mod state_update;
#[cfg(feature = "test-utils")]
pub mod test_utils;
pub mod trie;

pub use state_update::StateUpdate;

pub use header::{BlockHeader, BlockHeaderBuilder};

/// The address of a Starknet contract.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
pub struct ContractAddress(pub Felt);

macros::starkhash251::newtype!(ContractAddress);
macros::starkhash251::deserialization!(ContractAddress);

impl ContractAddress {
    /// The contract at 0x1 is special. It was never deployed and therefore
    /// has no class hash. It does however receive storage changes.
    ///
    /// It is used by starknet to store values for smart contracts to access
    /// using syscalls. For example the block hash.
    pub const ONE: ContractAddress = ContractAddress(felt!("0x1"));
}

/// A nonce that is associated with a particular deployed Starknet contract
/// distinguishing it from other contracts that use the same contract class.
#[derive(Copy, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ContractNonce(pub Felt);

/// The salt of a Starknet contract address.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord)]
pub struct ContractAddressSalt(pub Felt);

/// The hash of a Starknet contract. This is a hash over a class'
/// deployment properties e.g. code and ABI.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ClassHash(pub Felt);

/// The hash of a Starknet Sierra class.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
pub struct SierraHash(pub Felt);

macros::starkhash251::newtype!(SierraHash);
macros::starkhash251::deserialization!(SierraHash);

/// The hash of a Starknet Cairo assembly class.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
pub struct CasmHash(pub Felt);

macros::starkhash251::newtype!(CasmHash);
macros::starkhash251::deserialization!(CasmHash);

/// The root of a class commitment tree.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Default)]
pub struct ClassCommitment(pub Felt);

macros::starkhash251::newtype!(ClassCommitment);
macros::starkhash251::deserialization!(ClassCommitment);

/// A Cairo 1.0 class' leaf hash. This is the value stored
/// in the class commitment tree.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ClassCommitmentLeafHash(pub Felt);

/// A Starknet contract's state hash. This is the value stored
/// in the global state tree.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractStateHash(pub Felt);

/// A commitment root of a Starknet contract. This is the entry-point
/// for a contract's state at a specific point in time via the contract
/// state tree.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRoot(pub Felt);

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

/// Entry point of a Starknet `call`.
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

/// Offset of an entry point into the bytecode of a Starknet contract.
///
/// This is a StarkHash because we use it directly for computing the
/// class hashes.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ByteCodeOffset(pub Felt);

/// A single parameter passed to a Starknet `call`.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CallParam(pub Felt);

/// A single parameter passed to a Starknet contract constructor.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConstructorParam(pub Felt);

/// A single result value of a Starknet `call`.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CallResultValue(pub Felt);

/// The address of a storage element for a Starknet contract.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, PartialOrd, Ord, Hash)]
pub struct StorageAddress(Felt);

macros::starkhash251::newtype!(StorageAddress);
macros::starkhash251::deserialization!(StorageAddress);

/// The value of a storage element for a Starknet contract.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord)]
pub struct StorageValue(pub Felt);

/// The commitment for the state of a Starknet block.
///
/// Before Starknet v0.11.0 this was equivalent to [StorageCommitment].
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct StateCommitment(pub Felt);

impl StateCommitment {
    /// Calculates  global state commitment by combining the storage and class commitment.
    ///
    /// See
    /// <https://github.com/starkware-libs/cairo-lang/blob/12ca9e91bbdc8a423c63280949c7e34382792067/src/starkware/starknet/core/os/state.cairo#L125>
    /// for details.
    pub fn calculate(
        storage_commitment: StorageCommitment,
        class_commitment: ClassCommitment,
    ) -> Self {
        if class_commitment == ClassCommitment::ZERO {
            Self(storage_commitment.0)
        } else {
            const GLOBAL_STATE_VERSION: Felt = felt_bytes!(b"STARKNET_STATE_V0");

            StateCommitment(
                stark_poseidon::poseidon_hash_many(&[
                    GLOBAL_STATE_VERSION.into(),
                    storage_commitment.0.into(),
                    class_commitment.0.into(),
                ])
                .into(),
            )
        }
    }
}

/// The commitment for all contracts' storage of a Starknet block.
///
/// Before Starknet v0.11.0 this was equivalent to [StateCommitment].
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct StorageCommitment(pub Felt);

/// A Starknet block hash.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Default, Hash)]
pub struct BlockHash(pub Felt);

/// A Starknet block number.
#[derive(Copy, Debug, Clone, Default, PartialEq, Eq, PartialOrd, Hash)]
pub struct BlockNumber(u64);

macros::i64_backed_u64::new_get_partialeq!(BlockNumber);
macros::i64_backed_u64::serdes!(BlockNumber);

impl From<BlockNumber> for Felt {
    fn from(x: BlockNumber) -> Self {
        Felt::from(x.0)
    }
}

impl std::iter::Iterator for BlockNumber {
    type Item = BlockNumber;

    fn next(&mut self) -> Option<Self::Item> {
        Some(*self + 1)
    }
}

/// The timestamp of a Starknet block.
#[derive(Copy, Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockTimestamp(u64);

macros::i64_backed_u64::new_get_partialeq!(BlockTimestamp);
macros::i64_backed_u64::serdes!(BlockTimestamp);

/// A Starknet events commitment of a block.
#[derive(Copy, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct EventCommitment(pub Felt);

/// A Starknet transactions commitment of a block.
#[derive(Copy, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionCommitment(pub Felt);

/// A Starknet transaction hash.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionHash(pub Felt);

/// A Starknet transaction index.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TransactionIndex(u64);

macros::i64_backed_u64::new_get_partialeq!(TransactionIndex);
macros::i64_backed_u64::serdes!(TransactionIndex);

/// A single element of a signature used to secure a Starknet transaction.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionSignatureElem(pub Felt);

/// A nonce that is added to an L1 to L2 message in a Starknet transaction.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct L1ToL2MessageNonce(pub Felt);

/// A single element of the payload of an L1 to L2 message in a Starknet transaction.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct L1ToL2MessagePayloadElem(pub Felt);

/// A single element of the payload of an L2 to L1 message in a Starknet transaction.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct L2ToL1MessagePayloadElem(pub Felt);

/// Starknet transaction event data.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EventData(pub Felt);

/// Starknet transaction event key.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Hash)]
pub struct EventKey(pub Felt);

/// Starknet sequencer address.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct SequencerAddress(pub Felt);

/// Starknet fee value.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Fee(pub Felt);

/// Starknet gas price.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct GasPrice(pub u128);

// Starknet transaction nonce.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionNonce(pub Felt);

/// Starknet transaction version.
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

    pub const fn with_query_version(mut self) -> Self {
        self.0 .0[15] |= 0b0000_0001;
        self
    }

    pub const ZERO: Self = Self(H256::zero());
    pub const ONE: Self = Self(H256([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ]));
    pub const TWO: Self = Self(H256([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2,
    ]));
    pub const ZERO_WITH_QUERY_VERSION: Self = Self::ZERO.with_query_version();
    pub const ONE_WITH_QUERY_VERSION: Self = Self::ONE.with_query_version();
    pub const TWO_WITH_QUERY_VERSION: Self = Self::TWO.with_query_version();
}

/// A way of identifying a specific block.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "full-serde"), derive(Serialize))]
#[serde(deny_unknown_fields)]
pub enum BlockId {
    #[serde(rename = "block_number")]
    Number(BlockNumber),
    #[serde(rename = "block_hash")]
    Hash(BlockHash),
    #[serde(rename = "latest")]
    Latest,
    #[serde(rename = "pending")]
    Pending,
}

impl BlockNumber {
    pub const GENESIS: BlockNumber = BlockNumber::new_or_panic(0);
    /// The maximum [BlockNumber] we can support. Restricted to `u64::MAX/2` to
    /// match Sqlite's maximum integer value.
    pub const MAX: BlockNumber = BlockNumber::new_or_panic(i64::MAX as u64);
}

impl std::ops::Add<u64> for BlockNumber {
    type Output = BlockNumber;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl std::ops::AddAssign<u64> for BlockNumber {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl std::ops::Sub<u64> for BlockNumber {
    type Output = BlockNumber;

    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl std::ops::SubAssign<u64> for BlockNumber {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

/// An Ethereum address.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EthereumAddress(pub H160);

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

impl From<BlockNumber> for BlockId {
    fn from(number: BlockNumber) -> Self {
        Self::Number(number)
    }
}

impl From<BlockHash> for BlockId {
    fn from(hash: BlockHash) -> Self {
        Self::Hash(hash)
    }
}

/// Ethereum network chains running Starknet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthereumChain {
    Mainnet,
    Goerli,
    Other(primitive_types::U256),
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarknetVersion(String);

impl StarknetVersion {
    pub fn new(major: u64, minor: u64, patch: u64) -> Self {
        StarknetVersion(format!("{major}.{minor}.{patch}"))
    }

    /// Parses the version string.
    ///
    /// Note: there are known deviations from semver such as version 0.11.0.2, which
    /// will be truncated to 0.11.0 to still allow for parsing.
    pub fn parse_as_semver(&self) -> anyhow::Result<Option<semver::Version>> {
        // Truncate the 4th segment if present. This is a work-around for semver violating
        // version strings like `0.11.0.2`.
        let str = if self.0.is_empty() {
            return Ok(None);
        } else {
            &self.0
        };
        let truncated = str
            .match_indices('.')
            .nth(2)
            .map(|(index, _)| str.split_at(index).0)
            .unwrap_or(str);

        Some(semver::Version::parse(truncated).context("Parsing semver string")).transpose()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn take_inner(self) -> String {
        self.0
    }
}

impl From<String> for StarknetVersion {
    fn from(value: String) -> Self {
        Self(value)
    }
}

macros::starkhash::common_newtype!(
    ByteCodeOffset,
    CallParam,
    CallResultValue,
    CasmHash,
    ClassCommitment,
    ClassCommitmentLeafHash,
    ClassHash,
    ConstructorParam,
    ContractAddress,
    ContractAddressSalt,
    ContractNonce,
    ContractStateHash,
    ContractRoot,
    EntryPoint,
    EventCommitment,
    EventData,
    EventKey,
    Fee,
    L1ToL2MessageNonce,
    L1ToL2MessagePayloadElem,
    L2ToL1MessagePayloadElem,
    SequencerAddress,
    SierraHash,
    BlockHash,
    TransactionHash,
    StateCommitment,
    StorageAddress,
    StorageCommitment,
    StorageValue,
    TransactionCommitment,
    TransactionNonce,
    TransactionSignatureElem,
);

macros::fmt::thin_display!(BlockNumber);
macros::fmt::thin_display!(BlockTimestamp);

#[derive(Clone, Debug, PartialEq)]
pub enum AllowedOrigins {
    Any,
    List(Vec<String>),
}

impl<S> From<S> for AllowedOrigins
where
    S: ToString,
{
    fn from(value: S) -> Self {
        let s = value.to_string();

        if s == "*" {
            Self::Any
        } else {
            Self::List(vec![s])
        }
    }
}

/// See:
/// <https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/public/abi.py#L21-L26>
pub fn truncated_keccak(mut plain: [u8; 32]) -> Felt {
    // python code masks with (2**250 - 1) which starts 0x03 and is followed by 31 0xff in be
    // truncation is needed not to overflow the field element.
    plain[0] &= 0x03;
    Felt::from_be_bytes(plain).expect("cannot overflow: smaller than modulus")
}

/// Calculate class commitment tree leaf hash value.
///
/// See: <https://docs.starknet.io/documentation/starknet_versions/upcoming_versions/#state_commitment>
pub fn calculate_class_commitment_leaf_hash(
    compiled_class_hash: CasmHash,
) -> ClassCommitmentLeafHash {
    const CONTRACT_CLASS_HASH_VERSION: stark_hash::Felt = felt_bytes!(b"CONTRACT_CLASS_LEAF_V0");
    ClassCommitmentLeafHash(
        stark_poseidon::poseidon_hash(
            CONTRACT_CLASS_HASH_VERSION.into(),
            compiled_class_hash.0.into(),
        )
        .into(),
    )
}

#[cfg(test)]
mod tests {
    mod starknet_version {
        use super::super::StarknetVersion;

        #[test]
        fn valid_semver() {
            let version = serde_json::from_str::<StarknetVersion>(r#""0.11.0""#).unwrap();
            assert_eq!(version, StarknetVersion::new(0, 11, 0));
        }

        #[test]
        fn invalid_semver_is_coerced() {
            let version = serde_json::from_str::<StarknetVersion>(r#""0.11.0.2""#)
                .unwrap()
                .parse_as_semver()
                .unwrap()
                .unwrap();
            assert_eq!(version, semver::Version::new(0, 11, 0));
        }
    }

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
            use crate::BlockNumber;
            let result = serde_json::from_str::<BlockId>(r#"{"block_number": 123456}"#).unwrap();
            assert_eq!(result, BlockId::Number(BlockNumber(123456)));
        }

        #[test]
        fn hash() {
            use crate::felt;
            use crate::BlockHash;
            let result =
                serde_json::from_str::<BlockId>(r#"{"block_hash": "0xdeadbeef"}"#).unwrap();
            assert_eq!(result, BlockId::Hash(BlockHash(felt!("0xdeadbeef"))));
        }
    }
}
