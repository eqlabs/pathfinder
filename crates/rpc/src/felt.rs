//! Contains the [RpcFelt] and [RpcFelt251] wrappers around [Felt] which
//! implement RPC compliant serialization.
//!
//! The wrappers implement [serde_with::SerializeAs] which allows annotating
//! struct fields `serde_as(as = "RpcFelt")`to use the RPC compliant
//! serialization. It also allows specifying container types such as [Option],
//! [Vec] etc: `serde_as(as = "Vec<RpcFelt>")`.
//!
//! ```ignore
//! #[serde_with::serde_as]
//! #[derive(serde::Serialize)]
//! struct Example {
//!     #[serde_as(as = "RpcFelt")]
//!     hash: TransactionHash,
//!
//!     #[serde_as(as = "Option<RpcFelt>")]
//!     maybe_hash: Option<TransactionHash>,
//!
//!     #[serde_as(as = "Vec<RpcFelt>")]
//!     many_hashes: Vec<TransactionHash>,
//! }
//! ```

use pathfinder_common::prelude::*;
use pathfinder_common::ProofFactElem;
use pathfinder_crypto::Felt;

/// An RPC specific wrapper around [Felt] which implements
/// [serde::Serialize] in accordance with RPC specifications.
///
/// RPC output types should use this type for serialization instead of [Felt].
///
/// This can be easily accomplished by marking a field with `#[serde_as(as =
/// "RpcFelt")]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcFelt(pub Felt);

impl From<Felt> for RpcFelt {
    fn from(value: Felt) -> Self {
        Self(value)
    }
}

impl From<RpcFelt> for Felt {
    fn from(value: RpcFelt) -> Self {
        value.0
    }
}

/// An RPC specific wrapper around [Felt] for types which are restricted to 251
/// bits. It implements [serde::Serialize] in accordance with RPC
/// specifications.
///
/// RPC output types should use this type for serialization instead of [Felt].
///
/// This can be easily accomplished by marking a field with `#[serde_as(as =
/// "RpcFelt251")]`.
#[derive(serde::Serialize)]
pub struct RpcFelt251(pub RpcFelt);

mod serialization {
    //! Blanket [serde::Serialize] and [serde_with::SerializeAs] implementations
    //! for [RpcFelt] and [RpcFelt251] supported types.

    use super::*;

    impl serde::Serialize for RpcFelt {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            // StarkHash has a leading "0x" and at most 64 digits
            let mut buf = [0u8; 2 + 64];
            let s = self.0.as_hex_str(&mut buf);
            serializer.serialize_str(s)
        }
    }

    impl<T> serde_with::SerializeAs<T> for RpcFelt
    where
        T: Into<RpcFelt> + Clone,
    {
        fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::Serialize;

            RpcFelt::serialize(&value.clone().into(), serializer)
        }
    }

    impl<T> serde_with::SerializeAs<T> for RpcFelt251
    where
        T: Into<RpcFelt251> + Clone,
    {
        fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::Serialize;

            RpcFelt251::serialize(&value.clone().into(), serializer)
        }
    }
}

/// Generates the required `From` implementations required for the target type
/// to support `#[serde_as(as = "RpcFelt")]` and similar annotations.
///
/// In particular, it generates:
/// - `From<$target> for RpcFelt`
/// - `From<RpcFelt> for $target`
///
/// The target types must be a [Felt] newtype.
macro_rules! rpc_felt_serde {
    ($target:ident) => {
        impl From<$target> for RpcFelt {
            fn from(value: $target) -> Self {
                RpcFelt(value.0)
            }
        }

        #[cfg(test)]
        impl From<RpcFelt> for $target {
            fn from(value: RpcFelt) -> Self {
                $target(value.0)
            }
        }
    };

    ($head:ident, $($tail:ident),+ $(,)?) => {
        rpc_felt_serde!($head);
        rpc_felt_serde!($($tail),+);
    };
}

/// Generates the required `From` implementations required for the target type
/// to support `#[serde_as(as = "RpcFelt251")]` and similar annotations.
///
/// In particular, it generates:
/// - `From<$target> for RpcFelt251`
/// - `From<RpcFelt251> for $target`
///
/// The target types must be a private [Felt] newtype i.e. `$target::get() ->
/// &Felt` must exist.
macro_rules! rpc_felt_251_serde {
    ($target:ident) => {
        impl From<$target> for RpcFelt251 {
            fn from(value: $target) -> Self {
                RpcFelt251(RpcFelt(value.get().clone()))
            }
        }

        impl From<RpcFelt251> for $target {
            fn from(value: RpcFelt251) -> Self {
                $target::new_or_panic(value.0.0)
            }
        }
    };

    ($head:ident, $($tail:ident),+ $(,)?) => {
        rpc_felt_251_serde!($head);
        rpc_felt_251_serde!($($tail),+);
    };
}

rpc_felt_serde!(
    CallParam,
    CallResultValue,
    CasmHash,
    ChainId,
    ClassHash,
    ConstructorParam,
    ContractAddressSalt,
    ContractNonce,
    EntryPoint,
    EventKey,
    EventData,
    L1ToL2MessagePayloadElem,
    L2ToL1MessagePayloadElem,
    SequencerAddress,
    SierraHash,
    BlockHash,
    TransactionHash,
    StateCommitment,
    StorageValue,
    TransactionNonce,
    TransactionSignatureElem,
    PaymasterDataElem,
    AccountDeploymentDataElem,
    ProofFactElem,
);

rpc_felt_251_serde!(ContractAddress, StorageAddress);

mod deserialization {
    //! Blanket [serde::Deserialize] and [serde_with::DeserializeAs]
    //! implementations for [RpcFelt] and [RpcFelt251] supported types.
    use super::*;

    impl<'de, T> serde_with::DeserializeAs<'de, T> for RpcFelt
    where
        T: From<RpcFelt>,
    {
        fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::Deserialize;

            let rpc_felt: RpcFelt = Deserialize::deserialize(deserializer)?;

            Ok(T::from(rpc_felt))
        }
    }

    impl<'de> serde::Deserialize<'de> for RpcFelt {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct FeltVisitor;

            impl serde::de::Visitor<'_> for FeltVisitor {
                type Value = RpcFelt;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter
                        .write_str("a hex string of up to 64 digits with an optional '0x' prefix")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    // Felt::from_hex_str currently does not enforce `0x` prefix, add it here to
                    // prevent breaking other serde related code.
                    match v.as_bytes() {
                        &[b'0', b'x', ..] => pathfinder_crypto::Felt::from_hex_str(v)
                            .map_err(|e| serde::de::Error::custom(e))
                            .map(RpcFelt),
                        _missing_prefix => Err(serde::de::Error::custom("Missing '0x' prefix")),
                    }
                }
            }

            deserializer.deserialize_str(FeltVisitor)
        }
    }

    impl<'de, T> serde_with::DeserializeAs<'de, T> for RpcFelt251
    where
        T: From<RpcFelt251>,
    {
        fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::Deserialize;

            let rpc_felt: RpcFelt251 = Deserialize::deserialize(deserializer)?;

            Ok(T::from(rpc_felt))
        }
    }

    impl<'de> serde::Deserialize<'de> for RpcFelt251 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::Error;
            let felt: RpcFelt = serde::Deserialize::deserialize(deserializer)?;

            if felt.0.has_more_than_251_bits() {
                return Err(D::Error::custom("Value exceeded 251 bits"));
            }

            Ok(RpcFelt251(felt))
        }
    }
}
