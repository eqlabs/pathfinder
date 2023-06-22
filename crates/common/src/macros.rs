/// Macros for newtypes stored with an sqlite INTEGER column.
pub(super) mod i64_backed_u64 {

    /// Generates `new`, `new_or_panic` and `get` methods, and `PartialEq` against `i64` and `u64`.
    macro_rules! new_get_partialeq {
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

    /// Generates a u64 alike serialization and deserialization.
    macro_rules! serdes {
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

    pub(crate) use {new_get_partialeq, serdes};
}

/// Macros for general StarkHash newtypes.
pub(super) mod starkhash {
    /// Common trait implementations for *[stark_hash::Felt]* newtypes, meaning tuple structs
    /// with single field.
    macro_rules! common_newtype {
        ($target:ty) => {
            crate::macros::fmt::thin_debug!($target);
            crate::macros::fmt::thin_display!($target);

            impl $target {
                pub const ZERO: Self = Self(Felt::ZERO);

                pub fn as_inner(&self) -> &Felt {
                    &self.0
                }
            }
        };

        ($head:ty, $($tail:ty),+ $(,)?) => {
            crate::macros::starkhash::common_newtype!($head);
            crate::macros::starkhash::common_newtype!($($tail),+);
        };
    }

    pub(crate) use common_newtype;
}

pub(super) mod starkhash251 {
    macro_rules! newtype {
        ($target:ty) => {
            impl $target {
                pub const fn new(hash: Felt) -> Option<Self> {
                    if hash.has_more_than_251_bits() {
                        None
                    } else {
                        Some(Self(hash))
                    }
                }

                pub const fn new_or_panic(hash: Felt) -> Self {
                    match Self::new(hash) {
                        Some(key) => key,
                        None => panic!("Too many bits, need less for MPT keys"),
                    }
                }

                pub const fn get(&self) -> &Felt {
                    &self.0
                }

                pub fn view_bits(&self) -> &bitvec::slice::BitSlice<bitvec::order::Msb0, u8> {
                    self.0.view_bits()
                }
            }
        };
    }

    // this seems a lot of code copypasted around, but it is only used by two types. if there would
    // be a lot more types, I'd fully flesh out a separate StarkHash251 type (like the visitor is
    // currently called), then first deserialize to it, then have a From<_> conversion to any other
    // Starkhash251 newtype.
    macro_rules! deserialization {
        ($target:ty) => {
            impl $target {
                pub fn deserialize_value<E>(original: &str, raw: Felt) -> Result<Self, E>
                where
                    E: serde::de::Error,
                {
                    Self::new(raw).ok_or_else(|| {
                        serde::de::Error::invalid_value(
                            serde::de::Unexpected::Str(original),
                            &"At most 251-bit value",
                        )
                    })
                }
            }

            impl<'de> serde::Deserialize<'de> for $target {
                fn deserialize<D>(de: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    struct StarkHash251;

                    impl<'de> serde::de::Visitor<'de> for StarkHash251 {
                        type Value = $target;

                        fn expecting(
                            &self,
                            formatter: &mut std::fmt::Formatter<'_>,
                        ) -> std::fmt::Result {
                            formatter.write_str("A hex string with at most 251 bits set.")
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: serde::de::Error,
                        {
                            let hash = Felt::from_hex_str(v).map_err(serde::de::Error::custom)?;

                            <$target>::deserialize_value(v, hash)
                        }
                    }

                    de.deserialize_str(StarkHash251)
                }
            }
        };
    }
    pub(crate) use {deserialization, newtype};
}

pub(super) mod fmt {

    /// Adds a thin display implementation which uses the inner fields Display.
    macro_rules! thin_display {
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
    macro_rules! thin_debug {
        ($target:ty) => {
            impl std::fmt::Debug for $target {
                fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(fmt, "{}({})", stringify!($target), self.0)
                }
            }
        };
    }

    pub(crate) use {thin_debug, thin_display};
}

/// Creates a [Felt](stark_hash::Felt) from a hex string literal verified at compile time.
#[macro_export]
macro_rules! felt {
    ($hex:expr) => {{
        // This forces const evaluation of the macro call. Without this the invocation will only be evaluated
        // at runtime.
        const CONST_FELT: stark_hash::Felt = match stark_hash::Felt::from_hex_str($hex) {
            Ok(f) => f,
            Err(stark_hash::HexParseError::InvalidNibble(_)) => panic!("Invalid hex digit"),
            Err(stark_hash::HexParseError::InvalidLength { .. }) => panic!("Too many hex digits"),
            Err(stark_hash::HexParseError::Overflow) => panic!("Felt overflow"),
        };
        CONST_FELT
    }};
}

/// Creates a [`stark_hash::Felt`] from a byte slice, resulting in compile-time error when
/// invalid.
#[macro_export]
macro_rules! felt_bytes {
    ($bytes:expr) => {{
        match stark_hash::Felt::from_be_slice($bytes) {
            Ok(sh) => sh,
            Err(stark_hash::OverflowError) => panic!("Invalid constant: OverflowError"),
        }
    }};
}

/// Asserts a condition against the Starknet version on a given network. This is intended to let you mark code which may need refactoring
/// once a certain Starknet version condition comes false. For example, you can remind yourself that a field alias may be safely removed once
/// v0.11.0 of Starknet is released on mainnet.
///
/// Note that the assertion only occurs for `#[cfg(test)]`.
///
/// Usage:
/// ```rust,ignore
/// version_check!(<network> <operator> <version>, <optional assert message>);
/// version_check!(Testnet < 0-11-0, "Will not compile once Testnet has launched v0.11.0+");
/// ```
///
/// Supported operators: `<, <=, ==, >=, >`.
///
/// Example:
/// ```rust,ignore
/// version_check!(Mainnet < 0-11-0, "Drop field alias");
/// #[derive(serde::Serialize)]
/// struct MyType {
///     #[serde(alias = old_name)]
///     field: u32,
/// }
/// ```
#[macro_export]
macro_rules! version_check {
    ($network:ident $operator:tt $major:literal-$minor:literal-$patch:literal $(,$msg:literal)?) => {
        #[allow(dead_code)]
        const NETWORK: (u64, u64, u64) = match pathfinder_common::Chain::$network {
            pathfinder_common::Chain::Mainnet => (0, 11, 2),
            pathfinder_common::Chain::Testnet => (0, 11, 2),
            pathfinder_common::Chain::Testnet2 => (0, 11, 2),
            pathfinder_common::Chain::Integration => (0, 12, 0),
            pathfinder_common::Chain::Custom => panic!("Custom networks are not supported"),
        };
        const INPUT: (u64, u64, u64) = ($major, $minor, $patch);

        // Supress comparisons with `0` warnings.
        #[allow(unused_comparisons, dead_code)]
        const ASSERT: bool = pathfinder_common::version_check!(@compare NETWORK $operator INPUT);

        #[cfg(test)]
        const _: () = assert!(ASSERT, $($msg)?);
    };
    (@compare $left:ident < $right:ident) => {
        match ($left, $right) {
            (l, r) if l.0 < r.0 => true,
            (l, r) if l.0 == r.0 && l.1 < r.1 => true,
            (l, r) if l.0 == r.0 && l.1 == r.1 && l.2 < r.2 => true,
            _ => false,
        }
    };
    (@compare $left:ident <= $right:ident) => {
        match ($left, $right) {
            (l, r) if l.0 < r.0 => true,
            (l, r) if l.0 == r.0 && l.1 < r.1 => true,
            (l, r) if l.0 == r.0 && l.1 == r.1 && l.2 <= r.2 => true,
            _ => false,
        }
    };
    (@compare $left:ident > $right:ident) => {
        match ($left, $right) {
            (l, r) if l.0 > r.0 => true,
            (l, r) if l.0 == r.0 && l.1 > r.1 => true,
            (l, r) if l.0 == r.0 && l.1 == r.1 && l.2 > r.2 => true,
            _ => false,
        }
    };
    (@compare $left:ident >= $right:ident) => {
        match ($left, $right) {
            (l, r) if l.0 > r.0 => true,
            (l, r) if l.0 == r.0 && l.1 > r.1 => true,
            (l, r) if l.0 == r.0 && l.1 == r.1 && l.2 >= r.2 => true,
            _ => false,
        }
    };
    (@compare $left:ident == $right:ident) => {
        $left.0 == $right.0 && $left.1 == $right.1 && $left.2 == $right.2
    };
    (@compare $left:ident != $right:ident) => {
        $left.0 != $right.0 && $left.1 != $right.1 && $left.2 != $right.2
    };
}
