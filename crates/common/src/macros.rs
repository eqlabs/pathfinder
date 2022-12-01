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

    /// Generates the rusqlite ToSql and FromSql trait implementations which enable hiding the u64
    /// field but still being able to query and read values out.
    macro_rules! to_from_sql {
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
                    Ok(Self::new_or_panic(value.as_i64()? as u64))
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

    pub(crate) use {new_get_partialeq, serdes, to_from_sql};
}

/// Macros for general StarkHash newtypes.
pub(super) mod starkhash {

    /// Adds the common ToSql and FromSql implementations for the type.
    ///
    /// This avoids having to implement the traits over at `stark_hash` which would require a
    /// dependency to `rusqlite` over at `stark_hash`.
    ///
    /// This allows direct use of the values as sql parameters or reading them from the rows. It should
    /// be noted that `Option<_>` must be used to when reading a nullable column, as this
    /// implementation will error at `as_blob()?`.
    macro_rules! to_from_sql {
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

    /// Common trait implementations for *[stark_hash::StarkHash]* newtypes, meaning tuple structs
    /// with single field.
    macro_rules! common_newtype {
        ($target:ty) => {
            crate::macros::starkhash::to_from_sql!($target);
            crate::macros::fmt::thin_debug!($target);
            crate::macros::fmt::thin_display!($target);
        };

        ($head:ty, $($tail:ty),+ $(,)?) => {
            crate::macros::starkhash::common_newtype!($head);
            crate::macros::starkhash::common_newtype!($($tail),+);
        };
    }

    pub(crate) use {common_newtype, to_from_sql};
}

pub(super) mod starkhash251 {
    macro_rules! newtype {
        ($target:ty) => {
            impl $target {
                pub const fn new(hash: StarkHash) -> Option<Self> {
                    if hash.has_more_than_251_bits() {
                        None
                    } else {
                        Some(Self(hash))
                    }
                }

                pub const fn new_or_panic(hash: StarkHash) -> Self {
                    match Self::new(hash) {
                        Some(key) => key,
                        None => panic!("Too many bits, need less for MPT keys"),
                    }
                }

                pub const fn get(&self) -> &StarkHash {
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
                pub fn deserialize_value<E>(original: &str, raw: StarkHash) -> Result<Self, E>
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
                            let hash =
                                StarkHash::from_hex_str(v).map_err(serde::de::Error::custom)?;

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

/// Creates a [`stark_hash::StarkHash`] from an even hex string, resulting in compile-time error
/// when invalid.
#[macro_export]
macro_rules! starkhash {
    ($hex:expr) => {{
        let bytes = hex_literal::hex!($hex);
        match stark_hash::StarkHash::from_be_slice(bytes.as_slice()) {
            Ok(sh) => sh,
            Err(stark_hash::OverflowError) => panic!("Invalid constant: OverflowError"),
        }
    }};
}

/// Creates a [`stark_hash::StarkHash`] from a byte slice, resulting in compile-time error when
/// invalid.
#[macro_export]
macro_rules! starkhash_bytes {
    ($bytes:expr) => {{
        match stark_hash::StarkHash::from_be_slice($bytes) {
            Ok(sh) => sh,
            Err(stark_hash::OverflowError) => panic!("Invalid constant: OverflowError"),
        }
    }};
}
