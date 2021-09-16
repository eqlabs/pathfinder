use bigdecimal::BigDecimal;
use serde::{
    de::{Error, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use std::{
    collections::HashMap,
    fmt::{self, Display},
    hash::Hash,
    marker::PhantomData,
    str::FromStr,
};
use web3::{
    ethabi::ethereum_types::FromDecStrErr,
    types::{H160, H256, U256},
};

/// Large uint deserialization helper function.
///
/// The default [`web3::types::U256::deserialize`] implementation requires a hex string,
/// while the API serves decimal strings.
pub(super) fn from_decimal<'de, D, U>(deserializer: D) -> Result<U, D::Error>
where
    D: Deserializer<'de>,
    U: FromDecStr,
{
    let x: BigDecimal = Deserialize::deserialize(deserializer)?;
    U::from_dec_str(x.to_string().as_str()).map_err(Error::custom)
}

/// Deserialization helper function for arrays of large decimal uints, for example: `[1, 1234567890]`.
pub(super) fn from_decimal_array<'de, D, U>(deserializer: D) -> Result<Vec<U>, D::Error>
where
    D: Deserializer<'de>,
    U: FromDecStr,
{
    deserializer.deserialize_seq(MappingSequenceVisitor::new(
        |x| U::from_dec_str(BigDecimal::to_string(&x).as_str()),
        r#"Expected an array of decimals, for example [1, 1234567890]."#,
    ))
}

/// Deserialization helper function for arrays of strings representing large decimal uints, for example: `["1", "1234567890"]`.
pub(super) fn from_decimal_str_array<'de, D, U>(deserializer: D) -> Result<Vec<U>, D::Error>
where
    D: Deserializer<'de>,
    U: FromDecStr,
{
    deserializer.deserialize_seq(MappingSequenceVisitor::new(
        U::from_dec_str,
        r#"Expected an array of decimal strings, for example ["1", "1234567890"]."#,
    ))
}

/// A version of [`from_decimal_str_array`] that produces and optional value.
pub(super) fn from_optional_decimal_str_array<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<U256>>, D::Error>
where
    D: Deserializer<'de>,
{
    from_decimal_str_array(deserializer).map(Some)
}

/// Deserialization helper function for maps, where keys are strings representing large uints.
pub(super) fn from_decimal_str_keyed_map<'de, D, K, V>(
    deserializer: D,
) -> Result<HashMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Eq + FromDecStr + Hash,
    V: Deserialize<'de>,
{
    deserializer.deserialize_map(PhantomVisitor::<HashMap<K, V>>::new())
}

/// Fixed-size unspecified hash deserialization helper function.
///
/// Python's serde is more liberal, while [`web3::types::U256::deserialize`] requires exactly
/// a 0x-prefixed 64 character hex string.
pub(super) fn from_hex_str<'de, D, H>(deserializer: D) -> Result<H, D::Error>
where
    D: Deserializer<'de>,
    H: FromStr + Display + MaxLenChars,
    H::Err: Display,
{
    let x: &str = Deserialize::deserialize(deserializer)?;
    let has_0x = x.starts_with("0x");
    let req_len = if has_0x {
        2 + H::max_len_chars()
    } else {
        H::max_len_chars()
    };

    use std::cmp::Ordering;

    match x.len().cmp(&req_len) {
        Ordering::Equal => {
            if has_0x {
                H::from_str(x).map_err(Error::custom)
            } else {
                let x_clone = format!("0x{}", x);
                H::from_str(x_clone.as_str()).map_err(Error::custom)
            }
        }
        Ordering::Greater => Err(Error::custom(format!(
            "value: invalid lenght {}, expected a 0x-prefixed hex string with length of 64 or smaller",
            if has_0x { x.len() - 2 } else { x.len() }
        ))),
        Ordering::Less => {
            let start = if has_0x {2} else {0};
            // Pad with missing leading 0s
            H::from_str(format!("0x{:0>64}", &x[start..]).as_str()).map_err(Error::custom)
        }
    }
}

/// A version of [`from_hex_str`] that produces and optional value.
pub(super) fn from_optional_hex_str<'de, D, H>(deserializer: D) -> Result<Option<H>, D::Error>
where
    D: Deserializer<'de>,
    H: FromStr + Display + MaxLenChars,
    H::Err: Display,
{
    from_hex_str(deserializer).map(Some)
}

/// Helper trait which allows for some generalization of [`from_hex_str`].
pub(super) trait MaxLenChars {
    /// Maximum length of a hex string, excluding the `0x` prefix.
    fn max_len_chars() -> usize;
}

impl MaxLenChars for H160 {
    fn max_len_chars() -> usize {
        H160::len_bytes() * 2
    }
}

impl MaxLenChars for H256 {
    fn max_len_chars() -> usize {
        H256::len_bytes() * 2
    }
}

/// Helper trait which allows for some generalization of [`from_decimal`].
pub(super) trait FromDecStr
where
    Self: Sized,
{
    fn from_dec_str(value: &str) -> Result<Self, FromDecStrErr>;
}

impl FromDecStr for U256 {
    fn from_dec_str(value: &str) -> Result<U256, FromDecStrErr> {
        U256::from_dec_str(value)
    }
}

/// A simple sequence visitor which carries an arbitrary element conversion function.
struct MappingSequenceVisitor<F, In, Out, E>
where
    F: Fn(In) -> Result<Out, E>,
{
    /// Mapping/conversion function to be applied to each element of the deserialized sequence.
    map_fn: F,
    /// Message displayed upon deserialization failure, which describes the expected data format.
    expected: &'static str,
    phantom: PhantomData<(In, Out, E)>,
}

impl<F, In, Out, E> MappingSequenceVisitor<F, In, Out, E>
where
    F: Fn(In) -> Result<Out, E>,
{
    /// Constructs new visitor instance.
    fn new(map_fn: F, expected: &'static str) -> Self {
        Self {
            map_fn,
            expected,
            phantom: PhantomData,
        }
    }
}

impl<'de, F, In, Out, E> Visitor<'de> for MappingSequenceVisitor<F, In, Out, E>
where
    F: Fn(In) -> Result<Out, E>,
    In: Deserialize<'de>,
    E: Display,
{
    /// The type that the Visitor is going to produce.
    type Value = Vec<Out>;

    /// Format a message stating what data this Visitor expects to receive.
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(self.expected)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut vec = Vec::<Out>::with_capacity(seq.size_hint().unwrap_or(0));

        while let Some(element) = seq.next_element()? {
            let converted = (self.map_fn)(element).map_err(Error::custom)?;
            vec.push(converted);
        }

        Ok(vec)
    }
}

/// A generic ZST visitor.
struct PhantomVisitor<T>(PhantomData<T>);

impl<T> PhantomVisitor<T> {
    /// Simple constructor so as not to force additional bounds by requiring [Default](std::default::Default).
    fn new() -> Self {
        Self(PhantomData)
    }
}

impl<'de, K, V> Visitor<'de> for PhantomVisitor<HashMap<K, V>>
where
    K: Eq + FromDecStr + Hash,
    V: Deserialize<'de>,
{
    /// The type that the Visitor is going to produce.
    type Value = HashMap<K, V>;

    /// Format a message stating what data this Visitor expects to receive.
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(r#"Expected map, where keys are decimal strings, for example: {"1": {...}, "1234567890": {...}}."#)
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut map = HashMap::<K, V>::with_capacity(access.size_hint().unwrap_or(0));

        while let Some((key, value)) = access.next_entry()? {
            let key = K::from_dec_str(key).map_err(Error::custom)?;
            map.insert(key, value);
        }

        Ok(map)
    }
}
