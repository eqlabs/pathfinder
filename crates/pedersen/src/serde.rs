use super::StarkHash;
use serde::{de::Visitor, Deserialize, Serialize};

impl Serialize for StarkHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex_str())
    }
}

impl<'de> Deserialize<'de> for StarkHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(StarkHashVisitor)
    }
}

struct StarkHashVisitor;

impl<'de> Visitor<'de> for StarkHashVisitor {
    type Value = StarkHash;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a hex string of up to 64 digits with an optional '0x' prefix")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        StarkHash::from_hex_str(v).map_err(|e| serde::de::Error::custom(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    const ZERO: &str = r#""0x0""#;
    const ODD: &str = "0x1234567890abcde";
    const EVEN: &str = "0x1234567890abcdef";
    const MAX: &str = "0x800000000000011000000000000000000000000000000000000000000000000";

    #[test]
    fn empty() {
        assert_eq!(
            serde_json::from_str::<StarkHash>(r#""""#).unwrap(),
            StarkHash::ZERO
        );
        assert_eq!(
            serde_json::from_str::<StarkHash>(r#""0x""#).unwrap(),
            StarkHash::ZERO
        );
    }

    #[test]
    fn zero() {
        let original = StarkHash::ZERO;
        assert_eq!(serde_json::to_string(&original).unwrap(), ZERO);
        assert_eq!(serde_json::from_str::<StarkHash>(ZERO).unwrap(), original);
    }

    #[test]
    fn odd() {
        let original = StarkHash::from_hex_str(ODD).unwrap();
        let expected = format!("\"{}\"", ODD);
        assert_eq!(serde_json::to_string(&original).unwrap(), expected);
        assert_eq!(
            serde_json::from_str::<StarkHash>(&expected).unwrap(),
            original
        );
    }

    #[test]
    fn even() {
        let original = StarkHash::from_hex_str(EVEN).unwrap();
        let expected = format!("\"{}\"", EVEN);
        assert_eq!(serde_json::to_string(&original).unwrap(), expected);
        assert_eq!(
            serde_json::from_str::<StarkHash>(&expected).unwrap(),
            original
        );
    }

    #[test]
    fn max() {
        let original = StarkHash::from_hex_str(MAX).unwrap();
        let expected = format!("\"{}\"", MAX);
        assert_eq!(serde_json::to_string(&original).unwrap(), expected);
        assert_eq!(
            serde_json::from_str::<StarkHash>(&expected).unwrap(),
            original
        );
    }
}
