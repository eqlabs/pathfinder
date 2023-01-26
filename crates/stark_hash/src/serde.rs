use super::Felt;
use serde::{de::Visitor, Deserialize, Serialize};

impl Serialize for Felt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // StarkHash has a leading "0x" and at most 64 digits
        let mut buf = [0u8; 2 + 64];
        let s = self.as_hex_str(&mut buf);
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for Felt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StarkHashVisitor;

        impl<'de> Visitor<'de> for StarkHashVisitor {
            type Value = Felt;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a hex string of up to 64 digits with an optional '0x' prefix")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Felt::from_hex_str(v).map_err(|e| serde::de::Error::custom(e))
            }
        }

        deserializer.deserialize_str(StarkHashVisitor)
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
        assert_eq!(serde_json::from_str::<Felt>(r#""""#).unwrap(), Felt::ZERO);
        assert_eq!(serde_json::from_str::<Felt>(r#""0x""#).unwrap(), Felt::ZERO);
    }

    #[test]
    fn zero() {
        let original = Felt::ZERO;
        assert_eq!(serde_json::to_string(&original).unwrap(), ZERO);
        assert_eq!(serde_json::from_str::<Felt>(ZERO).unwrap(), original);
    }

    #[test]
    fn odd() {
        let original = Felt::from_hex_str(ODD).unwrap();
        let expected = format!("\"{ODD}\"");
        assert_eq!(serde_json::to_string(&original).unwrap(), expected);
        assert_eq!(serde_json::from_str::<Felt>(&expected).unwrap(), original);
    }

    #[test]
    fn even() {
        let original = Felt::from_hex_str(EVEN).unwrap();
        let expected = format!("\"{EVEN}\"");
        assert_eq!(serde_json::to_string(&original).unwrap(), expected);
        assert_eq!(serde_json::from_str::<Felt>(&expected).unwrap(), original);
    }

    #[test]
    fn max() {
        let original = Felt::from_hex_str(MAX).unwrap();
        let expected = format!("\"{MAX}\"");
        assert_eq!(serde_json::to_string(&original).unwrap(), expected);
        assert_eq!(serde_json::from_str::<Felt>(&expected).unwrap(), original);
    }
}
