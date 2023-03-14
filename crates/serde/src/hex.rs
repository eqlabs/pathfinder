use stark_hash::Felt;

use crate::newtype::NewType;

pub struct HexFelt(pub Felt);

impl<'de, T> serde_with::DeserializeAs<'de, T> for HexFelt
where
    T: NewType<Felt>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::Deserialize;

        let rpc_felt: HexFelt = Deserialize::deserialize(deserializer)?;

        Ok(T::from_inner(rpc_felt.0))
    }
}

impl<'de> serde::Deserialize<'de> for HexFelt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FeltVisitor;

        impl<'de> serde::de::Visitor<'de> for FeltVisitor {
            type Value = HexFelt;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("'0x' prefix followed by a hex string of up to 64 digits")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                // Felt::from_hex_str currently does not enforce `0x` prefix, add it here to prevent
                // breaking other serde related code.
                match v.as_bytes() {
                    &[b'0', b'x', ..] => stark_hash::Felt::from_hex_str(v)
                        .map_err(|e| serde::de::Error::custom(e))
                        .map(HexFelt),
                    _missing_prefix => Err(serde::de::Error::custom("Missing '0x' prefix")),
                }
            }
        }

        deserializer.deserialize_str(FeltVisitor)
    }
}

impl serde::Serialize for HexFelt {
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

impl<T> serde_with::SerializeAs<T> for HexFelt
where
    T: NewType<Felt> + Clone,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::Serialize;

        HexFelt::serialize(&HexFelt(value.clone().into_inner()), serializer)
    }
}
