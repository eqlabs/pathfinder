use serde::de::Error;

#[derive(Debug, Clone, Default)]
pub enum NewTxnFinalityStatus {
    PreConfirmed,
    #[default]
    AcceptedOnL2,
}

impl NewTxnFinalityStatus {
    pub fn is_pre_confirmed(&self) -> bool {
        matches!(self, Self::PreConfirmed)
    }
}

impl crate::dto::DeserializeForVersion for NewTxnFinalityStatus {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        let value: String = value.deserialize()?;
        match value.as_str() {
            "PRE_CONFIRMED" => Ok(Self::PreConfirmed),
            "ACCEPTED_ON_L2" => Ok(Self::AcceptedOnL2),
            _ => Err(serde_json::Error::custom("Invalid finality status")),
        }
    }
}
