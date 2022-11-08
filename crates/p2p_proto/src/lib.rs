use stark_hash::StarkHash;

pub mod proto {
    pub mod common {
        include!(concat!(env!("OUT_DIR"), "/starknet.common.rs"));
    }
    pub mod propagation {
        include!(concat!(env!("OUT_DIR"), "/starknet.propagation.rs"));
    }
    pub mod sync {
        include!(concat!(env!("OUT_DIR"), "/starknet.sync.rs"));
    }
}

impl TryFrom<proto::common::FieldElement> for StarkHash {
    type Error = std::io::Error;

    fn try_from(element: proto::common::FieldElement) -> Result<Self, Self::Error> {
        let stark_hash = StarkHash::from_be_slice(&element.elements).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid field element: {}", e),
            )
        })?;
        Ok(stark_hash)
    }
}

impl From<StarkHash> for proto::common::FieldElement {
    fn from(hash: StarkHash) -> Self {
        Self {
            elements: hash.to_be_bytes().into(),
        }
    }
}

pub mod common;
pub mod sync;
