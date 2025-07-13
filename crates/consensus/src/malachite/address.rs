use pathfinder_crypto::Felt;
use serde::{Deserialize, Serialize};

/// A validator address used to identify participants in the consensus protocol.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy, Default, Hash, Serialize, Deserialize)]
pub struct ValidatorAddress(pathfinder_common::ContractAddress);

impl ValidatorAddress {
    /// Create a new validator address from a contract address.
    pub fn new(address: pathfinder_common::ContractAddress) -> Self {
        Self(address)
    }

    /// Get the underlying contract address.
    pub fn into_inner(self) -> pathfinder_common::ContractAddress {
        self.0
    }

    /// Get a reference to the underlying contract address.
    pub fn as_inner(&self) -> &pathfinder_common::ContractAddress {
        &self.0
    }

    /// Convert the validator address to a hex string.
    pub fn to_hex_str(&self) -> String {
        format!("{}", self.0.get())
    }

    /// Try to create a validator address from a hex string.
    /// Returns an error if the conversion fails.
    pub fn try_from_hex_str(s: &str) -> Result<Self, &'static str> {
        let felt = Felt::from_hex_str(s).map_err(|_| "Invalid hex string")?;
        pathfinder_common::ContractAddress::new(felt)
            .map(Self)
            .ok_or("Invalid contract address")
    }

    /// Convert the validator address to a byte array.
    pub fn to_be_bytes(&self) -> Vec<u8> {
        self.0.get().to_be_bytes().to_vec()
    }
}

impl From<p2p_proto::common::Address> for ValidatorAddress {
    fn from(address: p2p_proto::common::Address) -> Self {
        Self(pathfinder_common::ContractAddress(address.0))
    }
}

impl From<ValidatorAddress> for p2p_proto::common::Address {
    fn from(address: ValidatorAddress) -> Self {
        Self(*address.0.get())
    }
}

impl From<pathfinder_common::ContractAddress> for ValidatorAddress {
    fn from(address: pathfinder_common::ContractAddress) -> Self {
        Self(address)
    }
}

impl TryFrom<&str> for ValidatorAddress {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::try_from_hex_str(s)
    }
}

impl malachite_types::Address for ValidatorAddress {}

impl std::fmt::Display for ValidatorAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let short_addr = short_addr(self);
        write!(f, "{short_addr}")
    }
}

impl std::fmt::Debug for ValidatorAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let short_addr = short_addr(self);
        write!(f, "{short_addr}")
    }
}

fn short_addr(addr: &ValidatorAddress) -> String {
    let addr_str = addr.0.get().to_string();
    addr_str.chars().skip(addr_str.len() - 4).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_hex() {
        let s = "0xdeadbeef";
        let addr = ValidatorAddress::try_from_hex_str(s).unwrap();
        assert_eq!(
            addr.to_hex_str(),
            "0x00000000000000000000000000000000000000000000000000000000DEADBEEF"
        );
    }

    #[test]
    fn test_round_trip() {
        let s = "0x000000000000000000000000000000000000000000000000000000000000dead";
        let addr = ValidatorAddress::try_from_hex_str(s).unwrap();
        let s2 = addr.to_hex_str();
        let addr2 = ValidatorAddress::try_from_hex_str(&s2).unwrap();
        assert_eq!(addr, addr2);
    }
}
