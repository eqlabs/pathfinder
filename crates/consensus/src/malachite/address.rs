use pathfinder_crypto::Felt;
use serde::{Deserialize, Serialize};

/// A validator address for the malachite context.
///
/// This is a wrapper around the `ContractAddress` type from the
/// `pathfinder_common` crate which implements the `Address` trait for the
/// malachite context.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy, Default, Hash, Serialize, Deserialize)]
pub struct ValidatorAddress(pathfinder_common::ContractAddress);

impl ValidatorAddress {
    /// Convert the validator address to a hex string.
    pub fn to_hex_str(&self) -> String {
        format!("{}", self.0.get())
    }

    /// Convert a hex string to a validator address.
    /// If the conversion fails, returns the default address.
    pub fn from_hex_str(s: &str) -> Self {
        let felt = Felt::from_hex_str(s)
            .map_err(|_| anyhow::anyhow!("Invalid felt address"))
            .ok();
        pathfinder_common::ContractAddress::new(felt.unwrap_or_default())
            .map(Self)
            .unwrap_or_default()
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

impl malachite_types::Address for ValidatorAddress {}

impl std::fmt::Display for ValidatorAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let short_addr = short_addr(self);
        write!(f, "{}", short_addr)
    }
}

impl std::fmt::Debug for ValidatorAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let short_addr = short_addr(self);
        write!(f, "{}", short_addr)
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
        let addr = ValidatorAddress::from_hex_str(s);
        assert_eq!(
            addr.to_hex_str(),
            "0x00000000000000000000000000000000000000000000000000000000DEADBEEF"
        );
    }

    #[test]
    fn test_round_trip() {
        let s = "0x000000000000000000000000000000000000000000000000000000000000dead";
        let addr = ValidatorAddress::from_hex_str(s);
        let s2 = addr.to_hex_str();
        let addr2 = ValidatorAddress::from_hex_str(&s2);
        assert_eq!(addr, addr2);
    }
}
