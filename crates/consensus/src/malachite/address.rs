use serde::{Deserialize, Serialize};

/// A validator address for the malachite context.
///
/// This is a wrapper around the `ContractAddress` type from the
/// `pathfinder_common` crate which implements the `Address` trait for the
/// malachite context.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy, Default, Hash, Serialize, Deserialize)]
pub struct ValidatorAddress(pathfinder_common::ContractAddress);

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
