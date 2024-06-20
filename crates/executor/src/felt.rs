use pathfinder_crypto::Felt;
use starknet_types_core::felt::Felt as CoreFelt;

pub trait IntoFelt {
    fn into_felt(self) -> Felt;
}

impl IntoFelt for CoreFelt {
    fn into_felt(self) -> Felt {
        Felt::from_be_bytes(self.to_bytes_be()).expect("StarkFelt should fit into Felt")
    }
}

impl IntoFelt for &CoreFelt {
    fn into_felt(self) -> Felt {
        Felt::from_be_bytes(self.to_bytes_be()).expect("StarkFelt should fit into Felt")
    }
}

pub trait IntoStarkFelt {
    fn into_starkfelt(self) -> CoreFelt;
}

impl IntoStarkFelt for Felt {
    fn into_starkfelt(self) -> CoreFelt {
        CoreFelt::from_bytes_be(self.as_be_bytes())
    }
}

impl IntoStarkFelt for pathfinder_common::transaction::DataAvailabilityMode {
    fn into_starkfelt(self) -> CoreFelt {
        match self {
            pathfinder_common::transaction::DataAvailabilityMode::L1 => CoreFelt::ZERO,
            pathfinder_common::transaction::DataAvailabilityMode::L2 => CoreFelt::ONE,
        }
    }
}
