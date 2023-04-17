use stark_hash::Felt;
use starknet_api::hash::StarkFelt;

pub trait IntoFelt {
    fn into_felt(self) -> Felt;
}

impl IntoFelt for StarkFelt {
    fn into_felt(self) -> Felt {
        Felt::from_be_slice(self.bytes()).expect("StarkFelt should fit into Felt")
    }
}

impl IntoFelt for &StarkFelt {
    fn into_felt(self) -> Felt {
        Felt::from_be_slice(self.bytes()).expect("StarkFelt should fit into Felt")
    }
}

pub trait IntoStarkFelt {
    fn into_starkfelt(self) -> StarkFelt;
}

impl IntoStarkFelt for Felt {
    fn into_starkfelt(self) -> StarkFelt {
        StarkFelt::new(self.to_be_bytes()).expect("Felt should fit into StarkFelt")
    }
}
