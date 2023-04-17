mod block_context;
mod call;
mod error;
mod estimate;
mod pending;
mod simulate;
mod state;
mod state_reader;
mod transaction;
pub(crate) mod types;

pub use call::call;
pub use error::CallError;
pub use estimate::{estimate_fee, estimate_fee_for_gateway_transactions, estimate_message_fee};
pub use simulate::simulate;
pub use state::ExecutionState;

pub(crate) mod felt {
    pub trait IntoFelt {
        fn into_felt(self) -> stark_hash::Felt;
    }

    impl IntoFelt for starknet_in_rust::felt::Felt252 {
        fn into_felt(self) -> stark_hash::Felt {
            stark_hash::Felt::from_be_slice(&self.to_be_bytes())
                .expect("Felt252 should fit into Felt")
        }
    }

    pub trait IntoFelt252 {
        fn into_felt252(self) -> starknet_in_rust::felt::Felt252;
    }

    impl IntoFelt252 for stark_hash::Felt {
        fn into_felt252(self) -> starknet_in_rust::felt::Felt252 {
            starknet_in_rust::felt::Felt252::from_bytes_be(self.as_be_bytes())
        }
    }
}
