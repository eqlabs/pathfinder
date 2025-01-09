use fake::{Dummy, Fake, Faker};
use pathfinder_crypto::Felt;

use crate::prelude::*;

#[derive(Clone, Default, Debug, PartialEq, Eq, Dummy)]
pub struct Receipt {
    pub actual_fee: Fee,
    pub execution_resources: ExecutionResources,
    pub l2_to_l1_messages: Vec<L2ToL1Message>,
    pub execution_status: ExecutionStatus,
    pub transaction_hash: TransactionHash,
    pub transaction_index: TransactionIndex,
}

impl Receipt {
    pub fn is_reverted(&self) -> bool {
        matches!(self.execution_status, ExecutionStatus::Reverted { .. })
    }

    pub fn revert_reason(&self) -> Option<&str> {
        match &self.execution_status {
            ExecutionStatus::Succeeded => None,
            ExecutionStatus::Reverted { reason } => Some(reason.as_str()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2ToL1Message {
    pub from_address: ContractAddress,
    pub payload: Vec<L2ToL1MessagePayloadElem>,
    // This is purposefully not EthereumAddress even though this
    // represents an Ethereum address normally. Starknet allows this value
    // to be Felt sized; so technically callers can send a message to a garbage
    // address.
    pub to_address: ContractAddress,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionResources {
    pub builtins: BuiltinCounters,
    pub n_steps: u64,
    pub n_memory_holes: u64,
    pub data_availability: L1Gas,
    pub total_gas_consumed: L1Gas,
    pub l2_gas: L2Gas,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Dummy)]
pub struct L1Gas {
    pub l1_gas: u128,
    pub l1_data_gas: u128,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Dummy, serde::Serialize)]
#[serde(transparent)]
pub struct L2Gas(pub u128);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuiltinCounters {
    pub output: u64,
    pub pedersen: u64,
    pub range_check: u64,
    pub ecdsa: u64,
    pub bitwise: u64,
    pub ec_op: u64,
    pub keccak: u64,
    pub poseidon: u64,
    pub segment_arena: u64,
    pub add_mod: u64,
    pub mul_mod: u64,
    pub range_check96: u64,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Dummy)]
pub enum ExecutionStatus {
    // This must be the default as pre v0.12.1 receipts did not contain this value and
    // were always success as reverted did not exist.
    #[default]
    Succeeded,
    Reverted {
        reason: String,
    },
}

impl<T> Dummy<T> for L2ToL1Message {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            from_address: Faker.fake_with_rng(rng),
            payload: Faker.fake_with_rng(rng),
            // P2P treats this field as an EthereumAddress
            to_address: ContractAddress(
                Felt::from_be_slice(Faker.fake_with_rng::<EthereumAddress, R>(rng).0.as_bytes())
                    .unwrap(),
            ),
        }
    }
}

impl<T> Dummy<T> for ExecutionResources {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            builtins: Faker.fake_with_rng(rng),
            // P2P values are capped at u32::MAX
            n_steps: rng.next_u32() as u64,
            n_memory_holes: rng.next_u32() as u64,
            data_availability: Faker.fake_with_rng(rng),
            // TODO fix this after total_gas_consumed is added to p2p messages
            total_gas_consumed: Default::default(),
            l2_gas: Default::default(),
        }
    }
}

impl<T> Dummy<T> for BuiltinCounters {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            // P2P values are capped at u32::MAX
            output: rng.next_u32() as u64,
            pedersen: rng.next_u32() as u64,
            range_check: rng.next_u32() as u64,
            ecdsa: rng.next_u32() as u64,
            bitwise: rng.next_u32() as u64,
            ec_op: rng.next_u32() as u64,
            keccak: rng.next_u32() as u64,
            poseidon: rng.next_u32() as u64,
            // This field is not used in p2p
            segment_arena: 0,
            add_mod: rng.next_u32() as u64,
            mul_mod: rng.next_u32() as u64,
            range_check96: rng.next_u32() as u64,
        }
    }
}
