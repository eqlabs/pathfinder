use serde::Serialize;

use crate::v06::method::get_transaction_receipt::types::ExecutionResourcesPropertiesV06;

#[derive(Serialize)]
pub struct ComputationResources(ExecutionResourcesPropertiesV06);

impl From<pathfinder_common::receipt::ExecutionResources> for ComputationResources {
    fn from(value: pathfinder_common::receipt::ExecutionResources) -> Self {
        Self(ExecutionResourcesPropertiesV06 {
            steps: value.n_steps,
            memory_holes: value.n_memory_holes,
            range_check_builtin_applications: value.builtin_instance_counter.range_check_builtin,
            pedersen_builtin_applications: value.builtin_instance_counter.pedersen_builtin,
            poseidon_builtin_applications: value.builtin_instance_counter.poseidon_builtin,
            ec_op_builtin_applications: value.builtin_instance_counter.ec_op_builtin,
            ecdsa_builtin_applications: value.builtin_instance_counter.ecdsa_builtin,
            bitwise_builtin_applications: value.builtin_instance_counter.bitwise_builtin,
            keccak_builtin_applications: value.builtin_instance_counter.keccak_builtin,
            segment_arena_builtin: value.builtin_instance_counter.segment_arena_builtin,
        })
    }
}
