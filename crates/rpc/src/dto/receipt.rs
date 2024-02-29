use std::num::NonZeroU64;

use primitive_types::H256;

use crate::dto::serialize::SerializeForVersion;
use crate::{dto::*, RpcVersion};

use super::serialize;

struct PriceUnit<'a>(&'a pathfinder_common::TransactionVersion);

struct ExecutionResources<'a>(&'a pathfinder_common::receipt::ExecutionResources);
struct ComputationResources<'a>(&'a pathfinder_common::receipt::ExecutionResources);

#[derive(Copy, Clone)]
enum TxnExecutionStatus {
    Succeeded,
    Reverted,
}

#[derive(Copy, Clone)]
pub enum TxnFinalityStatus {
    AcceptedOnL2,
    AcceptedOnL1,
}

struct MsgToL1<'a>(pub &'a pathfinder_common::receipt::L2ToL1Message);

enum TxnType {
    Declare,
    Deploy,
    DeployAccount,
    Invoke,
    L1Handler,
}

impl SerializeForVersion for TxnType {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        match self {
            TxnType::Declare => "DECLARE",
            TxnType::Deploy => "DEPLOY",
            TxnType::DeployAccount => "DEPLOY_ACCOUNT",
            TxnType::Invoke => "INVOKE",
            TxnType::L1Handler => "L1_HANDLER",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for TxnExecutionStatus {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        match self {
            TxnExecutionStatus::Succeeded => "SUCCEEDED",
            TxnExecutionStatus::Reverted => "REVERTED",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for TxnFinalityStatus {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        match self {
            TxnFinalityStatus::AcceptedOnL2 => "ACCEPTED_ON_L2",
            TxnFinalityStatus::AcceptedOnL1 => "ACCEPTED_ON_L1",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for MsgToL1<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("from_address", &Felt(self.0.from_address.get()))?;
        // The spec erroneously marks this as a Felt, but should be an ETH_ADDRESS.
        serializer.serialize_field(
            "to_address",
            // unwrap is safe as Ethereum address is 20 bytes and cannot overflow.
            &Felt(&pathfinder_crypto::Felt::from_be_slice(self.0.to_address.0.as_bytes()).unwrap()),
        )?;
        serializer.serialize_iter(
            "payload",
            self.0.payload.len(),
            &mut self.0.payload.iter().map(|x| Felt(&x.0)),
        )?;

        serializer.end()
    }
}

impl SerializeForVersion for ComputationResources<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut s = serializer.serialize_struct()?;

        s.serialize_field("steps", &self.0.n_steps)?;

        s.serialize_optional("memory_holes", NonZeroU64::new(self.0.n_memory_holes))?;
        s.serialize_optional(
            "range_check_builtin_applications",
            NonZeroU64::new(self.0.builtins.range_check),
        )?;
        s.serialize_optional(
            "pedersen_builtin_applications",
            NonZeroU64::new(self.0.builtins.pedersen),
        )?;
        s.serialize_optional(
            "poseidon_builtin_applications",
            NonZeroU64::new(self.0.builtins.poseidon),
        )?;
        s.serialize_optional(
            "ec_op_builtin_applications",
            NonZeroU64::new(self.0.builtins.ec_op),
        )?;
        s.serialize_optional(
            "ecdsa_builtin_applications",
            NonZeroU64::new(self.0.builtins.ecdsa),
        )?;
        s.serialize_optional(
            "bitwise_builtin_applications",
            NonZeroU64::new(self.0.builtins.bitwise),
        )?;
        s.serialize_optional(
            "keccak_builtin_applications",
            NonZeroU64::new(self.0.builtins.keccak),
        )?;
        s.serialize_optional(
            "segment_arena_builtin",
            NonZeroU64::new(self.0.builtins.segment_arena),
        )?;

        s.end()
    }
}

impl SerializeForVersion for ExecutionResources<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        // This object is defined inline in the spec.
        let mut s = serializer.serialize_struct()?;
        s.serialize_field("l1_gas", &self.0.data_availability.l1_gas)?;
        s.serialize_field("l1_data_gas", &self.0.data_availability.l1_data_gas)?;
        let data_availability = s.end()?;

        let computation = serializer.serialize(&ComputationResources(self.0))?;

        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("data_availability", &data_availability)?;
        serializer.flatten(&computation)?;
        serializer.end()
    }
}
impl SerializeForVersion for PriceUnit<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        use pathfinder_common::TransactionVersion;
        match self.0 {
            &TransactionVersion::ZERO | &TransactionVersion::ONE | &TransactionVersion::TWO => {
                "WEI"
            }
            _ => "FRI",
        }
        .serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use crate::dto::serialize::Serializer;

    use super::*;
    use pathfinder_common::macro_prelude::*;
    use pretty_assertions_sorted::assert_eq;
    use primitive_types::H160;
    use serde_json::json;

    #[test]
    fn msg_to_l1() {
        let s = Serializer::default();

        let to_address = felt!("0x5678");

        let message = pathfinder_common::receipt::L2ToL1Message {
            from_address: contract_address!("0x1234"),
            to_address: pathfinder_common::EthereumAddress(H160::from_slice(
                &to_address.to_be_bytes()[12..],
            )),
            payload: vec![
                l2_to_l1_message_payload_elem!("0x1"),
                l2_to_l1_message_payload_elem!("0x2"),
                l2_to_l1_message_payload_elem!("0x3"),
            ],
        };

        let expected = json!({
            "from_address": s.serialize(&Felt(message.from_address.get())).unwrap(),
            "to_address": s.serialize(&Felt(&to_address)).unwrap(),
            "payload": message.payload.iter().map(|x| Felt(&x.0).serialize(s).unwrap()).collect::<Vec<_>>(),
        });

        let encoded = MsgToL1(&message).serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn txn_finality_status() {
        let s = Serializer::default();
        let l2 = s.serialize(&TxnFinalityStatus::AcceptedOnL2).unwrap();
        let l1 = s.serialize(&TxnFinalityStatus::AcceptedOnL1).unwrap();

        assert_eq!(l2, json!("ACCEPTED_ON_L2"));
        assert_eq!(l1, json!("ACCEPTED_ON_L1"));
    }

    #[test]
    fn txn_execution_status() {
        let s = Serializer::default();
        let succeeded = s.serialize(&TxnExecutionStatus::Succeeded).unwrap();
        let reverted = s.serialize(&TxnExecutionStatus::Reverted).unwrap();

        assert_eq!(succeeded, json!("SUCCEEDED"));
        assert_eq!(reverted, json!("REVERTED"));
    }

    #[test]
    fn txn_type() {
        let s = Serializer::default();

        let declare = s.serialize(&TxnType::Declare).unwrap();
        let deploy = s.serialize(&TxnType::Deploy).unwrap();
        let deploy_account = s.serialize(&TxnType::DeployAccount).unwrap();
        let invoke = s.serialize(&TxnType::Invoke).unwrap();
        let l1_handler = s.serialize(&TxnType::L1Handler).unwrap();

        assert_eq!(declare, json!("DECLARE"));
        assert_eq!(deploy, json!("DEPLOY"));
        assert_eq!(deploy_account, json!("DEPLOY_ACCOUNT"));
        assert_eq!(invoke, json!("INVOKE"));
        assert_eq!(l1_handler, json!("L1_HANDLER"));
    }

    mod computation_resources {
        use super::*;
        use pretty_assertions_sorted::assert_eq;

        #[test]
        fn zeros_are_skipped() {
            let resources = pathfinder_common::receipt::ExecutionResources {
                builtins: Default::default(),
                n_steps: 10,
                n_memory_holes: 0,
                data_availability: Default::default(),
            };

            let expected = json!({
               "steps": 10
            });

            let encoded = Serializer::default()
                .serialize(&ComputationResources(&resources))
                .unwrap();

            assert_eq!(encoded, expected);
        }

        #[test]
        fn non_zeros_are_present() {
            let resources = pathfinder_common::receipt::ExecutionResources {
                builtins: pathfinder_common::receipt::BuiltinCounters {
                    output: 1,
                    pedersen: 2,
                    range_check: 3,
                    ecdsa: 4,
                    bitwise: 5,
                    ec_op: 6,
                    keccak: 7,
                    poseidon: 8,
                    segment_arena: 9,
                },
                n_steps: 10,
                n_memory_holes: 11,
                data_availability: Default::default(),
            };

            let expected = json!({
               "steps": 10,
               "memory_holes": resources.n_memory_holes,
               "range_check_builtin_applications": resources.builtins.range_check,
               "pedersen_builtin_applications": resources.builtins.pedersen,
               "poseidon_builtin_applications": resources.builtins.poseidon,
               "ec_op_builtin_applications": resources.builtins.ec_op,
               "ecdsa_builtin_applications": resources.builtins.ecdsa,
               "bitwise_builtin_applications": resources.builtins.bitwise,
               "keccak_builtin_applications": resources.builtins.keccak,
               "segment_arena_builtin": resources.builtins.segment_arena,
            });

            let encoded = Serializer::default()
                .serialize(&ComputationResources(&resources))
                .unwrap();

            assert_eq!(encoded, expected);
        }
    }

    #[test]
    fn execution_resources() {
        let s = Serializer::default();

        let resources = pathfinder_common::receipt::ExecutionResources {
            n_steps: 10,
            data_availability: pathfinder_common::receipt::ExecutionDataAvailability {
                l1_gas: 101,
                l1_data_gas: 200,
            },
            n_memory_holes: Default::default(),
            builtins: Default::default(),
        };

        let expected_computation = s.serialize(&ComputationResources(&resources)).unwrap();
        let expected_data_availability = json!({
            "data_availability": {
                "l1_gas": resources.data_availability.l1_gas,
                "l1_data_gas": resources.data_availability.l1_data_gas,
            }
        });
        let expected = crate::dto::merge_json(expected_computation, expected_data_availability);

        let encoded = ExecutionResources(&resources).serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn price_unit() {
        use pathfinder_common::TransactionVersion;

        let s = Serializer::default();
        let v0 = s.serialize(&PriceUnit(&TransactionVersion::ZERO)).unwrap();
        let v1 = s.serialize(&PriceUnit(&TransactionVersion::ONE)).unwrap();
        let v2 = s.serialize(&PriceUnit(&TransactionVersion::TWO)).unwrap();
        let v3 = s.serialize(&PriceUnit(&TransactionVersion::THREE)).unwrap();

        assert_eq!(v0, json!("WEI"));
        assert_eq!(v1, json!("WEI"));
        assert_eq!(v2, json!("WEI"));
        assert_eq!(v3, json!("FRI"));
    }
}
