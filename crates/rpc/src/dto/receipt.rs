use primitive_types::H256;

use crate::dto::serialize::SerializeForVersion;
use crate::{dto::*, RpcVersion};

use super::serialize;

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
}
