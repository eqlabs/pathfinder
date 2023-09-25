//! Workaround for the orphan rule - implement conversion fns for types ourside our crate.
use std::time::{Duration, SystemTime};

use pathfinder_common::{
    state_update::ContractUpdate, transaction::Transaction, BlockHeader, StateUpdate,
    TransactionVersion,
};
use stark_hash::Felt;

pub trait ToProto<T> {
    fn to_proto(self) -> T;
}

impl ToProto<p2p_proto_v1::block::BlockHeader> for BlockHeader {
    fn to_proto(self) -> p2p_proto_v1::block::BlockHeader {
        use p2p_proto_v1::common::{Address, Hash, Merkle, Patricia};
        const ZERO_MERKLE: Merkle = Merkle {
            n_leaves: 0,
            root: Hash(Felt::ZERO),
        };
        const ZERO_PATRICIA: Patricia = Patricia {
            height: 0,
            root: Hash(Felt::ZERO),
        };
        p2p_proto_v1::block::BlockHeader {
            parent_header: Hash(self.parent_hash.0),
            number: self.number.get(),
            time: SystemTime::UNIX_EPOCH // FIXME Dunno how to convert
                .checked_add(Duration::from_secs(self.timestamp.get()))
                .unwrap(),
            sequencer_address: Address(self.sequencer_address.0),
            // FIXME: calculate the merkles et al.
            state_diffs: ZERO_MERKLE,
            state: ZERO_PATRICIA,
            proof_fact: Hash(Felt::ZERO),
            transactions: ZERO_MERKLE,
            events: ZERO_MERKLE,
            receipts: ZERO_MERKLE,
            // FIXME extra fields added to make sync work
            block_hash: Hash(self.hash.0),
            gas_price: self.gas_price.0.to_be_bytes().into(),
            starknet_version: self.starknet_version.take_inner(),
        }
    }
}

impl ToProto<p2p_proto_v1::state::StateDiff> for StateUpdate {
    fn to_proto(self) -> p2p_proto_v1::state::StateDiff {
        use p2p_proto_v1::common::Address;
        use p2p_proto_v1::state::{ContractDiff, ContractStoredValue, StateDiff};
        StateDiff {
            domain: 0, // FIXME there will initially be 2 trees, dunno which id is which
            contract_diffs: self
                .system_contract_updates
                .into_iter()
                .map(|(address, update)| {
                    let address = Address(address.0);
                    let values = update
                        .storage
                        .into_iter()
                        .map(|(storage_address, storage_value)| ContractStoredValue {
                            key: storage_address.0,
                            value: storage_value.0,
                        })
                        .collect();
                    ContractDiff {
                        address,
                        nonce: None,
                        class_hash: None,
                        values,
                    }
                })
                .chain(self.contract_updates.into_iter().map(|(address, update)| {
                    let address = Address(address.0);
                    let ContractUpdate {
                        storage,
                        class,
                        nonce,
                    } = update;
                    let values = storage
                        .into_iter()
                        .map(|(storage_address, storage_value)| ContractStoredValue {
                            key: storage_address.0,
                            value: storage_value.0,
                        })
                        .collect();
                    ContractDiff {
                        address,
                        nonce: nonce.map(|n| n.0),
                        class_hash: class.map(|c| c.class_hash().0),
                        values,
                    }
                }))
                .collect(),
            // FIXME missing: declared classes cairo & sierra, replaced classes
        }
    }
}

impl ToProto<p2p_proto_v1::transaction::Transaction> for Transaction {
    fn to_proto(self) -> p2p_proto_v1::transaction::Transaction {
        use p2p_proto_v1::common::{Address, Hash};
        use p2p_proto_v1::transaction as proto;
        use p2p_proto_v1::transaction::AccountSignature;
        use pathfinder_common::transaction::TransactionVariant::{
            DeclareV0, DeclareV1, DeclareV2, Deploy, DeployAccount, InvokeV0, InvokeV1, L1Handler,
        };
        match self.variant {
            DeclareV0(x) => proto::Transaction::DeclareV0(proto::DeclareV0 {
                sender: Address(x.sender_address.0),
                max_fee: x.max_fee.0,
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                class_hash: Hash(x.class_hash.0),
                nonce: x.nonce.0,
            }),
            DeclareV1(x) => proto::Transaction::DeclareV1(proto::DeclareV1 {
                sender: Address(x.sender_address.0),
                max_fee: x.max_fee.0,
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                class_hash: Hash(x.class_hash.0),
                nonce: x.nonce.0,
            }),
            DeclareV2(x) => proto::Transaction::DeclareV2(proto::DeclareV2 {
                sender: Address(x.sender_address.0),
                max_fee: x.max_fee.0,
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                class_hash: Hash(x.class_hash.0),
                nonce: x.nonce.0,
                compiled_class_hash: x.compiled_class_hash.0,
            }),
            Deploy(x) => proto::Transaction::Deploy(proto::Deploy {
                class_hash: Hash(x.class_hash.0),
                address_salt: x.contract_address_salt.0,
                calldata: x.constructor_calldata.into_iter().map(|c| c.0).collect(),
                address: Address(x.contract_address.0),
                // Only these two values are allowed in storage
                version: if x.version.is_zero() { 0 } else { 1 },
            }),
            DeployAccount(x) => proto::Transaction::DeployAccountV1(proto::DeployAccountV1 {
                max_fee: x.max_fee.0,
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                class_hash: Hash(x.class_hash.0),
                nonce: x.nonce.0,
                address_salt: x.contract_address_salt.0,
                calldata: x.constructor_calldata.into_iter().map(|c| c.0).collect(),
                address: Address(x.contract_address.0),
            }),
            InvokeV0(x) => proto::Transaction::InvokeV0(proto::InvokeV0 {
                max_fee: x.max_fee.0,
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                address: Address(x.sender_address.0),
                entry_point_selector: x.entry_point_selector.0,
                calldata: x.calldata.into_iter().map(|c| c.0).collect(),
                entry_point_type: x.entry_point_type.map(|e| {
                    use pathfinder_common::transaction::EntryPointType::{External, L1Handler};
                    match e {
                        External => proto::EntryPointType::External,
                        L1Handler => proto::EntryPointType::L1Handler,
                    }
                }),
            }),
            InvokeV1(x) => proto::Transaction::InvokeV1(proto::InvokeV1 {
                sender: Address(x.sender_address.0),
                max_fee: x.max_fee.0,
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                nonce: x.nonce.0,
                calldata: x.calldata.into_iter().map(|c| c.0).collect(),
            }),
            L1Handler(x) => proto::Transaction::L1HandlerV1(proto::L1HandlerV1 {
                nonce: x.nonce.0,
                address: Address(x.contract_address.0),
                entry_point_selector: x.entry_point_selector.0,
                calldata: x.calldata.into_iter().map(|c| c.0).collect(),
            }),
        }
    }
}
