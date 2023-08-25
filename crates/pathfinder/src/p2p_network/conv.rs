//! Workaround for the orphan rule - implement conversion fns for types ourside our crate.

use pathfinder_common::{BlockHeader, StateUpdate};

trait ToProto<T> {
    fn to_proto(self) -> T;
}

trait TryFromProto<T> {
    fn try_from_proto(proto: T) -> anyhow::Result<Self>
    where
        Self: Sized;
}

impl ToProto<p2p_proto::block::BlockHeader> for BlockHeader {
    fn to_proto(self) -> p2p_proto::block::BlockHeader {
        p2p_proto::block::BlockHeader {
            parent_block: todo!(),
            time: todo!(),
            sequencer_address: todo!(),
            state_diffs: todo!(),
            state: todo!(),
            proof_fact: todo!(),
            transactions: todo!(),
            events: todo!(),
            receipts: todo!(),
            protocol_version: todo!(),
            chain_id: todo!(),
        }
    }
}

impl ToProto<p2p_proto::state::StateDiff> for StateUpdate {
    fn to_proto(self) -> p2p_proto::state::StateDiff {
        p2p_proto::state::StateDiff {
            tree_id: todo!(),
            contract_diffs: todo!(),
        }
    }
}
