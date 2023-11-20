use pathfinder_common::{BlockHash, BlockNumber};

use crate::context::RpcContext;
use crate::felt::RpcFelt;

crate::error::generate_rpc_error_subset!(SyncingError);

pub async fn syncing(context: RpcContext) -> Result<SyncingOutput, SyncingError> {
    // Scoped so I don't have to think too hard about mutex guard drop semantics.
    let value = { context.sync_status.status.read().await.clone() };

    use crate::v02::types::syncing::Syncing;
    let value = match value {
        Syncing::False(_) => SyncingOutput::False,
        Syncing::Status(status) => {
            let status = SyncingStatus {
                starting_block_num: status.starting.number,
                current_block_num: status.current.number,
                highest_block_num: status.highest.number,
                starting_block_hash: status.starting.hash,
                current_block_hash: status.current.hash,
                highest_block_hash: status.highest.hash,
            };
            SyncingOutput::Status(status)
        }
    };

    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncingOutput {
    False,
    Status(SyncingStatus),
}

impl serde::Serialize for SyncingOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SyncingOutput::False => serializer.serialize_str("false"),
            SyncingOutput::Status(inner) => serializer.serialize_newtype_struct("status", &inner),
        }
    }
}

#[serde_with::serde_as]
#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
pub struct SyncingStatus {
    starting_block_num: BlockNumber,
    current_block_num: BlockNumber,
    highest_block_num: BlockNumber,
    #[serde_as(as = "RpcFelt")]
    starting_block_hash: BlockHash,
    #[serde_as(as = "RpcFelt")]
    current_block_hash: BlockHash,
    #[serde_as(as = "RpcFelt")]
    highest_block_hash: BlockHash,
}

#[cfg(test)]
mod tests {
    use super::SyncingOutput;
    use crate::context::RpcContext;
    use pathfinder_common::macro_prelude::*;
    mod serde {
        use super::super::{SyncingOutput, SyncingStatus};

        #[test]
        fn not_syncing() {
            let json = serde_json::to_string(&SyncingOutput::False).unwrap();
            assert_eq!(json, r#""false""#);
        }

        #[test]
        fn syncing() {
            use super::*;
            use pathfinder_common::BlockNumber;

            let status = SyncingStatus {
                starting_block_num: BlockNumber::new_or_panic(12),
                current_block_num: BlockNumber::new_or_panic(45),
                highest_block_num: BlockNumber::new_or_panic(772),
                starting_block_hash: block_hash!("0xabcdef"),
                current_block_hash: block_hash!("0x12345677"),
                highest_block_hash: block_hash!("0x1144ffaacc"),
            };
            let value = SyncingOutput::Status(status);
            let json = serde_json::to_value(value).unwrap();

            let expected = serde_json::json!( {
                "starting_block_num": 12,
                "current_block_num": 45,
                "highest_block_num": 772,
                "starting_block_hash": "0xabcdef",
                "current_block_hash": "0x12345677",
                "highest_block_hash": "0x1144ffaacc",
            });

            assert_eq!(json, expected);
        }
    }

    #[tokio::test]
    async fn syncing() {
        use crate::v02::types::syncing::NumberedBlock;
        use crate::v02::types::syncing::Status as V2Status;
        use crate::v02::types::syncing::Syncing as V2Syncing;
        use pathfinder_common::BlockNumber;

        let status = V2Syncing::Status(V2Status {
            starting: NumberedBlock::from(("aabb", 1)),
            current: NumberedBlock::from(("ccddee", 2)),
            highest: NumberedBlock::from(("eeffaacc", 3)),
        });

        let expected = super::SyncingStatus {
            starting_block_num: BlockNumber::new_or_panic(1),
            current_block_num: BlockNumber::new_or_panic(2),
            highest_block_num: BlockNumber::new_or_panic(3),
            starting_block_hash: block_hash!("0xaabb"),
            current_block_hash: block_hash!("0xccddee"),
            highest_block_hash: block_hash!("0xeeffaacc"),
        };
        let expected = SyncingOutput::Status(expected);

        let context = RpcContext::for_tests();
        *context.sync_status.status.write().await = status;

        let result = super::syncing(context).await.unwrap();

        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn not_syncing() {
        let status = crate::v02::types::syncing::Syncing::False(false);

        let context = RpcContext::for_tests();
        *context.sync_status.status.write().await = status;

        let result = super::syncing(context).await.unwrap();

        assert_eq!(result, SyncingOutput::False);
    }
}
