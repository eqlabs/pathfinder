use crate::rpc::v02::RpcContext;
use pathfinder_common::{StarknetBlockHash, StarknetBlockNumber};
use pathfinder_serde::StarknetBlockNumberAsHexStr;
use serde::Serialize;

crate::rpc::error::generate_rpc_error_subset!(SyncingError);

#[allow(dead_code)]
pub async fn syncing(context: RpcContext) -> Result<SyncingOuput, SyncingError> {
    // Scoped so I don't have to think too hard about mutex guard drop semantics.
    let value = { context.sync_status.status.read().await.clone() };

    use crate::rpc::v01::types::reply::Syncing;
    let value = match value {
        Syncing::False(_) => SyncingOuput::False,
        Syncing::Status(status) => {
            let status = SyncingStatus {
                starting_block_num: status.starting.number,
                current_block_num: status.current.number,
                highest_block_num: status.highest.number,
                starting_block_hash: status.starting.hash,
                current_block_hash: status.current.hash,
                highest_block_hash: status.highest.hash,
            };
            SyncingOuput::Status(status)
        }
    };

    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
pub enum SyncingOuput {
    False,
    Status(SyncingStatus),
}

impl Serialize for SyncingOuput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SyncingOuput::False => serializer.serialize_str("false"),
            SyncingOuput::Status(inner) => serializer.serialize_newtype_struct("status", &inner),
        }
    }
}

#[serde_with::serde_as]
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
pub struct SyncingStatus {
    #[serde_as(as = "StarknetBlockNumberAsHexStr")]
    starting_block_num: StarknetBlockNumber,
    #[serde_as(as = "StarknetBlockNumberAsHexStr")]
    current_block_num: StarknetBlockNumber,
    #[serde_as(as = "StarknetBlockNumberAsHexStr")]
    highest_block_num: StarknetBlockNumber,
    starting_block_hash: StarknetBlockHash,
    current_block_hash: StarknetBlockHash,
    highest_block_hash: StarknetBlockHash,
}

#[cfg(test)]
mod tests {
    use super::SyncingOuput;
    use crate::rpc::v02::RpcContext;
    mod serde {
        use super::super::{SyncingOuput, SyncingStatus};

        #[test]
        fn not_syncing() {
            let json = serde_json::to_string(&SyncingOuput::False).unwrap();
            assert_eq!(json, r#""false""#);
        }

        #[test]
        fn syncing() {
            use pathfinder_common::{starkhash, StarknetBlockHash, StarknetBlockNumber};

            let status = SyncingStatus {
                starting_block_num: StarknetBlockNumber::new_or_panic(0x12),
                current_block_num: StarknetBlockNumber::new_or_panic(0x45),
                highest_block_num: StarknetBlockNumber::new_or_panic(0x772),
                starting_block_hash: StarknetBlockHash(starkhash!("abcdef")),
                current_block_hash: StarknetBlockHash(starkhash!("12345677")),
                highest_block_hash: StarknetBlockHash(starkhash!("1144ffaacc")),
            };
            let value = SyncingOuput::Status(status);
            let json = serde_json::to_value(value).unwrap();

            let expected = serde_json::json!( {
                "starting_block_num": "0x12",
                "current_block_num": "0x45",
                "highest_block_num": "0x772",
                "starting_block_hash": "0xabcdef",
                "current_block_hash": "0x12345677",
                "highest_block_hash": "0x1144ffaacc",
            });

            assert_eq!(json, expected);
        }
    }

    #[tokio::test]
    async fn syncing() {
        use crate::rpc::v01::types::reply::syncing::NumberedBlock;
        use crate::rpc::v01::types::reply::syncing::Status as V1Status;
        use crate::rpc::v01::types::reply::Syncing as V1Syncing;
        use pathfinder_common::{StarknetBlockHash, StarknetBlockNumber};

        let status = V1Syncing::Status(V1Status {
            starting: NumberedBlock::from(("aabb", 1)),
            current: NumberedBlock::from(("ccddee", 2)),
            highest: NumberedBlock::from(("eeffaacc", 3)),
        });

        let expected = super::SyncingStatus {
            starting_block_num: StarknetBlockNumber::new_or_panic(1),
            current_block_num: StarknetBlockNumber::new_or_panic(2),
            highest_block_num: StarknetBlockNumber::new_or_panic(3),
            starting_block_hash: StarknetBlockHash(pathfinder_common::starkhash!("aabb")),
            current_block_hash: StarknetBlockHash(pathfinder_common::starkhash!("ccddee")),
            highest_block_hash: StarknetBlockHash(pathfinder_common::starkhash!("eeffaacc")),
        };
        let expected = SyncingOuput::Status(expected);

        let context = RpcContext::for_tests();
        *context.sync_status.status.write().await = status;

        let result = super::syncing(context).await.unwrap();

        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn not_syncing() {
        let status = crate::rpc::v01::types::reply::Syncing::False(false);

        let context = RpcContext::for_tests();
        *context.sync_status.status.write().await = status;

        let result = super::syncing(context).await.unwrap();

        assert_eq!(result, SyncingOuput::False);
    }
}
