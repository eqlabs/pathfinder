use crate::context::RpcContext;
use crate::types::syncing::Syncing;

crate::error::generate_rpc_error_subset!(Error);

pub struct Output(Syncing);

pub async fn syncing(context: RpcContext) -> Result<Output, Error> {
    // Scoped so I don't have to think too hard about mutex guard drop semantics.
    let value = match *context.sync_status.status.read().await {
        Syncing::False(_) => Syncing::False(false),
        Syncing::Status(status) => {
            if status.highest.number.get() - status.current.number.get() < 6 {
                // In case we're (almost) caught up we just return false.
                Syncing::False(false)
            } else {
                Syncing::Status(status)
            }
        }
    };

    Ok(Output(value))
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        match self.0 {
            Syncing::False(_) => serializer.serialize_bool(false),
            Syncing::Status(status) => serializer.serialize(&crate::dto::SyncStatus(&status)),
        }
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::{block_hash, BlockNumber};

    use super::*;
    use crate::types::syncing::{NumberedBlock, Status};

    #[tokio::test]
    async fn not_started_yet() {
        let context = RpcContext::for_tests();

        *context.sync_status.status.write().await = Syncing::False(false);

        assert_eq!(syncing(context).await.unwrap().0, Syncing::False(false));
    }

    #[tokio::test]
    async fn caught_up() {
        let context = RpcContext::for_tests();

        *context.sync_status.status.write().await = Syncing::Status(Status {
            starting: NumberedBlock {
                hash: block_hash!("0xaaaa"),
                number: BlockNumber::new_or_panic(0),
            },
            current: NumberedBlock {
                hash: block_hash!("0xaaaa"),
                number: BlockNumber::new_or_panic(0),
            },
            highest: NumberedBlock {
                hash: block_hash!("0xaaaa"),
                number: BlockNumber::new_or_panic(0),
            },
        });

        assert_eq!(syncing(context).await.unwrap().0, Syncing::False(false));
    }

    #[tokio::test]
    async fn syncing_in_progress() {
        let context = RpcContext::for_tests();

        let status = Status {
            starting: NumberedBlock {
                hash: block_hash!("0xaaaa"),
                number: BlockNumber::new_or_panic(0),
            },
            current: NumberedBlock {
                hash: block_hash!("0xbbbb"),
                number: BlockNumber::new_or_panic(2),
            },
            highest: NumberedBlock {
                hash: block_hash!("0xcccc"),
                number: BlockNumber::new_or_panic(10),
            },
        };

        *context.sync_status.status.write().await = Syncing::Status(status);

        assert_eq!(syncing(context).await.unwrap().0, Syncing::Status(status));
    }
}
