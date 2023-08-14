use crate::common::Hash;
use crate::{proto, ToProtobuf, TryFromProtobuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetPooledTransactions {
    ByTransactionHashes(Hashes),
    ByMarker(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::mempool::get_pooled_transactions::Hashes")]
pub struct Hashes {
    pub hashes: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::mempool::NewPooledTransactions")]
pub struct NewPooledTransactions {
    // FIXME
    // pub transactions: Vec<Transaction>,
    pub marker: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::mempool::IncludedTransactions")]
pub struct IncludedTransactions {
    pub transactions: Vec<Hash>,
    pub marker: u64,
}

impl ToProtobuf<proto::mempool::GetPooledTransactions> for GetPooledTransactions {
    fn to_protobuf(self) -> proto::mempool::GetPooledTransactions {
        use proto::mempool::get_pooled_transactions::Known;

        proto::mempool::GetPooledTransactions {
            known: match self {
                GetPooledTransactions::ByTransactionHashes(hashes) => {
                    Some(Known::Txs(hashes.to_protobuf()))
                }
                GetPooledTransactions::ByMarker(marker) => Some(Known::Marker(marker)),
            },
        }
    }
}

impl TryFromProtobuf<proto::mempool::GetPooledTransactions> for GetPooledTransactions {
    fn try_from_protobuf(
        input: proto::mempool::GetPooledTransactions,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::mempool::get_pooled_transactions::Known;

        let known = input.known.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing field {field_name}"),
            )
        })?;
        match known {
            Known::Txs(hashes) => Ok(GetPooledTransactions::ByTransactionHashes(
                Hashes::try_from_protobuf(hashes, field_name)?,
            )),
            Known::Marker(marker) => Ok(GetPooledTransactions::ByMarker(marker)),
        }
    }
}
