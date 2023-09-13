use crate::common::{Fin, Hashes};
use crate::transaction::Transactions;
use crate::{proto, ToProtobuf, TryFromProtobuf};

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::mempool::PooledTransactionsRequest")]
struct PooledTransactionsRequest {
    #[optional]
    known: Option<Known>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Known {
    Hashes(Hashes),
    Marker(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::mempool::PolledTransactionsResponse")]
struct PolledTransactionsResponse {
    #[optional]
    marker: Option<u64>,
    baseline: bool,
    #[rename(responses)]
    kind: PolledTransactionsResponseKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolledTransactionsResponseKind {
    Pending(Transactions),
    Fin(Fin),
}

impl ToProtobuf<proto::mempool::pooled_transactions_request::Known> for Known {
    fn to_protobuf(self) -> proto::mempool::pooled_transactions_request::Known {
        use proto::mempool::pooled_transactions_request::known::Known::{Marker, Txs};
        proto::mempool::pooled_transactions_request::Known {
            known: Some(match self {
                Known::Hashes(hashes) => Txs(hashes.to_protobuf()),
                Known::Marker(marker) => Marker(marker),
            }),
        }
    }
}

impl TryFromProtobuf<proto::mempool::pooled_transactions_request::Known> for Known {
    fn try_from_protobuf(
        input: proto::mempool::pooled_transactions_request::Known,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::mempool::pooled_transactions_request::known::Known::{Marker, Txs};
        let inner = input.known.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing field known in {field_name}"),
            )
        })?;
        Ok(match inner {
            Txs(hashes) => Known::Hashes(Hashes::try_from_protobuf(hashes, field_name)?),
            Marker(marker) => Known::Marker(marker),
        })
    }
}

impl ToProtobuf<proto::mempool::polled_transactions_response::Responses>
    for PolledTransactionsResponseKind
{
    fn to_protobuf(self) -> proto::mempool::polled_transactions_response::Responses {
        use proto::mempool::polled_transactions_response::Responses::{Fin, Pending};
        match self {
            Self::Pending(transactions) => Pending(transactions.to_protobuf()),
            Self::Fin(fin) => Fin(fin.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::mempool::polled_transactions_response::Responses>
    for PolledTransactionsResponseKind
{
    fn try_from_protobuf(
        input: proto::mempool::polled_transactions_response::Responses,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::mempool::polled_transactions_response::Responses::{Fin, Pending};
        Ok(match input {
            Pending(transactions) => {
                Self::Pending(Transactions::try_from_protobuf(transactions, field_name)?)
            }
            Fin(fin) => Self::Fin(self::Fin::try_from_protobuf(fin, field_name)?),
        })
    }
}
