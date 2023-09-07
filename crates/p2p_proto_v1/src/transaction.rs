use crate::common::{Address, BlockId, Hash, Signature};
use crate::{proto, ToProtobuf, TryFromProtobuf};
use fake::Dummy;
use stark_hash::Felt;

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::TransactionCommon")]
pub struct TransactionCommon {
    pub nonce: Felt,
    pub version: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::L2TransactionCommon")]
pub struct L2TransactionCommon {
    pub sender: Address,
    pub signature: Signature,
    pub max_fee: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::InvokeTransaction")]
pub struct InvokeTransaction {
    pub calldata: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::DeclareTransaction")]
pub struct DeclareTransaction {
    pub class_hash: Hash,
    pub compiled_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum L2Transaction {
    Invoke {
        common: L2TransactionCommon,
        txn: InvokeTransaction,
    },
    Declare {
        common: L2TransactionCommon,
        txn: DeclareTransaction,
    },
}

impl ToProtobuf<proto::transaction::L2Transaction> for L2Transaction {
    fn to_protobuf(self) -> proto::transaction::L2Transaction {
        use proto::transaction::l2_transaction::Txn::{Declare, Invoke};
        match self {
            L2Transaction::Invoke { common, txn } => proto::transaction::L2Transaction {
                common: Some(common.to_protobuf()),
                txn: Some(Invoke(txn.to_protobuf())),
            },
            L2Transaction::Declare { common, txn } => proto::transaction::L2Transaction {
                common: Some(common.to_protobuf()),
                txn: Some(Declare(txn.to_protobuf())),
            },
        }
    }
}

impl TryFromProtobuf<proto::transaction::L2Transaction> for L2Transaction {
    fn try_from_protobuf(
        input: proto::transaction::L2Transaction,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::transaction::l2_transaction::Txn::{Declare, Invoke};
        let common = input.common.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing field common in {field_name}"),
            )
        })?;
        let txn = input.txn.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing field txn in {field_name}"),
            )
        })?;
        Ok(match txn {
            Invoke(txn) => L2Transaction::Invoke {
                common: TryFromProtobuf::try_from_protobuf(common, field_name)?,
                txn: TryFromProtobuf::try_from_protobuf(txn, field_name)?,
            },
            Declare(txn) => L2Transaction::Declare {
                common: TryFromProtobuf::try_from_protobuf(common, field_name)?,
                txn: TryFromProtobuf::try_from_protobuf(txn, field_name)?,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::L1HandlerTransaction")]
pub struct L1HandlerTransaction {
    pub contract: Address,
    pub entry_point_selector: Felt,
    pub calldata: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum Transaction {
    L2Transaction {
        common: TransactionCommon,
        txn: L2Transaction,
    },
    L1HandlerTransaction {
        common: TransactionCommon,
        txn: L1HandlerTransaction,
    },
}

impl ToProtobuf<proto::transaction::Transaction> for Transaction {
    fn to_protobuf(self) -> proto::transaction::Transaction {
        use proto::transaction::transaction::Txn::{L1handler, L2Transaction};
        match self {
            Transaction::L2Transaction { common, txn } => proto::transaction::Transaction {
                common: Some(common.to_protobuf()),
                txn: Some(L2Transaction(txn.to_protobuf())),
            },
            Transaction::L1HandlerTransaction { common, txn } => proto::transaction::Transaction {
                common: Some(common.to_protobuf()),
                txn: Some(L1handler(txn.to_protobuf())),
            },
        }
    }
}

impl TryFromProtobuf<proto::transaction::Transaction> for Transaction {
    fn try_from_protobuf(
        input: proto::transaction::Transaction,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::transaction::transaction::Txn::{L1handler, L2Transaction};
        let common = input.common.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing field common in {field_name}"),
            )
        })?;
        let txn = input.txn.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing field txn in {field_name}"),
            )
        })?;
        Ok(match txn {
            L2Transaction(txn) => Transaction::L2Transaction {
                common: TryFromProtobuf::try_from_protobuf(common, field_name)?,
                txn: TryFromProtobuf::try_from_protobuf(txn, field_name)?,
            },
            L1handler(txn) => Transaction::L1HandlerTransaction {
                common: TryFromProtobuf::try_from_protobuf(common, field_name)?,
                txn: TryFromProtobuf::try_from_protobuf(txn, field_name)?,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::GetTransactions")]
pub struct GetTransactions {
    pub id: BlockId,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::Transactions")]
pub struct Transactions {
    pub transactions: Vec<Transaction>,
}
