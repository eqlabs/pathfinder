use pathfinder_common::transaction::{
    DeclareTransactionV0V1, DeclareTransactionV2, DeployAccountTransaction, DeployTransaction,
    InvokeTransactionV0, InvokeTransactionV1, L1HandlerTransaction,
};
use pathfinder_common::TransactionHash;
use serde::ser::SerializeStruct;
use serde::Serialize;

/// Equivalent to the TXN type from the specification.
#[derive(PartialEq, Debug)]
pub struct Transaction(pub pathfinder_common::transaction::TransactionVariant);

/// A transaction and its hash, a common structure used in the spec.
#[derive(serde::Serialize, PartialEq, Debug)]
pub struct TransactionWithHash {
    pub transaction_hash: TransactionHash,
    #[serde(flatten)]
    pub txn: Transaction,
}

impl From<pathfinder_common::transaction::Transaction> for TransactionWithHash {
    fn from(value: pathfinder_common::transaction::Transaction) -> Self {
        Self {
            transaction_hash: value.hash,
            txn: Transaction(value.variant),
        }
    }
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use pathfinder_common::transaction::TransactionVariant;
        match &self.0 {
            TransactionVariant::DeclareV0(x) => DeclareV0Helper(x).serialize(serializer),
            TransactionVariant::DeclareV1(x) => DeclareV1Helper(x).serialize(serializer),
            TransactionVariant::DeclareV2(x) => DeclareV2Helper(x).serialize(serializer),
            TransactionVariant::Deploy(x) => DeployHelper(x).serialize(serializer),
            TransactionVariant::DeployAccount(x) => DeployAccountHelper(x).serialize(serializer),
            TransactionVariant::InvokeV0(x) => InvokeV0Helper(x).serialize(serializer),
            TransactionVariant::InvokeV1(x) => InvokeV1Helper(x).serialize(serializer),
            TransactionVariant::L1Handler(x) => L1HandlerHelper(x).serialize(serializer),
        }
    }
}

struct DeclareV0Helper<'a>(&'a DeclareTransactionV0V1);
struct DeclareV1Helper<'a>(&'a DeclareTransactionV0V1);
struct DeclareV2Helper<'a>(&'a DeclareTransactionV2);
struct DeployHelper<'a>(&'a DeployTransaction);
struct DeployAccountHelper<'a>(&'a DeployAccountTransaction);
struct InvokeV0Helper<'a>(&'a InvokeTransactionV0);
struct InvokeV1Helper<'a>(&'a InvokeTransactionV1);
struct L1HandlerHelper<'a>(&'a L1HandlerTransaction);

impl Serialize for DeclareV0Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("DeclareV0", 6)?;
        s.serialize_field("type", "DECLARE")?;
        s.serialize_field("sender_address", &self.0.sender_address)?;
        s.serialize_field("max_fee", &self.0.max_fee)?;
        s.serialize_field("version", "0x0")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.end()
    }
}

impl Serialize for DeclareV1Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("DeclareV1", 7)?;
        s.serialize_field("type", "DECLARE")?;
        s.serialize_field("sender_address", &self.0.sender_address)?;
        s.serialize_field("max_fee", &self.0.max_fee)?;
        s.serialize_field("version", "0x1")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.end()
    }
}

impl Serialize for DeclareV2Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("DeclareV2", 8)?;
        s.serialize_field("type", "DECLARE")?;
        s.serialize_field("sender_address", &self.0.sender_address)?;
        s.serialize_field("compiled_class_hash", &self.0.compiled_class_hash)?;
        s.serialize_field("max_fee", &self.0.max_fee)?;
        s.serialize_field("version", "0x2")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.end()
    }
}

impl Serialize for DeployHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("Deploy", 5)?;
        s.serialize_field("version", &self.0.version)?;
        s.serialize_field("type", "DEPLOY")?;
        s.serialize_field("contract_address_salt", &self.0.contract_address_salt)?;
        s.serialize_field("constructor_calldata", &self.0.constructor_calldata)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.end()
    }
}

impl Serialize for DeployAccountHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("DeployAccount", 8)?;
        s.serialize_field("type", "DEPLOY_ACCOUNT")?;
        s.serialize_field("max_fee", &self.0.max_fee)?;
        s.serialize_field("version", &self.0.version)?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.serialize_field("contract_address_salt", &self.0.contract_address_salt)?;
        s.serialize_field("constructor_calldata", &self.0.constructor_calldata)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.end()
    }
}

impl Serialize for InvokeV0Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("InvokeV0", 7)?;
        s.serialize_field("type", "INVOKE")?;
        s.serialize_field("max_fee", &self.0.max_fee)?;
        s.serialize_field("version", "0x0")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("contract_address", &self.0.sender_address)?;
        s.serialize_field("entry_point_selector", &self.0.entry_point_selector)?;
        s.serialize_field("calldata", &self.0.calldata)?;
        s.end()
    }
}

impl Serialize for InvokeV1Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("InvokeV1", 7)?;
        s.serialize_field("type", "INVOKE")?;
        s.serialize_field("sender_address", &self.0.sender_address)?;
        s.serialize_field("calldata", &self.0.calldata)?;
        s.serialize_field("max_fee", &self.0.max_fee)?;
        s.serialize_field("version", "0x1")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.end()
    }
}

impl Serialize for L1HandlerHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("L1Handler", 6)?;
        s.serialize_field("version", &self.0.version)?;
        s.serialize_field("type", "L1_HANDLER")?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.serialize_field("contract_address", &self.0.contract_address)?;
        s.serialize_field("entry_point_selector", &self.0.entry_point_selector)?;
        s.serialize_field("calldata", &self.0.calldata)?;
        s.end()
    }
}
