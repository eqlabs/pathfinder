use stark_hash::StarkHash;

use super::proto;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub parent_block_hash: StarkHash,
    pub block_number: u64,
    pub global_state_root: StarkHash,
    pub sequencer_address: StarkHash,
    pub block_timestamp: u64,

    pub transaction_count: u32,
    pub transaction_commitment: StarkHash,

    pub event_count: u32,
    pub event_commitment: StarkHash,

    pub protocol_version: u32,
}

impl TryFrom<proto::common::BlockHeader> for BlockHeader {
    type Error = std::io::Error;

    fn try_from(block: proto::common::BlockHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            parent_block_hash: block
                .parent_block_hash
                .ok_or_else(|| invalid_data("Missing parent_block_hash"))?
                .try_into()?,
            block_number: block.block_number,
            global_state_root: block
                .global_state_root
                .ok_or_else(|| invalid_data("Missing global_state_root"))?
                .try_into()?,
            sequencer_address: block
                .sequencer_address
                .ok_or_else(|| invalid_data("Missing sequencer_address"))?
                .try_into()?,
            block_timestamp: block.block_timestamp,
            transaction_count: block.transaction_count,
            transaction_commitment: block
                .transaction_commitment
                .ok_or_else(|| invalid_data("Missing transaction_commitment"))?
                .try_into()?,
            event_count: block.event_count,
            event_commitment: block
                .event_commitment
                .ok_or_else(|| invalid_data("Missing event_commitment"))?
                .try_into()?,
            protocol_version: block.protocol_version,
        })
    }
}

pub fn invalid_data(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

impl From<BlockHeader> for proto::common::BlockHeader {
    fn from(block: BlockHeader) -> Self {
        Self {
            parent_block_hash: Some(block.parent_block_hash.into()),
            block_number: block.block_number,
            global_state_root: Some(block.global_state_root.into()),
            sequencer_address: Some(block.sequencer_address.into()),
            block_timestamp: block.block_timestamp,
            transaction_count: block.transaction_count,
            transaction_commitment: Some(block.transaction_commitment.into()),
            event_count: block.event_count,
            event_commitment: Some(block.event_commitment.into()),
            protocol_version: block.protocol_version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBody {
    pub transactions: Vec<Transaction>,
    pub events: Vec<Event>,
}

impl TryFrom<proto::common::BlockBody> for BlockBody {
    type Error = std::io::Error;

    fn try_from(block: proto::common::BlockBody) -> Result<Self, Self::Error> {
        let transactions: Vec<_> = block
            .transactions
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e: _| invalid_data(&format!("Failed to parse transactions: {}", e)))?;

        let events: Vec<_> = block
            .events
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e: _| invalid_data(&format!("Failed to parse transactions: {}", e)))?;

        Ok(Self {
            transactions,
            events,
        })
    }
}

impl From<BlockBody> for proto::common::BlockBody {
    fn from(body: BlockBody) -> Self {
        Self {
            transaction_count: body
                .transactions
                .len()
                .try_into()
                .expect("Transaction count to fit into u32"),
            transactions: body.transactions.into_iter().map(Into::into).collect(),
            event_count: body
                .events
                .len()
                .try_into()
                .expect("Event count to fit into u32"),
            events: body.events.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transaction {
    Invoke(InvokeTransaction),
    Declare(DeclareTransaction),
    Deploy(DeployTransaction),
    L1Handler(L1HandlerTransaction),
}

impl TryFrom<proto::common::Transaction> for Transaction {
    type Error = std::io::Error;

    fn try_from(value: proto::common::Transaction) -> Result<Self, Self::Error> {
        match value.txn {
            Some(tx) => match tx {
                proto::common::transaction::Txn::Invoke(i) => {
                    Ok(Transaction::Invoke(i.try_into()?))
                }
                proto::common::transaction::Txn::Declare(d) => {
                    Ok(Transaction::Declare(d.try_into()?))
                }
                proto::common::transaction::Txn::Deploy(d) => {
                    Ok(Transaction::Deploy(d.try_into()?))
                }
                proto::common::transaction::Txn::L1Handler(l1) => {
                    Ok(Transaction::L1Handler(l1.try_into()?))
                }
            },
            None => Err(invalid_data("Missing txn field")),
        }
    }
}

impl From<Transaction> for proto::common::Transaction {
    fn from(tx: Transaction) -> Self {
        let txn = Some(match tx {
            Transaction::Invoke(tx) => proto::common::transaction::Txn::Invoke(tx.into()),
            Transaction::Declare(tx) => proto::common::transaction::Txn::Declare(tx.into()),
            Transaction::Deploy(tx) => proto::common::transaction::Txn::Deploy(tx.into()),
            Transaction::L1Handler(tx) => proto::common::transaction::Txn::L1Handler(tx.into()),
        });
        Self { txn }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeTransaction {
    pub contract_address: StarkHash,
    pub entry_point_selector: StarkHash,
    pub calldata: Vec<StarkHash>,
    pub signature: Vec<StarkHash>,
    pub max_fee: StarkHash,
    pub nonce: StarkHash,
    pub version: StarkHash,
}

impl TryFrom<proto::common::InvokeTransaction> for InvokeTransaction {
    type Error = std::io::Error;

    fn try_from(tx: proto::common::InvokeTransaction) -> Result<Self, Self::Error> {
        Ok(Self {
            contract_address: tx
                .contract_address
                .ok_or_else(|| invalid_data("Missing contract_address field"))?
                .try_into()?,
            entry_point_selector: tx
                .entry_point_selector
                .ok_or_else(|| invalid_data("Missing entry_point_selector field"))?
                .try_into()?,
            calldata: parse_felt_vector(tx.calldata, "calldata")?,
            signature: parse_felt_vector(tx.signature, "signature")?,
            max_fee: tx
                .max_fee
                .ok_or_else(|| invalid_data("Missing max_fee field"))?
                .try_into()?,
            nonce: tx
                .nonce
                .ok_or_else(|| invalid_data("Missing nonce field"))?
                .try_into()?,
            version: tx
                .version
                .ok_or_else(|| invalid_data("Missing version field"))?
                .try_into()?,
        })
    }
}

pub fn parse_felt_vector(
    felts: Vec<proto::common::FieldElement>,
    field_name: &str,
) -> std::io::Result<Vec<StarkHash>> {
    let felts: Result<Vec<_>, _> = felts.into_iter().map(TryInto::try_into).collect();
    let felts = felts.map_err(|e| invalid_data(&format!("Error parsing {}: {}", field_name, e)))?;
    Ok(felts)
}

impl From<InvokeTransaction> for proto::common::InvokeTransaction {
    fn from(tx: InvokeTransaction) -> Self {
        Self {
            contract_address: Some(tx.contract_address.into()),
            entry_point_selector: Some(tx.entry_point_selector.into()),
            calldata: tx.calldata.into_iter().map(Into::into).collect(),
            signature: tx.signature.into_iter().map(Into::into).collect(),
            max_fee: Some(tx.max_fee.into()),
            nonce: Some(tx.nonce.into()),
            version: Some(tx.version.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L1HandlerTransaction {
    pub contract_address: StarkHash,
    pub entry_point_selector: StarkHash,
    pub calldata: Vec<StarkHash>,
    pub nonce: StarkHash,
    pub version: StarkHash,
}

impl TryFrom<proto::common::L1HandlerTransaction> for L1HandlerTransaction {
    type Error = std::io::Error;

    fn try_from(tx: proto::common::L1HandlerTransaction) -> Result<Self, Self::Error> {
        Ok(Self {
            contract_address: tx
                .contract_address
                .ok_or_else(|| invalid_data("Missing contract_address field"))?
                .try_into()?,
            entry_point_selector: tx
                .entry_point_selector
                .ok_or_else(|| invalid_data("Missing entry_point_selector field"))?
                .try_into()?,
            calldata: parse_felt_vector(tx.calldata, "calldata")?,
            nonce: tx
                .nonce
                .ok_or_else(|| invalid_data("Missing nonce field"))?
                .try_into()?,
            version: tx
                .version
                .ok_or_else(|| invalid_data("Missing version field"))?
                .try_into()?,
        })
    }
}

impl From<L1HandlerTransaction> for proto::common::L1HandlerTransaction {
    fn from(tx: L1HandlerTransaction) -> Self {
        Self {
            contract_address: Some(tx.contract_address.into()),
            entry_point_selector: Some(tx.entry_point_selector.into()),
            calldata: tx.calldata.into_iter().map(Into::into).collect(),
            nonce: Some(tx.nonce.into()),
            version: Some(tx.version.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclareTransaction {
    pub contract_class: ContractClass,
    pub sender_address: StarkHash,
    pub signature: Vec<StarkHash>,
    pub max_fee: StarkHash,
    pub nonce: StarkHash,
    pub version: StarkHash,
}

impl TryFrom<proto::common::DeclareTransaction> for DeclareTransaction {
    type Error = std::io::Error;

    fn try_from(tx: proto::common::DeclareTransaction) -> Result<Self, Self::Error> {
        Ok(Self {
            contract_class: tx
                .contract_class
                .ok_or_else(|| invalid_data("Missing contract_class field"))?
                .try_into()?,
            sender_address: tx
                .sender_address
                .ok_or_else(|| invalid_data("Missing sender_address field"))?
                .try_into()?,
            signature: parse_felt_vector(tx.signature, "signature")?,
            max_fee: tx
                .max_fee
                .ok_or_else(|| invalid_data("Missing max_fee field"))?
                .try_into()?,
            nonce: tx
                .nonce
                .ok_or_else(|| invalid_data("Missing nonce field"))?
                .try_into()?,
            version: tx
                .version
                .ok_or_else(|| invalid_data("Missing version field"))?
                .try_into()?,
        })
    }
}

impl From<DeclareTransaction> for proto::common::DeclareTransaction {
    fn from(tx: DeclareTransaction) -> Self {
        Self {
            contract_class: Some(tx.contract_class.into()),
            sender_address: Some(tx.sender_address.into()),
            max_fee: Some(tx.max_fee.into()),
            signature: tx.signature.into_iter().map(Into::into).collect(),
            nonce: Some(tx.nonce.into()),
            version: Some(tx.version.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployTransaction {
    pub contract_class: ContractClass,
    pub contract_address_salt: StarkHash,
    pub constructor_calldata: Vec<StarkHash>,
    pub version: StarkHash,
}

impl TryFrom<proto::common::DeployTransaction> for DeployTransaction {
    type Error = std::io::Error;

    fn try_from(tx: proto::common::DeployTransaction) -> Result<Self, Self::Error> {
        Ok(Self {
            contract_class: tx
                .contract_class
                .ok_or_else(|| invalid_data("Missing contract_class field"))?
                .try_into()?,
            contract_address_salt: tx
                .contract_address_salt
                .ok_or_else(|| invalid_data("Missing contract_address_salt field"))?
                .try_into()?,
            constructor_calldata: parse_felt_vector(
                tx.constructor_calldata,
                "constructor_calldata",
            )?,
            version: tx
                .version
                .ok_or_else(|| invalid_data("Missing version field"))?
                .try_into()?,
        })
    }
}

impl From<DeployTransaction> for proto::common::DeployTransaction {
    fn from(tx: DeployTransaction) -> Self {
        Self {
            contract_class: Some(tx.contract_class.into()),
            contract_address_salt: Some(tx.contract_address_salt.into()),
            constructor_calldata: tx
                .constructor_calldata
                .into_iter()
                .map(Into::into)
                .collect(),
            version: Some(tx.version.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractClass {
    pub constructor_entry_points: Vec<EntryPoint>,
    pub external_entry_points: Vec<EntryPoint>,
    pub l1_handler_entry_points: Vec<EntryPoint>,
    pub used_builtins: Vec<String>,
    pub contract_program_hash: StarkHash,
    pub bytecode: Vec<StarkHash>,
    pub version: String,
}

impl TryFrom<proto::common::ContractClass> for ContractClass {
    type Error = std::io::Error;

    fn try_from(class: proto::common::ContractClass) -> Result<Self, Self::Error> {
        Ok(Self {
            constructor_entry_points: parse_entry_point_vector(
                class.constructor_entry_points,
                "constructor_entry_point",
            )?,
            external_entry_points: parse_entry_point_vector(
                class.external_entry_points,
                "external_entry_points",
            )?,
            l1_handler_entry_points: parse_entry_point_vector(
                class.l1_handler_entry_points,
                "l1_handler_entry_points",
            )?,
            used_builtins: class
                .used_builtins
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| invalid_data(&format!("Error parsing used builtins: {}", e)))?,
            contract_program_hash: class
                .contract_program_hash
                .ok_or_else(|| invalid_data("Missing contract_program_hash field"))?
                .try_into()?,
            bytecode: parse_felt_vector(class.bytecode, "bytecode")?,
            version: class.version,
        })
    }
}

fn parse_entry_point_vector(
    v: Vec<proto::common::contract_class::EntryPoint>,
    field_name: &str,
) -> std::io::Result<Vec<EntryPoint>> {
    let v: Result<Vec<_>, _> = v.into_iter().map(TryInto::try_into).collect();
    let v = v.map_err(|e| invalid_data(&format!("Error parsing {}: {}", field_name, e)))?;
    Ok(v)
}

impl From<ContractClass> for proto::common::ContractClass {
    fn from(class: ContractClass) -> Self {
        Self {
            constructor_entry_points: class
                .constructor_entry_points
                .into_iter()
                .map(Into::into)
                .collect(),
            external_entry_points: class
                .external_entry_points
                .into_iter()
                .map(Into::into)
                .collect(),
            l1_handler_entry_points: class
                .l1_handler_entry_points
                .into_iter()
                .map(Into::into)
                .collect(),
            used_builtins: class.used_builtins,
            contract_program_hash: Some(class.contract_program_hash.into()),
            bytecode: class.bytecode.into_iter().map(Into::into).collect(),
            version: class.version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPoint {
    pub selector: StarkHash,
    pub offset: StarkHash,
}

impl TryFrom<proto::common::contract_class::EntryPoint> for EntryPoint {
    type Error = std::io::Error;

    fn try_from(ep: proto::common::contract_class::EntryPoint) -> Result<Self, Self::Error> {
        Ok(Self {
            selector: ep
                .selector
                .ok_or_else(|| invalid_data("Missing selector field"))?
                .try_into()?,
            offset: ep
                .offset
                .ok_or_else(|| invalid_data("Missing selector field"))?
                .try_into()?,
        })
    }
}

impl From<EntryPoint> for proto::common::contract_class::EntryPoint {
    fn from(ep: EntryPoint) -> Self {
        Self {
            selector: Some(ep.selector.into()),
            offset: Some(ep.offset.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {}

impl TryFrom<proto::common::Event> for Event {
    type Error = std::io::Error;

    fn try_from(_event: proto::common::Event) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

impl From<Event> for proto::common::Event {
    fn from(_: Event) -> Self {
        Self {}
    }
}
