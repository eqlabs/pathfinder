use crate::receipt::Receipt;
use crate::transaction::Transaction;
use crate::BlockHeader;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct BlockBody {
    pub transaction_data: Vec<(crate::transaction::Transaction, crate::receipt::Receipt)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockWithBody {
    pub header: BlockHeader,
    pub body: BlockBody,
}

impl BlockBody {
    pub fn event_count(&self) -> usize {
        self.transaction_data
            .iter()
            .map(|(_, r)| r.events.len())
            .sum()
    }

    pub fn push_transaction(&mut self, transaction: Transaction, receipt: Receipt) {
        self.transaction_data.push((transaction, receipt));
    }

    pub fn with_transaction(mut self, transaction: Transaction, receipt: Receipt) -> Self {
        self.transaction_data.push((transaction, receipt));
        self
    }
}
