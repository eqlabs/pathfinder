use crate::event::Event;
use crate::receipt::Receipt;
use crate::state_update::StateUpdateData;
use crate::transaction::Transaction;
use crate::BlockHeader;

#[derive(Clone, Debug, Default)]
pub struct L2Block {
    pub header: BlockHeader,
    pub state_update: StateUpdateData,
    pub transactions_and_receipts: Vec<(Transaction, Receipt)>,
    pub events: Vec<Vec<Event>>,
}
