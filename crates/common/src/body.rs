pub struct BlockBody {
    pub transaction_data: Vec<(crate::transaction::Transaction, crate::receipt::Receipt)>,
}
