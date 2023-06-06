use crate::{ContractAddress, EventData, EventKey};

#[derive(Clone, Debug)]
pub struct Event {
    pub data: Vec<EventData>,
    pub from_address: ContractAddress,
    pub keys: Vec<EventKey>,
}
