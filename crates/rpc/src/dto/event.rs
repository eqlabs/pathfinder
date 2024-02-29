use crate::dto::primitives::*;
use crate::dto::serialize::*;

pub struct Event<'a>(pub &'a pathfinder_common::event::Event);

pub struct EventContent<'a>(&'a pathfinder_common::event::Event);

pub struct EmittedEvent<'a> {
    pub event: &'a pathfinder_common::event::Event,
    pub block_hash: Option<&'a pathfinder_common::BlockHash>,
    pub block_number: Option<pathfinder_common::BlockNumber>,
    pub transaction_hash: &'a pathfinder_common::TransactionHash,
}

impl SerializeForVersion for Event<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<Ok, Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("from_address", &Address(&self.0.from_address))?;
        serializer.flatten(&EventContent(&self.0))?;

        serializer.end()
    }
}

impl SerializeForVersion for EventContent<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<Ok, Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_iter(
            "keys",
            self.0.keys.len(),
            &mut self.0.keys.iter().map(|x| Felt(&x.0)),
        )?;

        serializer.serialize_iter(
            "data",
            self.0.data.len(),
            &mut self.0.data.iter().map(|x| Felt(&x.0)),
        )?;

        serializer.end()
    }
}

impl SerializeForVersion for EmittedEvent<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<Ok, Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.flatten(&Event(self.event))?;

        serializer.serialize_optional("block_hash", self.block_hash.map(BlockHash))?;
        serializer.serialize_optional("block_number", self.block_number.map(BlockNumber))?;

        serializer.serialize_field("transaction_hash", &TxnHash(self.transaction_hash))?;

        serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::macro_prelude::*;
    use pretty_assertions_sorted::assert_eq;

    fn test_event() -> pathfinder_common::event::Event {
        pathfinder_common::event::Event {
            data: vec![
                event_data!("0x1"),
                event_data!("0x2"),
                event_data!("0x3"),
                event_data!("0x4"),
            ],
            from_address: contract_address!("0xabcd"),
            keys: vec![
                event_key!("0x5"),
                event_key!("0x6"),
                event_key!("0x7"),
                event_key!("0x8"),
            ],
        }
    }

    #[test]
    fn event() {
        let event = test_event();
        let encoded = Event(&event).serialize(Default::default()).unwrap();

        let address = serde_json::json!({
            "from_address": Address(&event.from_address).serialize(Default::default()).unwrap(),
        });
        let content = EventContent(&event).serialize(Default::default()).unwrap();

        let expected = crate::dto::merge_json(content, address);

        assert_eq!(encoded, expected);
    }

    #[test]
    fn event_content() {
        let event = test_event();
        let expected = serde_json::json!({
            "data": event.data.iter()
                .map(|x| Felt(&x.0)
                .serialize(Default::default()).unwrap())
                .collect::<Vec<_>>(),
            "keys": event.keys.iter()
                .map(|x| Felt(&x.0)
                .serialize(Default::default()).unwrap())
                .collect::<Vec<_>>(),
        });
        let encoded = EventContent(&event).serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn emitted_event() {
        let s = Serializer::default();
        let event = test_event();
        let tx_hash = transaction_hash!("0x1234");
        let block_hash = block_hash!("0x222");
        let block_number = pathfinder_common::BlockNumber::GENESIS + 10;

        let encoded_event = s.serialize(&Event(&event)).unwrap();
        let encoded_context = serde_json::json!({
            "transaction_hash": s.serialize(&TxnHash(&tx_hash)).unwrap(),
            "block_hash": s.serialize(&BlockHash(&block_hash)).unwrap(),
            "block_number": s.serialize(&BlockNumber(block_number)).unwrap(),
        });
        let expected = crate::dto::merge_json(encoded_event, encoded_context);

        let encoded = EmittedEvent {
            event: &event,
            block_hash: Some(&block_hash),
            block_number: Some(block_number),
            transaction_hash: &tx_hash,
        }
        .serialize(s)
        .unwrap();

        assert_eq!(encoded, expected);
    }
}
