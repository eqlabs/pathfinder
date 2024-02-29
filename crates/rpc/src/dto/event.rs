use crate::dto::primitives::*;
use crate::dto::serialize::*;

struct EventContent<'a>(&'a pathfinder_common::event::Event);

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

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::macro_prelude::*;
    use pretty_assertions_sorted::assert_eq;

    #[test]
    fn event_content() {
        let uut = pathfinder_common::event::Event {
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
        };
        let uut = EventContent(&uut);
        let expected = serde_json::json!({
            "data": uut.0.data.iter()
                .map(|x| Felt(&x.0)
                .serialize(Default::default()).unwrap())
                .collect::<Vec<_>>(),
            "keys": uut.0.keys.iter()
                .map(|x| Felt(&x.0)
                .serialize(Default::default()).unwrap())
                .collect::<Vec<_>>(),
        });
        let encoded = uut.serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }
}
