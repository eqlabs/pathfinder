use anyhow::Context;
use pathfinder_common::{BlockHash, Felt};

use crate::reply::StateUpdate;

/// Deserialization from a gateway response
pub(crate) trait FromGateway
where
    Self: Sized,
{
    fn from_json(json: serde_json::Value) -> anyhow::Result<Self>;
}

pub(crate) trait ToGateway {
    fn to_json(&self) -> serde_json::Value;
}

impl FromGateway for StateUpdate {
    fn from_json(mut json: serde_json::Value) -> anyhow::Result<Self> {
        let mut json = json
            .as_object_mut()
            .context("State update should be a json object")?;

        let block_hash = json
            .remove("block_hash")
            .context("block_hash parameter missing")?;

        let new_root = json
            .remove("new_root")
            .context("new_root parameter missing")?;
        let old_root = json
            .remove("old_root")
            .context("old_root parameter missing")?;

        let state_diff = json
            .remove("state_diff")
            .context("state_diff parameter missing")?;

        if !json.is_empty() {
            let extra_fields: Vec<&String> = json.keys().collect();
            anyhow::bail!("Response contained unexpected fields: {:?}", extra_fields);
        }

        Ok(Self {
            block_hash: todo!(),
            new_root: todo!(),
            old_root: todo!(),
            state_diff: todo!(),
        })
    }
}

impl FromGateway for Felt {
    fn from_json(json: serde_json::Value) -> anyhow::Result<Self> {
        let hex_str = json.as_str().context("Expected a hex string")?;
        let felt = Felt::from_hex_str(hex_str).context("Failed to parse Felt from hex string")?;
        Ok(felt)
    }
}

impl FromGateway for BlockHash {
    fn from_json(json: serde_json::Value) -> anyhow::Result<Self> {
        let felt = Felt::from_json(json)?;
        Ok(BlockHash(felt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_update() {
        let fixture = starknet_gateway_test_fixtures::v0_11_0::state_update::NUMBER_315700;
        let mut json: serde_json::Value = serde_json::from_str(fixture).unwrap();
        json.as_object_mut().unwrap().remove("block_hash");
        dbg!(json.get_mut("block_hash"));

        StateUpdate::from_json(json).unwrap();
    }
}
