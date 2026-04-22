use pathfinder_common::Fee;
use starknet_api::transaction::fields::Fee as StarkFee;

pub trait TryIntoStarkFee {
    fn try_into_starkfee(self) -> anyhow::Result<StarkFee>
    where
        Self: Sized;
}

pub trait IntoFee {
    fn into_fee(self) -> Fee;
}

impl IntoFee for StarkFee {
    fn into_fee(self) -> Fee {
        Fee(self.0.into())
    }
}

impl TryIntoStarkFee for Fee {
    fn try_into_starkfee(self) -> anyhow::Result<StarkFee> {
        Ok(StarkFee(self.0.try_into()?))
    }
}
