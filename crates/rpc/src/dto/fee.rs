use super::U256Hex;

impl crate::dto::SerializeForVersion for pathfinder_executor::types::FeeEstimate {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        if serializer.version >= crate::dto::RpcVersion::V08 {
            serializer.serialize_field("l1_gas_consumed", &U256Hex(self.l1_gas_consumed))?;
            serializer.serialize_field("l1_gas_price", &U256Hex(self.l1_gas_price))?;
            serializer
                .serialize_field("l1_data_gas_consumed", &U256Hex(self.l1_data_gas_consumed))?;
            serializer.serialize_field("l1_data_gas_price", &U256Hex(self.l1_data_gas_price))?;
            serializer.serialize_field("l2_gas_consumed", &U256Hex(self.l2_gas_consumed))?;
            serializer.serialize_field("l2_gas_price", &U256Hex(self.l2_gas_price))?;
            serializer.serialize_field("overall_fee", &U256Hex(self.overall_fee))?;
            serializer.serialize_field("unit", &self.unit)?;
        } else {
            serializer.serialize_field("gas_price", &U256Hex(self.l1_gas_price))?;
            serializer.serialize_field("gas_consumed", &U256Hex(self.l1_gas_consumed))?;
            serializer.serialize_field("data_gas_consumed", &U256Hex(self.l1_data_gas_consumed))?;
            serializer.serialize_field("data_gas_price", &U256Hex(self.l1_data_gas_price))?;
            serializer.serialize_field("overall_fee", &U256Hex(self.overall_fee))?;
            serializer.serialize_field("unit", &self.unit)?;
        }

        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for pathfinder_executor::types::PriceUnit {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_str(match self {
            pathfinder_executor::types::PriceUnit::Wei => "WEI",
            pathfinder_executor::types::PriceUnit::Fri => "FRI",
        })
    }
}
