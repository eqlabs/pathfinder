use crate::dto::serialize;
use crate::dto::serialize::SerializeForVersion;

pub struct DeprecatedContractClass<'a>(pub &'a crate::v02::types::CairoContractClass);
pub struct ContractClass<'a>(pub &'a crate::v02::types::SierraContractClass);

pub struct DeprecatedCairoEntryPoint<'a>(pub &'a crate::v02::types::ContractEntryPoint);
pub struct ContractAbi<'a>(pub &'a [crate::v02::types::ContractAbiEntry]);

impl SerializeForVersion for DeprecatedContractClass<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        struct EntryPointsByType<'a>(&'a crate::v02::types::ContractEntryPoints);

        impl SerializeForVersion for EntryPointsByType<'_> {
            fn serialize(
                &self,
                serializer: serialize::Serializer,
            ) -> Result<serialize::Ok, serialize::Error> {
                let mut serializer = serializer.serialize_struct()?;

                serializer.serialize_iter(
                    "CONSTRUCTOR",
                    self.0.constructor.len(),
                    &mut self
                        .0
                        .constructor
                        .iter()
                        .map(|x| DeprecatedCairoEntryPoint(x)),
                )?;

                serializer.serialize_iter(
                    "EXTERNAL",
                    self.0.external.len(),
                    &mut self.0.external.iter().map(|x| DeprecatedCairoEntryPoint(x)),
                )?;

                serializer.serialize_iter(
                    "L1_HANDLER",
                    self.0.l1_handler.len(),
                    &mut self
                        .0
                        .l1_handler
                        .iter()
                        .map(|x| DeprecatedCairoEntryPoint(x)),
                )?;

                serializer.end()
            }
        }

        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("program", &self.0.program)?;
        serializer.serialize_field(
            "entry_points_by_type",
            &EntryPointsByType(&self.0.entry_points_by_type),
        )?;
        serializer.serialize_optional("abi", self.0.abi.as_ref().map(|x| ContractAbi(&x)))?;

        serializer.end()
    }
}

impl SerializeForVersion for ContractClass<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        todo!()
    }
}

impl SerializeForVersion for DeprecatedCairoEntryPoint<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        todo!()
    }
}

impl SerializeForVersion for ContractAbi<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        todo!()
    }
}
