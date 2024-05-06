use crate::dto::serialize::SerializeForVersion;

pub struct DeprecatedContractClass<'a>(pub &'a crate::v02::types::CairoContractClass);
pub struct ContractClass<'a>(pub &'a crate::v02::types::SierraContractClass);

impl SerializeForVersion for DeprecatedContractClass<'_> {
    fn serialize(
        &self,
        serializer: super::serialize::Serializer,
    ) -> Result<super::serialize::Ok, super::serialize::Error> {
        todo!()
    }
}

impl SerializeForVersion for ContractClass<'_> {
    fn serialize(
        &self,
        serializer: super::serialize::Serializer,
    ) -> Result<super::serialize::Ok, super::serialize::Error> {
        todo!()
    }
}
