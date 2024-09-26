use serde_with::ser::SerializeAsWrap;

use super::U64Hex;
use crate::dto::serialize::SerializeForVersion;
use crate::dto::{serialize, Felt};
use crate::v02::types;

pub struct DeprecatedContractClass<'a>(pub &'a types::CairoContractClass);
pub struct ContractClass<'a>(pub &'a types::SierraContractClass);

pub struct DeprecatedCairoEntryPoint<'a>(pub &'a types::ContractEntryPoint);
pub struct SierraEntryPoint<'a>(pub &'a types::SierraEntryPoint);

pub struct ContractAbi<'a>(pub &'a [types::ContractAbiEntry]);
pub struct ContractAbiEntry<'a>(pub &'a types::ContractAbiEntry);
pub struct FunctionAbiEntry<'a>(pub &'a types::FunctionAbiEntry);
pub struct EventAbiEntry<'a>(pub &'a types::EventAbiEntry);
pub struct StructAbiEntry<'a>(pub &'a types::StructAbiEntry);

pub struct FunctionAbiType(pub types::FunctionAbiType);
pub struct EventAbiType;
pub struct StructAbiType;

pub struct TypedParameter<'a>(pub &'a types::TypedParameter);
pub struct FunctionStateMutability;
pub struct StructMember<'a>(pub &'a types::StructMember);

impl SerializeForVersion for DeprecatedContractClass<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        struct EntryPointsByType<'a>(&'a types::ContractEntryPoints);

        impl SerializeForVersion for EntryPointsByType<'_> {
            fn serialize(
                &self,
                serializer: serialize::Serializer,
            ) -> Result<serialize::Ok, serialize::Error> {
                let mut serializer = serializer.serialize_struct()?;

                serializer.serialize_iter(
                    "CONSTRUCTOR",
                    self.0.constructor.len(),
                    &mut self.0.constructor.iter().map(DeprecatedCairoEntryPoint),
                )?;

                serializer.serialize_iter(
                    "EXTERNAL",
                    self.0.external.len(),
                    &mut self.0.external.iter().map(DeprecatedCairoEntryPoint),
                )?;

                serializer.serialize_iter(
                    "L1_HANDLER",
                    self.0.l1_handler.len(),
                    &mut self.0.l1_handler.iter().map(DeprecatedCairoEntryPoint),
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
        serializer.serialize_optional("abi", self.0.abi.as_ref().map(|x| ContractAbi(x)))?;

        serializer.end()
    }
}

impl SerializeForVersion for ContractClass<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        struct EntryPointsByType<'a>(&'a types::SierraEntryPoints);

        impl SerializeForVersion for EntryPointsByType<'_> {
            fn serialize(
                &self,
                serializer: serialize::Serializer,
            ) -> Result<serialize::Ok, serialize::Error> {
                let mut serializer = serializer.serialize_struct()?;

                serializer.serialize_iter(
                    "CONSTRUCTOR",
                    self.0.constructor.len(),
                    &mut self.0.constructor.iter().map(SierraEntryPoint),
                )?;

                serializer.serialize_iter(
                    "EXTERNAL",
                    self.0.external.len(),
                    &mut self.0.external.iter().map(SierraEntryPoint),
                )?;

                serializer.serialize_iter(
                    "L1_HANDLER",
                    self.0.l1_handler.len(),
                    &mut self.0.l1_handler.iter().map(SierraEntryPoint),
                )?;

                serializer.end()
            }
        }

        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_iter(
            "sierra_program",
            self.0.sierra_program.len(),
            &mut self.0.sierra_program.iter().map(Felt),
        )?;

        serializer.serialize_field("contract_class_version", &self.0.contract_class_version)?;
        serializer.serialize_field(
            "entry_points_by_type",
            &EntryPointsByType(&self.0.entry_points_by_type),
        )?;

        // ABI is optional, so skip if its empty.
        let abi = (!self.0.abi.is_empty()).then_some(&self.0.abi);
        serializer.serialize_optional("abi", abi)?;

        serializer.end()
    }
}

impl SerializeForVersion for DeprecatedCairoEntryPoint<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("offset", &self.0.offset)?;
        serializer.serialize_field("selector", &Felt(&self.0.selector))?;

        serializer.end()
    }
}

impl SerializeForVersion for SierraEntryPoint<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("selector", &Felt(&self.0.selector))?;
        serializer.serialize_field("function_idx", &self.0.function_idx)?;

        serializer.end()
    }
}

impl SerializeForVersion for ContractAbi<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        serializer.serialize_iter(self.0.len(), &mut self.0.iter().map(ContractAbiEntry))
    }
}

impl SerializeForVersion for ContractAbiEntry<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        match self.0 {
            types::ContractAbiEntry::Function(f) => FunctionAbiEntry(f).serialize(serializer),
            types::ContractAbiEntry::Event(e) => EventAbiEntry(e).serialize(serializer),
            types::ContractAbiEntry::Struct(s) => StructAbiEntry(s).serialize(serializer),
        }
    }
}

impl SerializeForVersion for FunctionAbiEntry<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &FunctionAbiType(self.0.r#type))?;
        serializer.serialize_field("name", &self.0.name)?;

        let inputs = self.0.inputs.as_deref().unwrap_or_default();
        serializer.serialize_iter(
            "inputs",
            inputs.len(),
            &mut inputs.iter().map(TypedParameter),
        )?;

        let outputs = self.0.outputs.as_deref().unwrap_or_default();
        serializer.serialize_iter(
            "outputs",
            outputs.len(),
            &mut outputs.iter().map(TypedParameter),
        )?;

        serializer.serialize_optional(
            "stateMutability",
            self.0
                .state_mutability
                .as_ref()
                .map(|_| FunctionStateMutability),
        );

        serializer.end()
    }
}

impl SerializeForVersion for EventAbiEntry<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &EventAbiType)?;
        serializer.serialize_field("name", &self.0.name)?;

        let keys = self.0.keys.as_deref().unwrap_or_default();
        serializer.serialize_iter("keys", keys.len(), &mut keys.iter().map(TypedParameter))?;

        let data = self.0.data.as_deref().unwrap_or_default();
        serializer.serialize_iter("data", data.len(), &mut data.iter().map(TypedParameter))?;

        serializer.end()
    }
}

impl SerializeForVersion for StructAbiEntry<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &StructAbiType)?;
        serializer.serialize_field("name", &self.0.name)?;
        // FIXME: this should be a NonZero according to the RPC spec.
        serializer.serialize_field("size", &self.0.size)?;

        serializer.serialize_iter(
            "members",
            self.0.members.len(),
            &mut self.0.members.iter().map(StructMember),
        )?;

        serializer.end()
    }
}

impl SerializeForVersion for FunctionAbiType {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        match self.0 {
            types::FunctionAbiType::Function => "function",
            types::FunctionAbiType::L1Handler => "l1_handler",
            types::FunctionAbiType::Constructor => "constructor",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for EventAbiType {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        serializer.serialize_str("event")
    }
}

impl SerializeForVersion for StructAbiType {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        serializer.serialize_str("struct")
    }
}

impl SerializeForVersion for TypedParameter<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("name", &self.0.name)?;
        serializer.serialize_field("type", &self.0.r#type)?;

        serializer.end()
    }
}

impl SerializeForVersion for FunctionStateMutability {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        serializer.serialize_str("view")
    }
}

impl SerializeForVersion for StructMember<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        // FIXME: these clones could be removed if the types::* definitions were
        // smarter.
        let parameter = types::TypedParameter {
            name: self.0.typed_parameter_name.clone(),
            r#type: self.0.typed_parameter_type.clone(),
        };
        serializer.flatten(&TypedParameter(&parameter))?;
        serializer.serialize_field("offset", &self.0.offset)?;

        serializer.end()
    }
}
