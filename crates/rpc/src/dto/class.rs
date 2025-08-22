use serde_with::ser::SerializeAsWrap;

use super::U64Hex;
use crate::dto::SerializeForVersion;
use crate::types;

impl SerializeForVersion for types::CairoContractClass {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("program", &self.program)?;
        serializer.serialize_field("entry_points_by_type", &self.entry_points_by_type)?;
        serializer.serialize_optional_with_null("abi", self.abi.clone())?;

        serializer.end()
    }
}

impl SerializeForVersion for types::SierraContractClass {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_iter(
            "sierra_program",
            self.sierra_program.len(),
            &mut self.sierra_program.iter(),
        )?;

        serializer.serialize_field("contract_class_version", &self.contract_class_version)?;
        serializer.serialize_field("entry_points_by_type", &self.entry_points_by_type)?;

        // ABI is optional, so skip if its empty.
        let abi = (!self.abi.is_empty()).then_some(&self.abi);
        serializer.serialize_optional_with_null("abi", abi)?;

        serializer.end()
    }
}

impl SerializeForVersion for types::SierraEntryPoints {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_iter(
            "CONSTRUCTOR",
            self.constructor.len(),
            &mut self.constructor.iter(),
        )?;

        serializer.serialize_iter("EXTERNAL", self.external.len(), &mut self.external.iter())?;

        serializer.serialize_iter(
            "L1_HANDLER",
            self.l1_handler.len(),
            &mut self.l1_handler.iter(),
        )?;

        serializer.end()
    }
}

impl SerializeForVersion for types::ContractEntryPoints {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_iter(
            "CONSTRUCTOR",
            self.constructor.len(),
            &mut self.constructor.iter(),
        )?;

        serializer.serialize_iter("EXTERNAL", self.external.len(), &mut self.external.iter())?;

        serializer.serialize_iter(
            "L1_HANDLER",
            self.l1_handler.len(),
            &mut self.l1_handler.iter(),
        )?;

        serializer.end()
    }
}

impl SerializeForVersion for &types::ContractEntryPoint {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("offset", &U64Hex(self.offset))?;
        serializer.serialize_field("selector", &self.selector)?;

        serializer.end()
    }
}

impl SerializeForVersion for &types::SierraEntryPoint {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("selector", &self.selector)?;
        serializer.serialize_field("function_idx", &self.function_idx)?;

        serializer.end()
    }
}

impl SerializeForVersion for [types::ContractAbiEntry] {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_iter(self.len(), &mut self.iter())
    }
}

impl SerializeForVersion for Vec<types::ContractAbiEntry> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_iter(self.len(), &mut self.iter())
    }
}

impl SerializeForVersion for &types::ContractAbiEntry {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self {
            types::ContractAbiEntry::Function(f) => f.serialize(serializer),
            types::ContractAbiEntry::Event(e) => e.serialize(serializer),
            types::ContractAbiEntry::Struct(s) => s.serialize(serializer),
        }
    }
}

impl SerializeForVersion for &types::FunctionAbiEntry {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &self.r#type)?;
        serializer.serialize_field("name", &self.name)?;

        let inputs = self.inputs.as_deref().unwrap_or_default();
        serializer.serialize_iter("inputs", inputs.len(), &mut inputs.iter())?;

        let outputs = self.outputs.as_deref().unwrap_or_default();
        serializer.serialize_iter("outputs", outputs.len(), &mut outputs.iter())?;

        serializer.serialize_optional(
            "stateMutability",
            self.state_mutability
                .as_ref()
                .map(|_| FunctionStateMutability),
        );

        serializer.end()
    }
}

impl SerializeForVersion for &types::EventAbiEntry {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &EventAbiType)?;
        serializer.serialize_field("name", &self.name)?;

        let keys = self.keys.as_deref().unwrap_or_default();
        serializer.serialize_iter("keys", keys.len(), &mut keys.iter())?;

        let data = self.data.as_deref().unwrap_or_default();
        serializer.serialize_iter("data", data.len(), &mut data.iter())?;

        serializer.end()
    }
}

impl SerializeForVersion for &types::StructAbiEntry {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &StructAbiType)?;
        serializer.serialize_field("name", &self.name)?;
        // FIXME: this should be a NonZero according to the RPC spec.
        serializer.serialize_field("size", &self.size)?;

        serializer.serialize_iter("members", self.members.len(), &mut self.members.iter())?;

        serializer.end()
    }
}

impl SerializeForVersion for types::FunctionAbiType {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self {
            types::FunctionAbiType::Function => "function",
            types::FunctionAbiType::L1Handler => "l1_handler",
            types::FunctionAbiType::Constructor => "constructor",
        }
        .serialize(serializer)
    }
}

pub struct EventAbiType;

impl SerializeForVersion for EventAbiType {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_str("event")
    }
}

pub struct StructAbiType;

impl SerializeForVersion for StructAbiType {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_str("struct")
    }
}

pub struct FunctionStateMutability;

impl SerializeForVersion for FunctionStateMutability {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_str("view")
    }
}

impl SerializeForVersion for &types::StructMember {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        // FIXME: these clones could be removed if the types::* definitions were
        // smarter.
        let parameter = &types::TypedParameter {
            name: self.typed_parameter_name.clone(),
            r#type: self.typed_parameter_type.clone(),
        };
        serializer.flatten(&parameter)?;
        serializer.serialize_field("offset", &self.offset)?;

        serializer.end()
    }
}

impl SerializeForVersion for &types::TypedParameter {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("name", &self.name)?;
        serializer.serialize_field("type", &self.r#type)?;

        serializer.end()
    }
}
