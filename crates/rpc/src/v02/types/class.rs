use anyhow::Context;
use pathfinder_serde::U64AsHexStr;
use serde::{Deserialize, Serialize};
use stark_hash::Felt;

impl ContractClass {
    pub fn from_definition_bytes(data: &[u8]) -> anyhow::Result<ContractClass> {
        let mut json = serde_json::from_slice::<serde_json::Value>(data).context("Parsing json")?;
        let json_obj = json
            .as_object_mut()
            .context("Class definition is not a json object")?;

        let entry = json_obj
            .get_mut("entry_points_by_type")
            .context("entry_points_by_type property is missing")?
            .take();
        let entry =
            serde_json::from_value::<ContractEntryPoints>(entry).context("Parsing entry points")?;

        // ABI is optional.
        let abi = json_obj.get_mut("abi").and_then(|json| {
            let json = json.take();
            // ABIs are set by users and not verified by starknet, therefore ABIs
            // can fail to parse (and just be nonsense). Discard these ABIs.
            serde_json::from_value::<Vec<ContractAbiEntry>>(json).ok()
        });

        let program = json_obj
            .get_mut("program")
            .context("program property is missing")?;

        // Program is expected to be a gzip-compressed then base64 encoded representation of the JSON.
        let mut gzip_encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        serde_json::to_writer(&mut gzip_encoder, &program).context("Compressing program")?;
        let compressed_program = gzip_encoder
            .finish()
            .context("Finalizing program compression")?;
        let encoded_program = base64::encode(compressed_program);
        let program = encoded_program;

        Ok(ContractClass {
            program,
            entry_points_by_type: entry,
            abi,
        })
    }
}

impl TryFrom<ContractClass>
    for starknet_gateway_types::request::add_transaction::ContractDefinition
{
    type Error = serde_json::Error;

    fn try_from(c: ContractClass) -> Result<Self, Self::Error> {
        use starknet_gateway_types::request::contract::{EntryPointType, SelectorAndOffset};
        use std::collections::HashMap;

        let abi = match c.abi {
            Some(abi) => Some(serde_json::to_value(abi)?),
            None => None,
        };
        let mut entry_points: HashMap<EntryPointType, Vec<SelectorAndOffset>> = Default::default();
        entry_points.insert(
            EntryPointType::Constructor,
            c.entry_points_by_type
                .constructor
                .into_iter()
                .map(Into::into)
                .collect(),
        );
        entry_points.insert(
            EntryPointType::External,
            c.entry_points_by_type
                .external
                .into_iter()
                .map(Into::into)
                .collect(),
        );
        entry_points.insert(
            EntryPointType::L1Handler,
            c.entry_points_by_type
                .l1_handler
                .into_iter()
                .map(Into::into)
                .collect(),
        );

        Ok(Self {
            program: c.program,
            entry_points_by_type: entry_points,
            abi,
        })
    }
}

// FIXME rename to DeprecatedContractClass?
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ContractClass {
    pub program: String,
    pub entry_points_by_type: ContractEntryPoints,
    pub abi: Option<Vec<ContractAbiEntry>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(deny_unknown_fields)]
pub struct ContractEntryPoints {
    pub constructor: Vec<ContractEntryPoint>,
    pub external: Vec<ContractEntryPoint>,
    pub l1_handler: Vec<ContractEntryPoint>,
}

#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContractEntryPoint {
    #[serde_as(as = "U64AsHexStr")]
    pub offset: u64,
    #[serde_as(as = "crate::felt::RpcFelt")]
    pub selector: Felt,
}

impl From<ContractEntryPoint> for starknet_gateway_types::request::contract::SelectorAndOffset {
    fn from(entry_point: ContractEntryPoint) -> Self {
        Self {
            selector: pathfinder_common::EntryPoint(entry_point.selector),
            offset: pathfinder_common::ByteCodeOffset(Felt::from_u64(entry_point.offset)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum ContractAbiEntry {
    Function(FunctionAbiEntry),
    Event(EventAbiEntry),
    Struct(StructAbiEntry),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub enum StructAbiType {
    Struct,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub enum EventAbiType {
    Event,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum FunctionAbiType {
    Function,
    L1Handler,
    // This is missing from the v0.2 RPC specification and will be added in the
    // next version. We add it as a deviation from the current spec, since it is
    // effectively a bug in the v0.2 specification.
    Constructor,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StructAbiEntry {
    r#type: StructAbiType,
    name: String,
    size: u64,
    members: Vec<StructMember>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StructMember {
    // Serde does not support deny_unknown_fields + flatten, so we
    // flatten TypedParameter manually here.
    #[serde(rename = "name")]
    typed_parameter_name: String,
    #[serde(rename = "type")]
    typed_parameter_type: String,
    offset: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventAbiEntry {
    r#type: EventAbiType,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    keys: Option<Vec<TypedParameter>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    data: Option<Vec<TypedParameter>>,
    // The `inputs` and `outputs` property is not part of the JSON-RPC
    // specification, but because we use these types to parse the
    // `starknet_estimateFee` request and then serialize the class definition in
    // the transaction for the Python layer we have to keep this property when
    // serializing.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    inputs: Option<Vec<TypedParameter>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    outputs: Option<Vec<TypedParameter>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FunctionAbiEntry {
    r#type: FunctionAbiType,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    inputs: Option<Vec<TypedParameter>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    outputs: Option<Vec<TypedParameter>>,
    // This is not part of the JSON-RPC specification, but because we use these
    // types to parse the `starknet_estimateFee` request and then serialize the
    // class definition in the transaction for the Python layer we have to keep
    // this property when serializing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "stateMutability")]
    state_mutability: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TypedParameter {
    name: String,
    r#type: String,
}

// FIXME rename to ContractClass?
#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SierraContractClass {
    pub entry_points_by_type: SierraEntryPoints,
    #[serde_as(as = "Vec<crate::felt::RpcFelt>")]
    pub sierra_program: Vec<Felt>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(deny_unknown_fields)]
pub struct SierraEntryPoints {
    pub constructor: Vec<SierraEntryPoint>,
    pub external: Vec<SierraEntryPoint>,
    pub l1_handler: Vec<SierraEntryPoint>,
}

#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SierraEntryPoint {
    pub function_idx: u64,
    #[serde_as(as = "crate::felt::RpcFelt")]
    pub selector: Felt,
}
