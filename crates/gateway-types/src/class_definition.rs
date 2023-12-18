use std::borrow::Cow;

use crate::request::contract::{SelectorAndFunctionIndex, SelectorAndOffset};
use fake::{Dummy, Fake, Faker};
use pathfinder_crypto::Felt;
use rand::Rng;
use serde::Serialize;
use serde_json::value::RawValue;

#[derive(Debug, Serialize)]
pub struct Sierra<'a> {
    /// Contract ABI.
    pub abi: Cow<'a, str>,

    /// Main program definition.
    pub sierra_program: Vec<Felt>,

    // Version
    pub contract_class_version: Cow<'a, str>,

    /// The contract entry points
    pub entry_points_by_type: SierraEntryPoints,
}

impl<T> Dummy<T> for Sierra<'_> {
    fn dummy_with_rng<R: Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            abi: Cow::Owned(Faker.fake_with_rng(rng)),
            sierra_program: Faker.fake_with_rng(rng),
            contract_class_version: "0.1.0".into(),
            entry_points_by_type: Faker.fake_with_rng(rng),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Cairo<'a> {
    /// Contract ABI, which has no schema definition.
    pub abi: Cow<'a, str>,

    /// Main program definition. __We assume that this is valid JSON.__
    pub program: Cow<'a, RawValue>,

    /// The contract entry points.
    pub entry_points_by_type: CairoEntryPoints,
}

impl<T> Dummy<T> for Cairo<'_> {
    fn dummy_with_rng<R: Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        let program = serde_json::Value::Object(Faker.fake_with_rng(rng));
        Self {
            abi: Cow::Owned(Faker.fake_with_rng(rng)),
            program: Cow::Owned(serde_json::value::to_raw_value(&program).unwrap()),
            entry_points_by_type: Faker.fake_with_rng(rng),
        }
    }
}

#[derive(Debug, Clone, Serialize, Dummy)]
pub struct SierraEntryPoints {
    #[serde(rename = "EXTERNAL")]
    pub external: Vec<SelectorAndFunctionIndex>,
    #[serde(rename = "L1_HANDLER")]
    pub l1_handler: Vec<SelectorAndFunctionIndex>,
    #[serde(rename = "CONSTRUCTOR")]
    pub constructor: Vec<SelectorAndFunctionIndex>,
}

#[derive(Debug, Serialize, Dummy)]
pub struct CairoEntryPoints {
    #[serde(rename = "EXTERNAL")]
    pub external: Vec<SelectorAndOffset>,
    #[serde(rename = "L1_HANDLER")]
    pub l1_handler: Vec<SelectorAndOffset>,
    #[serde(rename = "CONSTRUCTOR")]
    pub constructor: Vec<SelectorAndOffset>,
}
