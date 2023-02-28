use crate::request::contract::EntryPointType;
use anyhow::{Context, Error, Result};
use pathfinder_common::{felt_bytes, ClassHash};
use serde::Serialize;
use sha3::Digest;
use stark_hash::{Felt, HashChain};
use stark_poseidon::PoseidonHasher;

#[derive(Debug, PartialEq)]
pub enum ComputedClassHash {
    Cairo(ClassHash),
    Sierra(ClassHash),
}

impl ComputedClassHash {
    pub fn hash(&self) -> ClassHash {
        match self {
            ComputedClassHash::Cairo(h) => *h,
            ComputedClassHash::Sierra(h) => *h,
        }
    }
}

/// Computes the starknet class hash for given class definition JSON blob.
///
/// This function first parses the JSON blob to decide if it's a Cairo or Sierra class
/// definition and then calls the appropriate function to compute the class hash
/// with the parsed definition.
pub fn compute_class_hash(contract_definition_dump: &[u8]) -> Result<ComputedClassHash> {
    let contract_definition = parse_contract_definition(contract_definition_dump)
        .context("Failed to parse contract definition")?;

    match contract_definition {
        json::ContractDefinition::Sierra(definition) => compute_sierra_class_hash(definition)
            .map(ComputedClassHash::Sierra)
            .context("Compute class hash"),
        json::ContractDefinition::Cairo(definition) => compute_cairo_class_hash(definition)
            .map(ComputedClassHash::Cairo)
            .context("Compute class hash"),
    }
}

/// Parse either a Sierra or a Cairo contract definition.
///
/// Due to an issue in serde_json we can't use an untagged enum and simply derive a Deserialize
/// implementation: <https://github.com/serde-rs/json/issues/559>
fn parse_contract_definition(
    contract_definition_dump: &[u8],
) -> serde_json::Result<json::ContractDefinition<'_>> {
    serde_json::from_slice::<json::SierraContractDefinition<'_>>(contract_definition_dump)
        .map(json::ContractDefinition::Sierra)
        .or_else(|_| {
            serde_json::from_slice::<json::CairoContractDefinition<'_>>(contract_definition_dump)
                .map(json::ContractDefinition::Cairo)
        })
}

/// Sibling functionality to only [`compute_class_hash`], returning also the ABI, and bytecode
/// parts as json bytes.
///
/// NOTE: This function is deprecated. We no longer store ABI and bytecode in the database,
/// and this function is only used by _old_ database migration steps.
pub fn extract_abi_code_hash(
    contract_definition_dump: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, ClassHash)> {
    let contract_definition = parse_contract_definition(contract_definition_dump)
        .context("Failed to parse contract definition")?;

    match contract_definition {
        json::ContractDefinition::Sierra(contract_definition) => {
            let abi = serde_json::to_vec(&contract_definition.abi)
                .context("Serialize contract_definition.abi")?;
            let code = serde_json::to_vec(&contract_definition.sierra_program)
                .context("Serialize contract_definition.sierra_program")?;

            let hash =
                compute_sierra_class_hash(contract_definition).context("Compute class hash")?;

            Ok((abi, code, hash))
        }
        json::ContractDefinition::Cairo(contract_definition) => {
            // just in case we'd accidentially modify these in the compute_class_hash0
            let abi = serde_json::to_vec(&contract_definition.abi)
                .context("Serialize contract_definition.abi")?;
            let code = serde_json::to_vec(&contract_definition.program.data)
                .context("Serialize contract_definition.program.data")?;

            let hash =
                compute_cairo_class_hash(contract_definition).context("Compute class hash")?;

            Ok((abi, code, hash))
        }
    }
}

/// Computes the class hash for given Cairo class definition.
///
/// The structure of the blob is not strictly defined, so it lives in privacy under `json` module
/// of this module. The class hash has [official documentation][starknet-doc] and [cairo-lang
/// has an implementation][cairo-compute] which is half-python and half-[cairo][cairo-contract].
///
/// Outline of the hashing is:
///
/// 1. class definition is serialized with python's [`sort_keys=True` option][py-sortkeys], then
///    a truncated Keccak256 hash is calculated of the serialized json
/// 2. a [hash chain][`HashChain`] construction is used to process in order the contract
///    entry points, builtins, the truncated keccak hash and bytecodes
/// 3. each of the hashchains is hash chained together to produce a final class hash
///
/// Hash chain construction is explained at the [official documentation][starknet-doc], but it's
/// text explanations are much more complex than the actual implementation in `HashChain`.
///
/// [starknet-doc]: https://docs.starknet.io/documentation/architecture_and_concepts/Contracts/class-hash/
/// [cairo-compute]: https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/core/os/contract_hash.py
/// [cairo-contract]: https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/core/os/contracts.cairo#L76-L118
/// [py-sortkeys]: https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/core/os/contract_hash.py#L58-L71
fn compute_cairo_class_hash(
    mut contract_definition: json::CairoContractDefinition<'_>,
) -> Result<ClassHash> {
    use EntryPointType::*;

    // the other modification is handled by skipping if the attributes vec is empty
    contract_definition.program.debug_info = None;

    // Cairo 0.8 added "accessible_scopes" and "flow_tracking_data" attribute fields, which were
    // not present in older contracts. They present as null / empty for older contracts and should
    // not be included in the hash calculation in these cases.
    //
    // We therefore check and remove them from the definition before calculating the hash.
    contract_definition
        .program
        .attributes
        .iter_mut()
        .try_for_each(|attr| -> anyhow::Result<()> {
            let vals = attr
                .as_object_mut()
                .context("Program attribute was not an object")?;

            match vals.get_mut("accessible_scopes") {
                Some(serde_json::Value::Array(array)) => {
                    if array.is_empty() {
                        vals.remove("accessible_scopes");
                    }
                }
                Some(_other) => {
                    anyhow::bail!(
                        r#"A program's attribute["accessible_scopes"] was not an array type."#
                    );
                }
                None => {}
            }
            // We don't know what this type is supposed to be, but if its missing it is null.
            if let Some(serde_json::Value::Null) = vals.get_mut("flow_tracking_data") {
                vals.remove("flow_tracking_data");
            }

            Ok(())
        })?;

    fn add_extra_space_to_cairo_named_tuples(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Array(v) => walk_array(v),
            serde_json::Value::Object(m) => walk_map(m),
            _ => {}
        }
    }

    fn walk_array(array: &mut [serde_json::Value]) {
        for v in array.iter_mut() {
            add_extra_space_to_cairo_named_tuples(v);
        }
    }

    fn walk_map(object: &mut serde_json::Map<String, serde_json::Value>) {
        for (k, v) in object.iter_mut() {
            match v {
                serde_json::Value::String(s) => {
                    let new_value = add_extra_space_to_named_tuple_type_definition(k, s);
                    if new_value.as_ref() != s {
                        *v = serde_json::Value::String(new_value.into());
                    }
                }
                _ => add_extra_space_to_cairo_named_tuples(v),
            }
        }
    }

    fn add_extra_space_to_named_tuple_type_definition<'a>(
        key: &str,
        value: &'a str,
    ) -> std::borrow::Cow<'a, str> {
        use std::borrow::Cow::*;
        match key {
            "cairo_type" | "value" => Owned(add_extra_space_before_colon(value)),
            _ => Borrowed(value),
        }
    }

    fn add_extra_space_before_colon(v: &str) -> String {
        // This is required because if we receive an already correct ` : `, we will still
        // "repair" it to `  : ` which we then fix at the end.
        v.replace(": ", " : ").replace("  :", " :")
    }

    // Handle a backwards compatibility hack which is required if compiler_version is not present.
    // See `insert_space` for more details.
    if contract_definition.program.compiler_version.is_none() {
        add_extra_space_to_cairo_named_tuples(&mut contract_definition.program.identifiers);
        add_extra_space_to_cairo_named_tuples(&mut contract_definition.program.reference_manager);
    }

    let truncated_keccak = {
        let mut ser =
            serde_json::Serializer::with_formatter(KeccakWriter::default(), PythonDefaultFormatter);

        contract_definition
            .serialize(&mut ser)
            .context("Serializing contract_definition for Keccak256")?;

        let KeccakWriter(hash) = ser.into_inner();
        truncated_keccak(<[u8; 32]>::from(hash.finalize()))
    };

    // what follows is defined over at the contract.cairo

    const API_VERSION: Felt = Felt::ZERO;

    let mut outer = HashChain::default();

    // This wasn't in the docs, but similarly to contract_state hash, we start with this 0, so this
    // will yield outer == H(0, 0); However, dissimilarly to contract_state hash, we do include the
    // number of items in this class_hash.
    outer.update(API_VERSION);

    // It is important to process the different entrypoint hashchains in correct order.
    // Each of the entrypoint lists gets updated into the `outer` hashchain.
    //
    // This implementation doesn't preparse the strings, which makes it a bit more noisy. Late
    // parsing is made in an attempt to lean on the one big string allocation we've already got,
    // but these three hash chains could be constructed at deserialization time.
    [External, L1Handler, Constructor]
        .iter()
        .map(|key| {
            contract_definition
                .entry_points_by_type
                .get(key)
                .unwrap_or(&Vec::new())
                .iter()
                // flatten each entry point to get a list of (selector, offset, selector, offset, ...)
                .flat_map(|x| [x.selector.0, x.offset.0].into_iter())
                .fold(HashChain::default(), |mut hc, next| {
                    hc.update(next);
                    hc
                })
        })
        .for_each(|x| outer.update(x.finalize()));

    fn update_hash_chain(mut hc: HashChain, next: Result<Felt, Error>) -> Result<HashChain, Error> {
        hc.update(next?);
        Result::<_, Error>::Ok(hc)
    }

    let builtins = contract_definition
        .program
        .builtins
        .iter()
        .enumerate()
        .map(|(i, s)| (i, s.as_bytes()))
        .map(|(i, s)| {
            Felt::from_be_slice(s).with_context(|| format!("Invalid builtin at index {i}"))
        })
        .try_fold(HashChain::default(), update_hash_chain)
        .context("Failed to process contract_definition.program.builtins")?;

    outer.update(builtins.finalize());

    outer.update(truncated_keccak);

    let bytecodes = contract_definition
        .program
        .data
        .iter()
        .enumerate()
        .map(|(i, s)| {
            Felt::from_hex_str(s).with_context(|| format!("Invalid bytecode at index {i}"))
        })
        .try_fold(HashChain::default(), update_hash_chain)
        .context("Failed to process contract_definition.program.data")?;

    outer.update(bytecodes.finalize());

    Ok(ClassHash(outer.finalize()))
}

/// Computes the class hash for a Sierra class definition.
///
/// This matches the (not very precise) [official documentation][starknet-doc] and the [cairo-lang
/// implementation][cairo-compute] written in Cairo.
///
/// Calculation is somewhat simpler than for Cairo classes, since it does _not_ involve serializing
/// JSON and calculating hashes for the JSON output. Instead, ABI is handled as a string and all other
/// relevant parts of the class definition are transformed into Felts and hashed using Poseidon.
///
/// [starknet-doc]: https://docs.starknet.io/documentation/architecture_and_concepts/Contracts/class-hash/
/// [cairo-compute]: https://github.com/starkware-libs/cairo-lang/blob/12ca9e91bbdc8a423c63280949c7e34382792067/src/starkware/starknet/core/os/contract_class/contract_class.cairo#L42
fn compute_sierra_class_hash(
    contract_definition: json::SierraContractDefinition<'_>,
) -> Result<ClassHash> {
    use EntryPointType::*;

    if contract_definition.contract_class_version != "0.1.0" {
        anyhow::bail!("Unsupported Sierra class version");
    }

    let mut hash = PoseidonHasher::default();

    const SIERRA_VERSION: Felt = felt_bytes!(b"CONTRACT_CLASS_V0.1.0");
    hash.write(SIERRA_VERSION.into());

    // It is important to process the different entrypoint hashchains in correct order.
    // Each of the entrypoint lists gets updated into the `outer` hashchain.
    //
    // This implementation doesn't preparse the strings, which makes it a bit more noisy. Late
    // parsing is made in an attempt to lean on the one big string allocation we've already got,
    // but these three hash chains could be constructed at deserialization time.
    [External, L1Handler, Constructor]
        .iter()
        .map(|key| {
            contract_definition
                .entry_points_by_type
                .get(key)
                .unwrap_or(&Vec::new())
                .iter()
                // flatten each entry point to get a list of (selector, function_idx, selector, function_idx, ...)
                .flat_map(|x| [x.selector.0, x.function_idx.into()].into_iter())
                .fold(PoseidonHasher::default(), |mut hc, next| {
                    hc.write(next.into());
                    hc
                })
        })
        .for_each(|x| hash.write(x.finish()));

    let abi_truncated_keccak = {
        let mut keccak = sha3::Keccak256::default();
        keccak.update(contract_definition.abi.as_bytes());
        truncated_keccak(<[u8; 32]>::from(keccak.finalize()))
    };
    hash.write(abi_truncated_keccak.into());

    let program_hash = {
        let program_hash = contract_definition.sierra_program.iter().fold(
            PoseidonHasher::default(),
            |mut hc, next| {
                hc.write((*next).into());
                hc
            },
        );
        program_hash.finish()
    };
    hash.write(program_hash);

    Ok(ClassHash(hash.finish().into()))
}

/// See:
/// <https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/public/abi.py#L21-L26>
pub(crate) fn truncated_keccak(mut plain: [u8; 32]) -> Felt {
    // python code masks with (2**250 - 1) which starts 0x03 and is followed by 31 0xff in be
    // truncation is needed not to overflow the field element.
    plain[0] &= 0x03;
    Felt::from_be_bytes(plain).expect("cannot overflow: smaller than modulus")
}

/// `std::io::Write` adapter for Keccak256; we don't need the serialized version in
/// compute_class_hash, but we need the truncated_keccak hash.
///
/// When debugging mismatching hashes, it might be useful to check the length of each before trying
/// to find the wrongly serialized spot. Example length > 500kB.
#[derive(Default)]
struct KeccakWriter(sha3::Keccak256);

impl std::io::Write for KeccakWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // noop is fine, we'll finalize after the write phase
        Ok(())
    }
}

/// Starkware doesn't use compact formatting for JSON but default python formatting.
/// This is required to hash to the same value after sorted serialization.
struct PythonDefaultFormatter;

impl serde_json::ser::Formatter for PythonDefaultFormatter {
    fn begin_array_value<W>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_key<W>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_value<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        writer.write_all(b": ")
    }
}

mod json {
    use crate::request::contract::{EntryPointType, SelectorAndFunctionIndex, SelectorAndOffset};
    use std::borrow::Cow;
    use std::collections::{BTreeMap, HashMap};

    pub enum ContractDefinition<'a> {
        Cairo(CairoContractDefinition<'a>),
        Sierra(SierraContractDefinition<'a>),
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SierraContractDefinition<'a> {
        /// Contract ABI.
        #[serde(borrow)]
        pub abi: Cow<'a, str>,

        /// Main program definition.
        pub sierra_program: Vec<stark_hash::Felt>,

        // Version
        #[serde(borrow)]
        pub contract_class_version: Cow<'a, str>,

        /// The contract entry points
        pub entry_points_by_type: HashMap<EntryPointType, Vec<SelectorAndFunctionIndex>>,
    }

    /// Our version of the cairo contract definition used to deserialize and re-serialize a
    /// modified version for a hash of the contract definition.
    ///
    /// The implementation uses `serde_json::Value` extensively for the unknown/undefined
    /// structure, and the correctness of this implementation depends on the following features of
    /// serde_json:
    ///
    /// - feature `raw_value` has to be enabled for the thrown away `program.debug_info`
    /// - feature `preserve_order` has to be disabled, as we want everything sorted
    /// - feature `arbitrary_precision` has to be enabled, as there are big integers in the input
    ///
    /// It would be much more efficient to have a serde_json::Value which would only hold borrowed
    /// types.
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct CairoContractDefinition<'a> {
        /// Contract ABI, which has no schema definition.
        pub abi: serde_json::Value,

        /// Main program definition.
        #[serde(borrow)]
        pub program: CairoProgram<'a>,

        /// The contract entry points.
        ///
        /// These are left out of the re-serialized version with the ordering requirement to a
        /// Keccak256 hash.
        #[serde(skip_serializing)]
        pub entry_points_by_type: HashMap<EntryPointType, Vec<SelectorAndOffset>>,
    }

    // It's important that this is ordered alphabetically because the fields need to be in
    // sorted order for the keccak hashed representation.
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct CairoProgram<'a> {
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub attributes: Vec<serde_json::Value>,

        #[serde(borrow)]
        pub builtins: Vec<Cow<'a, str>>,

        // Added in Starknet 0.10, so we have to handle this not being present.
        #[serde(borrow, skip_serializing_if = "Option::is_none")]
        pub compiler_version: Option<Cow<'a, str>>,

        #[serde(borrow)]
        pub data: Vec<Cow<'a, str>>,

        #[serde(borrow)]
        pub debug_info: Option<&'a serde_json::value::RawValue>,

        // Important that this is ordered by the numeric keys, not lexicographically
        pub hints: BTreeMap<u64, Vec<serde_json::Value>>,

        pub identifiers: serde_json::Value,

        #[serde(borrow)]
        pub main_scope: Cow<'a, str>,

        // Unlike most other integers, this one is hex string. We don't need to interpret it,
        // it just needs to be part of the hashed output.
        #[serde(borrow)]
        pub prime: Cow<'a, str>,

        pub reference_manager: serde_json::Value,
    }

    #[cfg(test)]
    mod test_vectors {
        use super::super::{compute_class_hash, ComputedClassHash};
        use pathfinder_common::{felt, ClassHash};
        use starknet_gateway_test_fixtures::zstd_compressed_contracts::*;

        #[tokio::test]
        async fn first() {
            let contract_definition = zstd::decode_all(INTEGRATION_TEST).unwrap();
            let hash = compute_class_hash(&contract_definition).unwrap();

            assert_eq!(
                hash,
                ComputedClassHash::Cairo(ClassHash(felt!(
                    "0x031da92cf5f54bcb81b447e219e2b791b23f3052d12b6c9abd04ff2e5626576"
                )))
            );
        }

        #[test]
        fn second() {
            let contract_definition = zstd::decode_all(CONTRACT_DEFINITION).unwrap();
            let hash = super::super::compute_class_hash(&contract_definition).unwrap();

            assert_eq!(
                hash,
                ComputedClassHash::Cairo(ClassHash(felt!(
                    "0x50b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b"
                )))
            );
        }

        #[tokio::test]
        async fn genesis_contract() {
            let contract_definition = zstd::decode_all(GOERLI_GENESIS).unwrap();
            let hash = compute_class_hash(&contract_definition).unwrap();

            assert_eq!(
                hash,
                ComputedClassHash::Cairo(ClassHash(felt!(
                    "0x10455c752b86932ce552f2b0fe81a880746649b9aee7e0d842bf3f52378f9f8"
                )))
            );
        }

        #[tokio::test]
        async fn cairo_0_8() {
            // Cairo 0.8 update broke our class hash calculation by adding new attribute fields (which
            // we now need to ignore if empty).
            use felt;

            let expected = ComputedClassHash::Cairo(ClassHash(felt!(
                "056b96c1d1bbfa01af44b465763d1b71150fa00c6c9d54c3947f57e979ff68c3"
            )));

            // Known contract which triggered a hash mismatch failure.
            let contract_definition = zstd::decode_all(CAIRO_0_8_NEW_ATTRIBUTES).unwrap();

            let extract = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let hash = compute_class_hash(&contract_definition)?;
                Ok(hash)
            });
            let calculated_hash = extract.await.unwrap().unwrap();

            assert_eq!(calculated_hash, expected);
        }

        #[tokio::test]
        async fn cairo_0_10() {
            // Contract whose class triggered a deserialization issue because of the new `compiler_version` property.
            let contract_definition = zstd::decode_all(CAIRO_0_10_COMPILER_VERSION).unwrap();
            let hash = compute_class_hash(&contract_definition).unwrap();

            assert_eq!(
                hash,
                ComputedClassHash::Cairo(ClassHash(felt!(
                    "0xa69700a89b1fa3648adff91c438b79c75f7dcb0f4798938a144cce221639d6"
                )))
            );
        }

        #[tokio::test]
        async fn cairo_0_10_part_2() {
            // Contract who's class contains `compiler_version` property as well as `cairo_type` with tuple values.
            // These tuple values require a space to be injected in order to achieve the correct hash.
            let contract_definition = zstd::decode_all(CAIRO_0_10_TUPLES_INTEGRATION).unwrap();
            let hash = compute_class_hash(&contract_definition).unwrap();

            assert_eq!(
                hash,
                ComputedClassHash::Cairo(ClassHash(felt!(
                    "0x542460935cea188d21e752d8459d82d60497866aaad21f873cbb61621d34f7f"
                )))
            );
        }

        #[tokio::test]
        async fn cairo_0_10_part_3() {
            // Contract who's class contains `compiler_version` property as well as `cairo_type` with tuple values.
            // These tuple values require a space to be injected in order to achieve the correct hash.
            let contract_definition = zstd::decode_all(CAIRO_0_10_TUPLES_GOERLI).unwrap();
            let hash = compute_class_hash(&contract_definition).unwrap();

            assert_eq!(
                hash,
                ComputedClassHash::Cairo(ClassHash(felt!(
                    "0x66af14b94491ba4e2aea1117acf0a3155c53d92fdfd9c1f1dcac90dc2d30157"
                )))
            );
        }

        #[tokio::test]
        async fn cairo_0_11_sierra() {
            let contract_definition = zstd::decode_all(CAIRO_0_11_SIERRA).unwrap();
            let hash = compute_class_hash(&contract_definition).unwrap();

            assert_eq!(
                hash,
                ComputedClassHash::Sierra(ClassHash(felt!(
                    "0x4e70b19333ae94bd958625f7b61ce9eec631653597e68645e13780061b2136c"
                )))
            )
        }
    }

    #[cfg(test)]
    mod test_serde_features {
        #[test]
        fn serde_json_value_sorts_maps() {
            // this property is leaned on and the default implementation of serde_json works like
            // this. serde_json has a feature called "preserve_order" which could get enabled by
            // accident, and it would destroy the ability to compute_class_hash.

            let input = r#"{"foo": 1, "bar": 2}"#;
            let parsed = serde_json::from_str::<serde_json::Value>(input).unwrap();
            let output = serde_json::to_string(&parsed).unwrap();

            assert_eq!(output, r#"{"bar":2,"foo":1}"#);
        }

        #[test]
        fn serde_json_has_arbitrary_precision() {
            // the json has 251-bit ints, python handles them out of box, serde_json requires
            // feature "arbitrary_precision".

            // this is 2**256 - 1
            let input = r#"{"foo":115792089237316195423570985008687907853269984665640564039457584007913129639935}"#;

            let output =
                serde_json::to_string(&serde_json::from_str::<serde_json::Value>(input).unwrap())
                    .unwrap();

            assert_eq!(input, output);
        }

        #[test]
        fn serde_json_has_raw_value() {
            // raw value is needed for others but here for completness; this shouldn't compile if
            // you the feature wasn't enabled.

            #[derive(serde::Deserialize, serde::Serialize)]
            struct Program<'a> {
                #[serde(borrow)]
                debug_info: Option<&'a serde_json::value::RawValue>,
            }

            let mut input = serde_json::from_str::<Program<'_>>(
                r#"{"debug_info": {"long": {"tree": { "which": ["we dont", "care", "about", 0] }}}}"#,
            ).unwrap();

            input.debug_info = None;

            let output = serde_json::to_string(&input).unwrap();

            assert_eq!(output, r#"{"debug_info":null}"#);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn truncated_keccak_matches_pythonic() {
        use super::truncated_keccak;
        use pathfinder_common::felt;
        use sha3::{Digest, Keccak256};
        let all_set = Keccak256::digest([0xffu8; 32]);
        assert!(all_set[0] > 0xf);
        let truncated = truncated_keccak(all_set.into());
        assert_eq!(
            truncated,
            felt!("0x1c584056064687e149968cbab758a3376d22aedc6a55823d1b3ecbee81b8fb9")
        );
    }
}
