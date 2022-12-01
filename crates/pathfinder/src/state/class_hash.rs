use anyhow::{Context, Error, Result};
use pathfinder_common::ClassHash;
use serde::Serialize;
use sha3::Digest;
use stark_hash::{HashChain, StarkHash};
use starknet_gateway_types::request::contract::EntryPointType;

/// Computes the starknet class hash for given class definition json blob.
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
/// text explanations are much more complex than the actual implementation in `HashChain`, which
/// you can find from source file of this function.
///
/// [starknet-doc]: https://starknet.io/documentation/contracts/#contract_hash
/// [cairo-compute]: https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/core/os/contract_hash.py
/// [cairo-contract]: https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/core/os/contracts.cairo#L76-L118
/// [py-sortkeys]: https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/core/os/contract_hash.py#L58-L71
pub fn compute_class_hash(contract_definition_dump: &[u8]) -> Result<ClassHash> {
    let contract_definition =
        serde_json::from_slice::<json::ContractDefinition<'_>>(contract_definition_dump)
            .context("Failed to parse contract_definition")?;

    compute_class_hash0(contract_definition).context("Compute class hash")
}

/// Sibling functionality to only [`compute_class_hash`], returning also the ABI, and bytecode
/// parts as json bytes.
pub fn extract_abi_code_hash(
    contract_definition_dump: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, ClassHash)> {
    let contract_definition =
        serde_json::from_slice::<json::ContractDefinition<'_>>(contract_definition_dump)
            .context("Failed to parse contract_definition")?;

    // just in case we'd accidentially modify these in the compute_class_hash0
    let abi = serde_json::to_vec(&contract_definition.abi)
        .context("Serialize contract_definition.abi")?;
    let code = serde_json::to_vec(&contract_definition.program.data)
        .context("Serialize contract_definition.program.data")?;

    let hash = compute_class_hash0(contract_definition).context("Compute class hash")?;

    Ok((abi, code, hash))
}

/// Extract JSON representation of program and entry points from the contract definition.
pub(crate) fn extract_program_and_entry_points_by_type(
    contract_definition_dump: &[u8],
) -> Result<(serde_json::Value, serde_json::Value)> {
    #[derive(serde::Deserialize)]
    struct ContractDefinition {
        pub program: serde_json::Value,
        pub entry_points_by_type: serde_json::Value,
    }

    let contract_definition =
        serde_json::from_slice::<ContractDefinition>(contract_definition_dump)
            .context("Failed to parse contract_definition")?;

    Ok((
        contract_definition.program,
        contract_definition.entry_points_by_type,
    ))
}

fn compute_class_hash0(mut contract_definition: json::ContractDefinition<'_>) -> Result<ClassHash> {
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

    const API_VERSION: StarkHash = StarkHash::ZERO;

    let mut outer = HashChain::default();

    // This wasn't in the docs, but similarly to contract_state hash, we start with this 0, so this
    // will yield outer == H(0, 0); However, dissimilarly to contract_state hash, we do include the
    // number of items in this class_hash.
    outer.update(API_VERSION);

    // It is important process the different entrypoint hashchains in correct order.
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

    fn update_hash_chain(
        mut hc: HashChain,
        next: Result<StarkHash, Error>,
    ) -> Result<HashChain, Error> {
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
            StarkHash::from_be_slice(s).with_context(|| format!("Invalid builtin at index {i}"))
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
            StarkHash::from_hex_str(s).with_context(|| format!("Invalid bytecode at index {i}"))
        })
        .try_fold(HashChain::default(), update_hash_chain)
        .context("Failed to process contract_definition.program.data")?;

    outer.update(bytecodes.finalize());

    Ok(ClassHash(outer.finalize()))
}

/// See:
/// <https://github.com/starkware-libs/cairo-lang/blob/64a7f6aed9757d3d8d6c28bd972df73272b0cb0a/src/starkware/starknet/public/abi.py#L21-L26>
pub(crate) fn truncated_keccak(mut plain: [u8; 32]) -> StarkHash {
    // python code masks with (2**250 - 1) which starts 0x03 and is followed by 31 0xff in be
    // truncation is needed not to overflow the field element.
    plain[0] &= 0x03;
    StarkHash::from_be_bytes(plain).expect("cannot overflow: smaller than modulus")
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
    use starknet_gateway_types::request::contract::{EntryPointType, SelectorAndOffset};
    use std::borrow::Cow;
    use std::collections::{BTreeMap, HashMap};

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
    pub struct ContractDefinition<'a> {
        /// Contract ABI, which has no schema definition.
        pub abi: serde_json::Value,

        /// Main program definition.
        #[serde(borrow)]
        pub program: Program<'a>,

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
    pub struct Program<'a> {
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
    mod roundtrip_tests {
        // FIXME: we should have many test cases utilizing this.
        #[allow(unused)]
        fn roundtrips<'a, T>(input: &'a str)
        where
            T: serde::Deserialize<'a> + serde::Serialize,
        {
            use super::super::PythonDefaultFormatter;

            let parsed: T = serde_json::from_str(input).unwrap();
            let mut ser =
                serde_json::Serializer::with_formatter(Vec::new(), PythonDefaultFormatter);
            parsed.serialize(&mut ser).unwrap();
            let bytes = ser.into_inner();
            let output = std::str::from_utf8(&bytes).expect("serde does this unchecked");

            // these need to be byte for byte equal because we hash this
            assert_eq!(input, output);
        }
    }

    #[cfg(test)]
    mod test_vectors {
        use pathfinder_common::starkhash;

        #[tokio::test]
        async fn first() {
            // this test is a bit on the slow side because of the download and because of the long
            // processing time in dev builds. expected --release speed is 9 contracts/s.
            let expected =
                starkhash!("0031da92cf5f54bcb81b447e219e2b791b23f3052d12b6c9abd04ff2e5626576");

            // this is quite big payload, ~500kB
            let resp = reqwest::get("https://external.integration.starknet.io/feeder_gateway/get_full_contract?blockNumber=latest&contractAddress=0x4ae0618c330c59559a59a27d143dd1c07cd74cf4e5e5a7cd85d53c6bf0e89dc")
                .await
                .unwrap();

            let payload = resp.text().await.expect("response wasn't a string");

            // for bad urls the response looks like:
            // 500
            // {"code": "StarknetErrorCode.UNINITIALIZED_CONTRACT", "message": "Contract with address 2116724861677265616176388745625154424116334641142188761834194304782006389228 is not deployed."}

            let hash = super::super::compute_class_hash(payload.as_bytes()).unwrap();

            assert_eq!(hash.0, expected);
        }

        #[test]
        fn second() {
            let contract_definition = zstd::decode_all(
                // opening up a file requires a path relative to the test running
                starknet_gateway_test_fixtures::zstd_compressed::CONTRACT_DEFINITION,
            )
            .unwrap();

            let hash = super::super::compute_class_hash(&contract_definition).unwrap();

            assert_eq!(
                hash.0,
                starkhash!("050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b")
            );
        }

        #[tokio::test]
        async fn genesis_contract() {
            use crate::sequencer::ClientApi;
            use pathfinder_common::{Chain, ContractAddress};

            let contract =
                starkhash!("0546BA9763D33DC59A070C0D87D94F2DCAFA82C4A93B5E2BF5AE458B0013A9D3");
            let contract = ContractAddress::new_or_panic(contract);

            let chain = Chain::Testnet;
            let sequencer = crate::sequencer::Client::new(chain).unwrap();
            let contract_definition = sequencer
                .full_contract(contract)
                .await
                .expect("Download contract from sequencer");

            let _ = super::super::compute_class_hash(&contract_definition)
                .expect("Extract and compute  hash");
        }

        #[tokio::test]
        async fn cairo_0_8() {
            // Cairo 0.8 update broke our class hash calculation by adding new attribute fields (which
            // we now need to ignore if empty).
            use super::super::extract_abi_code_hash;
            use crate::sequencer::{self, ClientApi};
            use pathfinder_common::{Chain, ClassHash, ContractAddress};
            use starkhash;

            // Known contract which triggered a hash mismatch failure.
            let address = ContractAddress::new_or_panic(starkhash!(
                "0400D86342F474F14AAE562587F30855E127AD661F31793C49414228B54516EC"
            ));

            let expected = ClassHash(starkhash!(
                "056b96c1d1bbfa01af44b465763d1b71150fa00c6c9d54c3947f57e979ff68c3"
            ));
            let sequencer = sequencer::Client::new(Chain::Testnet).unwrap();

            let contract_definition = sequencer.full_contract(address).await.unwrap();
            let extract = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let (abi, bytecode, hash) = extract_abi_code_hash(&contract_definition)?;
                Ok((contract_definition, abi, bytecode, hash))
            });
            let (_, _, _, calculate_hash) = extract.await.unwrap().unwrap();

            assert_eq!(calculate_hash, expected);
        }

        #[tokio::test]
        async fn cairo_0_10() {
            let expected =
                starkhash!("a69700a89b1fa3648adff91c438b79c75f7dcb0f4798938a144cce221639d6");

            // Contract whose class triggered a deserialization issue because of the new `compiler_version` property.
            let resp = reqwest::get("https://external.integration.starknet.io/feeder_gateway/get_full_contract?blockNumber=latest&contractAddress=0x444453070729bf2db6a1f36541483c2952674e5de4bd05fcf538726b286bfa2")
                .await
                .unwrap();

            let payload = resp.text().await.expect("response wasn't a string");

            let hash = super::super::compute_class_hash(payload.as_bytes()).unwrap();

            assert_eq!(hash.0, expected);
        }

        #[tokio::test]
        async fn cairo_0_10_part_2() {
            let expected =
                starkhash!("0542460935cea188d21e752d8459d82d60497866aaad21f873cbb61621d34f7f");

            // Contract who's class contains `compiler_version` property as well as `cairo_type` with tuple values.
            // These tuple values require a space to be injected in order to achieve the correct hash.
            let resp = reqwest::get("https://external.integration.starknet.io/feeder_gateway/get_full_contract?blockNumber=latest&contractAddress=0x06f17fb7a052f3d18c1911c9d9c2fb0032bbe1ea57c58b0baca85bda9f3698be")
                .await
                .unwrap();

            let payload = resp.text().await.expect("response wasn't a string");

            let hash = super::super::compute_class_hash(payload.as_bytes()).unwrap();

            assert_eq!(hash.0, expected);
        }

        #[tokio::test]
        async fn cairo_0_10_part_3() {
            let expected =
                starkhash!("066af14b94491ba4e2aea1117acf0a3155c53d92fdfd9c1f1dcac90dc2d30157");

            // Contract who's class contains `compiler_version` property as well as `cairo_type` with tuple values.
            // These tuple values require a space to be injected in order to achieve the correct hash.
            let resp = reqwest::get("https://alpha4.starknet.io/feeder_gateway/get_full_contract?blockNumber=latest&contractAddress=0x0424e799d610433168a31aab44c0d3e38b45d97387b45de80089f56c184fa315")
                .await
                .unwrap();

            let payload = resp.text().await.expect("response wasn't a string");

            let hash = super::super::compute_class_hash(payload.as_bytes()).unwrap();

            assert_eq!(hash.0, expected);
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
        use pathfinder_common::starkhash;
        use sha3::{Digest, Keccak256};
        let all_set = Keccak256::digest(&[0xffu8; 32]);
        assert!(all_set[0] > 0xf);
        let truncated = truncated_keccak(all_set.into());
        assert_eq!(
            truncated,
            starkhash!("01c584056064687e149968cbab758a3376d22aedc6a55823d1b3ecbee81b8fb9")
        );
    }
}
