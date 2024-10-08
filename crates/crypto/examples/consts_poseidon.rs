//! This file generates the constants for the Poseidon hash function.
//!
//! It reads the constants from spec/poseidon3.txt, compresses them and writes
//! them to params.
use std::fmt::Write;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::str::FromStr;
use std::{env, fs};

use num_bigint::BigUint;
use pathfinder_crypto::algebra::field::*;

const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 83;

/// Generates poseidon_consts.rs
pub fn main() {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let dest_path = Path::new(&manifest_dir).join("consts.rs");

    let consts = generate_consts();
    fs::write(&dest_path, consts).expect("could not write $OUT_DIR/consts.rs");

    println!(
        "Poseidon constants successfully written to {}",
        dest_path.display()
    );
    println!("Please copy this file to crypto/src/hash/poseidon/consts.rs");
}

/// Generates Rust code to a string
fn generate_consts() -> String {
    // Read constants
    let constants = extract_roundkeys();

    // Convert into field elements
    let roundkeys = convert_roundkeys(&constants);

    // Compress roundkeys
    let comp = compress_roundkeys(&roundkeys);
    let comp_serialized = serialize_roundkeys(&comp);

    // Write them to the buffer
    let code_comp = generate_code("POSEIDON_COMP_CONSTS", &comp_serialized);
    format!("use crate::algebra::field::MontFelt;\n\n#[rustfmt::skip]\n{code_comp}")
}

/// Flattens the roundkeys
pub fn flatten_roundkeys(rcs: &[[MontFelt; 3]]) -> Vec<MontFelt> {
    let mut result = Vec::new();
    for triple in rcs {
        for entry in triple {
            result.push(*entry);
        }
    }
    result
}

/// Compress roundkeys
pub fn compress_roundkeys(rcs: &[[MontFelt; 3]]) -> Vec<MontFelt> {
    let mut result = Vec::new();

    // Add first full rounds
    result.extend(rcs[..FULL_ROUNDS / 2].iter().flatten());

    // Add compressed partial rounds and first of the last full rounds
    result.extend(compress_roundkeys_partial(rcs));

    // Add last full rounds except the first of them
    result.extend(
        rcs[(FULL_ROUNDS / 2 + PARTIAL_ROUNDS + 1)..]
            .iter()
            .flatten(),
    );

    result
}

pub fn compress_roundkeys_partial(rcs: &[[MontFelt; 3]]) -> Vec<MontFelt> {
    let mut result = Vec::new();

    let mut idx = FULL_ROUNDS / 2;
    let mut state: [MontFelt; 3] = [MontFelt::ZERO; 3];

    // Add keys for partial rounds
    for _ in 0..PARTIAL_ROUNDS {
        // AddRoundKey
        state[0] += rcs[idx][0];
        state[1] += rcs[idx][1];
        state[2] += rcs[idx][2];

        // Add last state
        result.push(state[2]);

        // Reset last state
        state[2] = MontFelt::ZERO;

        // MixLayer
        let t = state[0] + state[1] + state[2];
        state[0] = t + MontFelt::TWO * state[0];
        state[1] = t - MontFelt::TWO * state[1];
        state[2] = t - MontFelt::THREE * state[2];

        idx += 1;
    }

    // Add keys for first of the last full rounds
    state[0] += rcs[idx][0];
    state[1] += rcs[idx][1];
    state[2] += rcs[idx][2];
    result.push(state[0]);
    result.push(state[1]);
    result.push(state[2]);

    result
}

/// Serializes roundkeys to u64
pub fn serialize_roundkeys(rcs: &[MontFelt]) -> Vec<[u64; 4]> {
    rcs.iter().map(|v| v.0).collect()
}

/// Generates the Rust code
pub fn generate_code(name: &str, rcs: &[[u64; 4]]) -> String {
    let mut buf = String::with_capacity(1024 * 1024);

    write!(buf, "pub static {}: [MontFelt; {}] = [", name, rcs.len()).unwrap();

    let push_point = |buf: &mut String, rc: &[u64; 4]| {
        buf.push_str("\n    MontFelt::from_raw([");
        for r in rc {
            write!(buf, "{r:>20}u64,").unwrap();
        }
        buf.push_str("]),");
    };

    for rc in rcs.iter() {
        push_point(&mut buf, rc);
    }

    write!(buf, "\n];").unwrap();
    buf
}

/// Parses a number into a field element
pub fn convert_number(n: &BigUint) -> MontFelt {
    // Prepend zeros to fit 32 bytes
    let mut bytes = n.to_bytes_be();
    if bytes.len() < 32 {
        let zeros_to_add = 32 - bytes.len();
        let mut tmp = vec![0u8; zeros_to_add];
        tmp.extend(bytes);
        bytes = tmp;
    }

    // Convert bytes to field element
    let felt = Felt::from_be_slice(&bytes).unwrap();
    MontFelt::from(felt)
}

/// Converts roundkeys as big integers to u64 in Montgomery representation
pub fn convert_roundkeys(rcs: &[[BigUint; 3]]) -> Vec<[MontFelt; 3]> {
    let mut result = Vec::new();
    for rc in rcs.iter() {
        let mut converted = [MontFelt::ZERO; 3];
        for (idx, num) in rc.iter().enumerate() {
            converted[idx] = convert_number(num);
        }
        result.push(converted);
    }
    result
}

/// Extracts roundkeys from https://github.com/starkware-industries/poseidon/blob/main/poseidon3.txt
pub fn extract_roundkeys() -> Vec<[BigUint; 3]> {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let read_path = Path::new(&manifest_dir).join("spec/poseidon3.txt");

    let mut roundkeys = Vec::new();

    // Parse by reading one line at a time
    let file = File::open(read_path).expect("can read poseidon reference file");
    let lines = io::BufReader::new(file).lines();

    let mut at_keys = false;
    let mut line_ctr = 0;
    let mut buffer: [BigUint; 3] = [BigUint::default(), BigUint::default(), BigUint::default()];
    for line in lines.map_while(Result::ok) {
        // Skip until reaching RoundKeys
        if line.contains("RoundKeys") {
            at_keys = true;
        }

        // For each set of three RoundKeys
        if at_keys && line.contains('[') {
            line_ctr = 0;
        }

        // Read one element, append to buffer for ctr = 1,2,3
        if at_keys && line_ctr > 0 && line_ctr < 4 {
            let mut trimmed = line.trim().to_owned();
            trimmed.truncate(trimmed.len() - 1); // remove comma
            if let Ok(bn) = BigUint::from_str(&trimmed) {
                buffer[line_ctr - 1] = bn;
            }
        }

        // If buffer is full, push it to result
        if at_keys && line_ctr == 3 {
            roundkeys.push(buffer.clone());
        }

        line_ctr += 1;
    }

    roundkeys
}
