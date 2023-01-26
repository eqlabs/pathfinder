use anyhow::Context;
use pathfinder_merkle_tree::PedersenHash;
use stark_hash::{stark_hash, Felt};
use std::cell::RefCell;
use std::io::BufRead;
use std::num::NonZeroUsize;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args();
    let myself = args.next().unwrap_or_else(|| String::from("generate_tree"));
    let any = args.next().is_some();

    if any {
        eprintln!("USAGE: {myself}");
        eprintln!();
        eprintln!("Reads stdin for whitespace separated N-tuples of StarkHash::from_hex_str accepted strings, where key is the first value.");
        eprintln!("After the key, behaviour depends on the number of hashes:");
        eprintln!(" - one hash gets written to a merkle tree as is, like for tree_contracts");
        eprintln!(" - two or more hashes are collapsed to single value like contract state hashes");
        eprintln!("   - zero values will be provided for the missing values up to four values");
        eprintln!("   - using more values is allowed but probably a waste of time");
        eprintln!();
        eprintln!("Outputs the starknet merkle patricia tree for the input without leaf nodes.");
        eprintln!("(Leaf nodes used to be part before pathfinder v0.3.0.)");
        eprintln!();
        eprintln!("Purpose of the tool is to faciliate building custom blocks for py/ testing for example.");
        eprintln!();
        eprintln!("Usage example:
./{myself} << EOF
0x84 0x3
EOF

Above generates the py/test_call.py::populate_test_contract_with_132_on_3 tree_contracts table.

./{myself} << EOF
0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374 0x050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b 0x04fb440e8ca9b74fc12a22ebffe0bc0658206337897226117b985434c239c028
EOF

Above generates the py/test_call.py::populate_test_contract_with_132_on_3 tree_global table.");

        // it would be nice if you could invoke tree of another path, like
        // 0x1 class_hash $(contract-0x1.tree)
        // but that is quite annoying to do right now because merkletree takes ownership, cannot
        // how many folds are being done for the values..

        std::process::exit(1);
    }

    let mut buffer = String::new();

    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();

    let mut line_number = 0;

    let mut tree = pathfinder_merkle_tree::merkle_tree::MerkleTree::<_, PedersenHash>::empty(
        RefCell::new(Default::default()),
        251,
    );

    let mut folded_first = None;

    loop {
        buffer.clear();

        line_number += 1;

        let read = stdin
            .read_line(&mut buffer)
            .with_context(|| format!("Read stdin line {line_number}"))?;

        if read == 0 {
            // eof
            break;
        }

        if buffer.starts_with('#') {
            // ignore comments
            continue;
        }

        let buffer = buffer.trim();

        if buffer.is_empty() {
            // ignore empty lines
            continue;
        }

        let (key, value, folded) =
            parse_line(buffer).with_context(|| format!("Parse line {line_number} ({buffer:?})"))?;

        folded_first = folded_first.or(Some(folded));

        if let Some(folded_first) = folded_first.as_ref() {
            anyhow::ensure!(
                *folded_first == folded,
                "Line {line_number} had interesting number of columns: {folded:?} vs. {folded_first:?}"
            );
        }

        tree.set(key.view_bits(), value)
            .with_context(|| format!("Insert key and value to tree from line {line_number}"))?;
    }

    let root = tree.commit_mut().context("Compute tree")?;

    println!("root: {root:x}");

    let storage = tree.into_storage();

    println!("nodes:");
    let mut data = [0u8; 65];
    for (k, v) in storage.borrow().iter() {
        let amount = v.serialize(&mut data);
        println!("  (X'{k:x}', X'{:x}'),", Hex(&data[..amount]));
    }

    Ok(())
}

fn parse_line(buffer: &str) -> anyhow::Result<(Felt, Felt, NonZeroUsize)> {
    let mut parts = buffer.split_whitespace().map(Felt::from_hex_str);

    let key = parts
        .next()
        .expect("there should always be a key, and can't see how this could be hit")
        .context("invalid key in column 1")?;

    // just do hashchain construction on the input to handle all sorts of sane inputs (1 value
    // = contract tree, 2..4 values = global state tree) but only warn on when they are mixed

    let first = parts
        .next()
        .context("there should always be at least one value")?
        .context("invalid value in column 2")?;

    let (value, folded) = parts
        .enumerate()
        .map(|(i, x)| {
            // first value read will be from 3rd column
            (i + 3, x)
        })
        .try_fold((first, 1), |acc, next| {
            let (column, res) = next;
            let next = res.with_context(|| format!("invalid value in column {column}"))?;
            Ok::<_, anyhow::Error>((stark_hash::stark_hash(acc.0, next), acc.1 + 1))
        })?;

    let default_nonce = Felt::ZERO;
    let default_contract_version = Felt::ZERO;
    Ok(match folded {
        0 => unreachable!("zero values case would had exited already with questionmark"),
        1 => (key, value, NonZeroUsize::new(1).unwrap()),
        2 => (
            key,
            // pre 0.10.0 contract state hash:
            // value == stark_hash(class_hash, tree_root)
            stark_hash(stark_hash(value, default_nonce), default_contract_version),
            NonZeroUsize::new(4).unwrap(),
        ),
        3 => (
            key,
            // post 0.10.0 contract state hash with nonce, but as a triple:
            // value == stark_hash(stark_hash(class_hash, tree_root), nonce)
            stark_hash(value, default_contract_version),
            NonZeroUsize::new(4).unwrap(),
        ),
        // full contract state hash
        4 => (key, value, NonZeroUsize::new(4).unwrap()),
        // who knows what this is
        x => (key, value, NonZeroUsize::new(x).unwrap()),
    })
}

struct Hex<'a>(&'a [u8]);

impl std::fmt::LowerHex for Hex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|x| write!(f, "{x:02x}"))
    }
}
