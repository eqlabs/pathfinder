use std::io::Write;

use pathfinder_common::ClassHash;
use pathfinder_crypto::Felt;
use rayon::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().count() != 3 {
        println!(
            "USAGE: {} db_file output_file",
            std::env::args()
                .next()
                .as_deref()
                .unwrap_or("recompute_casm_class_hashes")
        );
        std::process::exit(1);
    }

    let database_path = std::env::args().nth(1).unwrap();
    let database_path = std::path::PathBuf::from(database_path);
    let output_path = std::env::args().nth(2).unwrap();
    let output_path = std::path::PathBuf::from(output_path);

    let mut db = rusqlite::Connection::open(database_path)?;
    let transaction = db.transaction()?;
    let mut stmt = transaction.prepare("SELECT hash, definition FROM casm_definitions")?;
    let casm_definitions: Vec<_> = stmt
        .query_map([], |row| {
            let class_hash: Vec<u8> = row.get(0)?;
            let class_hash = ClassHash(
                Felt::from_be_slice(&class_hash)
                    .map_err(|e| rusqlite::types::FromSqlError::Other(e.into()))?,
            );
            let definition: Vec<u8> = row.get(1)?;

            Ok((class_hash, definition))
        })?
        .collect();

    let casm_v2_hashes: Vec<_> = casm_definitions
        .into_par_iter()
        .map(|result| {
            let (class_hash, definition) = result.unwrap();
            let definition = zstd::decode_all(definition.as_slice())
                .map_err(|e| rusqlite::types::FromSqlError::Other(e.into()))
                .unwrap();
            let computed_hash = pathfinder_compiler::casm_class_hash_v2(&definition).unwrap();
            println!(
                "Computed CASM hash for class {:?}: {:x?}",
                class_hash, computed_hash.0
            );
            (class_hash, computed_hash)
        })
        .collect();

    println!("Computed {} CASM v2 hashes", casm_v2_hashes.len());

    let output = std::fs::File::create(output_path)?;
    let mut writer = std::io::BufWriter::new(output);
    for (class_hash, casm_v2_hash) in casm_v2_hashes {
        writer.write_all(class_hash.0.as_be_bytes())?;
        writer.write_all(casm_v2_hash.0.as_be_bytes())?;
    }
    writer.flush()?;

    Ok(())
}
