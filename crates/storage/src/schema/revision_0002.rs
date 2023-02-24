use anyhow::Context;
use rusqlite::Transaction;
use sha3::{Digest, Keccak256};

pub(crate) fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    // we had a mishap of forking the schema at version 1 so to really support all combinations of
    // schema at version 1 we need to make sure that contracts table still looks like:
    // CREATE TABLE contracts (
    //     address    BLOB PRIMARY KEY,
    //     hash       BLOB NOT NULL,
    //     bytecode   BLOB,
    //     abi        BLOB,
    //     definition BLOB
    // );

    {
        let migrateable = ["address", "hash", "bytecode", "abi", "definition"];
        let no_need = ["address", "hash"];

        let mut actual = Vec::with_capacity(5);

        let mut stmt = tx.prepare("select name from pragma_table_info(\"contracts\")")?;
        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            let name = row
                .get_ref_unwrap(0)
                .as_str()
                .expect("pragma_table_info has column name, for strings");
            // these are only borrowable for the lifetime of the row
            actual.push(name.to_owned());
        }

        if actual == no_need {
            return Ok(());
        }

        assert_eq!(
            &migrateable[..],
            &actual,
            "unknown columns for contracts table"
        );
    }

    tx.execute("alter table contracts rename to contracts_v1", [])?;
    tx.execute(
        "create table contract_code (
            hash       BLOB PRIMARY KEY,
            bytecode   BLOB,
            abi        BLOB,
            definition BLOB
        )",
        [],
    )?;

    // set this to true to have the contracts be dumped into files
    let dump_duplicate_contracts = false;

    let mut uniq_contracts = 0u32;
    let todo: u32 = tx
        .query_row(
            "select count(1) from (select definition from contracts_v1 group by definition)",
            [],
            |r| r.get(0),
        )
        .unwrap();

    let mut keccak256 = Keccak256::new();
    let mut output = vec![0u8; 64];

    let started_at = std::time::Instant::now();

    let mut duplicates = 0;

    // main body of this migration is to split cotracts table into two: contracts and
    // contracts_code *while* taking care of bug which had mixed up abi and bytecode columns.
    // the two "faster to access" columns are recreated from the definition.
    {
        let mut stmt = tx.prepare("select distinct definition from contracts_v1")?;
        let mut rows = stmt.query([])?;

        let mut exists = tx.prepare("select 1 from contract_code where hash = ?")?;

        while let Some(r) = rows.next()? {
            let definition = r.get_ref_unwrap(0).as_blob()?;
            let raw_definition = zstd::decode_all(definition)?;
            let (abi, code, hash) =
                starknet_gateway_types::class_hash::extract_abi_code_hash(&raw_definition)
                    .with_context(|| {
                        format!("Failed to process {} bytes of definition", definition.len())
                    })?;

            if exists.exists([&hash.0.to_be_bytes()[..]])? {
                if dump_duplicate_contracts {
                    // exists already, this could be a problem

                    keccak256.update(definition);
                    let cid = <[u8; 32]>::from(keccak256.finalize_reset());

                    hex::encode_to_slice(&cid[..], &mut output[..]).unwrap();

                    let name = std::str::from_utf8(&output[..]).unwrap();

                    let path = format!("duplicate-{:x}-{}.json.zst", hash.0, name);

                    std::fs::write(path, definition).unwrap();
                }
                duplicates += 1;
            } else {
                storage::contract_code_insert(tx, hash, &abi, &code, &raw_definition)?;
                uniq_contracts += 1;
            }

            let div = 100;
            if uniq_contracts > 0 && uniq_contracts % div == 0 {
                let per_one_from_start = started_at.elapsed() / uniq_contracts;

                println!(
                    "{} more contracts ready, {} to go {:?}, {} duplicates",
                    div,
                    todo - uniq_contracts,
                    (todo - uniq_contracts) * per_one_from_start,
                    duplicates
                );
            }
        }
    }

    println!(
        "{} unique contracts, {} duplicates, {:?}",
        uniq_contracts,
        duplicates,
        started_at.elapsed()
    );

    tx.execute(
        "create table contracts (
            address    BLOB PRIMARY KEY,
            hash       BLOB NOT NULL,

            FOREIGN KEY(hash) REFERENCES contract_code(hash)
        )",
        [],
    )?;

    // this could had been just an alter table to drop the columns + create the fk
    let copied_contracts = tx.execute(
        "insert into contracts (address, hash) select old.address, old.hash from contracts_v1 old",
        [],
    )?;

    println!("{copied_contracts} copied from contracts_v1 to contracts");

    let started_at = std::time::Instant::now();
    tx.execute("drop table contracts_v1", [])?;

    println!("table contracts_v1 dropped in {:?}", started_at.elapsed());

    Ok(())
}

/// These are copies of storage code we had matching the database schema for this migration.
mod storage {
    use anyhow::Context;
    use rusqlite::{named_params, Transaction};

    use pathfinder_common::ClassHash;

    #[derive(Clone, PartialEq, Eq)]
    pub struct CompressedContract {
        pub abi: Vec<u8>,
        pub bytecode: Vec<u8>,
        pub definition: Vec<u8>,
        pub hash: ClassHash,
    }

    /// Insert a class into the table.
    ///
    /// Does nothing if the class [hash](ClassHash) is already populated.
    pub fn contract_code_insert(
        transaction: &Transaction<'_>,
        hash: ClassHash,
        abi: &[u8],
        bytecode: &[u8],
        definition: &[u8],
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10)
            .context("Couldn't create zstd compressor for ContractCodeTable")?;
        let abi = compressor.compress(abi).context("Failed to compress ABI")?;
        let bytecode = compressor
            .compress(bytecode)
            .context("Failed to compress bytecode")?;
        let definition = compressor
            .compress(definition)
            .context("Failed to compress definition")?;

        let contract = CompressedContract {
            abi,
            bytecode,
            definition,
            hash,
        };

        contract_code_insert_compressed(transaction, &contract)
    }

    pub fn contract_code_insert_compressed(
        transaction: &Transaction<'_>,
        contract: &CompressedContract,
    ) -> anyhow::Result<()> {
        // check magics to verify these are zstd compressed files
        let magic = &[0x28, 0xb5, 0x2f, 0xfd];
        assert_eq!(&contract.abi[..4], magic);
        assert_eq!(&contract.bytecode[..4], magic);
        assert_eq!(&contract.definition[..4], magic);

        transaction.execute(
            r"INSERT INTO contract_code ( hash,  bytecode,  abi,  definition)
                             VALUES (:hash, :bytecode, :abi, :definition)",
            named_params! {
                ":hash": &contract.hash.0.to_be_bytes()[..],
                ":bytecode": &contract.bytecode[..],
                ":abi": &contract.abi[..],
                ":definition": &contract.definition[..],
            },
        )?;
        Ok(())
    }
}
