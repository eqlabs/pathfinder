use anyhow::Context;
use rusqlite::{params, Statement, Transaction};

/// Serialized to sqlite with full 32 bytes.
#[derive(Copy, Clone, serde::Deserialize)]
pub struct Felt(stark_hash::Felt);

/// Same as [Felt] but with leading zeros stripped when writing to sqlite.
#[derive(Copy, Clone, serde::Deserialize)]
pub struct CompressedFelt(stark_hash::Felt);

impl rusqlite::ToSql for Felt {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        use rusqlite::types::{ToSqlOutput, ValueRef};
        Ok(ToSqlOutput::Borrowed(ValueRef::Blob(self.0.as_be_bytes())))
    }
}

impl rusqlite::ToSql for CompressedFelt {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        use rusqlite::types::{ToSqlOutput, ValueRef};
        let bytes = self.0.as_be_bytes();
        let num_zeroes = bytes.iter().take_while(|v| **v == 0).count();
        Ok(ToSqlOutput::Borrowed(ValueRef::Blob(&bytes[num_zeroes..])))
    }
}

/// This migration transforms state update storage from json blobs into tables containing
/// the data.
pub(crate) fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute(
        r"-- contains all canonical deployed contracts and replaced class information
CREATE TABLE contract_updates (
    block_number INTEGER REFERENCES canonical_blocks(number) ON DELETE CASCADE,
    contract_address BLOB NOT NULL,
    class_hash BLOB NOT NULL
)",
        [],
    )
    .context("Creating contract_updates table")?;

    tx.execute(
        r"-- contains the nonce updates of all canonical blocks
CREATE TABLE nonce_updates (
    block_number INTEGER REFERENCES canonical_blocks(number) ON DELETE CASCADE,
    contract_address BLOB NOT NULL,
    nonce BLOB NOT NULL
)",
        [],
    )
    .context("Creating nonce_updates table")?;

    tx.execute(
        r"-- contains the storage updates of all of all canonical blocks
CREATE TABLE storage_updates (
    block_number INTEGER REFERENCES canonical_blocks(number) ON DELETE CASCADE,
    contract_address BLOB NOT NULL,
    storage_address BLOB NOT NULL,
    storage_value BLOB NOT NULL
)",
        [],
    )
    .context("Creating storage_updates table")?;

    let total: usize = tx
        .query_row("SELECT count(1) FROM starknet_state_updates", [], |row| {
            row.get(0)
        })
        .context("Counting number of rows in starknet_state_updates table")?;

    tracing::info!(rows=%total, "Flattening state updates - this may take a while, please be patient. Progress will be logged regularly.");

    let mut context = SqlContext::new(tx)?;

    let mut state_update_query_stmt = tx
        .prepare(
            r"SELECT starknet_state_updates.data FROM starknet_state_updates JOIN canonical_blocks ON (starknet_state_updates.block_hash = canonical_blocks.hash) ORDER BY canonical_blocks.number ASC",
        )
        .context("Preparing state update query statement")?;
    let mut rows = state_update_query_stmt
        .query([])
        .context("Querying for state updates")?;

    let mut timer = std::time::Instant::now();

    let mut block_number = 0usize;
    while let Some(row) = rows
        .next()
        .context("Fetching next row of state update query")?
    {
        let state_update = row.get_ref_unwrap(0).as_blob().with_context(|| {
            format!("Getting state update bytes from database row for block {block_number}")
        })?;
        let state_update = zstd::decode_all(state_update)
            .with_context(|| format!("Decompressing state update for block {block_number}"))?;

        let state_update: types::StateUpdate = serde_json::from_slice(&state_update)
            .with_context(|| format!("Deserializing state update for block {block_number}"))?;

        migrate_state_update(block_number, state_update, &mut context)
            .with_context(|| format!("Migrating state update for block {block_number}"))?;

        block_number += 1;

        if timer.elapsed() > std::time::Duration::from_secs(10) {
            let progress = Percentage(block_number * 100 / total);
            tracing::info!(%progress, "Flattening state updates");
            timer = std::time::Instant::now();
        }
    }

    tx.execute_batch(
        r"
        CREATE INDEX nonce_updates_contract_address_block_number ON nonce_updates(contract_address, block_number);
        CREATE INDEX contract_updates_address_block_number ON contract_updates(contract_address, block_number);
        CREATE INDEX contract_updates_block_number ON contract_updates(block_number);
        CREATE INDEX storage_updates_contract_address_storage_address_block_number ON storage_updates(contract_address, storage_address, block_number);
        CREATE INDEX storage_updates_block_number ON storage_updates(block_number);
        CREATE INDEX nonce_updates_block_number ON nonce_updates(block_number);"
    )
    .context("Creating indexes")?;

    tx.execute("DROP TABLE starknet_state_updates", [])
        .context("Dropping starknet_state_updates")?;

    Ok(())
}

struct SqlContext<'tx> {
    nonce_stmt: Statement<'tx>,
    storage_stmt: Statement<'tx>,
    contract_stmt: Statement<'tx>,
}

impl<'tx> SqlContext<'tx> {
    fn new(tx: &'tx Transaction<'tx>) -> anyhow::Result<Self> {
        let nonce_stmt = tx
            .prepare(
                "INSERT INTO nonce_updates (block_number, contract_address, nonce) VALUES (?, ?, ?)",
            )
            .context("Preparing nonce insert statement")?;

        let storage_stmt = tx
            .prepare("INSERT INTO storage_updates (block_number, contract_address, storage_address, storage_value) VALUES (?, ?, ?, ?)")
            .context("Preparing nonce insert statement")?;

        let contract_stmt = tx
            .prepare("INSERT INTO contract_updates (block_number, contract_address, class_hash) VALUES (?, ?, ?)")
            .context("Preparing contract insert statement")?;

        Ok(Self {
            nonce_stmt,
            storage_stmt,
            contract_stmt,
        })
    }
}

fn migrate_state_update(
    block_number: usize,
    state_update: types::StateUpdate,
    context: &mut SqlContext<'_>,
) -> anyhow::Result<()> {
    update_contracts(
        block_number,
        &state_update.state_diff.deployed_contracts,
        &state_update.state_diff.replaced_classes,
        context,
    )
    .context("Inserting contract updates")?;

    update_nonces(block_number, &state_update.state_diff.nonces, context)
        .context("Inserting nonce updates")?;

    update_storage(
        block_number,
        &state_update.state_diff.storage_diffs,
        context,
    )
    .context("Inserting storage updates")
}

fn update_contracts(
    block_number: usize,
    deployed: &[types::DeployedContract],
    replaced: &[types::ReplacedClass],
    context: &mut SqlContext<'_>,
) -> anyhow::Result<()> {
    for types::DeployedContract {
        address,
        class_hash,
    } in deployed
    {
        context
            .contract_stmt
            .execute(params![block_number, address, class_hash])
            .context("Inserting contract update")?;
    }

    for types::ReplacedClass {
        address,
        class_hash,
    } in replaced
    {
        context
            .contract_stmt
            .execute(params![block_number, address, class_hash])
            .context("Inserting replaced class")?;
    }

    Ok(())
}

fn update_nonces(
    block_number: usize,
    nonces: &[types::NonceUpdate],
    context: &mut SqlContext<'_>,
) -> anyhow::Result<()> {
    for types::NonceUpdate {
        contract_address,
        nonce,
    } in nonces
    {
        context
            .nonce_stmt
            .execute(params![block_number, contract_address, nonce])
            .context("Inserting nonce update")?;
    }

    Ok(())
}

fn update_storage(
    block_number: usize,
    storage: &[types::StorageDiff],
    context: &mut SqlContext<'_>,
) -> anyhow::Result<()> {
    for types::StorageDiff {
        address,
        key,
        value,
    } in storage
    {
        context
            .storage_stmt
            .execute(params![block_number, address, key, value])
            .context("Inserting storage update")?;
    }

    Ok(())
}

/// Helper which displays as an integer percentage.
struct Percentage(usize);
impl std::fmt::Display for Percentage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}%", self.0))
    }
}

mod types {
    //! Copy of state update types for deserialization so that this migration is
    //! not coupled to any external type changes.

    use super::{CompressedFelt, Felt};
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct StateUpdate {
        #[serde(default)]
        pub block_hash: Option<Felt>,
        pub new_root: Felt,
        pub old_root: Felt,
        pub state_diff: StateDiff,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct StateDiff {
        pub storage_diffs: Vec<StorageDiff>,
        /// Refers to Declare V0 & V1 txns, these contain Cairo classes
        pub declared_contracts: Vec<DeclaredCairoClass>,
        /// Refers to pre-Starknet-0.11.0 Deploy txns
        pub deployed_contracts: Vec<DeployedContract>,
        #[serde(default)]
        pub nonces: Vec<NonceUpdate>,
        /// Refers to Declare V2 txns, these contain Sierra classes
        #[serde(default)]
        pub declared_sierra_classes: Vec<DeclaredSierraClass>,
        /// Replaced classes, introduced in Starknet 0.11.0
        #[serde(default)]
        pub replaced_classes: Vec<ReplacedClass>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct StorageDiff {
        pub address: Felt,
        pub key: Felt,
        pub value: CompressedFelt,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DeclaredCairoClass {
        pub class_hash: Felt,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DeployedContract {
        pub address: Felt,
        pub class_hash: Felt,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DeclaredSierraClass {
        pub class_hash: Felt,
        pub compiled_class_hash: Felt,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct NonceUpdate {
        pub contract_address: Felt,
        pub nonce: CompressedFelt,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ReplacedClass {
        pub address: Felt,
        pub class_hash: Felt,
    }
}
