use anyhow::Context;

/// The base schema as dumped after revision 39.
pub(crate) fn base_schema(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(r#"
CREATE TABLE class_definitions (
    hash       BLOB PRIMARY KEY,
    definition BLOB,
    block_number INTEGER REFERENCES canonical_blocks(number) ON DELETE SET NULL
);
CREATE TABLE contract_states (
    state_hash BLOB PRIMARY KEY,
    hash       BLOB NOT NULL,
    root       BLOB NOT NULL,
    nonce      BLOB NOT NULL
);
CREATE TABLE refs (idx INTEGER PRIMARY KEY, l1_l2_head BLOB);
CREATE TABLE starknet_transactions (
    hash        BLOB PRIMARY KEY,
    idx         INTEGER NOT NULL,
    block_hash  BLOB NOT NULL,
    tx          BLOB,
    receipt     BLOB,
    execution_status INTEGER
);
CREATE TABLE starknet_versions (id INTEGER NOT NULL PRIMARY KEY, version TEXT NOT NULL UNIQUE);
CREATE TABLE block_headers (
    hash                        BLOB    PRIMARY KEY NOT NULL,
    number                      INTEGER NOT NULL,
    storage_commitment          BLOB    NOT NULL,
    timestamp                   INTEGER NOT NULL, 
    gas_price                   BLOB    NOT NULL,
    sequencer_address           BLOB NOT NULL,
    version_id                  INTEGER REFERENCES starknet_versions(id),
    transaction_commitment      BLOB NOT NULL, 
    event_commitment            BLOB NOT NULL, 
    class_commitment            BLOB NOT NULL, 
    state_commitment            BLOB NOT NULL, 
    transaction_count           INTEGER NOT NULL, 
    event_count                 INTEGER NOT NULL
);
CREATE TABLE canonical_blocks (
    number INTEGER PRIMARY KEY NOT NULL,
    hash   BLOB    NOT NULL,
    FOREIGN KEY(hash) REFERENCES block_headers(hash)
);
CREATE TABLE starknet_events (
    id INTEGER PRIMARY KEY NOT NULL,
    block_number  INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    transaction_hash BLOB NOT NULL,
    from_address BLOB NOT NULL,
    -- Keys are represented as base64 encoded strings separated by space
    keys TEXT,
    data BLOB,
    FOREIGN KEY(block_number) REFERENCES canonical_blocks(number) ON DELETE CASCADE
);
CREATE INDEX starknet_transactions_block_hash ON starknet_transactions(block_hash);
CREATE INDEX starknet_blocks_block_number ON block_headers(number);
CREATE INDEX starknet_events_block_number ON starknet_events(block_number);
CREATE INDEX starknet_events_from_address ON starknet_events(from_address);
CREATE UNIQUE INDEX canonical_block_hash_idx ON canonical_blocks(hash);
CREATE INDEX starknet_events_from_address_block_number ON starknet_events(from_address, block_number);
CREATE VIRTUAL TABLE starknet_events_keys_03 USING fts5(
    keys,
    content='',
    tokenize='ascii'
);
CREATE TRIGGER starknet_events_03_ai AFTER INSERT ON starknet_events BEGIN
    INSERT INTO starknet_events_keys_03(rowid, keys) VALUES (
        new.id,
        base64_felts_to_index_prefixed_base32_felts(new.keys)
    );
END;
CREATE TRIGGER starknet_events_03_ad AFTER DELETE ON starknet_events BEGIN
    INSERT INTO starknet_events_keys_03(starknet_events_keys_03, rowid, keys) VALUES (
        'delete',
        old.id,
        base64_felts_to_index_prefixed_base32_felts(old.keys)
    );
END;
CREATE TRIGGER starknet_events_03_au AFTER UPDATE ON starknet_events BEGIN
    INSERT INTO starknet_events_keys_03(starknet_events_keys_03, rowid, keys) VALUES (
        'delete',
        old.id,
        base64_felts_to_index_prefixed_base32_felts(old.keys)
    );
    INSERT INTO starknet_events_keys_03(rowid, keys) VALUES (
        new.id,
        base64_felts_to_index_prefixed_base32_felts(new.keys)
    );
END;
CREATE TABLE casm_compiler_versions (
    id      INTEGER     PRIMARY KEY NOT NULL,
    version TEXT        NOT NULL UNIQUE
);
CREATE TABLE casm_definitions (
    hash                BLOB    PRIMARY KEY NOT NULL,
    compiled_class_hash BLOB    NOT NULL,
    definition          BLOB    NOT NULL,
    compiler_version_id INTEGER NOT NULL REFERENCES casm_compiler_versions(id),
    FOREIGN KEY(hash) REFERENCES class_definitions(hash) ON DELETE CASCADE
);
CREATE INDEX casm_definitions_compiled_class_hash ON casm_definitions(compiled_class_hash);
CREATE TABLE class_commitment_leaves (
    hash                BLOB    PRIMARY KEY NOT NULL,
    compiled_class_hash BLOB    NOT NULL
);
CREATE TABLE tree_global (
    hash        BLOB PRIMARY KEY,
    data        BLOB,
    ref_count   INTEGER
);
CREATE TABLE tree_contracts (
    hash        BLOB PRIMARY KEY,
    data        BLOB,
    ref_count   INTEGER
);
CREATE TABLE tree_class (
    hash        BLOB PRIMARY KEY,
    data        BLOB,
    ref_count   INTEGER
);
CREATE TABLE contract_updates (
    block_number INTEGER REFERENCES canonical_blocks(number) ON DELETE CASCADE,
    contract_address BLOB NOT NULL,
    class_hash BLOB NOT NULL
);
CREATE TABLE nonce_updates (
    block_number INTEGER REFERENCES canonical_blocks(number) ON DELETE CASCADE,
    contract_address BLOB NOT NULL,
    nonce BLOB NOT NULL
);
CREATE TABLE storage_updates (
    block_number INTEGER REFERENCES canonical_blocks(number) ON DELETE CASCADE,
    contract_address BLOB NOT NULL,
    storage_address BLOB NOT NULL,
    storage_value BLOB NOT NULL
);
CREATE INDEX nonce_updates_contract_address_block_number ON nonce_updates(contract_address, block_number);
CREATE INDEX contract_updates_address_block_number ON contract_updates(contract_address, block_number);
CREATE INDEX contract_updates_block_number ON contract_updates(block_number);
CREATE INDEX storage_updates_contract_address_storage_address_block_number ON storage_updates(contract_address, storage_address, block_number);
CREATE INDEX storage_updates_block_number ON storage_updates(block_number);
CREATE INDEX nonce_updates_block_number ON nonce_updates(block_number);
CREATE INDEX class_definitions_block_number ON class_definitions(block_number);
CREATE TABLE l1_state (
    starknet_block_number      INTEGER PRIMARY KEY,
    starknet_block_hash        BLOB    NOT NULL,
    starknet_state_root        BLOB    NOT NULL
);"#)?;

    // Code expects there to always be one row here.
    tx.execute("INSERT INTO refs (idx, l1_l2_head) VALUES(1, NULL)", [])
        .context("Initializing L1 == L2 reference")?;

    Ok(())
}
