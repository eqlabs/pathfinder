use anyhow::Context;

/// The base schema as dumped after revision 30.
pub(crate) fn base_schema(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(r#"
CREATE TABLE IF NOT EXISTS "class_definitions" (
    hash       BLOB PRIMARY KEY,
    definition BLOB,
    declared_on BLOB DEFAULT NULL REFERENCES canonical_blocks(hash) ON DELETE SET NULL
);
CREATE TABLE contract_states (
    state_hash BLOB PRIMARY KEY,
    hash       BLOB NOT NULL,
    root       BLOB NOT NULL,
    nonce BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
);
CREATE TABLE l1_state (
    starknet_block_number      INTEGER PRIMARY KEY,
    starknet_global_root       BLOB    NOT NULL,
    ethereum_block_hash        BLOB    NOT NULL,
    ethereum_block_number      INTEGER NOT NULL,
    ethereum_transaction_hash  BLOB    NOT NULL,
    ethereum_transaction_index INTEGER NOT NULL,
    ethereum_log_index         INTEGER NOT NULL
);
CREATE TABLE refs (
    idx INTEGER PRIMARY KEY, 
    l1_l2_head BLOB
);
CREATE TABLE starknet_transactions (
    hash        BLOB PRIMARY KEY,
    idx         INTEGER NOT NULL,
    block_hash  BLOB NOT NULL,
    tx          BLOB,
    receipt     BLOB
);
CREATE INDEX starknet_transactions_block_hash ON starknet_transactions(block_hash);
CREATE TABLE starknet_versions (
    id INTEGER NOT NULL PRIMARY KEY, 
    version TEXT NOT NULL UNIQUE
);
CREATE TABLE starknet_state_updates (
    block_hash BLOB PRIMARY KEY NOT NULL,
    data BLOB NOT NULL,
    FOREIGN KEY(block_hash) REFERENCES starknet_blocks(hash) ON DELETE CASCADE
);
CREATE VIRTUAL TABLE starknet_events_keys USING fts5 (
    keys,
    content='starknet_events',
    content_rowid='id',
    tokenize='ascii'
);
CREATE TABLE IF NOT EXISTS 'starknet_events_keys_data'(
    id INTEGER PRIMARY KEY, 
    block BLOB
);
CREATE TABLE IF NOT EXISTS 'starknet_events_keys_idx'(
    segid, 
    term, 
    pgno, 
    PRIMARY KEY(segid, term)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS 'starknet_events_keys_docsize'(
    id INTEGER PRIMARY KEY, 
    sz BLOB
);
CREATE TABLE IF NOT EXISTS 'starknet_events_keys_config'(k PRIMARY KEY, v) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS "starknet_blocks" (
    hash      BLOB    PRIMARY KEY NOT NULL,
    number    INTEGER NOT NULL,
    root      BLOB    NOT NULL,
    timestamp INTEGER NOT NULL, 
    gas_price BLOB    NOT NULL,
    sequencer_address BLOB NOT NULL,
    version_id INTEGER REFERENCES starknet_versions(id),
    transaction_commitment BLOB, event_commitment BLOB, 
    class_commitment BLOB
);
CREATE INDEX starknet_blocks_block_number ON starknet_blocks(number);
CREATE TABLE canonical_blocks (
    number INTEGER PRIMARY KEY NOT NULL,
    hash   BLOB    NOT NULL,
    FOREIGN KEY(hash) REFERENCES starknet_blocks(hash)
);
CREATE TABLE IF NOT EXISTS "starknet_events" (
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
CREATE TRIGGER starknet_events_ai AFTER INSERT ON starknet_events BEGIN
    INSERT INTO starknet_events_keys(rowid, keys) VALUES (
        new.id,
        new.keys
    );
END;
CREATE TRIGGER starknet_events_ad AFTER DELETE ON starknet_events BEGIN
    INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys) VALUES (
        'delete',
        old.id,
        old.keys
    );
END;
CREATE TRIGGER starknet_events_au AFTER UPDATE ON starknet_events BEGIN
    INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys) VALUES (
        'delete',
        old.id,
        old.keys
    );
    INSERT INTO starknet_events_keys(rowid, keys) VALUES (
        new.id,
        new.keys
    );
END;
CREATE INDEX starknet_events_block_number ON starknet_events(block_number);
CREATE INDEX starknet_events_from_address ON starknet_events(from_address);
CREATE UNIQUE INDEX canonical_block_hash_idx ON canonical_blocks(hash);
CREATE INDEX starknet_events_from_address_block_number ON starknet_events(from_address, block_number);
CREATE VIRTUAL TABLE starknet_events_keys_03 USING fts5(
    keys,
    content='',
    tokenize='ascii'
);
CREATE TABLE IF NOT EXISTS 'starknet_events_keys_03_data'(id INTEGER PRIMARY KEY, block BLOB);
CREATE TABLE IF NOT EXISTS 'starknet_events_keys_03_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS 'starknet_events_keys_03_docsize'(id INTEGER PRIMARY KEY, sz BLOB);
CREATE TABLE IF NOT EXISTS 'starknet_events_keys_03_config'(k PRIMARY KEY, v) WITHOUT ROWID;
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
);"#)?;

    // Code expects there to always be one row here.
    tx.execute("INSERT INTO refs (idx, l1_l2_head) VALUES(1, NULL)", [])
        .context("Initializing L1 == L2 reference")?;

    Ok(())
}
