use anyhow::Context;
use ethers::types::H128;
use pathfinder_common::Fee;
use rusqlite::{named_params, Transaction as RusqliteTransaction};

// This is a copy of the sequencer reply types _without_ deny_unknown_fields
// The point is that with the old `struct Transaction` we had some optional
// null-valued fields that are now missing from the enum-based serialization
// format. The point of this migration is getting rid of those `null` values.
mod transaction {
    use pathfinder_common::{
        CallParam, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt, EntryPoint,
        Fee, StarknetTransactionHash, TransactionNonce, TransactionSignatureElem,
        TransactionVersion,
    };
    use pathfinder_serde::{
        CallParamAsDecimalStr, ConstructorParamAsDecimalStr, FeeAsHexStr,
        TransactionSignatureElemAsDecimalStr, TransactionVersionAsHexStr,
    };
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use starknet_gateway_types::reply::transaction::EntryPointType;

    /// Represents deserialized L2 transaction data.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(tag = "type")]
    pub enum Transaction {
        #[serde(rename = "DECLARE")]
        Declare(DeclareTransaction),
        #[serde(rename = "DEPLOY")]
        Deploy(DeployTransaction),
        #[serde(rename = "INVOKE_FUNCTION")]
        Invoke(InvokeTransaction),
    }

    impl Transaction {
        /// Returns hash of the transaction
        #[cfg(test)]
        pub fn hash(&self) -> StarknetTransactionHash {
            match self {
                Transaction::Declare(t) => t.transaction_hash,
                Transaction::Deploy(t) => t.transaction_hash,
                Transaction::Invoke(t) => t.transaction_hash,
            }
        }
    }

    /// Represents deserialized L2 declare transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct DeclareTransaction {
        pub class_hash: ClassHash,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        pub nonce: TransactionNonce,
        pub sender_address: ContractAddress,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        #[serde(default)]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: StarknetTransactionHash,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
    }

    /// Represents deserialized L2 deploy transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct DeployTransaction {
        pub contract_address: ContractAddress,
        pub contract_address_salt: ContractAddressSalt,
        // This is optional because there are old transactions in the DB which don't have it.
        // We fix up missing class hash before serializing the data.
        pub class_hash: Option<ClassHash>,
        #[serde_as(as = "Vec<ConstructorParamAsDecimalStr>")]
        pub constructor_calldata: Vec<ConstructorParam>,
        pub transaction_hash: StarknetTransactionHash,
    }

    /// Represents deserialized L2 invoke transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct InvokeTransaction {
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,
        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        pub entry_point_type: EntryPointType,
        // This is optional because there are old transactions in the DB which don't have it.
        // We fix up missing max_fee with the default (0) before serializing the data.
        #[serde_as(as = "Option<FeeAsHexStr>")]
        pub max_fee: Option<Fee>,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: StarknetTransactionHash,
    }
}

/// This migration reserializes transactions to match the change from a single variant to three
/// variants  (deploy, declare and invoke). It also adds the `class_hash` field for historic `Deploy`
/// transactions which did not have this field explicitly.
///
/// The reserialisation essentially removes null values from the old variant's optional fields. These
/// fields are no longer optional in the newer variants as they are now specialized.
pub(crate) fn migrate(transaction: &RusqliteTransaction<'_>) -> anyhow::Result<()> {
    let todo: usize = transaction
        .query_row("SELECT count(1) FROM starknet_transactions", [], |r| {
            r.get(0)
        })
        .context("Count rows in starknet transactions table")?;

    if todo == 0 {
        return Ok(());
    }

    tracing::info!(
        num_transactions=%todo,
        "Decompressing and migrating transactions, this may take a while.",
    );

    let mut compressor = zstd::bulk::Compressor::new(1).context("Create zstd compressor")?;

    let mut stmt = transaction
        .prepare("SELECT hash, tx FROM starknet_transactions")
        .context("Prepare transaction query")?;
    let mut update_stmt = transaction
        .prepare("UPDATE starknet_transactions SET tx = :tx WHERE hash = :hash")
        .context("Prepare transaction update statement")?;
    let mut query_class_hash_stmt = transaction
        .prepare("SELECT hash FROM contracts WHERE address = :contract_address")
        .context("Prepare class hash lookup statement")?;

    let mut old_uncompressed_size = 0usize;
    let mut old_compressed_size = 0usize;
    let mut new_uncompressed_size = 0usize;
    let mut new_compressed_size = 0usize;

    let mut processed_rows = 0;
    let batch_size = (todo / 11).max(100000);
    let start_of_run = std::time::Instant::now();
    let mut start_of_batch = start_of_run;

    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        let transaction_hash = r.get_ref_unwrap("hash").as_blob()?;
        let tx = r.get_ref_unwrap("tx").as_blob()?;

        old_compressed_size += tx.len();
        let tx = zstd::decode_all(tx).context("Decompressing transaction")?;
        old_uncompressed_size += tx.len();
        let tx: transaction::Transaction = serde_json::from_slice(&tx).context(format!(
            "Deserializing transaction '{}'",
            String::from_utf8_lossy(&tx)
        ))?;

        // Fix missing class_hash in deploy transactions
        let tx = match tx {
            transaction::Transaction::Deploy(mut deploy) => {
                if deploy.class_hash.is_none() {
                    let class_hash = query_class_hash_stmt
                        .query_row(
                            named_params![":contract_address": deploy.contract_address],
                            |r| r.get("hash"),
                        )
                        .context("Query class hash for contract")?;
                    deploy.class_hash = Some(class_hash);
                    tracing::trace!(transaction_hash = ?deploy.transaction_hash, "Fixed missing class_hash for deploy transaction");
                }
                transaction::Transaction::Deploy(deploy)
            }
            transaction::Transaction::Declare(declare) => {
                transaction::Transaction::Declare(declare)
            }
            transaction::Transaction::Invoke(mut invoke) => {
                if invoke.max_fee.is_none() {
                    invoke.max_fee = Some(Fee(H128::zero()));
                    tracing::trace!(transaction_hash = ?invoke.transaction_hash, "Fixed missing max_fee for invoke transaction");
                }
                transaction::Transaction::Invoke(invoke)
            }
        };

        let tx = serde_json::to_vec(&tx).context("Serializing transaction")?;
        new_uncompressed_size += tx.len();
        let tx = compressor
            .compress(&tx)
            .context("Compressing transaction")?;
        new_compressed_size += tx.len();
        update_stmt
            .execute(named_params![":hash": &transaction_hash, ":tx": &tx])
            .context("Updating transaction JSON")?;

        processed_rows += 1;

        if processed_rows % batch_size == 0 {
            let now = std::time::Instant::now();
            let total_elapsed = now - start_of_run;
            let batch_elapsed = now - start_of_batch;

            let total_per_row = total_elapsed.div_f64(processed_rows as f64);
            let batch_per_row = batch_elapsed.div_f64(batch_size as f64);

            // this is non-scientific, but perhaps the latest helps? seems to be very much off until 75% when divided by 2, 50% when divided by 1.5
            let est_per_row = (total_per_row + batch_per_row).div_f64(1.5);
            let remaining = est_per_row * ((todo - processed_rows) as u32);

            tracing::info!(
                "Fixing {:.1}% complete, estimated remaining {remaining:?}",
                (100.0 * processed_rows as f64 / todo as f64)
            );
            start_of_batch = now;
        }
    }

    tracing::info!(
        %old_compressed_size,
        %old_uncompressed_size,
        %new_uncompressed_size,
        %new_compressed_size,
        total_time=?start_of_run.elapsed(),
        "Finished transaction migration"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::transaction;
    use crate::schema;
    use ethers::types::H128;
    use pathfinder_common::{felt, StarknetTransactionHash};
    use rusqlite::{named_params, Connection};

    #[test]
    fn empty() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        migrate_to_previous_version(&transaction);

        super::migrate(&transaction).unwrap();
    }

    fn migrate_to_previous_version(transaction: &rusqlite::Transaction<'_>) {
        schema::revision_0001::migrate(transaction).unwrap();
        schema::revision_0002::migrate(transaction).unwrap();
        schema::revision_0003::migrate(transaction).unwrap();
        schema::revision_0004::migrate(transaction).unwrap();
        schema::revision_0005::migrate(transaction).unwrap();
        schema::revision_0006::migrate(transaction).unwrap();
        schema::revision_0007::migrate(transaction).unwrap();
        schema::revision_0008::migrate(transaction).unwrap();
        schema::revision_0009::migrate(transaction).unwrap();
        schema::revision_0010::migrate(transaction).unwrap();
        schema::revision_0011::migrate(transaction).unwrap();
        schema::revision_0012::migrate(transaction).unwrap();
        schema::revision_0013::migrate(transaction).unwrap();
        schema::revision_0014::migrate(transaction).unwrap();
    }

    const OLD_DEPLOY_TX: &str = r#"{
        "calldata":null,
        "class_hash":"0x25ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918",
        "constructor_calldata":["1758287985645384642592689047925649198321392050007099540447534039060479296296","215307247182100370520050591091822763712463273430149262739280891880522753123","2","898900680805551884939731794595262211795827363801567949161288957386233341890","0"],
        "contract_address":"0x1f2d42032cce9c8497527653ebc9cfd6b67569895562899ab947a2d1cc110da",
        "contract_address_salt":"0x1fcc27f574c791760dd7b99919e11379f0a5ad3b345596d2a76ba3d05ade7c2",
        "entry_point_type":null,
        "entry_point_selector":null,
        "max_fee":null,
        "nonce":null,
        "sender_address":null,
        "signature":null,
        "transaction_hash":"0x350a394b1f74c5e71d9d1a787da91033e877a106ca965c65ad691d7725ade67",
        "type":"DEPLOY",
        "version":null
    }"#;
    const OLD_INVOKE_TX: &str = r#"{
        "calldata":["1","2087021424722619777119509474943472645767659996348769578120564519014510906823","232670485425082704932579856502088130646006032362877466777181098476241604910","0","3","3","490809789286600582400843108881568438665982864055734060730291220939795284993","7700000000000000","0","0"],
        "class_hash":null,
        "constructor_calldata":null,
        "contract_address":"0x4f9e9d3f9d8138a97efda56b33bc5d2065043d015ff089e5a26360573ae8759",
        "contract_address_salt":null,
        "entry_point_type":"EXTERNAL",
        "entry_point_selector":"0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad",
        "max_fee":"0xb6bad3ab5367",
        "nonce":null,
        "sender_address":null,
        "signature":["1315154516032005373376104412744922964590083352995277496702591367622675229681","2722865577796457381979632752916119040497485378397880545907561256288316181904"],
        "transaction_hash":"0x5d08e1d6a87d87feaa97307e6746c1946fdcc21345f88cdee545efdda273a42",
        "type":"INVOKE_FUNCTION",
        "version":null
    }"#;
    const OLD_DECLARE_TX: &str = r#"{
        "calldata":null,
        "class_hash":"0x2759db6e3df9433b04c05e1dd1e634dd960fab8ea9b821bea4204e96ae68c9e",
        "constructor_calldata":null,
        "contract_address":null,
        "contract_address_salt":null,
        "entry_point_type":null,
        "entry_point_selector":null,
        "max_fee":"0x0",
        "nonce":"0x0",
        "sender_address":"0x1",
        "signature":[],
        "transaction_hash":"0x2304618d8803f7e46960352c8125f5c2316975c0ee29d5924fca956f7630f2b",
        "type":"DECLARE",
        "version":"0x0"
    }"#;

    #[test]
    fn old_schema_with_optional_nulls() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        migrate_to_previous_version(&transaction);

        insert_transaction(&transaction, OLD_DEPLOY_TX, 0);
        insert_transaction(&transaction, OLD_INVOKE_TX, 1);
        insert_transaction(&transaction, OLD_DECLARE_TX, 2);

        super::migrate(&transaction).unwrap();
    }

    fn insert_transaction(transaction: &rusqlite::Transaction<'_>, json: &str, idx: u64) {
        let tx: transaction::Transaction = serde_json::from_str(json).unwrap();
        let compressed_tx = zstd::bulk::compress(json.as_bytes(), 1).unwrap();
        transaction.execute("INSERT INTO starknet_transactions (hash, idx, block_hash, tx, receipt) VALUES (:hash, :idx, :block_hash, :tx, :receipt)",
            named_params![
                ":hash": tx.hash().0.as_be_bytes(),
                ":idx": idx,
                ":block_hash": pathfinder_common::felt!("0x1").as_be_bytes(),
                ":tx": &compressed_tx,
                ":receipt": &[],
            ]
        ).unwrap();
    }

    const OLD_DEPLOY_TX_WITHOUT_CLASS_HASH: &str = r#"{
        "calldata":null,
        "constructor_calldata":["3080361095405506737150169455874612808064922679726640693390570786953208555504","3468681769215879069828264006873144040317368534778938657407160341645658370624"],
        "contract_address":"0x20cfa74ee3564b4cd5435cdace0f9c4d43b939620e4a0bb5076105df0a626c6",
        "contract_address_salt":"0x546c86dc6e40a5e5492b782d8964e9a4274ff6ecb16d31eb09cee45a3564015",
        "entry_point_type":null,
        "entry_point_selector":null,
        "max_fee":null,
        "signature":null,
        "transaction_hash":"0xe0a2e45a80bb827967e096bcf58874f6c01c191e0a0530624cba66a508ae75",
        "type":"DEPLOY"}"#;

    #[test]
    fn old_declare_transaction_with_missing_class_hash() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        migrate_to_previous_version(&transaction);

        let fake_class_hash = felt!("0xdeadadd");
        let contract_address =
            felt!("0x20cfa74ee3564b4cd5435cdace0f9c4d43b939620e4a0bb5076105df0a626c6");

        // insert fake class
        transaction
            .execute(
                "INSERT INTO contract_code (hash) VALUES (:hash)",
                named_params![
                    ":hash": fake_class_hash.as_be_bytes(),
                ],
            )
            .unwrap();

        // insert contract pointing to fake class
        transaction
            .execute(
                "INSERT INTO contracts (address, hash) VALUES(:address, :hash)",
                named_params![
                    ":address": contract_address.as_be_bytes(),
                    ":hash": fake_class_hash.as_be_bytes(),
                ],
            )
            .unwrap();

        // insert transaction deploying the contract
        insert_transaction(&transaction, OLD_DEPLOY_TX_WITHOUT_CLASS_HASH, 0);

        super::migrate(&transaction).unwrap();

        let transaction_hash =
            felt!("0xe0a2e45a80bb827967e096bcf58874f6c01c191e0a0530624cba66a508ae75");

        let migrated_tx = crate::state::StarknetTransactionsTable::get_transaction(
            &transaction,
            StarknetTransactionHash(transaction_hash),
        )
        .unwrap()
        .unwrap();

        assert_matches::assert_matches!(migrated_tx, starknet_gateway_types::reply::transaction::Transaction::Deploy(deploy) => {
            assert_eq!(deploy.class_hash.0, fake_class_hash);
        });
    }

    const OLD_INVOKE_TX_WITHOUT_MAX_FEE: &str = r#"{
        "calldata":["1","2087021424722619777119509474943472645767659996348769578120564519014510906823","232670485425082704932579856502088130646006032362877466777181098476241604910","0","3","3","490809789286600582400843108881568438665982864055734060730291220939795284993","7700000000000000","0","0"],
        "class_hash":null,
        "constructor_calldata":null,
        "contract_address":"0x4f9e9d3f9d8138a97efda56b33bc5d2065043d015ff089e5a26360573ae8759",
        "contract_address_salt":null,
        "entry_point_type":"EXTERNAL",
        "entry_point_selector":"0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad",
        "max_fee":null,
        "nonce":null,
        "sender_address":null,
        "signature":["1315154516032005373376104412744922964590083352995277496702591367622675229681","2722865577796457381979632752916119040497485378397880545907561256288316181904"],
        "transaction_hash":"0x5d08e1d6a87d87feaa97307e6746c1946fdcc21345f88cdee545efdda273a42",
        "type":"INVOKE_FUNCTION",
        "version":null
    }"#;

    #[test]
    fn old_invoke_transaction_with_missing_max_fee() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        migrate_to_previous_version(&transaction);

        insert_transaction(&transaction, OLD_INVOKE_TX_WITHOUT_MAX_FEE, 0);

        super::migrate(&transaction).unwrap();

        let transaction_hash =
            felt!("0x5d08e1d6a87d87feaa97307e6746c1946fdcc21345f88cdee545efdda273a42");

        let migrated_tx = crate::state::StarknetTransactionsTable::get_transaction(
            &transaction,
            StarknetTransactionHash(transaction_hash),
        )
        .unwrap()
        .unwrap();

        use starknet_gateway_types::reply::transaction::{InvokeTransaction, Transaction};
        assert_matches::assert_matches!(migrated_tx, Transaction::Invoke(InvokeTransaction::V0(invoke)) => {
            assert_eq!(invoke.max_fee.0, H128::zero());
        });
    }
}
