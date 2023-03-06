//! Simple tool for downloading missing state updates of a given pathfinder db.

use pathfinder_common::Chain;

#[tokio::main]
async fn main() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    let path = match std::env::args().nth(1) {
        Some(name) if std::env::args().count() == 2 => name,
        _ => {
            println!(
                "USAGE: {} db_file",
                std::env::args()
                    .next()
                    .as_deref()
                    .unwrap_or("download_state_updates")
            );
            std::process::exit(1);
        }
    };

    let path = std::path::PathBuf::from(path);

    use pathfinder_storage::{JournalMode, StarknetBlocksTable, Storage};

    let storage = Storage::migrate(path, JournalMode::WAL).unwrap();
    let mut connection = storage.connection().unwrap();

    let (chain, work_todo) = {
        let tx = connection.transaction().unwrap();
        let chain = match StarknetBlocksTable::get_chain(&tx).unwrap() {
            Some(x) => x,
            None => return,
        };

        let work_todo = tx.query_row("select count(1) from starknet_blocks b left outer join starknet_state_updates up on (b.hash = up.block_hash) where up.block_hash is null", [], |row| Ok(row.get_unwrap::<_, i64>(0))).unwrap();
        (chain, work_todo as u64)
    };

    tracing::info!("Downloading state updates for all blocks, this can take a while...");

    let started = std::time::Instant::now();

    let handle = tokio::runtime::Handle::current();

    let (downloaded_tx, downloaded_rx) = std::sync::mpsc::sync_channel(2);
    let (compressed_tx, compressed_rx) = std::sync::mpsc::sync_channel(2);

    let downloader = std::thread::spawn(move || {
        use pathfinder_common::BlockId;
        use starknet_gateway_client::{Client, ClientApi};

        let client = match chain {
            Chain::Mainnet => Client::mainnet(),
            Chain::Testnet => Client::testnet(),
            Chain::Testnet2 => Client::testnet2(),
            Chain::Integration => Client::integration(),
            Chain::Custom => panic!("Not supported for custom networks"),
        };

        let mut con = storage.connection()?;
        let tx = con.transaction()?;

        let mut query = tx.prepare("select b.number from starknet_blocks b left outer join starknet_state_updates up on (b.hash = up.block_hash) where up.block_hash is null")?;
        let mut rows = query.query([])?;

        while let Some(row) = rows.next()? {
            let block_num = row.get_unwrap(0);
            let state_update = handle.block_on(client.state_update(BlockId::Number(block_num)))?;

            downloaded_tx.send((block_num, state_update))?;
        }

        Ok::<_, anyhow::Error>(())
    });

    let compressor = std::thread::spawn(move || {
        let mut compressor = zstd::bulk::Compressor::new(10).unwrap();

        for (block_num, sequencer_state_update) in downloaded_rx.iter() {
            use pathfinder_storage::types::StateUpdate;
            use starknet_gateway_types::reply::MaybePendingStateUpdate;

            let sequencer_state_update = match sequencer_state_update {
                MaybePendingStateUpdate::Pending(_) => {
                    panic!("Got unexpected pending block for block number {block_num}");
                }
                MaybePendingStateUpdate::StateUpdate(su) => su,
            };

            let block_hash = sequencer_state_update.block_hash;
            let rpc_state_update: StateUpdate = sequencer_state_update.into();
            let rpc_state_update = serde_json::to_vec(&rpc_state_update).unwrap();
            let rpc_state_update = compressor.compress(&rpc_state_update).unwrap();

            compressed_tx
                .send((block_num, block_hash, rpc_state_update))
                .unwrap();
        }
    });

    let mut done = 0;

    for (block_num, block_hash, compressed_state_update) in compressed_rx.iter() {
        let tx = connection.transaction().unwrap();
        tx.execute(
            r"INSERT INTO starknet_state_updates (block_hash, data) VALUES(?1, ?2);",
            rusqlite::params![block_hash.0.as_be_bytes(), &compressed_state_update],
        )
        .unwrap_or_else(|_| panic!("Inserting state update for block {block_hash} or {block_num}"));

        tx.commit().unwrap();

        done += 1;

        tracing::info!("Downloaded {block_num}, {done}/{work_todo}");
    }

    downloader.join().unwrap().unwrap();
    compressor.join().unwrap();

    tracing::info!("Done after {:?}", started.elapsed());
}
