use anyhow::Context;
use futures::StreamExt;
use pathfinder_common::ClassHash;
use pathfinder_storage::Storage;
use starknet_gateway_client::GatewayApi;

use super::class::{download_class, DownloadedClass};

pub async fn repair_missing_class_definitions<S: GatewayApi + Clone + Send + 'static>(
    storage: Storage,
    sequencer: S,
    compiler_resource_limits: pathfinder_compiler::ResourceLimits,
    fetch_casm_from_fgw: bool,
) -> anyhow::Result<()> {
    repair_missing_class_definitions_with(storage, move |hash| {
        let sequencer = sequencer.clone();
        async move {
            download_class(
                &sequencer,
                hash,
                compiler_resource_limits,
                fetch_casm_from_fgw,
            )
            .await
        }
    })
    .await
}

/// Inner implementation that accepts an injectable download function for
/// tests, allowing us to pass a fake that returns known [`DownloadedClass`]
/// values without using the sequencer or running hash computation.
async fn repair_missing_class_definitions_with<F, Fut>(
    storage: Storage,
    download: F,
) -> anyhow::Result<()>
where
    F: Fn(ClassHash) -> Fut + Clone,
    Fut: std::future::Future<Output = anyhow::Result<DownloadedClass>>,
{
    let missing = tokio::task::spawn_blocking({
        let storage = storage.clone();
        move || {
            let mut db = storage
                .connection()
                .context("Creating database connection")?;
            let tx = db.transaction().context("Creating transaction")?;
            tx.class_hashes_with_missing_definitions()
                .context("Querying missing class definitions")
        }
    })
    .await
    .context("Joining database task")??;

    if missing.is_empty() {
        return Ok(());
    }

    let total = missing.len();
    tracing::info!(count = total, "Repairing missing class definitions");

    let mut repaired = 0usize;
    let mut failed = 0usize;

    let results = futures::stream::iter(missing)
        .map(|hash| {
            let download = download.clone();
            async move { (hash, download(hash).await) }
        })
        .buffer_unordered(4);

    tokio::pin!(results);

    while let Some((declared_hash, result)) = results.next().await {
        match result {
            Err(e) => {
                tracing::warn!(hash=%declared_hash, error=%e, "Failed to download class definition for repair");
                failed += 1;
            }
            Ok(downloaded) => {
                let store_result = tokio::task::spawn_blocking({
                    let storage = storage.clone();
                    move || store_repaired_class(&storage, declared_hash, downloaded)
                })
                .await
                .context("Joining database task")?;

                match store_result {
                    Err(e) => {
                        tracing::warn!(hash=%declared_hash, error=%e, "Failed to store repaired class definition");
                        failed += 1;
                    }
                    Ok(()) => {
                        repaired += 1;
                    }
                }
            }
        }
    }

    if failed == 0 {
        tracing::info!(repaired, "Finished repairing class definitions");
    } else {
        tracing::warn!(repaired, failed, "Finished repairing class definitions");
    }

    Ok(())
}

fn store_repaired_class(
    storage: &Storage,
    declared_hash: ClassHash,
    downloaded: DownloadedClass,
) -> anyhow::Result<()> {
    let mut db = storage
        .connection()
        .context("Creating database connection")?;
    let tx = db.transaction().context("Creating transaction")?;

    match downloaded {
        DownloadedClass::Cairo { definition, .. } => {
            tx.update_cairo_class_definition(declared_hash, &definition)
                .context("Storing repaired Cairo class definition")?;
        }
        DownloadedClass::Sierra {
            sierra_definition,
            casm_definition,
            casm_hash_v2,
            ..
        } => {
            tx.update_sierra_class_definition(
                &pathfinder_common::SierraHash(declared_hash.0),
                &sierra_definition,
                &casm_definition,
                &casm_hash_v2,
            )
            .context("Storing repaired Sierra class definition")?;
        }
    }

    tx.commit().context("Committing repaired class definition")
}
