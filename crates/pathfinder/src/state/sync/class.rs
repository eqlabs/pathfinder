use anyhow::Context;
use pathfinder_common::{Chain, ClassHash, StarknetVersion};
use pathfinder_storage::types::{CompressedCasmClass, CompressedContract};
use starknet_gateway_client::GatewayApi;

pub enum DownloadedClass {
    Cairo(CompressedContract),
    Sierra(CompressedContract, CompressedCasmClass),
}

pub async fn download_class<SequencerClient: GatewayApi>(
    sequencer: &SequencerClient,
    class_hash: ClassHash,
    chain: Chain,
    version: StarknetVersion,
) -> Result<DownloadedClass, anyhow::Error> {
    use starknet_gateway_types::class_hash::compute_class_hash;

    let definition = sequencer
        .pending_class_by_hash(class_hash)
        .await
        .with_context(|| format!("Downloading class {}", class_hash.0))?;

    tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let hash = compute_class_hash(&definition).context("Computing class hash")?;

        anyhow::ensure!(
            class_hash == hash.hash(),
            "Class hash mismatch, {} instead of {}",
            hash.hash(),
            class_hash.0
        );

        let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;

        use starknet_gateway_types::class_hash::ComputedClassHash;
        match hash {
            ComputedClassHash::Cairo(_) => {
                let definition = compressor
                .compress(&definition)
                .context("Compressing class definition")?;
            let compressed_contract = CompressedContract {
                definition,
                hash: class_hash,
            };
                Ok(DownloadedClass::Cairo(compressed_contract))
            }
            starknet_gateway_types::class_hash::ComputedClassHash::Sierra(hash) => {
                // FIXME(integration reset): work-around for integration containing Sierra classes
                // that are incompatible with production compiler. This will get "fixed" in the future
                // by resetting integration to remove these classes at which point we can revert this.
                //
                // The work-around ignores compilation errors on integration, and instead replaces the
                // casm definition with empty bytes.
                let casm_definition = crate::sierra::compile_to_casm(&definition, &version)
                    .context("Compiling Sierra class");
                let casm_definition = match (casm_definition, chain) {
                    (Ok(casm_definition), _) => casm_definition,
                    (Err(_), Chain::Integration) => {
                        tracing::info!(class_hash=%hash, "Ignored CASM compilation failure integration network");
                        Vec::new()
                    }
                    (Err(e), _) => return Err(e),
                };

                let definition = compressor
                    .compress(&definition)
                    .context("Compressing class definition")?;
                let compressed_contract = CompressedContract {
                    definition,
                    hash: class_hash,
                };

                let casm_definition = compressor
                    .compress(&casm_definition)
                    .context("Compressing CASM definition")?;
                let compressed_casm = pathfinder_storage::types::CompressedCasmClass {
                    definition: casm_definition,
                    hash,
                };

                Ok(DownloadedClass::Sierra(
                    compressed_contract,
                    compressed_casm,
                ))
            }
        }
    }).await.context("Joining class processing task")?
}
