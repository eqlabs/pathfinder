use anyhow::Context;
use pathfinder_common::{Chain, ClassHash, StarknetVersion};
use starknet_gateway_client::GatewayApi;

pub enum DownloadedClass {
    Cairo {
        definition: Vec<u8>,
        hash: ClassHash,
    },
    Sierra {
        sierra_definition: Vec<u8>,
        sierra_hash: ClassHash,
        casm_definition: Vec<u8>,
    },
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
        .with_context(|| format!("Downloading class {}", class_hash.0))?
        .to_vec();

    tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let hash = compute_class_hash(&definition).context("Computing class hash")?;

        anyhow::ensure!(
            class_hash == hash.hash(),
            "Class hash mismatch, {} instead of {}",
            hash.hash(),
            class_hash.0
        );

        use starknet_gateway_types::class_hash::ComputedClassHash;
        match hash {
            ComputedClassHash::Cairo(hash) => {
                Ok(DownloadedClass::Cairo {
                    definition,
                    hash,
                })
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

                Ok(DownloadedClass::Sierra {
                    sierra_definition: definition,
                    sierra_hash: hash,
                    casm_definition,
                }                )
            }
        }
    }).await.context("Joining class processing task")?
}
