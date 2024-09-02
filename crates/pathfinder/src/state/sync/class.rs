use anyhow::Context;
use pathfinder_common::{ClassHash, SierraHash};
use starknet_gateway_client::GatewayApi;

pub enum DownloadedClass {
    Cairo {
        definition: Vec<u8>,
        hash: ClassHash,
    },
    Sierra {
        sierra_definition: Vec<u8>,
        sierra_hash: SierraHash,
        casm_definition: Vec<u8>,
    },
}

pub async fn download_class<SequencerClient: GatewayApi>(
    sequencer: &SequencerClient,
    class_hash: ClassHash,
) -> Result<DownloadedClass, anyhow::Error> {
    use starknet_gateway_types::class_hash::compute_class_hash;

    let definition = sequencer
        .pending_class_by_hash(class_hash)
        .await
        .with_context(|| format!("Downloading class {}", class_hash.0))?
        .to_vec();

    let (hash, definition) = tokio::task::spawn_blocking(move || -> (anyhow::Result<_>, _) {
        (
            compute_class_hash(&definition).context("Computing class hash"),
            definition,
        )
    })
    .await?;
    let hash = hash?;

    use starknet_gateway_types::class_hash::ComputedClassHash;
    match hash {
        ComputedClassHash::Cairo(hash) => {
            if class_hash != hash {
                tracing::warn!(expected=%class_hash, computed=%hash, "Cairo 0 class hash mismatch");
            }

            Ok(DownloadedClass::Cairo { definition, hash })
        }
        starknet_gateway_types::class_hash::ComputedClassHash::Sierra(hash) => {
            anyhow::ensure!(
                class_hash == hash,
                "Class hash mismatch, {} instead of {}",
                hash,
                class_hash.0
            );

            // FIXME(integration reset): work-around for integration containing Sierra
            // classes that are incompatible with production compiler. This will
            // get "fixed" in the future by resetting integration to remove
            // these classes at which point we can revert this.
            //
            // The work-around ignores compilation errors on integration, and instead
            // replaces the casm definition with empty bytes.
            let span = tracing::Span::current();
            let (send, recv) = tokio::sync::oneshot::channel();
            rayon::spawn(move || {
                let _span = span.entered();
                let compile_result = pathfinder_compiler::compile_to_casm(&definition)
                    .context("Compiling Sierra class");

                let _ = send.send((compile_result, definition));
            });
            let (casm_definition, sierra_definition) = recv.await.expect("Panic on rayon thread");

            let casm_definition = match casm_definition {
                Ok(casm_definition) => casm_definition,
                Err(error) => {
                    tracing::info!(class_hash=%hash, ?error, "CASM compilation failed, falling back to fetching from gateway");
                    sequencer
                        .pending_casm_by_hash(class_hash)
                        .await
                        .with_context(|| format!("Downloading CASM {}", class_hash.0))?
                        .to_vec()
                }
            };

            Ok(DownloadedClass::Sierra {
                sierra_definition,
                sierra_hash: SierraHash(hash.0),
                casm_definition,
            })
        }
    }
}
