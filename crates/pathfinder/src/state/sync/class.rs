use anyhow::Context;
use pathfinder_common::{CasmHash, ClassHash, SierraHash};
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
        casm_hash_v2: CasmHash,
    },
}

pub async fn download_class<SequencerClient: GatewayApi>(
    sequencer: &SequencerClient,
    class_hash: ClassHash,
    fetch_casm_from_fgw: bool,
) -> Result<DownloadedClass, anyhow::Error> {
    use pathfinder_class_hash::compute_class_hash;

    let definition = sequencer
        .pending_class_by_hash(class_hash)
        .await
        .with_context(|| format!("Downloading class {}", class_hash.0))?
        .to_vec();

    let (tx, rx) = tokio::sync::oneshot::channel();
    rayon::spawn(move || {
        let computed_hash = compute_class_hash(&definition).context("Computing class hash");
        let _ = tx.send((computed_hash, definition));
    });
    let (hash, definition) = rx.await.context("Panic on rayon thread")?;
    let hash = hash?;

    use pathfinder_class_hash::ComputedClassHash;
    match hash {
        ComputedClassHash::Cairo(hash) => {
            if class_hash != hash {
                tracing::warn!(expected=%class_hash, computed=%hash, "Cairo 0 class hash mismatch");
            }

            Ok(DownloadedClass::Cairo { definition, hash })
        }
        ComputedClassHash::Sierra(hash) => {
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

            let (sierra_definition, casm_definition) = if fetch_casm_from_fgw {
                (
                    definition,
                    sequencer
                        .pending_casm_by_hash(class_hash)
                        .await
                        .with_context(|| format!("Downloading CASM {}", class_hash.0))?
                        .to_vec(),
                )
            } else {
                let (send, recv) = tokio::sync::oneshot::channel();
                rayon::spawn(move || {
                    let _span = span.entered();
                    let compile_result = pathfinder_compiler::compile_to_casm_ser(&definition)
                        .context("Compiling Sierra class");

                    let _ = send.send((compile_result, definition));
                });
                let (casm_definition, sierra_definition) =
                    recv.await.expect("Panic on rayon thread");

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
                (sierra_definition, casm_definition)
            };

            // Check if the CASM v2 hash has been pre-computed for this class
            let (casm_definition, casm_hash_v2) =
                match pathfinder_casm_hashes::get_precomputed_casm_v2_hash(&hash) {
                    Some(casm_hash_v2) => (casm_definition, *casm_hash_v2),
                    None => {
                        // Compute Blake2 hash for CASM class
                        let (send, recv) = tokio::sync::oneshot::channel();
                        rayon::spawn(move || {
                            let casm_hash_v2 =
                                pathfinder_compiler::casm_class_hash_v2(&casm_definition)
                                    .context("Computing CASM Blake2 hash");
                            let _ = send.send((casm_definition, casm_hash_v2));
                        });
                        let (casm_definition, casm_hash_v2) =
                            recv.await.expect("Panic on rayon thread");

                        let casm_hash_v2 = casm_hash_v2?;

                        (casm_definition, casm_hash_v2)
                    }
                };

            Ok(DownloadedClass::Sierra {
                sierra_definition,
                sierra_hash: SierraHash(hash.0),
                casm_definition,
                casm_hash_v2,
            })
        }
    }
}
