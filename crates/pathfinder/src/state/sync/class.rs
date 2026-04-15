use anyhow::Context;
use pathfinder_common::class_definition::{
    SerializedCairoDefinition,
    SerializedCasmDefinition,
    SerializedClassDefinition,
    SerializedSierraDefinition,
};
use pathfinder_common::{CasmHash, ClassHash, SierraHash};
use starknet_gateway_client::{BlockId, GatewayApi};

pub enum DownloadedClass {
    Cairo {
        definition: SerializedCairoDefinition,
        hash: ClassHash,
    },
    Sierra {
        sierra_definition: SerializedSierraDefinition,
        sierra_hash: SierraHash,
        casm_definition: SerializedCasmDefinition,
        casm_hash_v2: CasmHash,
    },
}

pub async fn download_class<SequencerClient: GatewayApi>(
    sequencer: &SequencerClient,
    class_hash: ClassHash,
    compiler_resource_limit: pathfinder_compiler::ResourceLimits,
    blockifier_libfuncs: pathfinder_compiler::BlockifierLibfuncs,
    fetch_casm_from_fgw: bool,
) -> Result<DownloadedClass, anyhow::Error> {
    use pathfinder_class_hash::compute_class_hash;

    let definition = sequencer
        .class_by_hash(class_hash, BlockId::Latest)
        .await
        .with_context(|| format!("Downloading class {}", class_hash.0))?;

    let (tx, rx) = tokio::sync::oneshot::channel();
    rayon::spawn(move || {
        let result = compute_class_hash(definition).context("Computing class hash");
        let _ = tx.send(result);
    });
    let (hash, serialized_class) = rx.await.context("Panic on rayon thread")??;

    use pathfinder_class_hash::ComputedClassHash;
    match (hash, serialized_class) {
        (ComputedClassHash::Cairo(hash), SerializedClassDefinition::Cairo(definition)) => {
            if class_hash != hash {
                tracing::warn!(expected=%class_hash, computed=%hash, "Cairo 0 class hash mismatch");
            }

            Ok(DownloadedClass::Cairo { definition, hash })
        }
        (ComputedClassHash::Sierra(hash), SerializedClassDefinition::Sierra(sierra_definition)) => {
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
                    sierra_definition,
                    sequencer
                        .casm_by_hash(class_hash, BlockId::Latest)
                        .await
                        .with_context(|| format!("Downloading CASM {}", class_hash.0))?,
                )
            } else {
                let (send, recv) = tokio::sync::oneshot::channel();
                rayon::spawn(move || {
                    let _span = span.entered();
                    let compile_result = pathfinder_compiler::compile_sierra_to_casm(
                        &sierra_definition,
                        compiler_resource_limit,
                        blockifier_libfuncs,
                    )
                    .context("Compiling Sierra class");
                    let _ = send.send((compile_result, sierra_definition));
                });
                let (casm_definition, sierra_definition) =
                    recv.await.expect("Panic on rayon thread");

                let casm_definition = match casm_definition {
                    Ok(casm_definition) => casm_definition,
                    Err(error) => {
                        tracing::info!(class_hash=%hash, ?error, "CASM compilation failed, falling back to fetching from gateway");
                        sequencer
                            .casm_by_hash(class_hash, BlockId::Latest)
                            .await
                            .with_context(|| format!("Downloading CASM {}", class_hash.0))?
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
        _ => unreachable!("compute_class_hash returns matching hash and class variants"),
    }
}
