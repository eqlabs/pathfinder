use std::sync::{Arc, Mutex};

use blockifier::execution::native::contract_class::NativeCompiledClassV1;
use blockifier::state::errors::StateError;
use cached::{Cached, SizedCache};
use cairo_native::executor::AotContractExecutor;
use cairo_vm::types::errors::program_errors::ProgramError;
use pathfinder_common::ClassHash;
use starknet_api::contract_class::SierraVersion;

struct CompilerInput {
    class_hash: ClassHash,
    sierra_version: SierraVersion,
    class_definition: Vec<u8>,
    casm_definition: Vec<u8>,
}

enum CacheItem {
    CompiledClass(NativeCompiledClassV1),
    CompilationPending,
}

type Cache = Mutex<SizedCache<ClassHash, CacheItem>>;

pub struct NativeClassCache {
    cache: Arc<Cache>,
    compiler_tx: std::sync::mpsc::Sender<CompilerInput>,
}

impl NativeClassCache {
    pub fn spawn(cache_size: usize) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();

        let cache = Arc::new(Mutex::new(SizedCache::with_size(cache_size)));

        std::thread::spawn({
            let cache = Arc::clone(&cache);
            move || compiler_thread(cache, rx)
        });

        NativeClassCache {
            cache,
            compiler_tx: tx,
        }
    }

    pub fn get(
        &self,
        class_hash: ClassHash,
        sierra_version: SierraVersion,
        class_definition: Vec<u8>,
        casm_definition: Vec<u8>,
    ) -> Option<NativeCompiledClassV1> {
        let mut locked = self.cache.lock().unwrap();

        match locked.cache_get(&class_hash) {
            Some(CacheItem::CompiledClass(cached_class)) => {
                tracing::trace!(%class_hash, "Native class cache hit");
                Some(cached_class.clone())
            }
            Some(CacheItem::CompilationPending) => {
                tracing::trace!(%class_hash, "Native class cache miss (pending)");
                None
            }
            None => {
                tracing::trace!(%class_hash, "Native class cache miss (compiling)");
                locked.cache_set(class_hash, CacheItem::CompilationPending);
                let _ = self.compiler_tx.send(CompilerInput {
                    class_hash,
                    sierra_version,
                    class_definition,
                    casm_definition,
                });
                None
            }
        }
    }
}

fn compiler_thread(cache: Arc<Cache>, rx: std::sync::mpsc::Receiver<CompilerInput>) {
    while let Ok(input) = rx.recv() {
        let class_hash = input.class_hash;

        let _span =
            tracing::span!(tracing::Level::DEBUG, "native_class_compiler", %class_hash).entered();

        tracing::trace!("Compiling native class");
        let started_at = std::time::Instant::now();
        match sierra_class_as_native(input) {
            Ok(compiled_class) => {
                tracing::trace!(elapsed=?started_at.elapsed(), "Compilation finished");
                cache
                    .lock()
                    .unwrap()
                    .cache_set(class_hash, CacheItem::CompiledClass(compiled_class));
            }
            Err(error) => {
                tracing::error!(elapsed=?started_at.elapsed(), %error, "Error compiling native class");
            }
        }
    }
}

fn sierra_class_as_native(input: CompilerInput) -> Result<NativeCompiledClassV1, StateError> {
    let mut sierra_definition: serde_json::Value = serde_json::from_slice(&input.class_definition)
        .map_err(|e| StateError::ProgramError(ProgramError::Parse(e)))?;
    let sierra_abi_str = sierra_definition
        .get("abi")
        .ok_or_else(|| StateError::StateReadError("Sierra ABI is missing".to_owned()))?
        .as_str()
        .ok_or_else(|| StateError::StateReadError("Sierra ABI is not a string".to_owned()))?;
    sierra_definition["abi"] = serde_json::from_str(sierra_abi_str)
        .map_err(|e| StateError::ProgramError(ProgramError::Parse(e)))?;

    let sierra_class: cairo_lang_starknet_classes::contract_class::ContractClass =
        serde_json::from_value(sierra_definition)
            .map_err(|e| StateError::ProgramError(ProgramError::Parse(e)))?;

    let sierra_program = sierra_class.extract_sierra_program().map_err(|e| {
        StateError::StateReadError(format!(
            "Error parsing Sierra
                program: {}",
            e
        ))
    })?;

    let mut class_path = std::env::temp_dir();
    class_path.push(format!("native_class_{}", input.class_hash));
    let version_id = cairo_lang_starknet_classes::compiler_version::VersionId {
        major: input.sierra_version.major as usize,
        minor: input.sierra_version.minor as usize,
        patch: input.sierra_version.patch as usize,
    };
    let contract_executor = AotContractExecutor::new(
        &sierra_program,
        &sierra_class.entry_points_by_type,
        version_id,
        cairo_native::OptLevel::Default,
    )
    .map_err(|e| StateError::StateReadError(format!("Error compiling native class: {e}")))?;

    let casm_definition = String::from_utf8(input.casm_definition).map_err(|error| {
        StateError::StateReadError(format!("Class definition is not valid UTF-8: {}", error))
    })?;

    let casm_class = blockifier::execution::contract_class::CompiledClassV1::try_from_json_string(
        &casm_definition,
        input.sierra_version,
    )
    .map_err(StateError::ProgramError)?;

    let native_class = NativeCompiledClassV1::new(contract_executor, casm_class);

    Ok(native_class)
}
