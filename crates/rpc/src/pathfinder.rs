mod methods;

pub fn register_all_methods(module: &mut jsonrpsee::RpcModule<()>) -> anyhow::Result<()> {
    use anyhow::Context;

    module
        .register_method("pathfinder_version", |_, _| {
            Ok(pathfinder_common::consts::VERGEN_GIT_SEMVER_LIGHTWEIGHT)
        })
        .with_context(|| "Registering pathfinder_version".to_string())?;
    // module.register_method("pathfinder_getProof", get_proof::get_proof)?; TODO: expose this

    Ok(())
}
