pub fn register_all_methods(module: &mut jsonrpsee::RpcModule<()>) -> anyhow::Result<()> {
    use anyhow::Context;

    module
        .register_async_method(
            "pathfinder_version",
            |_, _| async move { Ok(version().await) },
        )
        .with_context(|| format!("Registering pathfinder_version"))?;

    Ok(())
}

async fn version() -> &'static str {
    return env!("VERGEN_GIT_SEMVER_LIGHTWEIGHT");
}
