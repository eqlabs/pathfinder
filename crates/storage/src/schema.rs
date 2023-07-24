mod base;

mod revision_0031;
mod revision_0032;
mod revision_0033;
mod revision_0034;
mod revision_0035;
mod revision_0036;
mod revision_0037;
mod revision_0038;

pub(crate) use base::base_schema;

type MigrationFn = fn(&rusqlite::Transaction<'_>) -> anyhow::Result<()>;

/// The full list of pathfinder migrations.
pub fn migrations() -> &'static [MigrationFn] {
    // Don't forget to update `call.py` database version number!
    &[
        revision_0031::migrate,
        revision_0032::migrate,
        revision_0033::migrate,
        revision_0034::migrate,
        revision_0035::migrate,
        revision_0036::migrate,
        revision_0037::migrate,
        revision_0038::migrate,
    ]
}

/// The number of schema revisions replaced by the [base schema](base::base_schema).
pub(crate) const BASE_SCHEMA_REVISION: usize = 30;
