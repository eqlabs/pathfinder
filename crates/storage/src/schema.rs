mod base;

mod revision_0040;

pub(crate) use base::base_schema;

type MigrationFn = fn(&rusqlite::Transaction<'_>) -> anyhow::Result<()>;

/// The full list of pathfinder migrations.
pub fn migrations() -> &'static [MigrationFn] {
    // Don't forget to update `call.py` database version number!
    &[revision_0040::migrate]
}

/// The number of schema revisions replaced by the [base schema](base::base_schema).
pub(crate) const BASE_SCHEMA_REVISION: usize = 39;
