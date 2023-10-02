mod base;

pub(crate) use base::base_schema;

type MigrationFn = fn(&rusqlite::Transaction<'_>) -> anyhow::Result<()>;

/// The full list of pathfinder migrations.
pub fn migrations() -> &'static [MigrationFn] {
    &[]
}

/// The number of schema revisions replaced by the [base schema](base::base_schema).
pub(crate) const BASE_SCHEMA_REVISION: usize = 39;
