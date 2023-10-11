mod base;

mod revision_0041;
mod revision_0042;

pub(crate) use base::base_schema;

type MigrationFn = fn(&rusqlite::Transaction<'_>) -> anyhow::Result<()>;

/// The full list of pathfinder migrations.
pub fn migrations() -> &'static [MigrationFn] {
    &[revision_0041::migrate, revision_0042::migrate]
}

/// The number of schema revisions replaced by the [base schema](base::base_schema).
///
/// Note that 40 was a no-op as we wanted to disallow versions <= 39.
pub(crate) const BASE_SCHEMA_REVISION: usize = 40;
