pub(crate) mod revision_0001;
pub(crate) mod revision_0002;
pub(crate) mod revision_0003;
pub(crate) mod revision_0004;
pub(crate) mod revision_0005;
pub(crate) mod revision_0006;
pub(crate) mod revision_0007;

/// Used to indicate which action the caller should perform after a schema migration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PostMigrationAction {
    /// A database VACUUM should be performed.
    Vacuum,
    /// No further action requried.
    None,
}
