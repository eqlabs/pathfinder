mod revision_0001;
mod revision_0002;
mod revision_0003;
mod revision_0004;
mod revision_0005;
mod revision_0006;
mod revision_0007;
mod revision_0008;
mod revision_0009;
mod revision_0010;
mod revision_0011;
mod revision_0012;
mod revision_0013;
mod revision_0014;
mod revision_0015;
mod revision_0016;
mod revision_0017;

pub type MigrationFn = dyn Fn(&rusqlite::Transaction<'_>) -> anyhow::Result<()>;

/// The full list of pathfinder migrations.
pub fn migrations() -> Vec<Box<MigrationFn>> {
    // Don't forget to update `call.py` database version number!
    vec![
        Box::new(revision_0001::migrate),
        Box::new(revision_0002::migrate),
        Box::new(revision_0003::migrate),
        Box::new(revision_0004::migrate),
        Box::new(revision_0005::migrate),
        Box::new(revision_0006::migrate),
        Box::new(revision_0007::migrate),
        Box::new(revision_0008::migrate),
        Box::new(revision_0009::migrate),
        Box::new(revision_0010::migrate),
        Box::new(revision_0011::migrate),
        Box::new(revision_0012::migrate),
        Box::new(revision_0013::migrate),
        Box::new(revision_0014::migrate),
        Box::new(revision_0015::migrate),
        Box::new(revision_0016::migrate),
        Box::new(revision_0017::migrate),
    ]
}
