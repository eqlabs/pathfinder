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
mod revision_0018;
mod revision_0019;
mod revision_0020;
mod revision_0021;
mod revision_0022;
mod revision_0023;
mod revision_0024;
mod revision_0025;
mod revision_0026;
mod revision_0027;
mod revision_0028;
mod revision_0029;

type MigrationFn = fn(&rusqlite::Transaction<'_>) -> anyhow::Result<()>;

/// The full list of pathfinder migrations.
pub fn migrations() -> &'static [MigrationFn] {
    // Don't forget to update `call.py` database version number!
    &[
        revision_0001::migrate,
        revision_0002::migrate,
        revision_0003::migrate,
        revision_0004::migrate,
        revision_0005::migrate,
        revision_0006::migrate,
        revision_0007::migrate,
        revision_0008::migrate,
        revision_0009::migrate,
        revision_0010::migrate,
        revision_0011::migrate,
        revision_0012::migrate,
        revision_0013::migrate,
        revision_0014::migrate,
        revision_0015::migrate,
        revision_0016::migrate,
        revision_0017::migrate,
        revision_0018::migrate,
        revision_0019::migrate,
        revision_0020::migrate,
        revision_0021::migrate,
        revision_0022::migrate,
        revision_0023::migrate,
        revision_0024::migrate,
        revision_0025::migrate,
        revision_0026::migrate,
        revision_0027::migrate,
        revision_0028::migrate,
        revision_0029::migrate,
    ]
}
