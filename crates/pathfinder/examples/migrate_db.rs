fn main() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "pathfinder=info");
    }
    tracing_subscriber::fmt::init();
    // simple tool for running and timing the database migrations on a given file.
    let path = match std::env::args().nth(1) {
        Some(name) if std::env::args().count() == 2 => name,
        _ => {
            println!(
                "USAGE: {} db_file",
                std::env::args().next().as_deref().unwrap_or("migrate_db")
            );
            std::process::exit(1);
        }
    };

    let path = std::path::PathBuf::from(path);

    let size_before = std::fs::metadata(&path).expect("Path does not exist").len() as i64;

    let started_at = std::time::Instant::now();
    pathfinder_storage::Storage::migrate(path.clone(), pathfinder_storage::JournalMode::WAL)
        .unwrap();
    let migrated_at = std::time::Instant::now();

    let size_after_migration = std::fs::metadata(&path)
        .expect("Migration removed the database?")
        .len() as i64;

    println!(
        "migrated in {:?}, size change: {}",
        migrated_at - started_at,
        size_after_migration - size_before
    );

    println!("Reminder: database vacuum must be performed manually if desired");
}
