use std::{
    ops::ControlFlow,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed},
        mpsc::{Receiver, TrySendError},
        Arc, Mutex,
    },
};

use pathfinder_lib::{
    core::{ContractAddress, ContractRoot, ContractStateHash},
    state::merkle_tree::Visit,
};
use stark_hash::StarkHash;

fn main() {
    let db = match std::env::args().nth(1).map(|path| {
        pathfinder_lib::storage::Storage::migrate(
            path.into(),
            pathfinder_lib::storage::JournalMode::WAL,
        )
    }) {
        Some(Ok(db)) => db,
        Some(Err(e)) => {
            eprintln!("Failed to open database file: {e:?}");
            std::process::exit(1);
        }
        None => {
            // FIXME
            let me = std::env::args()
                .nth(0)
                .unwrap_or_else(|| "bad_leaves".into());
            eprintln!("USAGE: {me} [DBFILE]");
            std::process::exit(1);
        }
    };

    let (sender, rx) = std::sync::mpsc::sync_channel(100);

    let rx = Arc::new(Mutex::new(rx));

    let counters: Arc<Counters> = Default::default();
    let done: Arc<AtomicBool> = Default::default();

    let started_at = std::time::Instant::now();

    let visited_subtrees = Arc::new(Mutex::new(lru_cache::LruCache::with_hasher(
        10_000_000,
        SeaHasherBuilder,
    )));

    let helpers = (0..8)
        .map(|_| {
            std::thread::spawn({
                let db = db.clone();
                let counters = counters.clone();
                let rx = rx.clone();
                let visited_subtrees = visited_subtrees.clone();

                move || contract_walker(db, rx, counters, visited_subtrees)
            })
        })
        .collect::<Vec<_>>();

    let printer_jh = std::thread::spawn({
        let counters = counters.clone();
        let done = done.clone();

        move || {
            let every = std::time::Duration::from_secs(1);

            let mut last = Counters::default();

            while !done.load(Relaxed) {
                std::thread::sleep(every);

                let block = counters.block.load(Relaxed);
                let global_skipped_subtrees = counters.global_skipped_subtrees.load(Relaxed);
                let contract_walker_busy = counters.contract_walker_busy.load(Relaxed);
                let contract_visited_states = counters.contract_visited_states.load(Relaxed);
                let contract_skipped_states = counters.contract_skipped_states.load(Relaxed);
                let contract_skipped_subtrees = counters.contract_skipped_subtrees.load(Relaxed);

                let roots_sent = counters.roots_sent.load(Relaxed);
                let contract_trees_walked = counters.contract_trees_walked.load(Relaxed);

                let global_nodes = counters.global_nodes.load(Relaxed);
                let contract_nodes = counters.contract_nodes.load(Relaxed);

                let d_block = block - *last.block.get_mut();
                let _d_global_skipped_subtrees =
                    global_skipped_subtrees - *last.global_skipped_subtrees.get_mut();
                let d_contract_walker_busy =
                    contract_walker_busy - *last.contract_walker_busy.get_mut();
                let _d_contract_visited_states =
                    contract_visited_states - *last.contract_visited_states.get_mut();
                let _d_contract_skipped_states =
                    contract_skipped_states - *last.contract_skipped_states.get_mut();
                let _d_contract_skipped_subtrees =
                    contract_skipped_subtrees - *last.contract_skipped_subtrees.get_mut();

                let _d_roots_sent = roots_sent - *last.roots_sent.get_mut();
                let d_contract_trees_walked =
                    contract_trees_walked - *last.contract_trees_walked.get_mut();

                let d_global_nodes = global_nodes - *last.global_nodes.get_mut();
                let d_contract_nodes = contract_nodes - *last.contract_nodes.get_mut();

                let fullness = roots_sent.saturating_sub(contract_visited_states);
                let cs_hit_rate = 100.0 * contract_skipped_states as f64
                    / (contract_skipped_states as f64 + contract_visited_states as f64);
                let global_cache_hit_rate = 100.0 * global_skipped_subtrees as f64
                    / (global_skipped_subtrees as f64 + global_nodes as f64);
                let contract_cache_hit_rate = 100.0 * contract_skipped_subtrees as f64
                    / (contract_skipped_subtrees as f64 + contract_nodes as f64);

                println!(
                    "at {block:>6} ({d_block:>4}), \
                    {fullness:>4}% full, \
                    {d_contract_trees_walked:>4} roots walked, \
                    {d_global_nodes:>4} global nodes, \
                    {d_contract_nodes:>4} contract nodes, \
                    {cs_hit_rate:>4.1}% cs rate \
                    {global_cache_hit_rate:>4.1}% global rate \
                    {contract_cache_hit_rate:>4.1}% contract rate \
                    {d_contract_walker_busy:>6} times busy"
                );

                *last.block.get_mut() = block;
                *last.global_skipped_subtrees.get_mut() = global_skipped_subtrees;
                *last.contract_walker_busy.get_mut() = contract_walker_busy;
                *last.contract_visited_states.get_mut() = contract_visited_states;
                *last.contract_skipped_states.get_mut() = contract_skipped_states;
                *last.contract_skipped_subtrees.get_mut() = contract_skipped_subtrees;
                *last.roots_sent.get_mut() = roots_sent;
                *last.contract_trees_walked.get_mut() = contract_trees_walked;
                *last.global_nodes.get_mut() = global_nodes;
                *last.contract_nodes.get_mut() = contract_nodes;
            }
        }
    });

    let mut conn = db.connection().unwrap();

    conn.pragma_update(None, "mmap_size", isize::MAX).unwrap();

    let tx = conn.transaction().unwrap();

    let mut stmt = tx
        .prepare("select root, number from starknet_blocks order by number asc")
        .unwrap();

    let mut rows = stmt.query([]).unwrap();

    let mut visited_global = lru_cache::LruCache::with_hasher(10_000_000, SeaHasherBuilder);

    let mut visited_contract_states = lru_cache::LruCache::with_hasher(1_000_000, SeaHasherBuilder);

    let mut query = tx
        .prepare("select root from contract_states where state_hash = ?")
        .unwrap();

    while let Some(row) = rows.next().unwrap() {
        let root = row.get_unwrap::<_, pathfinder_lib::core::GlobalRoot>(0);
        let block = row.get_unwrap::<_, u64>(1);

        counters
            .block
            .store(usize::try_from(block).unwrap(), Relaxed);

        if visited_global.contains_key(&root.0) {
            counters.global_skipped_subtrees.fetch_add(1, Relaxed);
            continue;
        }

        let tree = pathfinder_lib::state::state_tree::GlobalStateTree::load(&tx, root).unwrap();

        let mut walker = |node: &_, p: &_| -> ControlFlow<(), Visit> {
            use pathfinder_lib::state::merkle_node::Node::*;
            match node {
                Unresolved(h) => {
                    if visited_global.contains_key(h) {
                        counters.global_skipped_subtrees.fetch_add(1, Relaxed);
                        ControlFlow::Continue(Visit::StopSubtree)
                    } else {
                        ControlFlow::Continue(Visit::ContinueDeeper)
                    }
                }
                Binary(b) => {
                    counters.global_nodes.fetch_add(1, Relaxed);
                    visited_global.insert(b.hash.unwrap(), ());
                    ControlFlow::Continue(Default::default())
                }
                Edge(e) => {
                    counters.global_nodes.fetch_add(1, Relaxed);
                    visited_global.insert(e.hash.unwrap(), ());
                    ControlFlow::Continue(Default::default())
                }
                Leaf(l) => {
                    let cs = ContractStateHash(*l);

                    if visited_contract_states.insert(cs.0, ()).is_some() {
                        counters.contract_skipped_states.fetch_add(1, Relaxed);
                    } else {
                        // do query here because other thread seems busier
                        let root = query
                            .query_row([cs], |row| row.get::<_, ContractRoot>(0))
                            .unwrap();

                        let addr = ContractAddress::new(StarkHash::from_bits(p).unwrap()).unwrap();

                        match sender.try_send((block, addr, cs, root)) {
                            Ok(()) => {
                                counters.roots_sent.fetch_add(1, Relaxed);
                            }
                            Err(TrySendError::Full(t)) => {
                                counters.contract_walker_busy.fetch_add(1, Relaxed);
                                sender.send(t).unwrap();
                                counters.roots_sent.fetch_add(1, Relaxed);
                            }
                            Err(TrySendError::Disconnected(_)) => return ControlFlow::Break(()),
                        }
                    }
                    ControlFlow::Continue(Default::default())
                }
            }
        };

        if tree.dfs(&mut walker).unwrap().is_some() {
            break;
        }
    }

    drop(sender);

    helpers.into_iter().for_each(|jh| jh.join().unwrap());
    done.store(true, Relaxed);
    printer_jh.join().unwrap();

    println!("done in {:?}", started_at.elapsed());
}

fn contract_walker(
    db: pathfinder_lib::storage::Storage,
    rx: Arc<Mutex<Receiver<(u64, ContractAddress, ContractStateHash, ContractRoot)>>>,
    counters: Arc<Counters>,
    visited_subtrees: Arc<Mutex<lru_cache::LruCache<stark_hash::StarkHash, (), SeaHasherBuilder>>>,
) {
    let mut conn = db.connection().unwrap();
    conn.pragma_update(None, "mmap_size", isize::MAX).unwrap();
    let tx = conn.transaction().unwrap();

    loop {
        let (block, ca, csh, root) = {
            let g = rx.lock().unwrap_or_else(|e| e.into_inner());
            match g.recv() {
                Ok(t) => t,
                Err(_) => break,
            }
        };

        counters.contract_visited_states.fetch_add(1, Relaxed);

        let tree = pathfinder_lib::state::state_tree::ContractsStateTree::load(&tx, root).unwrap();

        let mut walker = |node: &_, _: &_| -> ControlFlow<(), Visit> {
            use pathfinder_lib::state::merkle_node::Node::*;

            match node {
                Unresolved(h) => {
                    if visited_subtrees
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(*h, ())
                        .is_some()
                    {
                        counters.contract_skipped_subtrees.fetch_add(1, Relaxed);
                        ControlFlow::Continue(Visit::StopSubtree)
                    } else {
                        ControlFlow::Continue(Default::default())
                    }
                }
                Binary(_) => {
                    counters.contract_nodes.fetch_add(1, Relaxed);
                    ControlFlow::Continue(Default::default())
                }
                Edge(_) => {
                    counters.contract_nodes.fetch_add(1, Relaxed);
                    ControlFlow::Continue(Default::default())
                }
                Leaf(_h) => ControlFlow::Continue(Default::default()),
            }
        };

        match tree.dfs(&mut walker) {
            Ok(None) => { /* expected */ }
            Ok(Some(_)) => unreachable!("no breaking returns"),
            Err(e) => {
                println!("should repair tree {root} referenced by {ca:?} through {csh:?} block {block}: {e:?}");
            }
        };

        counters.contract_trees_walked.fetch_add(1, Relaxed);
    }
}

struct SeaHasherBuilder;

impl std::hash::BuildHasher for SeaHasherBuilder {
    type Hasher = seahash::SeaHasher;

    fn build_hasher(&self) -> Self::Hasher {
        seahash::SeaHasher::default()
    }
}

#[derive(Debug, Default)]
struct Counters {
    block: AtomicUsize,

    global_skipped_subtrees: AtomicUsize,
    global_nodes: AtomicUsize,
    contract_nodes: AtomicUsize,

    roots_sent: AtomicUsize,
    contract_walker_busy: AtomicUsize,

    contract_visited_states: AtomicUsize,
    contract_skipped_states: AtomicUsize,
    contract_skipped_subtrees: AtomicUsize,

    contract_trees_walked: AtomicUsize,
}
