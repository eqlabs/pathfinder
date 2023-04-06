use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pathfinder_common::{ContractRoot, StorageAddress, StorageValue};
use pathfinder_merkle_tree::ContractsStateTree;
use stark_hash::Felt;

fn gen_random_keys(n: usize) -> Vec<Felt> {
    let mut out = Vec::with_capacity(n);
    let mut rng = rand::rngs::ThreadRng::default();

    while out.len() < n {
        let sh = Felt::random(&mut rng);
        if sh.has_more_than_251_bits() {
            continue;
        }
        out.push(sh);
    }

    out
}

pub fn chunked_inserts(tx: &rusqlite::Transaction<'_>, keys: &[Felt], batch_size: usize) -> Felt {
    let mut hash = ContractRoot::ZERO;

    for keys in keys.chunks(batch_size) {
        let mut uut = ContractsStateTree::load(tx, hash);

        keys.iter()
            .enumerate()
            .try_for_each(|(value, key)| {
                uut.set(
                    StorageAddress::new_or_panic(*key),
                    StorageValue(stark_hash::Felt::from_be_slice(&value.to_be_bytes()).unwrap()),
                )
            })
            .unwrap();

        hash = uut.commit_and_persist_changes().unwrap();
    }

    hash.0
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let s = pathfinder_storage::Storage::in_memory().unwrap();
    let mut connection = s.connection().unwrap();

    c.bench_function("merkle_tree of 1000", |b| {
        b.iter_batched_ref(
            || gen_random_keys(1000),
            |keys| {
                let tx = connection.transaction().unwrap();
                black_box(chunked_inserts(&tx, keys, 1000))
            },
            criterion::BatchSize::PerIteration,
        )
    });

    c.bench_function("merkle_tree of 1000 in 10 batches", |b| {
        b.iter_batched_ref(
            || gen_random_keys(1000),
            |keys| {
                let tx = connection.transaction().unwrap();
                black_box(chunked_inserts(&tx, keys, 100))
            },
            criterion::BatchSize::PerIteration,
        )
    });

    c.bench_function("merkle_tree of 1000 in 100 batches", |b| {
        b.iter_batched_ref(
            || gen_random_keys(1000),
            |keys| {
                let tx = connection.transaction().unwrap();
                black_box(chunked_inserts(&tx, keys, 10))
            },
            criterion::BatchSize::PerIteration,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
