use ::stark_hash::{stark_hash, Felt, HashChain};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    // These are the test vectors also used in tests, taken from
    // https://github.com/starkware-libs/crypto-cpp/blob/master/src/starkware/crypto/pedersen_hash_test.cc
    let e0 = "03d937c035c878245caf64531a5756109c53068da139362728feb561405371cb";
    let e1 = "0208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a";

    let e0 = Felt::from_hex_str(e0).unwrap();
    let e1 = Felt::from_hex_str(e1).unwrap();

    // this is useful for testing out the branch predictor
    c.bench_function("pedersen_hash", |b| {
        b.iter(|| {
            black_box(stark_hash(e0, e1));
        });
    });

    let mut rng = rand::thread_rng();

    c.bench_function("random_stark_hash", |b| {
        b.iter_batched(
            || {
                let a = Felt::random(&mut rng);
                let b = Felt::random(&mut rng);
                (a, b)
            },
            |(a, b)| black_box(stark_hash(a, b)),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("random_hashchain", |b| {
        b.iter_batched_ref(
            || {
                std::iter::from_fn(|| Some(Felt::random(&mut rng)))
                    .take(100)
                    .collect::<Vec<_>>()
            },
            |input| {
                let mut hc = HashChain::default();
                for x in input.drain(..) {
                    hc.update(x);
                }
                black_box(hc.finalize())
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
