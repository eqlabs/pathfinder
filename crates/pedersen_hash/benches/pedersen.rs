use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pedersen_hash::{pedersen_hash, pedersen_hash_slow, StarkHash};

pub fn criterion_benchmark(c: &mut Criterion) {
    // These are the test vectors also used in tests, taken from
    // https://github.com/starkware-libs/crypto-cpp/blob/master/src/starkware/crypto/pedersen_hash_test.cc
    let e0 = "03d937c035c878245caf64531a5756109c53068da139362728feb561405371cb";
    let e1 = "0208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a";

    let e0 = StarkHash::from_hex_str(e0).unwrap();
    let e1 = StarkHash::from_hex_str(e1).unwrap();

    c.bench_function("pedersen_hash_preprocessed", |b| {
        b.iter(|| {
            black_box(pedersen_hash(e0, e1));
        });
    });
    c.bench_function("pedersen_hash", |b| {
        b.iter(|| {
            black_box(pedersen_hash_slow(e0, e1));
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
