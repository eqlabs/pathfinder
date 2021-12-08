use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::PrimeField;
use pathfinder_lib::pedersen::{pedersen_hash, Fp};

pub fn criterion_benchmark(c: &mut Criterion) {
    // these are the test vectors also used in tests
    let e0 = Fp::from_str_vartime(
        "1740729136829561885683894917751815192814966525555656371386868611731128807883",
    )
    .unwrap();
    let e1 = Fp::from_str_vartime(
        "919869093895560023824014392670608914007817594969197822578496829435657368346",
    )
    .unwrap();

    c.bench_function("pedersen_hash", |b| {
        b.iter(|| {
            black_box(pedersen_hash(e0, e1));
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
