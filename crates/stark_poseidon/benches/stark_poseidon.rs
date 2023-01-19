use ::stark_curve::FieldElement;
use ::stark_poseidon::poseidon::{permute, PoseidonState};
use criterion::{criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("poseidon_permute", |b| {
        b.iter(|| {
            let mut state: PoseidonState =
                [FieldElement::ZERO, FieldElement::ZERO, FieldElement::ZERO];
            permute(&mut state);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
