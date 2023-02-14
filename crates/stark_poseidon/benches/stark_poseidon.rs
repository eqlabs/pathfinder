use ::stark_curve::FieldElement;
use ::stark_poseidon::{permute, permute_comp, PoseidonState};
use criterion::{criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("poseidon_permute", |b| {
        b.iter(|| {
            let mut state: PoseidonState =
                [FieldElement::ZERO, FieldElement::ZERO, FieldElement::ZERO];
            permute(&mut state);
        });
    });
    c.bench_function("poseidon_permute_comp", |b| {
        b.iter(|| {
            let mut state: PoseidonState =
                [FieldElement::ZERO, FieldElement::ZERO, FieldElement::ZERO];
            permute_comp(&mut state);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
