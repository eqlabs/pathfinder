use ::pathfinder_crypto::hash::poseidon::poseidon_hash;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pathfinder_crypto::algebra::curve::{ProjectivePoint, CURVE_G};
use pathfinder_crypto::algebra::field::{CurveOrderMontFelt, Felt, MontFelt};
use pathfinder_crypto::hash::pedersen::pedersen_hash;
use pathfinder_crypto::signature::{ecdsa_sign, ecdsa_sign_k, ecdsa_verify_partial, get_pk};

pub fn criterion_benchmark(c: &mut Criterion) {
    // Bench algebra
    bench_algebra(c);

    // Bench hash functions
    bench_hash(c);

    // Bench signatures
    bench_signature(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

pub fn bench_algebra(c: &mut Criterion) {
    let rng = &mut rand::thread_rng();

    let mut grp_alg = c.benchmark_group("algebra");

    grp_alg.bench_function("generator_mul", |b| {
        b.iter_batched(
            || CurveOrderMontFelt::random(rng),
            |x| black_box(CURVE_G.multiply_elm(&x)),
            criterion::BatchSize::SmallInput,
        )
    });

    grp_alg.bench_function("generator_mul_lut", |b| {
        b.iter_batched(
            || CurveOrderMontFelt::random(rng),
            |x| black_box(ProjectivePoint::gen_multiply_elm(x)),
            criterion::BatchSize::SmallInput,
        )
    });

    grp_alg.finish();
}

pub fn bench_hash(c: &mut Criterion) {
    let rng = &mut rand::thread_rng();

    let mut grp_hash = c.benchmark_group("hash");
    grp_hash.bench_function("poseidon_hash", |b| {
        b.iter_batched(
            || (MontFelt::random(rng), MontFelt::random(rng)),
            |(a, b)| black_box(poseidon_hash(a, b)),
            criterion::BatchSize::SmallInput,
        )
    });
    grp_hash.bench_function("pedersen_hash", |b| {
        b.iter_batched(
            || (Felt::random(rng), Felt::random(rng)),
            |(a, b)| black_box(pedersen_hash(a, b)),
            criterion::BatchSize::SmallInput,
        )
    });
    grp_hash.finish();
}

pub fn bench_signature(c: &mut Criterion) {
    pub fn rand_251bit_felt() -> Felt {
        let rng = &mut rand::thread_rng();
        loop {
            let felt = Felt::random(rng);
            if !felt.has_more_than_251_bits() {
                return felt;
            }
        }
    }

    let mut grp_sig = c.benchmark_group("signature");
    grp_sig.bench_function("ecdsa_sign", |b| {
        b.iter_batched(
            || {
                let sk = rand_251bit_felt();
                let z = rand_251bit_felt();
                let k = rand_251bit_felt();
                (sk, z, k)
            },
            |(sk, z, k)| black_box(ecdsa_sign_k(sk, z, k)),
            criterion::BatchSize::SmallInput,
        )
    });
    grp_sig.bench_function("ecdsa_verify_partial", |b| {
        b.iter_batched(
            || {
                let sk = rand_251bit_felt();
                let z = rand_251bit_felt();
                let (r, s) = ecdsa_sign(sk, z).unwrap();
                let pk = get_pk(sk).unwrap();
                (pk, z, r, s)
            },
            |(pk, z, r, s)| black_box(ecdsa_verify_partial(pk, z, r, s)),
            criterion::BatchSize::SmallInput,
        )
    });
    grp_sig.finish();
}
