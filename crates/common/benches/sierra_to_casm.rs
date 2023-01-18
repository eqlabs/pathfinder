use cairo_lang_starknet::{casm_contract_class::CasmContractClass, contract_class::ContractClass};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

#[inline]
fn sierra_to_casm(sierra: ContractClass) -> CasmContractClass {
    CasmContractClass::from_contract_class(sierra).unwrap()
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("sierra_to_casm", |b| {
        // ContractClass is neither Copy nor Clone :(
        b.iter_batched(
            || {
                serde_json::from_slice::<ContractClass>(include_bytes!(
                    "../fixtures/test_contract.json"
                ))
                .unwrap()
            },
            |sierra| {
                black_box(sierra_to_casm(sierra));
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
