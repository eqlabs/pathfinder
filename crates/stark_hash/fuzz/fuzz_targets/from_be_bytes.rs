#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 32]| {
    let constified = stark_hash::Felt::from_be_bytes(data);
    let orig = stark_hash::Felt::from_be_bytes_orig(data);
    assert_eq!(constified, orig);
});
