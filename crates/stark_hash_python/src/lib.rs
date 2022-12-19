use num_bigint::BigUint;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use stark_hash::{stark_hash, Felt};

/// Computes the Pedersen hash.
///
/// Inputs are expected to be big-endian 32 byte slices.
#[pyfunction]
fn pedersen_hash_func(a: &[u8], b: &[u8]) -> PyResult<Vec<u8>> {
    let a = Felt::from_be_slice(a).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let b = Felt::from_be_slice(b).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let hash = stark_hash(a, b);

    Ok(hash.to_be_bytes().to_vec())
}

/// Computes the Pedersen hash.
///
/// Inputs are expected to be Python integers.
#[pyfunction]
fn pedersen_hash(a: BigUint, b: BigUint) -> PyResult<BigUint> {
    let a =
        Felt::from_be_slice(&a.to_bytes_be()).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let b =
        Felt::from_be_slice(&b.to_bytes_be()).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let hash = stark_hash(a, b);

    Ok(BigUint::from_bytes_be(&hash.to_be_bytes()))
}

#[pymodule]
fn stark_hash_rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(pedersen_hash, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_hash_func, m)?)?;
    Ok(())
}
