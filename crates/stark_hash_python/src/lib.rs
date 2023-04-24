use num_bigint::BigUint;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use stark_curve::FieldElement;
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

/// Computes the Poseidon hash of two felts.
///
/// Inputs are expected to be big-endian 32 byte slices.
#[pyfunction]
fn poseidon_hash_func(a: &[u8], b: &[u8]) -> PyResult<Vec<u8>> {
    let a = Felt::from_be_slice(a).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let b = Felt::from_be_slice(b).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let hash: Felt = stark_poseidon::poseidon_hash(a.into(), b.into()).into();

    Ok(hash.to_be_bytes().to_vec())
}

/// Computes the Poseidon hash of two felts.
///
/// Inputs are expected to be Python integers.
#[pyfunction]
fn poseidon_hash(a: BigUint, b: BigUint, poseidon_params: Option<PyObject>) -> PyResult<BigUint> {
    assert!(
        poseidon_params.is_none(),
        "Non-default Poseidon parameters are not supported"
    );

    let a =
        Felt::from_be_slice(&a.to_bytes_be()).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let b =
        Felt::from_be_slice(&b.to_bytes_be()).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let hash: Felt = stark_poseidon::poseidon_hash(a.into(), b.into()).into();

    Ok(BigUint::from_bytes_be(&hash.to_be_bytes()))
}

/// Computes the Poseidon hash of a sequence of felts.
///
/// Input is expected to be a sequence of Python integers.
#[pyfunction]
fn poseidon_hash_many(array: Vec<BigUint>, poseidon_params: Option<PyObject>) -> PyResult<BigUint> {
    assert!(
        poseidon_params.is_none(),
        "Non-default Poseidon parameters are not supported"
    );

    let array = array
        .into_iter()
        .map(|a| {
            Felt::from_be_slice(&a.to_bytes_be())
                .map(Into::into)
                .map_err(|e| PyValueError::new_err(e.to_string()))
        })
        .collect::<Result<Vec<FieldElement>, PyErr>>()?;

    let hash: Felt = stark_poseidon::poseidon_hash_many(&array).into();

    Ok(BigUint::from_bytes_be(&hash.to_be_bytes()))
}

#[pyfunction]
fn poseidon_perm(a: BigUint, b: BigUint, c: BigUint) -> PyResult<Vec<BigUint>> {
    let a =
        Felt::from_be_slice(&a.to_bytes_be()).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let b =
        Felt::from_be_slice(&b.to_bytes_be()).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let c =
        Felt::from_be_slice(&c.to_bytes_be()).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let mut state: stark_poseidon::PoseidonState = [a.into(), b.into(), c.into()];

    stark_poseidon::permute_comp(&mut state);

    let output = state
        .into_iter()
        .map(|e| BigUint::from_bytes_be(&Felt::from(e).to_be_bytes()))
        .collect();

    Ok(output)
}

#[pymodule]
fn starknet_pathfinder_crypto(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(pedersen_hash, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_hash_func, m)?)?;
    m.add_function(wrap_pyfunction!(poseidon_hash, m)?)?;
    m.add_function(wrap_pyfunction!(poseidon_hash_func, m)?)?;
    m.add_function(wrap_pyfunction!(poseidon_hash_many, m)?)?;
    m.add_function(wrap_pyfunction!(poseidon_perm, m)?)?;
    Ok(())
}
