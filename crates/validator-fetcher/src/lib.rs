//! Validator and Proposer Fetcher
//!
//! This crate provides functionality to fetch validator and proposer
//! information from Starknet contracts. It supports both validators (with
//! voting power) and proposers (with priority) for consensus mechanisms.

use anyhow::Context;
use pathfinder_common::{CallParam, CallResultValue, ChainId, ContractAddress, EntryPoint};
use pathfinder_consensus::PublicKey;
use pathfinder_crypto::Felt;
use pathfinder_executor::{ExecutionState, L1BlobDataAvailability};
use pathfinder_storage::Storage;
use thiserror::Error;

/// Validator information structure matching the Cairo contract
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorInfo {
    pub address: ContractAddress,
    pub public_key: PublicKey,
    pub voting_power: u64,
}

/// Proposer information structure matching the Cairo contract
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposerInfo {
    pub address: ContractAddress,
    pub public_key: PublicKey,
    pub priority: u64, // Priority for proposer selection
}

/// Error types for validator fetching operations
#[derive(Error, Debug)]
pub enum ValidatorFetcherError {
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),

    #[error("Contract call error: {0}")]
    ContractCall(String),

    #[error("Invalid validator data: {0}")]
    InvalidValidatorData(String),

    #[error("Invalid proposer data: {0}")]
    InvalidProposerData(String),

    #[error("No validators found at height {height}")]
    NoValidators { height: u64 },

    #[error("No proposers found at height {height}")]
    NoProposers { height: u64 },

    #[error("Block not found")]
    BlockNotFound,

    #[error("Unsupported network: {0}")]
    UnsupportedNetwork(String),
}

impl From<pathfinder_executor::CallError> for ValidatorFetcherError {
    fn from(err: pathfinder_executor::CallError) -> Self {
        use pathfinder_executor::CallError::*;
        match err {
            ContractNotFound => Self::ContractCall("Contract not found".to_string()),
            InvalidMessageSelector => Self::ContractCall("Entry point not found".to_string()),
            ContractError(error, _) => Self::ContractCall(format!("Contract error: {error}")),
            Internal(e) => Self::Database(e),
            Custom(e) => Self::Database(e),
        }
    }
}

/// Returns the validator contract address for the given network
fn get_validator_contract_address(
    chain_id: ChainId,
) -> Result<ContractAddress, ValidatorFetcherError> {
    match chain_id {
        ChainId::SEPOLIA_TESTNET => {
            // Sepolia testnet mock validator contract
            parse_contract_address(
                "0x06473b97715c7b665923bc0629c66f2a7b8a1ce144699be12bcbe1e3278f109c",
            )
        }
        ChainId::MAINNET => {
            // TODO: Add mainnet validator contract address when available
            Err(ValidatorFetcherError::UnsupportedNetwork(
                chain_id.as_str().to_string(),
            ))
        }
        _ => Err(ValidatorFetcherError::UnsupportedNetwork(
            chain_id.as_str().to_string(),
        )),
    }
}

/// Returns the proposer contract address for the given network
fn get_proposer_contract_address(
    chain_id: ChainId,
) -> Result<ContractAddress, ValidatorFetcherError> {
    match chain_id {
        ChainId::SEPOLIA_TESTNET => {
            // Sepolia testnet mock proposer contract
            // TODO: Replace with actual proposer contract address when available
            parse_contract_address(
                "0x06473b97715c7b665923bc0629c66f2a7b8a1ce144699be12bcbe1e3278f109d",
            )
        }
        ChainId::MAINNET => {
            // TODO: Add mainnet proposer contract address when available
            Err(ValidatorFetcherError::UnsupportedNetwork(
                chain_id.as_str().to_string(),
            ))
        }
        _ => Err(ValidatorFetcherError::UnsupportedNetwork(
            chain_id.as_str().to_string(),
        )),
    }
}

/// Fetches validators from a Starknet contract at a specific height
///
/// This function calls the validator contract to retrieve a list of validators
/// with their addresses, public keys, and voting power at the specified height.
pub fn get_validators_at_height(
    storage: &Storage,
    chain_id: ChainId,
    height: u64,
) -> Result<Vec<ValidatorInfo>, ValidatorFetcherError> {
    let mut db_conn = storage
        .connection()
        .context("Failed to create database connection")?;

    let db_tx = db_conn
        .transaction()
        .context("Failed to create database transaction")?;

    // Always use the latest block for validator fetching
    let block_id = pathfinder_common::BlockId::Latest;
    let header = db_tx
        .block_header(block_id)
        .context("Querying latest block header")?
        .ok_or(ValidatorFetcherError::BlockNotFound)?;

    // Get the hardcoded contract address for this network
    let contract_address = get_validator_contract_address(chain_id)?;

    // Create execution state for call
    let execution_state = ExecutionState::simulation(
        chain_id,
        header,
        None, // No pending state for this call
        L1BlobDataAvailability::Disabled,
        Default::default(),    // VersionedConstantsMap::default()
        ContractAddress::ZERO, // ETH fee address (not used for calls)
        ContractAddress::ZERO, // STRK fee address (not used for calls)
        None,                  // No native class cache
    );

    // The entry point selector for get_validators_at_height
    let entry_point_selector = EntryPoint::hashed(b"get_validator_info_at_height");

    // Prepare calldata - the height parameter
    let height_felt = Felt::from_u64(height);
    let calldata = vec![CallParam(height_felt)];

    // Call the contract
    let result = pathfinder_executor::call(
        db_tx,
        execution_state,
        contract_address,
        entry_point_selector,
        calldata,
    )?;

    // Parse the result into ValidatorInfo structs
    parse_validators_from_result(result, height)
}

/// Fetches proposers from a Starknet contract at a specific height
///
/// This function calls the proposer contract to retrieve a list of proposers
/// with their addresses, public keys, and priority at the specified height.
pub fn get_proposers_at_height(
    storage: &Storage,
    chain_id: ChainId,
    height: u64,
) -> Result<Vec<ProposerInfo>, ValidatorFetcherError> {
    let mut db_conn = storage
        .connection()
        .context("Failed to create database connection")?;

    let db_tx = db_conn
        .transaction()
        .context("Failed to create database transaction")?;

    // Always use the latest block for proposer fetching
    let block_id = pathfinder_common::BlockId::Latest;
    let header = db_tx
        .block_header(block_id)
        .context("Querying latest block header")?
        .ok_or(ValidatorFetcherError::BlockNotFound)?;

    // Get the hardcoded contract address for this network
    let contract_address = get_proposer_contract_address(chain_id)?;

    // Create execution state for call
    let execution_state = ExecutionState::simulation(
        chain_id,
        header,
        None, // No pending state for this call
        L1BlobDataAvailability::Disabled,
        Default::default(),    // VersionedConstantsMap::default()
        ContractAddress::ZERO, // ETH fee address (not used for calls)
        ContractAddress::ZERO, // STRK fee address (not used for calls)
        None,                  // No native class cache
    );

    // The entry point selector for get_proposers_at_height
    let entry_point_selector = EntryPoint::hashed(b"get_proposer_info_at_height");

    // Prepare calldata - the height parameter
    let height_felt = Felt::from_u64(height);
    let calldata = vec![CallParam(height_felt)];

    // Call the contract
    let result = pathfinder_executor::call(
        db_tx,
        execution_state,
        contract_address,
        entry_point_selector,
        calldata,
    )?;

    // Parse the result into ProposerInfo structs
    parse_proposers_from_result(result, height)
}

/// Parses the contract call result into a vector of ValidatorInfo
/// The mock contract now returns an array of ValidatorInfo structs, where each
/// struct contains:
/// - address: ContractAddress
/// - public_key: felt252 (32 bytes as a single felt)
/// - voting_power: u64
fn parse_validators_from_result(
    result: Vec<CallResultValue>,
    height: u64,
) -> Result<Vec<ValidatorInfo>, ValidatorFetcherError> {
    if result.is_empty() {
        return Err(ValidatorFetcherError::NoValidators { height });
    }

    // The contract returns an array with length first, then ValidatorInfo structs
    // Format: [length, address1, public_key1, voting_power1, address2, public_key2,
    // voting_power2, ...]
    let mut validators = Vec::new();

    // The first element is the array length
    let first_element = result[0].0;
    let first_bytes = first_element.to_be_bytes();
    let array_length = u64::from_be_bytes(first_bytes[24..32].try_into().unwrap());

    // Skip the first element (array length) and process the data
    // The remaining elements are the validator data (address, public_key,
    // voting_power) for each validator
    let data = &result[1..];

    // Validate that we have the expected number of elements
    let expected_elements = array_length * 3; // 3 fields per validator
    if data.len() != expected_elements as usize {
        return Err(ValidatorFetcherError::InvalidValidatorData(format!(
            "Expected {} elements for {} validators, got {}",
            expected_elements,
            array_length,
            data.len()
        )));
    }

    // Process the data in chunks of 3 (address, public_key, voting_power)
    for (i, chunk) in data.chunks(3).enumerate() {
        if chunk.len() != 3 {
            return Err(ValidatorFetcherError::InvalidValidatorData(format!(
                "Invalid chunk length {} at index {}",
                chunk.len(),
                i
            )));
        }

        let address = ContractAddress(chunk[0].0);
        let public_key_felt = chunk[1].0;
        let voting_power_felt = chunk[2].0;

        // Convert voting_power from Felt to u64
        let voting_power_bytes = voting_power_felt.to_be_bytes();
        let voting_power = u64::from_be_bytes(voting_power_bytes[24..32].try_into().unwrap());

        // Convert the actual public_key Felt to PublicKey
        let public_key = felt_to_public_key(&public_key_felt)?;

        validators.push(ValidatorInfo {
            address,
            public_key,
            voting_power,
        });
    }

    if validators.is_empty() {
        return Err(ValidatorFetcherError::NoValidators { height });
    }

    // Validate that we processed the expected number of validators
    if validators.len() != array_length as usize {
        return Err(ValidatorFetcherError::InvalidValidatorData(format!(
            "Expected {} validators, processed {}",
            array_length,
            validators.len()
        )));
    }

    Ok(validators)
}

/// Parses the contract call result into a vector of ProposerInfo
/// The mock contract returns an array of ProposerInfo structs, where each
/// struct contains:
/// - address: ContractAddress
/// - public_key: felt252 (32 bytes as a single felt)
/// - priority: u64
fn parse_proposers_from_result(
    result: Vec<CallResultValue>,
    height: u64,
) -> Result<Vec<ProposerInfo>, ValidatorFetcherError> {
    if result.is_empty() {
        return Err(ValidatorFetcherError::NoProposers { height });
    }

    // The contract returns an array with length first, then ProposerInfo structs
    // Format: [length, address1, public_key1, priority1, address2, public_key2,
    // priority2, ...]
    let mut proposers = Vec::new();

    // The first element is the array length
    let first_element = result[0].0;
    let first_bytes = first_element.to_be_bytes();
    let array_length = u64::from_be_bytes(first_bytes[24..32].try_into().unwrap());

    // Skip the first element (array length) and process the data
    // The remaining elements are the proposer data (address, public_key,
    // priority) for each proposer
    let data = &result[1..];

    // Validate that we have the expected number of elements
    let expected_elements = array_length * 3; // 3 fields per proposer
    if data.len() != expected_elements as usize {
        return Err(ValidatorFetcherError::InvalidProposerData(format!(
            "Expected {} elements for {} proposers, got {}",
            expected_elements,
            array_length,
            data.len()
        )));
    }

    // Process the data in chunks of 3 (address, public_key, priority)
    for (i, chunk) in data.chunks(3).enumerate() {
        if chunk.len() != 3 {
            return Err(ValidatorFetcherError::InvalidProposerData(format!(
                "Invalid chunk length {} at index {}",
                chunk.len(),
                i
            )));
        }

        let address = ContractAddress(chunk[0].0);
        let public_key_felt = chunk[1].0;
        let priority_felt = chunk[2].0;

        // Convert priority from Felt to u64
        let priority_bytes = priority_felt.to_be_bytes();
        let priority = u64::from_be_bytes(priority_bytes[24..32].try_into().unwrap());

        // Convert the actual public_key Felt to PublicKey
        let public_key = felt_to_public_key(&public_key_felt)?;

        proposers.push(ProposerInfo {
            address,
            public_key,
            priority,
        });
    }

    if proposers.is_empty() {
        return Err(ValidatorFetcherError::NoProposers { height });
    }

    // Validate that we processed the expected number of proposers
    if proposers.len() != array_length as usize {
        return Err(ValidatorFetcherError::InvalidProposerData(format!(
            "Expected {} proposers, processed {}",
            array_length,
            proposers.len()
        )));
    }

    Ok(proposers)
}

/// Attempts to convert a Felt to a PublicKey
pub fn felt_to_public_key(felt: &Felt) -> Result<PublicKey, ValidatorFetcherError> {
    // Convert Felt to bytes (32 bytes for Ed25519 public key)
    let mut key_bytes = [0u8; 32];
    let felt_bytes = felt.to_be_bytes();

    // Take the last 32 bytes (rightmost 32 bytes)
    if felt_bytes.len() >= 32 {
        key_bytes.copy_from_slice(&felt_bytes[felt_bytes.len() - 32..]);
    } else {
        // If the Felt is smaller than 32 bytes, pad with zeros
        let start = 32 - felt_bytes.len();
        key_bytes[start..].copy_from_slice(&felt_bytes);
    }

    // Try to create the public key from the actual bytes
    // If it fails, it means the contract returned invalid key data
    match std::panic::catch_unwind(|| PublicKey::from_bytes(key_bytes)) {
        Ok(public_key) => Ok(public_key),
        Err(_) => Err(ValidatorFetcherError::InvalidValidatorData(
            "Invalid public key data from contract".to_string(),
        )),
    }
}

/// Helper function to create a contract address from a hex string
pub fn parse_contract_address(hex_str: &str) -> Result<ContractAddress, ValidatorFetcherError> {
    let felt = Felt::from_hex_str(hex_str).map_err(|e| {
        ValidatorFetcherError::InvalidValidatorData(format!("Invalid contract address: {e}"))
    })?;
    Ok(ContractAddress(felt))
}
