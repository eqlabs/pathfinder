use p2p::consensus::HeightAndRound;
use p2p_proto::consensus::{ProposalInit, ProposalPart};
use pathfinder_common::ContractAddress;

use crate::consensus::{ProposalError, ProposalHandlingError};

/// Validates the structure of incoming proposal parts and stores them.
///
/// Enforces the following order:
/// 1. Proposal Init (must be first)
/// 2. For non-empty proposals: Block Info (must be second)
/// 3. In any order: Transaction Batches (non-empty), ExecutedTransactionCount
///    (at most once)
/// 4. Proposal Fin (must be last)
///
/// Empty proposals consist of Init + Fin only.
pub struct ProposalPartsValidator {
    height_and_round: HeightAndRound,
    parts: Vec<ProposalPart>,
    has_init: bool,
    has_block_info: bool,
    has_fin: bool,
    has_executed_txn_count: bool,
    transaction_batch_count: usize,
    proposer_address: Option<ContractAddress>,
    valid_round: Option<u32>,
}

/// Result of validating and accepting a proposal part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    /// Part is valid; proposal is still being assembled.
    Accepted,
    /// Fin received: this is an empty proposal (Init + Fin only).
    EmptyProposal,
    /// Fin received: this is a non-empty proposal (Init + BlockInfo + content +
    /// Fin).
    NonEmptyProposal,
}

impl ProposalPartsValidator {
    pub fn new(height_and_round: HeightAndRound) -> Self {
        Self {
            height_and_round,
            parts: Vec::new(),
            has_init: false,
            has_block_info: false,
            has_fin: false,
            has_executed_txn_count: false,
            transaction_batch_count: 0,
            proposer_address: None,
            valid_round: None,
        }
    }

    /// Validate structure and store the part.
    pub fn accept_part(
        &mut self,
        part: &ProposalPart,
    ) -> Result<ValidationResult, ProposalHandlingError> {
        match part {
            ProposalPart::Init(init) => self.accept_init(init),
            ProposalPart::BlockInfo(_) => self.accept_block_info(part),
            ProposalPart::TransactionBatch(tx_batch) => {
                self.accept_transaction_batch(tx_batch, part)
            }
            ProposalPart::ExecutedTransactionCount(_) => self.accept_executed_txn_count(part),
            ProposalPart::Fin(_) => self.accept_fin(part),
        }
    }

    /// Returns the proposer address extracted from the Init part, or `None` if
    /// Init has not been accepted yet.
    pub fn proposer_address(&self) -> Option<ContractAddress> {
        self.proposer_address
    }

    /// Returns the valid round extracted from the Init part.
    pub fn valid_round(&self) -> Option<u32> {
        self.valid_round
    }

    /// Returns the stored proposal parts.
    pub fn parts(&self) -> &[ProposalPart] {
        &self.parts
    }

    fn accept_init(
        &mut self,
        init: &ProposalInit,
    ) -> Result<ValidationResult, ProposalHandlingError> {
        if !self.parts.is_empty() {
            return Err(ProposalHandlingError::Recoverable(
                ProposalError::UnexpectedProposalPart {
                    message: format!(
                        "Unexpected proposal Init for {} at position {}",
                        self.height_and_round,
                        self.parts.len()
                    ),
                },
            ));
        }

        self.has_init = true;
        self.proposer_address = Some(ContractAddress(init.proposer.0));
        self.valid_round = init.valid_round;
        self.parts.push(ProposalPart::Init(init.clone()));
        Ok(ValidationResult::Accepted)
    }

    fn accept_block_info(
        &mut self,
        part: &ProposalPart,
    ) -> Result<ValidationResult, ProposalHandlingError> {
        if self.parts.len() != 1 {
            return Err(ProposalHandlingError::Recoverable(
                ProposalError::UnexpectedProposalPart {
                    message: format!(
                        "Unexpected proposal BlockInfo for {} at position {}",
                        self.height_and_round,
                        self.parts.len()
                    ),
                },
            ));
        }

        self.has_block_info = true;
        self.parts.push(part.clone());
        Ok(ValidationResult::Accepted)
    }

    fn accept_transaction_batch(
        &mut self,
        tx_batch: &[p2p_proto::consensus::Transaction],
        part: &ProposalPart,
    ) -> Result<ValidationResult, ProposalHandlingError> {
        if self.parts.len() < 2 {
            return Err(ProposalHandlingError::Recoverable(
                ProposalError::UnexpectedProposalPart {
                    message: format!(
                        "Unexpected proposal TransactionBatch for {} at position {}",
                        self.height_and_round,
                        self.parts.len()
                    ),
                },
            ));
        }

        if tx_batch.is_empty() {
            return Err(ProposalHandlingError::Recoverable(
                ProposalError::UnexpectedProposalPart {
                    message: format!(
                        "Received empty TransactionBatch for {} at position {}",
                        self.height_and_round,
                        self.parts.len()
                    ),
                },
            ));
        }

        self.transaction_batch_count += 1;
        self.parts.push(part.clone());
        Ok(ValidationResult::Accepted)
    }

    fn accept_executed_txn_count(
        &mut self,
        part: &ProposalPart,
    ) -> Result<ValidationResult, ProposalHandlingError> {
        if !self.has_block_info {
            return Err(ProposalHandlingError::Recoverable(
                ProposalError::UnexpectedProposalPart {
                    message: format!(
                        "Unexpected proposal ExecutedTransactionCount for {} at position {}",
                        self.height_and_round,
                        self.parts.len()
                    ),
                },
            ));
        }

        if self.has_executed_txn_count {
            return Err(ProposalHandlingError::Recoverable(
                ProposalError::UnexpectedProposalPart {
                    message: format!(
                        "Duplicate ExecutedTransactionCount for {}",
                        self.height_and_round,
                    ),
                },
            ));
        }

        self.has_executed_txn_count = true;
        self.parts.push(part.clone());
        Ok(ValidationResult::Accepted)
    }

    fn accept_fin(
        &mut self,
        part: &ProposalPart,
    ) -> Result<ValidationResult, ProposalHandlingError> {
        if self.has_fin {
            return Err(ProposalHandlingError::Recoverable(
                ProposalError::UnexpectedProposalPart {
                    message: format!("Duplicate ProposalFin for {}", self.height_and_round),
                },
            ));
        }

        // Empty proposal: Init + Fin
        if self.parts.len() == 1 && self.has_init {
            self.has_fin = true;
            self.parts.push(part.clone());
            return Ok(ValidationResult::EmptyProposal);
        }

        // Non-empty proposal: at least Init + BlockInfo + 2 content parts before Fin
        if self.parts.len() >= 4 && self.has_block_info {
            self.has_fin = true;
            self.parts.push(part.clone());
            return Ok(ValidationResult::NonEmptyProposal);
        }

        Err(ProposalHandlingError::Recoverable(
            ProposalError::UnexpectedProposalPart {
                message: format!(
                    "Unexpected proposal ProposalFin for {} at position {}",
                    self.height_and_round,
                    self.parts.len()
                ),
            },
        ))
    }
}
