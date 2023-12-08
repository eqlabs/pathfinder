use fake::Dummy;

use crate::BlockCommitmentSignatureElem;

#[derive(Default, Debug, Clone, PartialEq, Dummy)]
pub struct BlockCommitmentSignature {
    pub r: BlockCommitmentSignatureElem,
    pub s: BlockCommitmentSignatureElem,
}
