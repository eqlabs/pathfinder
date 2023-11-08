use crate::BlockCommitmentSignatureElem;

#[derive(Default, Debug, Clone, PartialEq)]
pub struct BlockCommitmentSignature {
    pub r: BlockCommitmentSignatureElem,
    pub s: BlockCommitmentSignatureElem,
}
