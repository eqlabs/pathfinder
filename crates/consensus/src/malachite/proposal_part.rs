use p2p_proto::consensus as p2p_proto;

use super::MalachiteContext;

/// A proposal part for the consensus logic.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProposalPart(p2p_proto::ProposalPart);

impl malachite_types::ProposalPart<MalachiteContext> for ProposalPart {
    fn is_first(&self) -> bool {
        matches!(self.0, p2p_proto::ProposalPart::Init(_))
    }

    fn is_last(&self) -> bool {
        matches!(self.0, p2p_proto::ProposalPart::Fin(_))
    }
}
