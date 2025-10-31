use p2p_proto::consensus as proto;
use pathfinder_common::{receipt, state_update};
use pathfinder_storage::{
    DataAvailabilityMode,
    DeclareTransactionV4,
    DeployAccountTransactionV4,
    InvokeTransactionV4,
    L1HandlerTransactionV0,
    ResourceBound,
    ResourceBoundsV1,
    TransactionV2,
};

use crate::consensus::inner::dto;
use crate::validator::FinalizedBlock;

/// Convert a DTO type to a data model type (`protobuf` in case of raw
/// proposals, and `pathfinder_common` types in case of finalized blocks)
pub trait IntoModel<T> {
    fn into_model(self) -> T;
}

/// Convert a data model type into a DTO, fallibly
pub trait TryIntoDto<T> {
    fn try_into_dto(dto: T) -> anyhow::Result<Self>
    where
        Self: Sized;
}

impl IntoModel<proto::ProposalPart> for dto::ProposalPart {
    fn into_model(self) -> proto::ProposalPart {
        match self {
            dto::ProposalPart::Init(p) => proto::ProposalPart::Init(proto::ProposalInit {
                block_number: p.block_number,
                round: p.round,
                valid_round: p.valid_round,
                proposer: p2p_proto::common::Address(p.proposer.into()),
            }),
            dto::ProposalPart::Fin(p) => proto::ProposalPart::Fin(proto::ProposalFin {
                proposal_commitment: p2p_proto::common::Hash(p.proposal_commitment.into()),
            }),
            dto::ProposalPart::BlockInfo(p) => proto::ProposalPart::BlockInfo(proto::BlockInfo {
                block_number: p.block_number,
                builder: p2p_proto::common::Address(p.builder.into()),
                timestamp: p.timestamp,
                l2_gas_price_fri: p.l2_gas_price_fri,
                l1_gas_price_wei: p.l1_gas_price_wei,
                l1_data_gas_price_wei: p.l1_data_gas_price_wei,
                eth_to_strk_rate: p.eth_to_strk_rate,
                l1_da_mode: p.l1_da_mode.into_model(),
            }),
            dto::ProposalPart::TransactionBatch(batch) => proto::ProposalPart::TransactionBatch(
                batch.into_iter().map(|t| t.into_model()).collect(),
            ),
            dto::ProposalPart::ProposalCommitment(p) => {
                proto::ProposalPart::ProposalCommitment(proto::ProposalCommitment {
                    block_number: p.block_number,
                    parent_commitment: p2p_proto::common::Hash(p.parent_commitment.into()),
                    builder: p2p_proto::common::Address(p.builder.into()),
                    timestamp: p.timestamp,
                    protocol_version: p.protocol_version,
                    old_state_root: p2p_proto::common::Hash(p.old_state_root.into()),
                    version_constant_commitment: p2p_proto::common::Hash(
                        p.version_constant_commitment.into(),
                    ),
                    state_diff_commitment: p2p_proto::common::Hash(p.state_diff_commitment.into()),
                    transaction_commitment: p2p_proto::common::Hash(
                        p.transaction_commitment.into(),
                    ),
                    event_commitment: p2p_proto::common::Hash(p.event_commitment.into()),
                    receipt_commitment: p2p_proto::common::Hash(p.receipt_commitment.into()),
                    concatenated_counts: p.concatenated_counts.into(),
                    l1_gas_price_fri: p.l1_gas_price_fri,
                    l1_data_gas_price_fri: p.l1_data_gas_price_fri,
                    l2_gas_price_fri: p.l2_gas_price_fri,
                    l2_gas_used: p.l2_gas_used,
                    next_l2_gas_price_fri: p.next_l2_gas_price_fri,
                    l1_da_mode: p.l1_da_mode.into_model(),
                })
            }
        }
    }
}

impl IntoModel<proto::Transaction> for dto::TransactionWithClass {
    fn into_model(self) -> proto::Transaction {
        let dto::TransactionWithClass { variant, hash } = self;
        proto::Transaction {
            txn: variant.into_model(),
            transaction_hash: p2p_proto::common::Hash(hash.into()),
        }
    }
}

impl IntoModel<proto::TransactionVariant> for dto::TransactionVariantWithClass {
    fn into_model(self) -> proto::TransactionVariant {
        match self {
            dto::TransactionVariantWithClass::Declare(dcl) => {
                proto::TransactionVariant::DeclareV3(p2p_proto::transaction::DeclareV3WithClass {
                    common: dcl.declare_transaction.into_model(),
                    class: dcl.class.into_model(),
                })
            }
            dto::TransactionVariantWithClass::DeployAccount(dpl) => {
                proto::TransactionVariant::DeployAccountV3(dpl.into_model())
            }
            dto::TransactionVariantWithClass::Invoke(inv) => {
                proto::TransactionVariant::InvokeV3(inv.into_model())
            }
            dto::TransactionVariantWithClass::L1Handler(h) => {
                proto::TransactionVariant::L1HandlerV0(h.into_model())
            }
        }
    }
}

impl IntoModel<p2p_proto::transaction::DeclareV3Common> for DeclareTransactionV4 {
    fn into_model(self) -> p2p_proto::transaction::DeclareV3Common {
        p2p_proto::transaction::DeclareV3Common {
            sender: p2p_proto::common::Address(self.sender_address.into()),
            signature: p2p_proto::transaction::AccountSignature {
                parts: self.signature.into_iter().map(|s| s.into()).collect(),
            },
            nonce: self.nonce.into(),
            compiled_class_hash: p2p_proto::common::Hash(self.compiled_class_hash.into()),
            resource_bounds: self.resource_bounds.into_model(),
            tip: self.tip.0,
            paymaster_data: self.paymaster_data.into_iter().map(|e| e.into()).collect(),
            account_deployment_data: self
                .account_deployment_data
                .into_iter()
                .map(|e| e.into())
                .collect(),
            nonce_data_availability_mode: self.nonce_data_availability_mode.into_model(),
            fee_data_availability_mode: self.fee_data_availability_mode.into_model(),
        }
    }
}

impl IntoModel<p2p_proto::transaction::DeployAccountV3> for DeployAccountTransactionV4 {
    fn into_model(self) -> p2p_proto::transaction::DeployAccountV3 {
        p2p_proto::transaction::DeployAccountV3 {
            signature: p2p_proto::transaction::AccountSignature {
                parts: self.signature.into_iter().map(|s| s.into()).collect(),
            },
            class_hash: p2p_proto::common::Hash(self.class_hash.into()),
            nonce: self.nonce.into(),
            address_salt: self.contract_address_salt.into(),
            calldata: self
                .constructor_calldata
                .into_iter()
                .map(|e| e.into())
                .collect(),
            resource_bounds: self.resource_bounds.into_model(),
            tip: self.tip.0,
            paymaster_data: self.paymaster_data.into_iter().map(|e| e.into()).collect(),
            nonce_data_availability_mode: self.nonce_data_availability_mode.into_model(),
            fee_data_availability_mode: self.fee_data_availability_mode.into_model(),
        }
    }
}

impl IntoModel<p2p_proto::transaction::InvokeV3> for InvokeTransactionV4 {
    fn into_model(self) -> p2p_proto::transaction::InvokeV3 {
        p2p_proto::transaction::InvokeV3 {
            sender: p2p_proto::common::Address(self.sender_address.into()),
            signature: p2p_proto::transaction::AccountSignature {
                parts: self.signature.into_iter().map(|s| s.into()).collect(),
            },
            calldata: self.calldata.into_iter().map(|e| e.into()).collect(),
            resource_bounds: self.resource_bounds.into_model(),
            tip: self.tip.0,
            paymaster_data: self.paymaster_data.into_iter().map(|e| e.into()).collect(),
            account_deployment_data: self
                .account_deployment_data
                .into_iter()
                .map(|e| e.into())
                .collect(),
            nonce_data_availability_mode: self.nonce_data_availability_mode.into_model(),
            fee_data_availability_mode: self.fee_data_availability_mode.into_model(),
            nonce: self.nonce.into(),
        }
    }
}

impl IntoModel<p2p_proto::transaction::L1HandlerV0> for L1HandlerTransactionV0 {
    fn into_model(self) -> p2p_proto::transaction::L1HandlerV0 {
        let L1HandlerTransactionV0 {
            contract_address,
            entry_point_selector,
            nonce,
            calldata,
        } = self;
        p2p_proto::transaction::L1HandlerV0 {
            nonce: nonce.into(),
            address: p2p_proto::common::Address(contract_address.into()),
            entry_point_selector: entry_point_selector.into(),
            calldata: calldata.into_iter().map(|e| e.into()).collect(),
        }
    }
}

impl IntoModel<p2p_proto::transaction::ResourceBounds> for ResourceBoundsV1 {
    fn into_model(self) -> p2p_proto::transaction::ResourceBounds {
        let ResourceBoundsV1 {
            l1_gas,
            l2_gas,
            l1_data_gas,
        } = self;
        p2p_proto::transaction::ResourceBounds {
            l1_gas: l1_gas.into_model(),
            l2_gas: l2_gas.into_model(),
            l1_data_gas: l1_data_gas.map(|r| r.into_model()),
        }
    }
}

impl IntoModel<p2p_proto::transaction::ResourceLimits> for ResourceBound {
    fn into_model(self) -> p2p_proto::transaction::ResourceLimits {
        let ResourceBound {
            max_amount,
            max_price_per_unit,
        } = self;
        p2p_proto::transaction::ResourceLimits {
            max_amount: max_amount.0.into(),
            max_price_per_unit: max_price_per_unit.0.into(),
        }
    }
}

impl IntoModel<p2p_proto::common::VolitionDomain> for DataAvailabilityMode {
    fn into_model(self) -> p2p_proto::common::VolitionDomain {
        match self {
            DataAvailabilityMode::L1 => p2p_proto::common::VolitionDomain::L1,
            DataAvailabilityMode::L2 => p2p_proto::common::VolitionDomain::L2,
        }
    }
}

impl IntoModel<p2p_proto::class::Cairo1Class> for dto::Cairo1Class {
    fn into_model(self) -> p2p_proto::class::Cairo1Class {
        p2p_proto::class::Cairo1Class {
            abi: self.abi,
            entry_points: self.entry_points.into_model(),
            program: self.program.into_iter().map(|e| e.into()).collect(),
            contract_class_version: self.contract_class_version,
        }
    }
}

impl IntoModel<p2p_proto::class::Cairo1EntryPoints> for dto::Cairo1EntryPoints {
    fn into_model(self) -> p2p_proto::class::Cairo1EntryPoints {
        let dto::Cairo1EntryPoints {
            externals,
            l1_handlers,
            constructors,
        } = self;
        p2p_proto::class::Cairo1EntryPoints {
            externals: externals.into_iter().map(|e| e.into_model()).collect(),
            l1_handlers: l1_handlers.into_iter().map(|e| e.into_model()).collect(),
            constructors: constructors.into_iter().map(|e| e.into_model()).collect(),
        }
    }
}

impl IntoModel<p2p_proto::class::SierraEntryPoint> for dto::SierraEntryPoint {
    fn into_model(self) -> p2p_proto::class::SierraEntryPoint {
        let dto::SierraEntryPoint { index, selector } = self;
        p2p_proto::class::SierraEntryPoint {
            index,
            selector: selector.into(),
        }
    }
}

impl IntoModel<p2p_proto::common::L1DataAvailabilityMode> for u8 {
    fn into_model(self) -> p2p_proto::common::L1DataAvailabilityMode {
        match self {
            0 => p2p_proto::common::L1DataAvailabilityMode::Calldata,
            1 => p2p_proto::common::L1DataAvailabilityMode::Blob,
            _ => panic!("DB has unexpected L1DataAvailabilityMode"),
        }
    }
}

impl TryIntoDto<proto::ProposalPart> for dto::ProposalPart {
    fn try_into_dto(p: proto::ProposalPart) -> anyhow::Result<dto::ProposalPart> {
        let r = match p {
            proto::ProposalPart::Init(q) => dto::ProposalPart::Init(dto::ProposalInit {
                block_number: q.block_number,
                round: q.round,
                valid_round: q.valid_round,
                proposer: q.proposer.0.into(),
            }),
            proto::ProposalPart::Fin(q) => dto::ProposalPart::Fin(dto::ProposalFin {
                proposal_commitment: q.proposal_commitment.0.into(),
            }),
            proto::ProposalPart::BlockInfo(q) => dto::ProposalPart::BlockInfo(dto::BlockInfo {
                block_number: q.block_number,
                builder: q.builder.0.into(),
                timestamp: q.timestamp,
                l2_gas_price_fri: q.l2_gas_price_fri,
                l1_gas_price_wei: q.l1_gas_price_wei,
                l1_data_gas_price_wei: q.l1_data_gas_price_wei,
                eth_to_strk_rate: q.eth_to_strk_rate,
                l1_da_mode: u8::try_into_dto(q.l1_da_mode)?,
            }),
            proto::ProposalPart::TransactionBatch(proto_batch) => {
                dto::ProposalPart::TransactionBatch(
                    proto_batch
                        .into_iter()
                        .map(dto::TransactionWithClass::try_into_dto)
                        .collect::<Result<Vec<dto::TransactionWithClass>, _>>()?,
                )
            }
            proto::ProposalPart::TransactionsFin(_) => {
                todo!("TODO: TransactionsFin not supported yet")
            }
            proto::ProposalPart::ProposalCommitment(q) => {
                dto::ProposalPart::ProposalCommitment(Box::new(dto::ProposalCommitment {
                    block_number: q.block_number,
                    parent_commitment: q.parent_commitment.0.into(),
                    builder: q.builder.0.into(),
                    timestamp: q.timestamp,
                    protocol_version: q.protocol_version,
                    old_state_root: q.old_state_root.0.into(),
                    version_constant_commitment: q.version_constant_commitment.0.into(),
                    state_diff_commitment: q.state_diff_commitment.0.into(),
                    transaction_commitment: q.transaction_commitment.0.into(),
                    event_commitment: q.event_commitment.0.into(),
                    receipt_commitment: q.receipt_commitment.0.into(),
                    concatenated_counts: q.concatenated_counts.into(),
                    l1_gas_price_fri: q.l1_gas_price_fri,
                    l1_data_gas_price_fri: q.l1_data_gas_price_fri,
                    l2_gas_price_fri: q.l2_gas_price_fri,
                    l2_gas_used: q.l2_gas_used,
                    next_l2_gas_price_fri: q.next_l2_gas_price_fri,
                    l1_da_mode: u8::try_into_dto(q.l1_da_mode)?,
                }))
            }
        };
        Ok(r)
    }
}

impl TryIntoDto<proto::Transaction> for dto::TransactionWithClass {
    fn try_into_dto(tx: proto::Transaction) -> anyhow::Result<dto::TransactionWithClass> {
        let proto::Transaction {
            txn,
            transaction_hash,
        } = tx;
        Ok(dto::TransactionWithClass {
            variant: dto::TransactionVariantWithClass::try_into_dto(txn)?,
            hash: transaction_hash.0.into(),
        })
    }
}

impl TryIntoDto<proto::TransactionVariant> for dto::TransactionVariantWithClass {
    fn try_into_dto(
        tx: proto::TransactionVariant,
    ) -> anyhow::Result<dto::TransactionVariantWithClass> {
        let res = match tx {
            proto::TransactionVariant::DeclareV3(dcl) => {
                dto::TransactionVariantWithClass::Declare(dto::DeclareTransactionWithClass {
                    declare_transaction: DeclareTransactionV4::try_into_dto(dcl.common)?,
                    class: dto::Cairo1Class::try_into_dto(dcl.class)?,
                })
            }
            proto::TransactionVariant::DeployAccountV3(dpl) => {
                dto::TransactionVariantWithClass::DeployAccount(
                    DeployAccountTransactionV4::try_into_dto(dpl)?,
                )
            }
            proto::TransactionVariant::InvokeV3(inv) => {
                dto::TransactionVariantWithClass::Invoke(InvokeTransactionV4::try_into_dto(inv)?)
            }
            proto::TransactionVariant::L1HandlerV0(h) => {
                dto::TransactionVariantWithClass::L1Handler(L1HandlerTransactionV0::try_into_dto(
                    h,
                )?)
            }
        };
        Ok(res)
    }
}

impl TryIntoDto<p2p_proto::transaction::DeclareV3Common> for DeclareTransactionV4 {
    fn try_into_dto(
        dc: p2p_proto::transaction::DeclareV3Common,
    ) -> anyhow::Result<DeclareTransactionV4> {
        let res = DeclareTransactionV4 {
            class_hash: Default::default(), // not used
            nonce: dc.nonce.into(),
            nonce_data_availability_mode: DataAvailabilityMode::try_into_dto(
                dc.nonce_data_availability_mode,
            )?,
            fee_data_availability_mode: DataAvailabilityMode::try_into_dto(
                dc.fee_data_availability_mode,
            )?,
            resource_bounds: ResourceBoundsV1::try_into_dto(dc.resource_bounds)?,
            tip: pathfinder_common::Tip(dc.tip),
            paymaster_data: dc.paymaster_data.into_iter().map(|e| e.into()).collect(),
            signature: dc.signature.parts.into_iter().map(|e| e.into()).collect(),
            account_deployment_data: dc
                .account_deployment_data
                .into_iter()
                .map(|e| e.into())
                .collect(),
            sender_address: dc.sender.0.into(),
            compiled_class_hash: dc.compiled_class_hash.0.into(),
        };
        Ok(res)
    }
}

impl TryIntoDto<p2p_proto::transaction::DeployAccountV3> for DeployAccountTransactionV4 {
    fn try_into_dto(
        dp: p2p_proto::transaction::DeployAccountV3,
    ) -> anyhow::Result<DeployAccountTransactionV4> {
        let res = DeployAccountTransactionV4 {
            sender_address: Default::default(), // not used
            signature: dp.signature.parts.into_iter().map(|e| e.into()).collect(),
            nonce: dp.nonce.into(),
            nonce_data_availability_mode: DataAvailabilityMode::try_into_dto(
                dp.nonce_data_availability_mode,
            )?,
            fee_data_availability_mode: DataAvailabilityMode::try_into_dto(
                dp.fee_data_availability_mode,
            )?,
            resource_bounds: ResourceBoundsV1::try_into_dto(dp.resource_bounds)?,
            tip: pathfinder_common::Tip(dp.tip),
            paymaster_data: dp.paymaster_data.into_iter().map(|e| e.into()).collect(),
            contract_address_salt: dp.address_salt.into(),
            constructor_calldata: dp.calldata.into_iter().map(|e| e.into()).collect(),
            class_hash: dp.class_hash.0.into(),
        };
        Ok(res)
    }
}

impl TryIntoDto<p2p_proto::transaction::InvokeV3> for InvokeTransactionV4 {
    fn try_into_dto(inv: p2p_proto::transaction::InvokeV3) -> anyhow::Result<InvokeTransactionV4> {
        let res = InvokeTransactionV4 {
            signature: inv.signature.parts.into_iter().map(|e| e.into()).collect(),
            nonce: inv.nonce.into(),
            nonce_data_availability_mode: DataAvailabilityMode::try_into_dto(
                inv.nonce_data_availability_mode,
            )?,
            fee_data_availability_mode: DataAvailabilityMode::try_into_dto(
                inv.fee_data_availability_mode,
            )?,
            resource_bounds: ResourceBoundsV1::try_into_dto(inv.resource_bounds)?,
            tip: pathfinder_common::Tip(inv.tip),
            paymaster_data: inv.paymaster_data.into_iter().map(|e| e.into()).collect(),
            account_deployment_data: inv
                .account_deployment_data
                .into_iter()
                .map(|e| e.into())
                .collect(),
            calldata: inv.calldata.into_iter().map(|e| e.into()).collect(),
            sender_address: inv.sender.0.into(),
        };
        Ok(res)
    }
}

impl TryIntoDto<p2p_proto::transaction::L1HandlerV0> for L1HandlerTransactionV0 {
    fn try_into_dto(
        h: p2p_proto::transaction::L1HandlerV0,
    ) -> anyhow::Result<L1HandlerTransactionV0> {
        let p2p_proto::transaction::L1HandlerV0 {
            nonce,
            address,
            entry_point_selector,
            calldata,
        } = h;
        let res = L1HandlerTransactionV0 {
            contract_address: address.0.into(),
            entry_point_selector: entry_point_selector.into(),
            nonce: nonce.into(),
            calldata: calldata.into_iter().map(|e| e.into()).collect(),
        };
        Ok(res)
    }
}

impl TryIntoDto<p2p_proto::common::VolitionDomain> for DataAvailabilityMode {
    fn try_into_dto(vd: p2p_proto::common::VolitionDomain) -> anyhow::Result<DataAvailabilityMode> {
        let res = match vd {
            p2p_proto::common::VolitionDomain::L1 => DataAvailabilityMode::L1,
            p2p_proto::common::VolitionDomain::L2 => DataAvailabilityMode::L2,
        };
        Ok(res)
    }
}

impl TryIntoDto<p2p_proto::transaction::ResourceBounds> for ResourceBoundsV1 {
    fn try_into_dto(
        rb: p2p_proto::transaction::ResourceBounds,
    ) -> anyhow::Result<ResourceBoundsV1> {
        let p2p_proto::transaction::ResourceBounds {
            l1_gas,
            l2_gas,
            l1_data_gas,
        } = rb;
        let res = ResourceBoundsV1 {
            l1_gas: ResourceBound::try_into_dto(l1_gas)?,
            l2_gas: ResourceBound::try_into_dto(l2_gas)?,
            l1_data_gas: match l1_data_gas {
                Some(dg) => Some(ResourceBound::try_into_dto(dg)?),
                None => None,
            },
        };
        Ok(res)
    }
}

impl TryIntoDto<p2p_proto::transaction::ResourceLimits> for ResourceBound {
    fn try_into_dto(rl: p2p_proto::transaction::ResourceLimits) -> anyhow::Result<ResourceBound> {
        let p2p_proto::transaction::ResourceLimits {
            max_amount,
            max_price_per_unit,
        } = rl;
        let res = ResourceBound {
            max_amount: pathfinder_common::ResourceAmount(max_amount.try_into()?),
            max_price_per_unit: pathfinder_common::ResourcePricePerUnit(
                max_price_per_unit.try_into()?,
            ),
        };
        Ok(res)
    }
}

impl TryIntoDto<p2p_proto::class::Cairo1Class> for dto::Cairo1Class {
    fn try_into_dto(cls: p2p_proto::class::Cairo1Class) -> anyhow::Result<dto::Cairo1Class> {
        let p2p_proto::class::Cairo1Class {
            abi,
            entry_points,
            program,
            contract_class_version,
        } = cls;
        let res = dto::Cairo1Class {
            abi,
            entry_points: dto::Cairo1EntryPoints::try_into_dto(entry_points)?,
            program: program.into_iter().map(|e| e.into()).collect(),
            contract_class_version,
        };
        Ok(res)
    }
}

impl TryIntoDto<p2p_proto::class::Cairo1EntryPoints> for dto::Cairo1EntryPoints {
    fn try_into_dto(
        eps: p2p_proto::class::Cairo1EntryPoints,
    ) -> anyhow::Result<dto::Cairo1EntryPoints> {
        let p2p_proto::class::Cairo1EntryPoints {
            externals,
            l1_handlers,
            constructors,
        } = eps;
        let res = dto::Cairo1EntryPoints {
            externals: externals
                .into_iter()
                .map(dto::SierraEntryPoint::try_into_dto)
                .collect::<Result<Vec<dto::SierraEntryPoint>, _>>()?,
            l1_handlers: l1_handlers
                .into_iter()
                .map(dto::SierraEntryPoint::try_into_dto)
                .collect::<Result<Vec<dto::SierraEntryPoint>, _>>()?,
            constructors: constructors
                .into_iter()
                .map(dto::SierraEntryPoint::try_into_dto)
                .collect::<Result<Vec<dto::SierraEntryPoint>, _>>()?,
        };
        Ok(res)
    }
}

impl TryIntoDto<p2p_proto::class::SierraEntryPoint> for dto::SierraEntryPoint {
    fn try_into_dto(
        ep: p2p_proto::class::SierraEntryPoint,
    ) -> anyhow::Result<dto::SierraEntryPoint> {
        let p2p_proto::class::SierraEntryPoint { index, selector } = ep;
        let res = dto::SierraEntryPoint {
            index,
            selector: selector.into(),
        };
        Ok(res)
    }
}

impl TryIntoDto<p2p_proto::common::L1DataAvailabilityMode> for u8 {
    fn try_into_dto(da: p2p_proto::common::L1DataAvailabilityMode) -> anyhow::Result<u8> {
        let res = match da {
            p2p_proto::common::L1DataAvailabilityMode::Calldata => 0,
            p2p_proto::common::L1DataAvailabilityMode::Blob => 1,
        };
        Ok(res)
    }
}

impl IntoModel<FinalizedBlock> for dto::FinalizedBlock {
    fn into_model(self) -> FinalizedBlock {
        let dto::FinalizedBlock {
            header,
            state_update,
            transactions_and_receipts,
            events,
        } = self;
        FinalizedBlock {
            header: header.into_model(),
            state_update: state_update.into_model(),
            transactions_and_receipts: transactions_and_receipts
                .into_iter()
                .map(|(t, r)| (t.into(), r.into_model()))
                .collect(),
            events,
        }
    }
}

impl IntoModel<pathfinder_common::BlockHeader> for dto::BlockHeader {
    fn into_model(self) -> pathfinder_common::BlockHeader {
        let dto::BlockHeader {
            hash,
            parent_hash,
            number,
            timestamp,
            eth_l1_gas_price,
            strk_l1_gas_price,
            eth_l1_data_gas_price,
            strk_l1_data_gas_price,
            eth_l2_gas_price,
            strk_l2_gas_price,
            sequencer_address,
            starknet_version,
            event_commitment,
            state_commitment,
            transaction_commitment,
            transaction_count,
            event_count,
            receipt_commitment,
            state_diff_commitment,
            state_diff_length,
            l1_da_mode,
        } = self;
        pathfinder_common::BlockHeader {
            hash,
            parent_hash,
            number,
            timestamp,
            eth_l1_gas_price,
            strk_l1_gas_price,
            eth_l1_data_gas_price,
            strk_l1_data_gas_price,
            eth_l2_gas_price,
            strk_l2_gas_price,
            sequencer_address,
            starknet_version: pathfinder_common::StarknetVersion::from_u32(starknet_version),
            event_commitment,
            state_commitment,
            transaction_commitment,
            transaction_count: transaction_count as usize,
            event_count: event_count as usize,
            l1_da_mode,
            receipt_commitment,
            state_diff_commitment,
            state_diff_length,
        }
    }
}

impl IntoModel<state_update::StateUpdateData> for dto::StateUpdateData {
    fn into_model(self) -> state_update::StateUpdateData {
        let dto::StateUpdateData {
            contract_updates,
            system_contract_updates,
            declared_cairo_classes,
            declared_sierra_classes,
        } = self;
        state_update::StateUpdateData {
            contract_updates: contract_updates
                .line
                .into_iter()
                .map(|(k, v)| (k, v.into_model()))
                .collect(),
            system_contract_updates: system_contract_updates
                .line
                .into_iter()
                .map(|(k, v)| (k, v.into_model()))
                .collect(),
            declared_cairo_classes: declared_cairo_classes.into_iter().collect(),
            declared_sierra_classes: declared_sierra_classes.line.into_iter().collect(),
            // TODO: add migrated compiled classes to consensus protocol
            migrated_compiled_classes: Default::default(),
        }
    }
}

impl IntoModel<state_update::ContractUpdate> for dto::ContractUpdate {
    fn into_model(self) -> state_update::ContractUpdate {
        let dto::ContractUpdate {
            storage,
            class,
            nonce,
        } = self;
        state_update::ContractUpdate {
            storage: storage.line.into_iter().collect(),
            class: class.map(|c| c.into_model()),
            nonce,
        }
    }
}

impl IntoModel<state_update::SystemContractUpdate> for dto::SystemContractUpdate {
    fn into_model(self) -> state_update::SystemContractUpdate {
        let dto::SystemContractUpdate { storage } = self;
        state_update::SystemContractUpdate {
            storage: storage.line.into_iter().collect(),
        }
    }
}

impl IntoModel<state_update::ContractClassUpdate> for dto::ContractClassUpdate {
    fn into_model(self) -> state_update::ContractClassUpdate {
        match self {
            dto::ContractClassUpdate::Deploy(c) => state_update::ContractClassUpdate::Deploy(c),
            dto::ContractClassUpdate::Replace(c) => state_update::ContractClassUpdate::Replace(c),
        }
    }
}

impl IntoModel<receipt::Receipt> for dto::Receipt {
    fn into_model(self) -> receipt::Receipt {
        let dto::Receipt {
            actual_fee,
            execution_resources,
            l2_to_l1_messages,
            execution_status,
            transaction_hash,
            transaction_index,
        } = self;
        receipt::Receipt {
            actual_fee,
            execution_resources: execution_resources.into_model(),
            l2_to_l1_messages: l2_to_l1_messages
                .into_iter()
                .map(|m| m.into_model())
                .collect(),
            execution_status: execution_status.into_model(),
            transaction_hash,
            transaction_index,
        }
    }
}

impl IntoModel<receipt::L2ToL1Message> for dto::L2ToL1Message {
    fn into_model(self) -> receipt::L2ToL1Message {
        let dto::L2ToL1Message {
            from_address,
            payload,
            to_address,
        } = self;
        receipt::L2ToL1Message {
            from_address,
            payload,
            to_address,
        }
    }
}

impl IntoModel<receipt::ExecutionResources> for dto::ExecutionResources {
    fn into_model(self) -> receipt::ExecutionResources {
        let dto::ExecutionResources {
            builtins,
            n_steps,
            n_memory_holes,
            data_availability,
            total_gas_consumed,
            l2_gas,
        } = self;
        receipt::ExecutionResources {
            builtins: builtins.into_model(),
            n_steps,
            n_memory_holes,
            data_availability: data_availability.into_model(),
            total_gas_consumed: total_gas_consumed.into_model(),
            l2_gas: receipt::L2Gas(l2_gas),
        }
    }
}

impl IntoModel<receipt::L1Gas> for dto::L1Gas {
    fn into_model(self) -> receipt::L1Gas {
        let dto::L1Gas {
            l1_gas,
            l1_data_gas,
        } = self;
        receipt::L1Gas {
            l1_gas,
            l1_data_gas,
        }
    }
}

impl IntoModel<receipt::BuiltinCounters> for dto::BuiltinCounters {
    fn into_model(self) -> receipt::BuiltinCounters {
        let dto::BuiltinCounters {
            output,
            pedersen,
            range_check,
            ecdsa,
            bitwise,
            ec_op,
            keccak,
            poseidon,
            segment_arena,
            add_mod,
            mul_mod,
            range_check96,
        } = self;
        receipt::BuiltinCounters {
            output,
            pedersen,
            range_check,
            ecdsa,
            bitwise,
            ec_op,
            keccak,
            poseidon,
            segment_arena,
            add_mod,
            mul_mod,
            range_check96,
        }
    }
}

impl IntoModel<receipt::ExecutionStatus> for dto::ExecutionStatus {
    fn into_model(self) -> receipt::ExecutionStatus {
        match self {
            dto::ExecutionStatus::Succeeded => receipt::ExecutionStatus::Succeeded,
            dto::ExecutionStatus::Reverted { reason } => {
                receipt::ExecutionStatus::Reverted { reason }
            }
        }
    }
}

impl TryIntoDto<FinalizedBlock> for dto::FinalizedBlock {
    fn try_into_dto(b: FinalizedBlock) -> anyhow::Result<dto::FinalizedBlock> {
        let FinalizedBlock {
            header,
            state_update,
            transactions_and_receipts,
            events,
        } = b;
        let res = dto::FinalizedBlock {
            header: dto::BlockHeader::try_into_dto(header)?,
            state_update: dto::StateUpdateData::try_into_dto(state_update)?,
            transactions_and_receipts: transactions_and_receipts
                .into_iter()
                .map(|(tx, rcpt)| {
                    let dtx = TransactionV2::from(&tx);
                    let drcpt = dto::Receipt::try_into_dto(rcpt)?;
                    anyhow::Ok((dtx, drcpt))
                })
                .collect::<Result<Vec<(TransactionV2, dto::Receipt)>, _>>()?,
            events,
        };
        Ok(res)
    }
}

impl TryIntoDto<pathfinder_common::BlockHeader> for dto::BlockHeader {
    fn try_into_dto(h: pathfinder_common::BlockHeader) -> anyhow::Result<dto::BlockHeader> {
        let pathfinder_common::BlockHeader {
            hash,
            parent_hash,
            number,
            timestamp,
            eth_l1_gas_price,
            strk_l1_gas_price,
            eth_l1_data_gas_price,
            strk_l1_data_gas_price,
            eth_l2_gas_price,
            strk_l2_gas_price,
            sequencer_address,
            starknet_version,
            event_commitment,
            state_commitment,
            transaction_commitment,
            transaction_count,
            event_count,
            l1_da_mode,
            receipt_commitment,
            state_diff_commitment,
            state_diff_length,
        } = h;
        let res = dto::BlockHeader {
            hash,
            parent_hash,
            number,
            timestamp,
            eth_l1_gas_price,
            strk_l1_gas_price,
            eth_l1_data_gas_price,
            strk_l1_data_gas_price,
            eth_l2_gas_price,
            strk_l2_gas_price,
            sequencer_address,
            starknet_version: starknet_version.as_u32(),
            event_commitment,
            state_commitment,
            transaction_commitment,
            transaction_count: transaction_count.try_into()?,
            event_count: event_count.try_into()?,
            receipt_commitment,
            state_diff_commitment,
            state_diff_length,
            l1_da_mode,
        };
        Ok(res)
    }
}

impl TryIntoDto<state_update::StateUpdateData> for dto::StateUpdateData {
    fn try_into_dto(u: state_update::StateUpdateData) -> anyhow::Result<dto::StateUpdateData> {
        let state_update::StateUpdateData {
            contract_updates,
            system_contract_updates,
            declared_cairo_classes,
            declared_sierra_classes,
            migrated_compiled_classes: _,
        } = u;
        let res = dto::StateUpdateData {
            contract_updates:
                dto::LinearMap {
                    line:
                        contract_updates
                            .into_iter()
                            .map(|(a, u)| anyhow::Ok((a, dto::ContractUpdate::try_into_dto(u)?)))
                            .collect::<Result<
                                Vec<(pathfinder_common::ContractAddress, dto::ContractUpdate)>,
                                _,
                            >>()?,
                },
            system_contract_updates: dto::LinearMap {
                line: system_contract_updates
                    .into_iter()
                    .map(|(a, u)| anyhow::Ok((a, dto::SystemContractUpdate::try_into_dto(u)?)))
                    .collect::<Result<
                        Vec<(
                            pathfinder_common::ContractAddress,
                            dto::SystemContractUpdate,
                        )>,
                        _,
                    >>()?,
            },
            declared_cairo_classes: declared_cairo_classes.into_iter().collect(),
            declared_sierra_classes: dto::LinearMap {
                line: declared_sierra_classes.into_iter().collect(),
            },
        };
        Ok(res)
    }
}

impl TryIntoDto<state_update::ContractUpdate> for dto::ContractUpdate {
    fn try_into_dto(u: state_update::ContractUpdate) -> anyhow::Result<dto::ContractUpdate> {
        let state_update::ContractUpdate {
            storage,
            class,
            nonce,
        } = u;
        let res = dto::ContractUpdate {
            storage: dto::LinearMap {
                line: storage.into_iter().collect(),
            },
            class: class
                .map(dto::ContractClassUpdate::try_into_dto)
                .transpose()?,
            nonce,
        };
        Ok(res)
    }
}

impl TryIntoDto<state_update::SystemContractUpdate> for dto::SystemContractUpdate {
    fn try_into_dto(
        u: state_update::SystemContractUpdate,
    ) -> anyhow::Result<dto::SystemContractUpdate> {
        let state_update::SystemContractUpdate { storage } = u;
        let res = dto::SystemContractUpdate {
            storage: dto::LinearMap {
                line: storage.into_iter().collect(),
            },
        };
        Ok(res)
    }
}

impl TryIntoDto<state_update::ContractClassUpdate> for dto::ContractClassUpdate {
    fn try_into_dto(
        u: state_update::ContractClassUpdate,
    ) -> anyhow::Result<dto::ContractClassUpdate> {
        let res = match u {
            state_update::ContractClassUpdate::Deploy(c) => dto::ContractClassUpdate::Deploy(c),
            state_update::ContractClassUpdate::Replace(c) => dto::ContractClassUpdate::Replace(c),
        };
        Ok(res)
    }
}

impl TryIntoDto<receipt::Receipt> for dto::Receipt {
    fn try_into_dto(r: receipt::Receipt) -> anyhow::Result<dto::Receipt> {
        let receipt::Receipt {
            actual_fee,
            execution_resources,
            l2_to_l1_messages,
            execution_status,
            transaction_hash,
            transaction_index,
        } = r;
        let res = dto::Receipt {
            actual_fee,
            execution_resources: dto::ExecutionResources::try_into_dto(execution_resources)?,
            l2_to_l1_messages: l2_to_l1_messages
                .into_iter()
                .map(dto::L2ToL1Message::try_into_dto)
                .collect::<Result<Vec<dto::L2ToL1Message>, _>>()?,
            execution_status: dto::ExecutionStatus::try_into_dto(execution_status)?,
            transaction_hash,
            transaction_index,
        };
        Ok(res)
    }
}

impl TryIntoDto<receipt::L2ToL1Message> for dto::L2ToL1Message {
    fn try_into_dto(m: receipt::L2ToL1Message) -> anyhow::Result<dto::L2ToL1Message> {
        let receipt::L2ToL1Message {
            from_address,
            payload,
            to_address,
        } = m;
        let res = dto::L2ToL1Message {
            from_address,
            payload,
            to_address,
        };
        Ok(res)
    }
}

impl TryIntoDto<receipt::ExecutionResources> for dto::ExecutionResources {
    fn try_into_dto(er: receipt::ExecutionResources) -> anyhow::Result<dto::ExecutionResources> {
        let receipt::ExecutionResources {
            builtins,
            n_steps,
            n_memory_holes,
            data_availability,
            total_gas_consumed,
            l2_gas,
        } = er;
        let res = dto::ExecutionResources {
            builtins: dto::BuiltinCounters::try_into_dto(builtins)?,
            n_steps,
            n_memory_holes,
            data_availability: dto::L1Gas::try_into_dto(data_availability)?,
            total_gas_consumed: dto::L1Gas::try_into_dto(total_gas_consumed)?,
            l2_gas: l2_gas.0,
        };
        Ok(res)
    }
}

impl TryIntoDto<receipt::L1Gas> for dto::L1Gas {
    fn try_into_dto(g: receipt::L1Gas) -> anyhow::Result<dto::L1Gas> {
        let receipt::L1Gas {
            l1_gas,
            l1_data_gas,
        } = g;
        let res = dto::L1Gas {
            l1_gas,
            l1_data_gas,
        };
        Ok(res)
    }
}

impl TryIntoDto<receipt::BuiltinCounters> for dto::BuiltinCounters {
    fn try_into_dto(bc: receipt::BuiltinCounters) -> anyhow::Result<dto::BuiltinCounters> {
        let receipt::BuiltinCounters {
            output,
            pedersen,
            range_check,
            ecdsa,
            bitwise,
            ec_op,
            keccak,
            poseidon,
            segment_arena,
            add_mod,
            mul_mod,
            range_check96,
        } = bc;
        let res = dto::BuiltinCounters {
            output,
            pedersen,
            range_check,
            ecdsa,
            bitwise,
            ec_op,
            keccak,
            poseidon,
            segment_arena,
            add_mod,
            mul_mod,
            range_check96,
        };
        Ok(res)
    }
}

impl TryIntoDto<receipt::ExecutionStatus> for dto::ExecutionStatus {
    fn try_into_dto(e: receipt::ExecutionStatus) -> anyhow::Result<dto::ExecutionStatus> {
        let res = match e {
            receipt::ExecutionStatus::Succeeded => dto::ExecutionStatus::Succeeded,
            receipt::ExecutionStatus::Reverted { reason } => {
                dto::ExecutionStatus::Reverted { reason }
            }
        };
        Ok(res)
    }
}
