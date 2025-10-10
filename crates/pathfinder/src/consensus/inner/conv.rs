use p2p_proto::consensus as proto;
use pathfinder_storage::{
    DataAvailabilityMode,
    DeclareTransactionV4,
    DeployAccountTransactionV4,
    InvokeTransactionV4,
    L1HandlerTransactionV0,
    ResourceBound,
    ResourceBoundsV1,
};

use crate::consensus::inner::dto;

/// Convert a DTO type to a protobuf type
pub trait IntoProto<T> {
    fn into_proto(self) -> T;
}

/// Convert a protobuf type to a DTO, fallibly
pub trait TryIntoDto<T> {
    fn try_into_dto(dto: T) -> anyhow::Result<Self>
    where
        Self: Sized;
}

impl IntoProto<proto::ProposalPart> for dto::ProposalPart {
    fn into_proto(self) -> proto::ProposalPart {
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
                l1_da_mode: p.l1_da_mode.into_proto(),
            }),
            dto::ProposalPart::TransactionBatch(batch) => proto::ProposalPart::TransactionBatch(
                batch.into_iter().map(|t| t.into_proto()).collect(),
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
                    l1_da_mode: p.l1_da_mode.into_proto(),
                })
            }
        }
    }
}

impl IntoProto<proto::Transaction> for dto::TransactionWithClass {
    fn into_proto(self) -> proto::Transaction {
        let dto::TransactionWithClass { variant, hash } = self;
        proto::Transaction {
            txn: variant.into_proto(),
            transaction_hash: p2p_proto::common::Hash(hash.into()),
        }
    }
}

impl IntoProto<proto::TransactionVariant> for dto::TransactionVariantWithClass {
    fn into_proto(self) -> proto::TransactionVariant {
        match self {
            dto::TransactionVariantWithClass::Declare(dcl) => {
                proto::TransactionVariant::DeclareV3(p2p_proto::transaction::DeclareV3WithClass {
                    common: dcl.declare_transaction.into_proto(),
                    class: dcl.class.into_proto(),
                })
            }
            dto::TransactionVariantWithClass::DeployAccount(dpl) => {
                proto::TransactionVariant::DeployAccountV3(dpl.into_proto())
            }
            dto::TransactionVariantWithClass::Invoke(inv) => {
                proto::TransactionVariant::InvokeV3(inv.into_proto())
            }
            dto::TransactionVariantWithClass::L1Handler(h) => {
                proto::TransactionVariant::L1HandlerV0(h.into_proto())
            }
        }
    }
}

impl IntoProto<p2p_proto::transaction::DeclareV3Common> for DeclareTransactionV4 {
    fn into_proto(self) -> p2p_proto::transaction::DeclareV3Common {
        p2p_proto::transaction::DeclareV3Common {
            sender: p2p_proto::common::Address(self.sender_address.into()),
            signature: p2p_proto::transaction::AccountSignature {
                parts: self.signature.into_iter().map(|s| s.into()).collect(),
            },
            nonce: self.nonce.into(),
            compiled_class_hash: p2p_proto::common::Hash(self.compiled_class_hash.into()),
            resource_bounds: self.resource_bounds.into_proto(),
            tip: self.tip.0,
            paymaster_data: self.paymaster_data.into_iter().map(|e| e.into()).collect(),
            account_deployment_data: self
                .account_deployment_data
                .into_iter()
                .map(|e| e.into())
                .collect(),
            nonce_data_availability_mode: self.nonce_data_availability_mode.into_proto(),
            fee_data_availability_mode: self.fee_data_availability_mode.into_proto(),
        }
    }
}

impl IntoProto<p2p_proto::transaction::DeployAccountV3> for DeployAccountTransactionV4 {
    fn into_proto(self) -> p2p_proto::transaction::DeployAccountV3 {
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
            resource_bounds: self.resource_bounds.into_proto(),
            tip: self.tip.0,
            paymaster_data: self.paymaster_data.into_iter().map(|e| e.into()).collect(),
            nonce_data_availability_mode: self.nonce_data_availability_mode.into_proto(),
            fee_data_availability_mode: self.fee_data_availability_mode.into_proto(),
        }
    }
}

impl IntoProto<p2p_proto::transaction::InvokeV3> for InvokeTransactionV4 {
    fn into_proto(self) -> p2p_proto::transaction::InvokeV3 {
        p2p_proto::transaction::InvokeV3 {
            sender: p2p_proto::common::Address(self.sender_address.into()),
            signature: p2p_proto::transaction::AccountSignature {
                parts: self.signature.into_iter().map(|s| s.into()).collect(),
            },
            calldata: self.calldata.into_iter().map(|e| e.into()).collect(),
            resource_bounds: self.resource_bounds.into_proto(),
            tip: self.tip.0,
            paymaster_data: self.paymaster_data.into_iter().map(|e| e.into()).collect(),
            account_deployment_data: self
                .account_deployment_data
                .into_iter()
                .map(|e| e.into())
                .collect(),
            nonce_data_availability_mode: self.nonce_data_availability_mode.into_proto(),
            fee_data_availability_mode: self.fee_data_availability_mode.into_proto(),
            nonce: self.nonce.into(),
        }
    }
}

impl IntoProto<p2p_proto::transaction::L1HandlerV0> for L1HandlerTransactionV0 {
    fn into_proto(self) -> p2p_proto::transaction::L1HandlerV0 {
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

impl IntoProto<p2p_proto::transaction::ResourceBounds> for ResourceBoundsV1 {
    fn into_proto(self) -> p2p_proto::transaction::ResourceBounds {
        let ResourceBoundsV1 {
            l1_gas,
            l2_gas,
            l1_data_gas,
        } = self;
        p2p_proto::transaction::ResourceBounds {
            l1_gas: l1_gas.into_proto(),
            l2_gas: l2_gas.into_proto(),
            l1_data_gas: l1_data_gas.map(|r| r.into_proto()),
        }
    }
}

impl IntoProto<p2p_proto::transaction::ResourceLimits> for ResourceBound {
    fn into_proto(self) -> p2p_proto::transaction::ResourceLimits {
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

impl IntoProto<p2p_proto::common::VolitionDomain> for DataAvailabilityMode {
    fn into_proto(self) -> p2p_proto::common::VolitionDomain {
        match self {
            DataAvailabilityMode::L1 => p2p_proto::common::VolitionDomain::L1,
            DataAvailabilityMode::L2 => p2p_proto::common::VolitionDomain::L2,
        }
    }
}

impl IntoProto<p2p_proto::class::Cairo1Class> for dto::Cairo1Class {
    fn into_proto(self) -> p2p_proto::class::Cairo1Class {
        p2p_proto::class::Cairo1Class {
            abi: self.abi,
            entry_points: self.entry_points.into_proto(),
            program: self.program.into_iter().map(|e| e.into()).collect(),
            contract_class_version: self.contract_class_version,
        }
    }
}

impl IntoProto<p2p_proto::class::Cairo1EntryPoints> for dto::Cairo1EntryPoints {
    fn into_proto(self) -> p2p_proto::class::Cairo1EntryPoints {
        let dto::Cairo1EntryPoints {
            externals,
            l1_handlers,
            constructors,
        } = self;
        p2p_proto::class::Cairo1EntryPoints {
            externals: externals.into_iter().map(|e| e.into_proto()).collect(),
            l1_handlers: l1_handlers.into_iter().map(|e| e.into_proto()).collect(),
            constructors: constructors.into_iter().map(|e| e.into_proto()).collect(),
        }
    }
}

impl IntoProto<p2p_proto::class::SierraEntryPoint> for dto::SierraEntryPoint {
    fn into_proto(self) -> p2p_proto::class::SierraEntryPoint {
        let dto::SierraEntryPoint { index, selector } = self;
        p2p_proto::class::SierraEntryPoint {
            index,
            selector: selector.into(),
        }
    }
}

impl IntoProto<p2p_proto::common::L1DataAvailabilityMode> for u8 {
    fn into_proto(self) -> p2p_proto::common::L1DataAvailabilityMode {
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
