//! We don't want to introduce circular dependencies between crates and we need
//! to work around for the orphan rule - implement conversion fns for types
//! ourside our crate.

use std::borrow::Cow;
use std::io::Read;

use anyhow::Context;
use base64::prelude::*;
use p2p_proto::class::{Cairo0Class, Cairo1Class, Cairo1EntryPoints, SierraEntryPoint};
use p2p_proto::common::{Address, Hash, Hash256};
use p2p_proto::sync::receipt::execution_resources::BuiltinCounter;
use p2p_proto::sync::receipt::{
    DeclareTransactionReceipt,
    DeployAccountTransactionReceipt,
    DeployTransactionReceipt,
    EthereumAddress,
    InvokeTransactionReceipt,
    L1HandlerTransactionReceipt,
    MessageToL1,
    ReceiptCommon,
};
use p2p_proto::transaction::AccountSignature;
use pathfinder_common::class_definition::{
    Cairo,
    SelectorAndFunctionIndex,
    SelectorAndOffset,
    Sierra,
};
use pathfinder_common::event::Event;
use pathfinder_common::prelude::*;
use pathfinder_common::receipt::{
    BuiltinCounters,
    ExecutionResources,
    ExecutionStatus,
    L1Gas,
    L2Gas,
    L2ToL1Message,
    Receipt,
};
use pathfinder_common::transaction::{
    DataAvailabilityMode,
    DeclareTransactionV0V1,
    DeclareTransactionV2,
    DeclareTransactionV3,
    DeployAccountTransactionV1,
    DeployAccountTransactionV3,
    DeployTransactionV0,
    DeployTransactionV1,
    InvokeTransactionV0,
    InvokeTransactionV1,
    InvokeTransactionV3,
    L1HandlerTransaction,
    ResourceBound,
    ResourceBounds,
    Transaction,
    TransactionVariant,
};
use pathfinder_common::ProofFactElem;
use pathfinder_crypto::Felt;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// Convert a pathfinder common (ie. core) type to a p2p dto type
pub trait ToDto<T> {
    fn to_dto(self) -> T;
}

/// Convert a p2p dto type to a pathfinder common (ie. core) type
pub trait FromDto<T> {
    fn from_dto(dto: T) -> Self;
}

/// Fallible version of [`FromDto`]
pub trait TryFromDto<T> {
    fn try_from_dto(dto: T) -> anyhow::Result<Self>
    where
        Self: Sized;
}

impl ToDto<p2p_proto::sync::header::SignedBlockHeader> for SignedBlockHeader {
    fn to_dto(self) -> p2p_proto::sync::header::SignedBlockHeader {
        use p2p_proto::sync::header as proto;

        proto::SignedBlockHeader {
            block_hash: Hash(self.header.hash.0),
            parent_hash: Hash(self.header.parent_hash.0),
            number: self.header.number.get(),
            time: self.header.timestamp.get(),
            sequencer_address: Address(self.header.sequencer_address.0),
            state_root: Hash(self.header.state_commitment.0),
            state_diff_commitment: p2p_proto::sync::common::StateDiffCommitment {
                state_diff_length: self.header.state_diff_length,
                root: Hash(self.header.state_diff_commitment.0),
            },
            transactions: p2p_proto::common::Patricia {
                n_leaves: self
                    .header
                    .transaction_count
                    .try_into()
                    .expect("ptr size is 64 bits"),
                root: Hash(self.header.transaction_commitment.0),
            },
            events: p2p_proto::common::Patricia {
                n_leaves: self
                    .header
                    .event_count
                    .try_into()
                    .expect("ptr size is 64 bits"),
                root: Hash(self.header.event_commitment.0),
            },
            receipts: Hash(self.header.receipt_commitment.0),
            protocol_version: self.header.starknet_version.to_string(),
            l1_gas_price_fri: self.header.strk_l1_gas_price.0,
            l1_gas_price_wei: self.header.eth_l1_gas_price.0,
            l1_data_gas_price_fri: self.header.strk_l1_data_gas_price.0,
            l1_data_gas_price_wei: self.header.eth_l1_data_gas_price.0,
            l2_gas_price_fri: Some(self.header.strk_l2_gas_price.0),
            l2_gas_price_wei: Some(self.header.eth_l2_gas_price.0),
            l1_data_availability_mode: self.header.l1_da_mode.to_dto(),
            signatures: vec![p2p_proto::common::ConsensusSignature {
                r: self.signature.r.0,
                s: self.signature.s.0,
            }],
        }
    }
}

impl ToDto<p2p_proto::sync::transaction::TransactionVariant> for TransactionVariant {
    fn to_dto(self) -> p2p_proto::sync::transaction::TransactionVariant {
        use pathfinder_common::transaction::TransactionVariant::*;

        match self {
            DeclareV0(x) => p2p_proto::sync::transaction::TransactionVariant::DeclareV0(
                p2p_proto::sync::transaction::DeclareV0WithoutClass {
                    sender: Address(x.sender_address.0),
                    max_fee: x.max_fee.0,
                    signature: AccountSignature {
                        parts: x.signature.into_iter().map(|s| s.0).collect(),
                    },
                    class_hash: Hash(x.class_hash.0),
                },
            ),
            DeclareV1(x) => p2p_proto::sync::transaction::TransactionVariant::DeclareV1(
                p2p_proto::sync::transaction::DeclareV1WithoutClass {
                    sender: Address(x.sender_address.0),
                    max_fee: x.max_fee.0,
                    signature: AccountSignature {
                        parts: x.signature.into_iter().map(|s| s.0).collect(),
                    },
                    class_hash: Hash(x.class_hash.0),
                    nonce: x.nonce.0,
                },
            ),
            DeclareV2(x) => p2p_proto::sync::transaction::TransactionVariant::DeclareV2(
                p2p_proto::sync::transaction::DeclareV2WithoutClass {
                    sender: Address(x.sender_address.0),
                    max_fee: x.max_fee.0,
                    signature: AccountSignature {
                        parts: x.signature.into_iter().map(|s| s.0).collect(),
                    },
                    class_hash: Hash(x.class_hash.0),
                    nonce: x.nonce.0,
                    compiled_class_hash: Hash(x.compiled_class_hash.0),
                },
            ),
            DeclareV3(x) => p2p_proto::sync::transaction::TransactionVariant::DeclareV3(
                p2p_proto::sync::transaction::DeclareV3WithoutClass {
                    common: p2p_proto::transaction::DeclareV3Common {
                        sender: Address(x.sender_address.0),
                        signature: AccountSignature {
                            parts: x.signature.into_iter().map(|s| s.0).collect(),
                        },
                        nonce: x.nonce.0,
                        compiled_class_hash: Hash(x.compiled_class_hash.0),
                        resource_bounds: p2p_proto::transaction::ResourceBounds {
                            l1_gas: x.resource_bounds.l1_gas.to_dto(),
                            l2_gas: x.resource_bounds.l2_gas.to_dto(),
                            l1_data_gas: x.resource_bounds.l1_data_gas.map(|g| g.to_dto()),
                        },
                        tip: x.tip.0,
                        paymaster_data: x.paymaster_data.into_iter().map(|p| p.0).collect(),
                        account_deployment_data: x
                            .account_deployment_data
                            .into_iter()
                            .map(|a| a.0)
                            .collect(),
                        nonce_data_availability_mode: x.nonce_data_availability_mode.to_dto(),
                        fee_data_availability_mode: x.fee_data_availability_mode.to_dto(),
                    },
                    class_hash: Hash(x.class_hash.0),
                },
            ),
            DeployV0(x) => p2p_proto::sync::transaction::TransactionVariant::Deploy(
                p2p_proto::sync::transaction::Deploy {
                    class_hash: Hash(x.class_hash.0),
                    address_salt: x.contract_address_salt.0,
                    calldata: x.constructor_calldata.into_iter().map(|c| c.0).collect(),
                    version: 0,
                },
            ),
            DeployV1(x) => p2p_proto::sync::transaction::TransactionVariant::Deploy(
                p2p_proto::sync::transaction::Deploy {
                    class_hash: Hash(x.class_hash.0),
                    address_salt: x.contract_address_salt.0,
                    calldata: x.constructor_calldata.into_iter().map(|c| c.0).collect(),
                    version: 1,
                },
            ),
            DeployAccountV1(x) => {
                p2p_proto::sync::transaction::TransactionVariant::DeployAccountV1(
                    p2p_proto::sync::transaction::DeployAccountV1 {
                        max_fee: x.max_fee.0,
                        signature: AccountSignature {
                            parts: x.signature.into_iter().map(|s| s.0).collect(),
                        },
                        class_hash: Hash(x.class_hash.0),
                        nonce: x.nonce.0,
                        address_salt: x.contract_address_salt.0,
                        calldata: x.constructor_calldata.into_iter().map(|c| c.0).collect(),
                    },
                )
            }
            DeployAccountV3(x) => {
                p2p_proto::sync::transaction::TransactionVariant::DeployAccountV3(
                    p2p_proto::transaction::DeployAccountV3 {
                        signature: AccountSignature {
                            parts: x.signature.into_iter().map(|s| s.0).collect(),
                        },
                        class_hash: Hash(x.class_hash.0),
                        nonce: x.nonce.0,
                        address_salt: x.contract_address_salt.0,
                        calldata: x.constructor_calldata.into_iter().map(|c| c.0).collect(),
                        resource_bounds: p2p_proto::transaction::ResourceBounds {
                            l1_gas: x.resource_bounds.l1_gas.to_dto(),
                            l2_gas: x.resource_bounds.l2_gas.to_dto(),
                            l1_data_gas: x.resource_bounds.l1_data_gas.map(|g| g.to_dto()),
                        },
                        tip: x.tip.0,
                        paymaster_data: x.paymaster_data.into_iter().map(|p| p.0).collect(),
                        nonce_data_availability_mode: x.nonce_data_availability_mode.to_dto(),
                        fee_data_availability_mode: x.fee_data_availability_mode.to_dto(),
                    },
                )
            }
            InvokeV0(x) => p2p_proto::sync::transaction::TransactionVariant::InvokeV0(
                p2p_proto::sync::transaction::InvokeV0 {
                    max_fee: x.max_fee.0,
                    signature: AccountSignature {
                        parts: x.signature.into_iter().map(|s| s.0).collect(),
                    },
                    address: Address(x.sender_address.0),
                    entry_point_selector: x.entry_point_selector.0,
                    calldata: x.calldata.into_iter().map(|c| c.0).collect(),
                },
            ),
            InvokeV1(x) => p2p_proto::sync::transaction::TransactionVariant::InvokeV1(
                p2p_proto::sync::transaction::InvokeV1 {
                    sender: Address(x.sender_address.0),
                    max_fee: x.max_fee.0,
                    signature: AccountSignature {
                        parts: x.signature.into_iter().map(|s| s.0).collect(),
                    },
                    nonce: x.nonce.0,
                    calldata: x.calldata.into_iter().map(|c| c.0).collect(),
                },
            ),
            InvokeV3(x) => p2p_proto::sync::transaction::TransactionVariant::InvokeV3(
                p2p_proto::transaction::InvokeV3 {
                    sender: Address(x.sender_address.0),
                    signature: AccountSignature {
                        parts: x.signature.into_iter().map(|s| s.0).collect(),
                    },
                    calldata: x.calldata.into_iter().map(|c| c.0).collect(),
                    resource_bounds: p2p_proto::transaction::ResourceBounds {
                        l1_gas: x.resource_bounds.l1_gas.to_dto(),
                        l2_gas: x.resource_bounds.l2_gas.to_dto(),
                        l1_data_gas: x.resource_bounds.l1_data_gas.map(|g| g.to_dto()),
                    },
                    tip: x.tip.0,
                    paymaster_data: x.paymaster_data.into_iter().map(|p| p.0).collect(),
                    account_deployment_data: x
                        .account_deployment_data
                        .into_iter()
                        .map(|a| a.0)
                        .collect(),
                    nonce_data_availability_mode: x.nonce_data_availability_mode.to_dto(),
                    fee_data_availability_mode: x.fee_data_availability_mode.to_dto(),
                    nonce: x.nonce.0,
                    proof_facts: x.proof_facts.into_iter().map(|p| p.0).collect(),
                    // Proofs are present only when adding new invoke v3 transactions, but are then
                    // not stored as part of the chain.
                    proof: vec![],
                },
            ),
            L1Handler(x) => p2p_proto::sync::transaction::TransactionVariant::L1HandlerV0(
                p2p_proto::transaction::L1HandlerV0 {
                    nonce: x.nonce.0,
                    address: Address(x.contract_address.0),
                    entry_point_selector: x.entry_point_selector.0,
                    calldata: x.calldata.into_iter().map(|c| c.0).collect(),
                },
            ),
        }
    }
}

impl ToDto<p2p_proto::sync::receipt::Receipt> for (&TransactionVariant, Receipt) {
    fn to_dto(self) -> p2p_proto::sync::receipt::Receipt {
        use p2p_proto::sync::receipt::Receipt::{
            Declare,
            Deploy,
            DeployAccount,
            Invoke,
            L1Handler,
        };
        let revert_reason = self.1.revert_reason().map(ToOwned::to_owned);
        let common = ReceiptCommon {
            actual_fee: self.1.actual_fee.0,
            price_unit: p2p_proto::sync::receipt::PriceUnit::Wei, // TODO
            messages_sent: self
                .1
                .l2_to_l1_messages
                .into_iter()
                .map(|m| MessageToL1 {
                    from_address: m.from_address.0,
                    payload: m.payload.into_iter().map(|p| p.0).collect(),
                    // FIXME: to_address is incorrect in the p2p specification and should actually
                    // be a Felt type. Once the spec is fixed, we can remove this temporary hack.
                    to_address: EthereumAddress(primitive_types::H160::from_slice(
                        &m.to_address.0.to_be_bytes()[12..],
                    )),
                })
                .collect(),
            execution_resources: {
                let e = self.1.execution_resources;
                let da = e.data_availability;
                let total = e.total_gas_consumed;
                // Assumption: the values are small enough to fit into u32
                p2p_proto::sync::receipt::ExecutionResources {
                    builtins: BuiltinCounter {
                        bitwise: e.builtins.bitwise.try_into().unwrap(),
                        ecdsa: e.builtins.ecdsa.try_into().unwrap(),
                        ec_op: e.builtins.ec_op.try_into().unwrap(),
                        pedersen: e.builtins.pedersen.try_into().unwrap(),
                        range_check: e.builtins.range_check.try_into().unwrap(),
                        poseidon: e.builtins.poseidon.try_into().unwrap(),
                        keccak: e.builtins.keccak.try_into().unwrap(),
                        output: e.builtins.output.try_into().unwrap(),
                        add_mod: e.builtins.add_mod.try_into().unwrap(),
                        mul_mod: e.builtins.mul_mod.try_into().unwrap(),
                        range_check96: e.builtins.range_check96.try_into().unwrap(),
                    },
                    steps: e.n_steps.try_into().unwrap(),
                    memory_holes: e.n_memory_holes.try_into().unwrap(),
                    l1_gas: Some(da.l1_gas.into()),
                    l1_data_gas: Some(da.l1_data_gas.into()),
                    total_l1_gas: Some(total.l1_gas.into()),
                    l2_gas: Some(e.l2_gas.0.into()),
                }
            },
            revert_reason,
        };

        use pathfinder_common::transaction::TransactionVariant;
        match &self.0 {
            TransactionVariant::DeclareV0(_)
            | TransactionVariant::DeclareV1(_)
            | TransactionVariant::DeclareV2(_)
            | TransactionVariant::DeclareV3(_) => Declare(DeclareTransactionReceipt { common }),
            TransactionVariant::DeployV0(x) => Deploy(DeployTransactionReceipt {
                common,
                contract_address: x.contract_address.0,
            }),
            TransactionVariant::DeployV1(x) => Deploy(DeployTransactionReceipt {
                common,
                contract_address: x.contract_address.0,
            }),
            TransactionVariant::DeployAccountV1(x) => {
                DeployAccount(DeployAccountTransactionReceipt {
                    common,
                    contract_address: x.contract_address.0,
                })
            }
            TransactionVariant::DeployAccountV3(x) => {
                DeployAccount(DeployAccountTransactionReceipt {
                    common,
                    contract_address: x.contract_address.0,
                })
            }
            TransactionVariant::InvokeV0(_)
            | TransactionVariant::InvokeV1(_)
            | TransactionVariant::InvokeV3(_) => Invoke(InvokeTransactionReceipt { common }),
            TransactionVariant::L1Handler(tx) => L1Handler(L1HandlerTransactionReceipt {
                common,
                msg_hash: Hash256(tx.calculate_message_hash()),
            }),
        }
    }
}

#[cfg(test)]
impl ToDto<p2p_proto::sync::receipt::Receipt>
    for (&TransactionVariant, crate::sync::client::types::Receipt)
{
    fn to_dto(self) -> p2p_proto::sync::receipt::Receipt {
        let (t, r) = self;
        (
            t,
            Receipt {
                transaction_hash: Default::default(),
                actual_fee: r.actual_fee,
                execution_resources: r.execution_resources,
                execution_status: r.execution_status,
                l2_to_l1_messages: r.l2_to_l1_messages,
                transaction_index: r.transaction_index,
            },
        )
            .to_dto()
    }
}

impl ToDto<p2p_proto::sync::event::Event> for (TransactionHash, Event) {
    fn to_dto(self) -> p2p_proto::sync::event::Event {
        p2p_proto::sync::event::Event {
            transaction_hash: p2p_proto::common::Hash(self.0 .0),
            from_address: self.1.from_address.0,
            keys: self.1.keys.into_iter().map(|k| k.0).collect(),
            data: self.1.data.into_iter().map(|d| d.0).collect(),
        }
    }
}

impl ToDto<p2p_proto::transaction::ResourceLimits> for ResourceBound {
    fn to_dto(self) -> p2p_proto::transaction::ResourceLimits {
        p2p_proto::transaction::ResourceLimits {
            max_amount: self.max_amount.0.into(),
            max_price_per_unit: self.max_price_per_unit.0.into(),
        }
    }
}

impl ToDto<p2p_proto::common::VolitionDomain> for DataAvailabilityMode {
    fn to_dto(self) -> p2p_proto::common::VolitionDomain {
        match self {
            Self::L1 => p2p_proto::common::VolitionDomain::L1,
            Self::L2 => p2p_proto::common::VolitionDomain::L2,
        }
    }
}

impl ToDto<p2p_proto::common::L1DataAvailabilityMode> for L1DataAvailabilityMode {
    fn to_dto(self) -> p2p_proto::common::L1DataAvailabilityMode {
        use p2p_proto::common::L1DataAvailabilityMode::{Blob, Calldata};
        match self {
            L1DataAvailabilityMode::Calldata => Calldata,
            L1DataAvailabilityMode::Blob => Blob,
        }
    }
}

impl TryFromDto<p2p_proto::sync::transaction::TransactionVariant> for TransactionVariant {
    /// Caller must take care to compute the contract address for deploy and
    /// deploy account transactions separately in a non-async context.
    fn try_from_dto(dto: p2p_proto::sync::transaction::TransactionVariant) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        use p2p_proto::sync::transaction::TransactionVariant::{
            DeclareV0,
            DeclareV1,
            DeclareV2,
            DeclareV3,
            Deploy,
            DeployAccountV1,
            DeployAccountV3,
            InvokeV0,
            InvokeV1,
            InvokeV3,
            L1HandlerV0,
        };
        Ok(match dto {
            DeclareV0(x) => Self::DeclareV0(DeclareTransactionV0V1 {
                class_hash: ClassHash(x.class_hash.0),
                max_fee: Fee(x.max_fee),
                nonce: TransactionNonce::ZERO,
                sender_address: ContractAddress(x.sender.0),
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
            }),
            DeclareV1(x) => Self::DeclareV1(DeclareTransactionV0V1 {
                class_hash: ClassHash(x.class_hash.0),
                max_fee: Fee(x.max_fee),
                nonce: TransactionNonce(x.nonce),
                sender_address: ContractAddress(x.sender.0),
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
            }),
            DeclareV2(x) => Self::DeclareV2(DeclareTransactionV2 {
                class_hash: ClassHash(x.class_hash.0),
                max_fee: Fee(x.max_fee),
                nonce: TransactionNonce(x.nonce),
                sender_address: ContractAddress(x.sender.0),
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
                compiled_class_hash: CasmHash(x.compiled_class_hash.0),
            }),
            DeclareV3(x) => Self::DeclareV3(DeclareTransactionV3 {
                class_hash: ClassHash(x.class_hash.0),
                nonce: TransactionNonce(x.common.nonce),
                nonce_data_availability_mode: DataAvailabilityMode::try_from_dto(
                    x.common.nonce_data_availability_mode,
                )?,
                fee_data_availability_mode: DataAvailabilityMode::try_from_dto(
                    x.common.fee_data_availability_mode,
                )?,
                resource_bounds: ResourceBounds::try_from_dto(x.common.resource_bounds)?,
                tip: pathfinder_common::Tip(x.common.tip),
                paymaster_data: x
                    .common
                    .paymaster_data
                    .into_iter()
                    .map(pathfinder_common::PaymasterDataElem)
                    .collect(),
                signature: x
                    .common
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
                account_deployment_data: x
                    .common
                    .account_deployment_data
                    .into_iter()
                    .map(AccountDeploymentDataElem)
                    .collect(),
                sender_address: ContractAddress(x.common.sender.0),
                compiled_class_hash: CasmHash(x.common.compiled_class_hash.0),
            }),
            Deploy(x) if x.version == 0 => {
                let constructor_calldata: Vec<ConstructorParam> =
                    x.calldata.into_iter().map(ConstructorParam).collect();
                let contract_address_salt = ContractAddressSalt(x.address_salt);
                let class_hash = ClassHash(x.class_hash.0);

                Self::DeployV0(DeployTransactionV0 {
                    // Computing the address is CPU intensive, so we do it later on.
                    contract_address: ContractAddress::ZERO,
                    contract_address_salt,
                    class_hash,
                    constructor_calldata,
                })
            }
            Deploy(x) if x.version == 1 => {
                let constructor_calldata: Vec<ConstructorParam> =
                    x.calldata.into_iter().map(ConstructorParam).collect();
                let contract_address_salt = ContractAddressSalt(x.address_salt);
                let class_hash = ClassHash(x.class_hash.0);

                Self::DeployV1(DeployTransactionV1 {
                    // Computing the address is CPU intensive, so we do it later on.
                    contract_address: ContractAddress::ZERO,
                    contract_address_salt,
                    class_hash,
                    constructor_calldata,
                })
            }
            Deploy(_) => anyhow::bail!("Invalid deploy transaction version"),
            DeployAccountV1(x) => {
                let constructor_calldata: Vec<CallParam> =
                    x.calldata.into_iter().map(CallParam).collect();
                let contract_address_salt = ContractAddressSalt(x.address_salt);
                let class_hash = ClassHash(x.class_hash.0);

                Self::DeployAccountV1(DeployAccountTransactionV1 {
                    // Computing the address is CPU intensive, so we do it later on.
                    contract_address: ContractAddress::ZERO,
                    max_fee: Fee(x.max_fee),
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                    nonce: TransactionNonce(x.nonce),
                    contract_address_salt,
                    constructor_calldata,
                    class_hash,
                })
            }
            DeployAccountV3(x) => {
                let constructor_calldata: Vec<CallParam> =
                    x.calldata.into_iter().map(CallParam).collect();
                let contract_address_salt = ContractAddressSalt(x.address_salt);
                let class_hash = ClassHash(x.class_hash.0);

                Self::DeployAccountV3(DeployAccountTransactionV3 {
                    // Computing the address is CPU intensive, so we do it later on.
                    contract_address: ContractAddress::ZERO,
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                    nonce: TransactionNonce(x.nonce),
                    nonce_data_availability_mode: DataAvailabilityMode::try_from_dto(
                        x.nonce_data_availability_mode,
                    )?,
                    fee_data_availability_mode: DataAvailabilityMode::try_from_dto(
                        x.fee_data_availability_mode,
                    )?,
                    resource_bounds: ResourceBounds::try_from_dto(x.resource_bounds)?,
                    tip: pathfinder_common::Tip(x.tip),
                    paymaster_data: x
                        .paymaster_data
                        .into_iter()
                        .map(pathfinder_common::PaymasterDataElem)
                        .collect(),
                    contract_address_salt,
                    constructor_calldata,
                    class_hash,
                })
            }
            InvokeV0(x) => Self::InvokeV0(InvokeTransactionV0 {
                calldata: x.calldata.into_iter().map(CallParam).collect(),
                sender_address: ContractAddress(x.address.0),
                entry_point_selector: EntryPoint(x.entry_point_selector),
                entry_point_type: None,
                max_fee: Fee(x.max_fee),
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
            }),
            InvokeV1(x) => Self::InvokeV1(InvokeTransactionV1 {
                calldata: x.calldata.into_iter().map(CallParam).collect(),
                sender_address: ContractAddress(x.sender.0),
                max_fee: Fee(x.max_fee),
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
                nonce: TransactionNonce(x.nonce),
            }),
            InvokeV3(x) => Self::InvokeV3(InvokeTransactionV3 {
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
                nonce: TransactionNonce(x.nonce),
                nonce_data_availability_mode: DataAvailabilityMode::try_from_dto(
                    x.nonce_data_availability_mode,
                )?,
                fee_data_availability_mode: DataAvailabilityMode::try_from_dto(
                    x.fee_data_availability_mode,
                )?,
                resource_bounds: ResourceBounds::try_from_dto(x.resource_bounds)?,
                tip: pathfinder_common::Tip(x.tip),
                paymaster_data: x
                    .paymaster_data
                    .into_iter()
                    .map(pathfinder_common::PaymasterDataElem)
                    .collect(),
                account_deployment_data: x
                    .account_deployment_data
                    .into_iter()
                    .map(AccountDeploymentDataElem)
                    .collect(),
                calldata: x.calldata.into_iter().map(CallParam).collect(),
                sender_address: ContractAddress(x.sender.0),
                proof_facts: x.proof_facts.into_iter().map(ProofFactElem).collect(),
            }),
            L1HandlerV0(x) => Self::L1Handler(L1HandlerTransaction {
                contract_address: ContractAddress(x.address.0),
                entry_point_selector: EntryPoint(x.entry_point_selector),
                nonce: TransactionNonce(x.nonce),
                calldata: x.calldata.into_iter().map(CallParam).collect(),
            }),
        })
    }
}

impl TryFromDto<p2p_proto::sync::transaction::Transaction> for Transaction {
    /// Caller must take care to compute the contract address for deploy and
    /// deploy account transactions separately in a non-async context.
    fn try_from_dto(dto: p2p_proto::sync::transaction::Transaction) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Transaction {
            hash: TransactionHash(dto.transaction_hash.0),
            variant: TransactionVariant::try_from_dto(dto.txn)?,
        })
    }
}

impl TryFrom<(p2p_proto::sync::receipt::Receipt, TransactionIndex)>
    for crate::sync::client::types::Receipt
{
    type Error = anyhow::Error;

    fn try_from(
        (dto, transaction_index): (p2p_proto::sync::receipt::Receipt, TransactionIndex),
    ) -> anyhow::Result<Self> {
        use p2p_proto::sync::receipt::Receipt::{
            Declare,
            Deploy,
            DeployAccount,
            Invoke,
            L1Handler,
        };
        use p2p_proto::sync::receipt::{
            DeclareTransactionReceipt,
            DeployAccountTransactionReceipt,
            DeployTransactionReceipt,
            InvokeTransactionReceipt,
            L1HandlerTransactionReceipt,
        };
        match dto {
            Invoke(InvokeTransactionReceipt { common })
            | Declare(DeclareTransactionReceipt { common })
            | L1Handler(L1HandlerTransactionReceipt { common, .. })
            | Deploy(DeployTransactionReceipt { common, .. })
            | DeployAccount(DeployAccountTransactionReceipt { common, .. }) => Ok(Self {
                actual_fee: Fee(common.actual_fee),
                execution_resources: ExecutionResources {
                    builtins: BuiltinCounters {
                        output: common.execution_resources.builtins.output.into(),
                        pedersen: common.execution_resources.builtins.pedersen.into(),
                        range_check: common.execution_resources.builtins.range_check.into(),
                        ecdsa: common.execution_resources.builtins.ecdsa.into(),
                        bitwise: common.execution_resources.builtins.bitwise.into(),
                        ec_op: common.execution_resources.builtins.ec_op.into(),
                        keccak: common.execution_resources.builtins.keccak.into(),
                        poseidon: common.execution_resources.builtins.poseidon.into(),
                        segment_arena: 0,
                        add_mod: common.execution_resources.builtins.add_mod.into(),
                        mul_mod: common.execution_resources.builtins.mul_mod.into(),
                        range_check96: common.execution_resources.builtins.range_check96.into(),
                    },
                    n_steps: common.execution_resources.steps.into(),
                    n_memory_holes: common.execution_resources.memory_holes.into(),
                    data_availability: L1Gas {
                        l1_gas: GasPrice::try_from(
                            common.execution_resources.l1_gas.unwrap_or_default(),
                        )?
                        .0,
                        l1_data_gas: GasPrice::try_from(
                            common.execution_resources.l1_data_gas.unwrap_or_default(),
                        )?
                        .0,
                    },
                    total_gas_consumed: L1Gas {
                        l1_gas: GasPrice::try_from(
                            common.execution_resources.total_l1_gas.unwrap_or_default(),
                        )?
                        .0,
                        l1_data_gas: 0, // Data point no longer present in p2p spec
                    },
                    l2_gas: L2Gas(
                        GasPrice::try_from(common.execution_resources.l2_gas.unwrap_or_default())?
                            .0,
                    ),
                },
                l2_to_l1_messages: common
                    .messages_sent
                    .into_iter()
                    .map(|x| L2ToL1Message {
                        from_address: ContractAddress(x.from_address),
                        payload: x
                            .payload
                            .into_iter()
                            .map(L2ToL1MessagePayloadElem)
                            .collect(),
                        to_address: ContractAddress::new_or_panic(
                            Felt::from_be_slice(x.to_address.0.as_bytes())
                                .expect("H160 should always fix in Felt"),
                        ),
                    })
                    .collect(),
                execution_status: match common.revert_reason {
                    Some(reason) => ExecutionStatus::Reverted { reason },
                    None => ExecutionStatus::Succeeded,
                },
                transaction_index,
            }),
        }
    }
}

impl TryFromDto<p2p_proto::transaction::ResourceBounds> for ResourceBounds {
    fn try_from_dto(dto: p2p_proto::transaction::ResourceBounds) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            l1_gas: ResourceBound {
                max_amount: pathfinder_common::ResourceAmount(dto.l1_gas.max_amount.try_into()?),
                max_price_per_unit: pathfinder_common::ResourcePricePerUnit(
                    dto.l1_gas.max_price_per_unit.try_into()?,
                ),
            },
            l2_gas: ResourceBound {
                max_amount: pathfinder_common::ResourceAmount(dto.l2_gas.max_amount.try_into()?),
                max_price_per_unit: pathfinder_common::ResourcePricePerUnit(
                    dto.l2_gas.max_price_per_unit.try_into()?,
                ),
            },
            l1_data_gas: if let Some(g) = dto.l1_data_gas {
                Some(ResourceBound {
                    max_amount: pathfinder_common::ResourceAmount(g.max_amount.try_into()?),
                    max_price_per_unit: pathfinder_common::ResourcePricePerUnit(
                        g.max_price_per_unit.try_into()?,
                    ),
                })
            } else {
                None
            },
        })
    }
}

impl TryFromDto<p2p_proto::common::VolitionDomain> for DataAvailabilityMode {
    fn try_from_dto(dto: p2p_proto::common::VolitionDomain) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(match dto {
            p2p_proto::common::VolitionDomain::L1 => Self::L1,
            p2p_proto::common::VolitionDomain::L2 => Self::L2,
        })
    }
}

impl FromDto<p2p_proto::sync::event::Event> for pathfinder_common::event::Event {
    fn from_dto(value: p2p_proto::sync::event::Event) -> Self {
        Self {
            from_address: ContractAddress(value.from_address),
            keys: value.keys.into_iter().map(EventKey).collect(),
            data: value.data.into_iter().map(EventData).collect(),
        }
    }
}

impl TryFromDto<p2p_proto::sync::event::Event> for pathfinder_common::event::Event {
    fn try_from_dto(proto: p2p_proto::sync::event::Event) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            from_address: ContractAddress(proto.from_address),
            keys: proto.keys.into_iter().map(EventKey).collect(),
            data: proto.data.into_iter().map(EventData).collect(),
        })
    }
}

impl TryFromDto<p2p_proto::common::L1DataAvailabilityMode> for L1DataAvailabilityMode {
    fn try_from_dto(dto: p2p_proto::common::L1DataAvailabilityMode) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        use p2p_proto::common::L1DataAvailabilityMode::{Blob, Calldata};
        Ok(match dto {
            Calldata => Self::Calldata,
            Blob => Self::Blob,
        })
    }
}

#[derive(Debug)]
pub struct CairoDefinition(pub Vec<u8>);

impl TryFromDto<p2p_proto::class::Cairo0Class> for CairoDefinition {
    fn try_from_dto(dto: p2p_proto::class::Cairo0Class) -> anyhow::Result<Self> {
        #[derive(Debug, Serialize)]
        struct SelectorAndOffset {
            pub selector: EntryPoint,
            pub offset: ByteCodeOffset,
        }

        #[derive(Debug, Serialize)]
        struct CairoEntryPoints {
            #[serde(rename = "EXTERNAL")]
            pub external: Vec<SelectorAndOffset>,
            #[serde(rename = "L1_HANDLER")]
            pub l1_handler: Vec<SelectorAndOffset>,
            #[serde(rename = "CONSTRUCTOR")]
            pub constructor: Vec<SelectorAndOffset>,
        }

        #[derive(Debug, Serialize)]
        #[serde(deny_unknown_fields)]
        struct Cairo<'a> {
            // Contract ABI, which has no schema definition.
            pub abi: Cow<'a, RawValue>,
            // Main program definition. __We assume that this is valid JSON.__
            pub program: Cow<'a, RawValue>,
            // The contract entry points.
            pub entry_points_by_type: CairoEntryPoints,
        }

        let from_dto = |x: Vec<p2p_proto::class::EntryPoint>| {
            x.into_iter()
                .map(|e| SelectorAndOffset {
                    selector: EntryPoint(e.selector),
                    offset: ByteCodeOffset(Felt::from_u64(e.offset)),
                })
                .collect::<Vec<_>>()
        };

        let abi = dto.abi;

        let compressed_program = BASE64_STANDARD.decode(dto.program)?;
        let gzip_decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(compressed_program));
        let mut program = Vec::new();
        gzip_decoder
            .take(pathfinder_common::class_definition::CLASS_DEFINITION_MAX_ALLOWED_SIZE)
            .read_to_end(&mut program)
            .context("Decompressing program JSON")?;

        let external = from_dto(dto.externals);
        let l1_handler = from_dto(dto.l1_handlers);
        let constructor = from_dto(dto.constructors);

        #[derive(Debug, Deserialize)]
        struct Abi<'a>(#[serde(borrow)] &'a RawValue);

        let class_def = Cairo {
            abi: Cow::Borrowed(serde_json::from_str::<Abi<'_>>(&abi).unwrap().0),
            program: serde_json::from_slice(&program)
                .context("verify that cairo class program is UTF-8")?,
            entry_points_by_type: CairoEntryPoints {
                external,
                l1_handler,
                constructor,
            },
        };
        let class_def =
            serde_json::to_vec(&class_def).context("serialize cairo class definition")?;
        Ok(Self(class_def))
    }
}

pub struct SierraDefinition(pub Vec<u8>);

impl TryFromDto<p2p_proto::class::Cairo1Class> for SierraDefinition {
    fn try_from_dto(dto: p2p_proto::class::Cairo1Class) -> anyhow::Result<Self> {
        #[derive(Debug, Serialize)]
        pub struct SelectorAndFunctionIndex {
            pub selector: EntryPoint,
            pub function_idx: u64,
        }

        #[derive(Debug, Serialize)]
        pub struct SierraEntryPoints {
            #[serde(rename = "EXTERNAL")]
            pub external: Vec<SelectorAndFunctionIndex>,
            #[serde(rename = "L1_HANDLER")]
            pub l1_handler: Vec<SelectorAndFunctionIndex>,
            #[serde(rename = "CONSTRUCTOR")]
            pub constructor: Vec<SelectorAndFunctionIndex>,
        }

        #[derive(Debug, Serialize)]
        pub struct Sierra<'a> {
            /// Contract ABI.
            pub abi: Cow<'a, str>,

            /// Main program definition.
            pub sierra_program: Vec<Felt>,

            // Version
            pub contract_class_version: Cow<'a, str>,

            /// The contract entry points
            pub entry_points_by_type: SierraEntryPoints,
        }

        let from_dto = |x: Vec<p2p_proto::class::SierraEntryPoint>| {
            x.into_iter()
                .map(|e| SelectorAndFunctionIndex {
                    selector: EntryPoint(e.selector),
                    function_idx: e.index,
                })
                .collect::<Vec<_>>()
        };

        let entry_points = SierraEntryPoints {
            external: from_dto(dto.entry_points.externals),
            l1_handler: from_dto(dto.entry_points.l1_handlers),
            constructor: from_dto(dto.entry_points.constructors),
        };
        let program = dto.program;
        let contract_class_version = dto.contract_class_version;

        let sierra = Sierra {
            abi: dto.abi.into(),
            sierra_program: program,
            contract_class_version: contract_class_version.into(),
            entry_points_by_type: entry_points,
        };

        let sierra = serde_json::to_vec(&sierra).context("serialize sierra class definition")?;

        Ok(Self(sierra))
    }
}

impl ToDto<Cairo1Class> for Sierra<'_> {
    fn to_dto(self) -> Cairo1Class {
        let into_dto = |x: SelectorAndFunctionIndex| SierraEntryPoint {
            selector: x.selector.0,
            index: x.function_idx,
        };

        let entry_points = Cairo1EntryPoints {
            externals: self
                .entry_points_by_type
                .external
                .into_iter()
                .map(into_dto)
                .collect(),
            l1_handlers: self
                .entry_points_by_type
                .l1_handler
                .into_iter()
                .map(into_dto)
                .collect(),
            constructors: self
                .entry_points_by_type
                .constructor
                .into_iter()
                .map(into_dto)
                .collect(),
        };

        Cairo1Class {
            abi: self.abi.to_string(),
            program: self.sierra_program,
            entry_points,
            contract_class_version: self.contract_class_version.into(),
        }
    }
}

impl ToDto<Cairo0Class> for Cairo<'_> {
    fn to_dto(self) -> Cairo0Class {
        let into_dto = |x: SelectorAndOffset| p2p_proto::class::EntryPoint {
            selector: x.selector.0,
            offset: u64::from_be_bytes(
                x.offset.0.as_be_bytes()[24..]
                    .try_into()
                    .expect("slice len matches"),
            ),
        };

        let mut gzip_encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        serde_json::to_writer(&mut gzip_encoder, &self.program).unwrap();
        let program = gzip_encoder.finish().unwrap();
        let program = BASE64_STANDARD.encode(program);

        Cairo0Class {
            abi: self.abi.to_string(),
            externals: self
                .entry_points_by_type
                .external
                .into_iter()
                .map(into_dto)
                .collect(),
            l1_handlers: self
                .entry_points_by_type
                .l1_handler
                .into_iter()
                .map(into_dto)
                .collect(),
            constructors: self
                .entry_points_by_type
                .constructor
                .into_iter()
                .map(into_dto)
                .collect(),
            program,
        }
    }
}
