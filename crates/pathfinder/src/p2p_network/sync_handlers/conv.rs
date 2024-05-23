//! Workaround for the orphan rule - implement conversion fns for types ourside
//! our crate.
use p2p_proto::class::{Cairo0Class, Cairo1Class, Cairo1EntryPoints, EntryPoint, SierraEntryPoint};
use p2p_proto::common::{Address, Hash};
use p2p_proto::receipt::execution_resources::BuiltinCounter;
use p2p_proto::receipt::{
    DeclareTransactionReceipt,
    DeployAccountTransactionReceipt,
    DeployTransactionReceipt,
    EthereumAddress,
    ExecutionResources,
    InvokeTransactionReceipt,
    L1HandlerTransactionReceipt,
    MessageToL1,
    ReceiptCommon,
};
use p2p_proto::transaction::{AccountSignature, ResourceBounds};
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::{DataAvailabilityMode, ResourceBound, Transaction};
use pathfinder_common::{L1DataAvailabilityMode, TransactionHash};
use pathfinder_crypto::Felt;
use starknet_gateway_types::class_definition::{Cairo, Sierra};
use starknet_gateway_types::request::contract::{SelectorAndFunctionIndex, SelectorAndOffset};

/// Convert pathfinder common (ie. core) type to a p2p dto type
pub trait ToDto<T> {
    fn to_dto(self) -> T;
}

impl ToDto<p2p_proto::transaction::Transaction> for Transaction {
    fn to_dto(self) -> p2p_proto::transaction::Transaction {
        use p2p_proto::transaction as proto;
        use pathfinder_common::transaction::TransactionVariant::*;

        match self.variant {
            DeclareV0(x) => proto::Transaction::DeclareV0(proto::DeclareV0 {
                sender: Address(x.sender_address.0),
                max_fee: x.max_fee.0,
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                class_hash: Hash(x.class_hash.0),
            }),
            DeclareV1(x) => proto::Transaction::DeclareV1(proto::DeclareV1 {
                sender: Address(x.sender_address.0),
                max_fee: x.max_fee.0,
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                class_hash: Hash(x.class_hash.0),
                nonce: x.nonce.0,
            }),
            DeclareV2(x) => proto::Transaction::DeclareV2(proto::DeclareV2 {
                sender: Address(x.sender_address.0),
                max_fee: x.max_fee.0,
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                class_hash: Hash(x.class_hash.0),
                nonce: x.nonce.0,
                compiled_class_hash: Hash(x.compiled_class_hash.0),
            }),
            DeclareV3(x) => proto::Transaction::DeclareV3(proto::DeclareV3 {
                sender: Address(x.sender_address.0),
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                class_hash: Hash(x.class_hash.0),
                nonce: x.nonce.0,
                compiled_class_hash: Hash(x.compiled_class_hash.0),
                resource_bounds: ResourceBounds {
                    l1_gas: x.resource_bounds.l1_gas.to_dto(),
                    l2_gas: x.resource_bounds.l2_gas.to_dto(),
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
            }),
            DeployV0(x) => proto::Transaction::Deploy(proto::Deploy {
                class_hash: Hash(x.class_hash.0),
                address_salt: x.contract_address_salt.0,
                calldata: x.constructor_calldata.into_iter().map(|c| c.0).collect(),
                version: 0,
            }),
            DeployV1(x) => proto::Transaction::Deploy(proto::Deploy {
                class_hash: Hash(x.class_hash.0),
                address_salt: x.contract_address_salt.0,
                calldata: x.constructor_calldata.into_iter().map(|c| c.0).collect(),
                version: 1,
            }),
            DeployAccountV1(x) => proto::Transaction::DeployAccountV1(proto::DeployAccountV1 {
                max_fee: x.max_fee.0,
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                class_hash: Hash(x.class_hash.0),
                nonce: x.nonce.0,
                address_salt: x.contract_address_salt.0,
                calldata: x.constructor_calldata.into_iter().map(|c| c.0).collect(),
            }),
            DeployAccountV3(x) => proto::Transaction::DeployAccountV3(proto::DeployAccountV3 {
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                class_hash: Hash(x.class_hash.0),
                nonce: x.nonce.0,
                address_salt: x.contract_address_salt.0,
                calldata: x.constructor_calldata.into_iter().map(|c| c.0).collect(),
                resource_bounds: ResourceBounds {
                    l1_gas: x.resource_bounds.l1_gas.to_dto(),
                    l2_gas: x.resource_bounds.l2_gas.to_dto(),
                },
                tip: x.tip.0,
                paymaster_data: x.paymaster_data.into_iter().map(|p| p.0).collect(),
                nonce_data_availability_mode: x.nonce_data_availability_mode.to_dto(),
                fee_data_availability_mode: x.fee_data_availability_mode.to_dto(),
            }),
            InvokeV0(x) => proto::Transaction::InvokeV0(proto::InvokeV0 {
                max_fee: x.max_fee.0,
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                address: Address(x.sender_address.0),
                entry_point_selector: x.entry_point_selector.0,
                calldata: x.calldata.into_iter().map(|c| c.0).collect(),
            }),
            InvokeV1(x) => proto::Transaction::InvokeV1(proto::InvokeV1 {
                sender: Address(x.sender_address.0),
                max_fee: x.max_fee.0,
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                nonce: x.nonce.0,
                calldata: x.calldata.into_iter().map(|c| c.0).collect(),
            }),
            InvokeV3(x) => proto::Transaction::InvokeV3(proto::InvokeV3 {
                sender: Address(x.sender_address.0),
                signature: AccountSignature {
                    parts: x.signature.into_iter().map(|s| s.0).collect(),
                },
                calldata: x.calldata.into_iter().map(|c| c.0).collect(),
                resource_bounds: ResourceBounds {
                    l1_gas: x.resource_bounds.l1_gas.to_dto(),
                    l2_gas: x.resource_bounds.l2_gas.to_dto(),
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
            }),
            L1Handler(x) => proto::Transaction::L1HandlerV0(proto::L1HandlerV0 {
                nonce: x.nonce.0,
                address: Address(x.contract_address.0),
                entry_point_selector: x.entry_point_selector.0,
                calldata: x.calldata.into_iter().map(|c| c.0).collect(),
            }),
        }
    }
}

impl ToDto<p2p_proto::receipt::Receipt> for (&Transaction, Receipt) {
    fn to_dto(self) -> p2p_proto::receipt::Receipt {
        use p2p_proto::receipt::Receipt::{Declare, Deploy, DeployAccount, Invoke, L1Handler};
        let revert_reason = self.1.revert_reason().map(ToOwned::to_owned);
        let common = ReceiptCommon {
            actual_fee: self.1.actual_fee.0,
            price_unit: p2p_proto::receipt::PriceUnit::Wei, // TODO
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
                // Assumption: the values are small enough to fit into u32
                ExecutionResources {
                    builtins: BuiltinCounter {
                        bitwise: e.builtins.bitwise.try_into().unwrap(),
                        ecdsa: e.builtins.ecdsa.try_into().unwrap(),
                        ec_op: e.builtins.ec_op.try_into().unwrap(),
                        pedersen: e.builtins.pedersen.try_into().unwrap(),
                        range_check: e.builtins.range_check.try_into().unwrap(),
                        poseidon: e.builtins.poseidon.try_into().unwrap(),
                        keccak: e.builtins.keccak.try_into().unwrap(),
                        output: e.builtins.output.try_into().unwrap(),
                    },
                    steps: e.n_steps.try_into().unwrap(),
                    memory_holes: e.n_memory_holes.try_into().unwrap(),
                    l1_gas: da.l1_gas.into(),
                    l1_data_gas: da.l1_data_gas.into(),
                }
            },
            revert_reason,
        };

        use pathfinder_common::transaction::TransactionVariant;
        match &self.0.variant {
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
            TransactionVariant::L1Handler(_) => L1Handler(L1HandlerTransactionReceipt {
                common,
                msg_hash: Hash(Felt::ZERO), // TODO what is this
            }),
        }
    }
}

impl ToDto<p2p_proto::event::Event> for (TransactionHash, Event) {
    fn to_dto(self) -> p2p_proto::event::Event {
        p2p_proto::event::Event {
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

pub fn sierra_def_into_dto(sierra: Sierra<'_>) -> Cairo1Class {
    let into_dto = |x: SelectorAndFunctionIndex| SierraEntryPoint {
        selector: x.selector.0,
        index: x.function_idx,
    };

    let entry_points = Cairo1EntryPoints {
        externals: sierra
            .entry_points_by_type
            .external
            .into_iter()
            .map(into_dto)
            .collect(),
        l1_handlers: sierra
            .entry_points_by_type
            .l1_handler
            .into_iter()
            .map(into_dto)
            .collect(),
        constructors: sierra
            .entry_points_by_type
            .constructor
            .into_iter()
            .map(into_dto)
            .collect(),
    };

    Cairo1Class {
        abi: sierra.abi.to_string(),
        program: sierra.sierra_program,
        entry_points,
        contract_class_version: sierra.contract_class_version.into(),
    }
}

pub fn cairo_def_into_dto(cairo: Cairo<'_>) -> Cairo0Class {
    let into_dto = |x: SelectorAndOffset| EntryPoint {
        selector: x.selector.0,
        offset: u64::from_be_bytes(
            x.offset.0.as_be_bytes()[24..]
                .try_into()
                .expect("slice len matches"),
        ),
    };

    Cairo0Class {
        abi: cairo.abi.to_string(),
        externals: cairo
            .entry_points_by_type
            .external
            .into_iter()
            .map(into_dto)
            .collect(),
        l1_handlers: cairo
            .entry_points_by_type
            .l1_handler
            .into_iter()
            .map(into_dto)
            .collect(),
        constructors: cairo
            .entry_points_by_type
            .constructor
            .into_iter()
            .map(into_dto)
            .collect(),
        program: cairo.program.to_string(),
    }
}
