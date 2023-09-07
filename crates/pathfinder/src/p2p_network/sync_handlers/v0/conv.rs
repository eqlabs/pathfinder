//! Workaround for the orphan rule - implement conversion fns for types ourside our crate.

pub(crate) mod header {
    use pathfinder_common::BlockHeader;

    pub fn from(
        header: BlockHeader,
        transaction_count: u32,
        event_count: u32,
    ) -> p2p_proto_v0::common::BlockHeader {
        p2p_proto_v0::common::BlockHeader {
            hash: header.hash.0,
            parent_hash: header.parent_hash.0,
            number: header.number.get(),
            state_commitment: header.state_commitment.0,
            storage_commitment: header.storage_commitment.0,
            class_commitment: header.class_commitment.0,
            sequencer_address: header.sequencer_address.0,
            timestamp: header.timestamp.get(),
            gas_price: header.gas_price.0.into(),
            transaction_count,
            transaction_commitment: header.transaction_commitment.0,
            event_count,
            event_commitment: header.event_commitment.0,
            starknet_version: header.starknet_version.take_inner(),
        }
    }
}

pub(super) mod body {
    use p2p_proto_v0::common::{
        execution_resources::BuiltinInstanceCounter, invoke_transaction::EntryPoint,
        CommonTransactionReceiptProperties, DeclareTransaction, DeclareTransactionReceipt,
        DeployAccountTransaction, DeployAccountTransactionReceipt, DeployTransaction,
        DeployTransactionReceipt, Event, ExecutionResources, ExecutionStatus, InvokeTransaction,
        InvokeTransactionReceipt, MessageToL1, MessageToL2, Receipt, Transaction,
    };
    use pathfinder_common::{Fee, L1ToL2MessageNonce, TransactionNonce};
    use stark_hash::Felt;
    use starknet_gateway_types::reply::transaction as gw;

    pub fn from((gw_t, gw_r): (gw::Transaction, gw::Receipt)) -> (Transaction, Receipt) {
        let common = CommonTransactionReceiptProperties {
            transaction_hash: gw_t.hash().0,
            transaction_index: gw_r
                .transaction_index
                .get()
                .try_into()
                .expect("Transaction index fits in 32 bits"),
            actual_fee: gw_r.actual_fee.unwrap_or(Fee::ZERO).0,
            messages_sent: gw_r
                .l2_to_l1_messages
                .into_iter()
                .map(|m| MessageToL1 {
                    from_address: *m.from_address.get(),
                    payload: m.payload.into_iter().map(|x| x.0).collect(),
                    to_address: m.to_address.0,
                })
                .collect(),
            events: gw_r
                .events
                .into_iter()
                .map(|e| Event {
                    from_address: *e.from_address.get(),
                    keys: e.keys.into_iter().map(|k| k.0).collect(),
                    data: e.data.into_iter().map(|d| d.0).collect(),
                })
                .collect(),
            consumed_message: gw_r.l1_to_l2_consumed_message.map(|x| MessageToL2 {
                from_address: x.from_address.0,
                payload: x.payload.into_iter().map(|e| e.0).collect(),
                to_address: *x.to_address.get(),
                entry_point_selector: x.selector.0,
                nonce: x.nonce.unwrap_or(L1ToL2MessageNonce::ZERO).0,
            }),
            execution_resources: {
                let x = gw_r.execution_resources.unwrap_or_default();
                let b = x.builtin_instance_counter;
                ExecutionResources {
                    builtin_instance_counter: BuiltinInstanceCounter {
                        bitwise_builtin: b.bitwise_builtin,
                        ecdsa_builtin: b.ecdsa_builtin,
                        ec_op_builtin: b.ec_op_builtin,
                        output_builtin: b.output_builtin,
                        pedersen_builtin: b.pedersen_builtin,
                        range_check_builtin: b.range_check_builtin,
                        keccak_builtin: b.keccak_builtin,
                        poseidon_builtin: b.poseidon_builtin,
                        segment_arena_builtin: b.segment_arena_builtin,
                    },
                    n_steps: x.n_steps,
                    n_memory_holes: x.n_memory_holes,
                }
            },
            execution_status: match gw_r.execution_status {
                gw::ExecutionStatus::Succeeded => ExecutionStatus::Succeeded,
                gw::ExecutionStatus::Reverted => ExecutionStatus::Reverted,
            },
            revert_error: match gw_r.execution_status {
                gw::ExecutionStatus::Succeeded => Default::default(),
                gw::ExecutionStatus::Reverted => gw_r.revert_error.unwrap_or_default(),
            },
        };

        let version = Felt::from_be_slice(gw_t.version().0.as_bytes())
            .expect("Transaction version fits into felt");

        match gw_t {
            gw::Transaction::Declare(
                gw::DeclareTransaction::V0(t) | gw::DeclareTransaction::V1(t),
            ) => {
                let r = Receipt::Declare(DeclareTransactionReceipt { common });
                let t = Transaction::Declare(DeclareTransaction {
                    class_hash: t.class_hash.0,
                    sender_address: *t.sender_address.get(),
                    signature: t.signature.into_iter().map(|x| x.0).collect(),
                    max_fee: t.max_fee.0,
                    nonce: t.nonce.0,
                    version,
                    casm_hash: Felt::ZERO,
                });
                (t, r)
            }
            gw::Transaction::Declare(gw::DeclareTransaction::V2(t)) => {
                let r = Receipt::Declare(DeclareTransactionReceipt { common });
                let t = Transaction::Declare(DeclareTransaction {
                    class_hash: t.class_hash.0,
                    sender_address: *t.sender_address.get(),
                    signature: t.signature.into_iter().map(|x| x.0).collect(),
                    max_fee: t.max_fee.0,
                    nonce: t.nonce.0,
                    version,
                    casm_hash: t.compiled_class_hash.0,
                });
                (t, r)
            }
            gw::Transaction::Deploy(t) => {
                let r = Receipt::Deploy(DeployTransactionReceipt {
                    common,
                    contract_address: *t.contract_address.get(),
                });
                let t = Transaction::Deploy(DeployTransaction {
                    class_hash: t.class_hash.0,
                    contract_address_salt: t.contract_address_salt.0,
                    constructor_calldata: t.constructor_calldata.into_iter().map(|x| x.0).collect(),
                    version,
                });
                (t, r)
            }
            gw::Transaction::DeployAccount(t) => {
                let r = Receipt::DeployAccount(DeployAccountTransactionReceipt {
                    common,
                    contract_address: *t.contract_address.get(),
                });
                let t = Transaction::DeployAccount(DeployAccountTransaction {
                    class_hash: t.class_hash.0,
                    contract_address_salt: t.contract_address_salt.0,
                    constructor_calldata: t.constructor_calldata.into_iter().map(|x| x.0).collect(),
                    max_fee: t.max_fee.0,
                    nonce: t.nonce.0,
                    signature: t.signature.into_iter().map(|x| x.0).collect(),
                    version,
                });
                (t, r)
            }
            gw::Transaction::Invoke(gw::InvokeTransaction::V0(t)) => {
                let r = Receipt::Invoke(InvokeTransactionReceipt { common });
                let t = Transaction::Invoke(InvokeTransaction {
                    sender_address: *t.sender_address.get(),
                    deprecated_entry_point_selector: match t.entry_point_type {
                        Some(gw::EntryPointType::External) => {
                            Some(EntryPoint::External(t.entry_point_selector.0))
                        }
                        Some(gw::EntryPointType::L1Handler) => {
                            Some(EntryPoint::L1Handler(t.entry_point_selector.0))
                        }
                        None => Some(EntryPoint::Unspecified(t.entry_point_selector.0)),
                    },
                    calldata: t.calldata.into_iter().map(|x| x.0).collect(),
                    signature: t.signature.into_iter().map(|x| x.0).collect(),
                    max_fee: t.max_fee.0,
                    nonce: TransactionNonce::ZERO.0,
                    version,
                });
                (t, r)
            }
            gw::Transaction::Invoke(gw::InvokeTransaction::V1(t)) => {
                let r = Receipt::Invoke(InvokeTransactionReceipt { common });
                let t = Transaction::Invoke(InvokeTransaction {
                    sender_address: *t.sender_address.get(),
                    deprecated_entry_point_selector: None,
                    calldata: t.calldata.into_iter().map(|x| x.0).collect(),
                    signature: t.signature.into_iter().map(|x| x.0).collect(),
                    max_fee: t.max_fee.0,
                    nonce: t.nonce.0,
                    version,
                });
                (t, r)
            }
            gw::Transaction::L1Handler(t) => {
                let r = Receipt::L1Handler(p2p_proto_v0::common::L1HandlerTransactionReceipt {
                    common,
                });
                let t = Transaction::L1Handler(p2p_proto_v0::common::L1HandlerTransaction {
                    contract_address: *t.contract_address.get(),
                    entry_point_selector: t.entry_point_selector.0,
                    calldata: t.calldata.into_iter().map(|x| x.0).collect(),
                    nonce: t.nonce.0,
                    version,
                });
                (t, r)
            }
        }
    }
}

pub(super) mod state_update {
    use p2p_proto_v0::propagation::{
        BlockStateUpdate, ContractDiff, DeclaredClass, DeployedContract, ReplacedClass, StorageDiff,
    };
    use pathfinder_common::{
        state_update::{ContractClassUpdate, StateUpdate},
        ContractNonce,
    };

    pub fn from(x: StateUpdate) -> BlockStateUpdate {
        let mut deployed_contracts = Vec::new();
        let mut replaced_classes = Vec::new();
        let contract_diffs = x
            .contract_updates
            .into_iter()
            .map(|(contract_address, update)| {
                let nonce = update.nonce.unwrap_or_default().0;
                let storage_diffs = update
                    .storage
                    .into_iter()
                    .map(|(key, value)| StorageDiff {
                        key: key.0,
                        value: value.0,
                    })
                    .collect();
                match update.class {
                    Some(ContractClassUpdate::Deploy(class_hash)) => {
                        deployed_contracts.push(DeployedContract {
                            contract_address: contract_address.0,
                            class_hash: class_hash.0,
                        })
                    }
                    Some(ContractClassUpdate::Replace(class_hash)) => {
                        replaced_classes.push(ReplacedClass {
                            contract_address: contract_address.0,
                            class_hash: class_hash.0,
                        })
                    }
                    None => {}
                }

                ContractDiff {
                    contract_address: contract_address.0,
                    nonce,
                    storage_diffs,
                }
            })
            .chain(
                x.system_contract_updates
                    .into_iter()
                    .map(|(contract_address, update)| {
                        let storage_diffs = update
                            .storage
                            .into_iter()
                            .map(|(key, value)| StorageDiff {
                                key: key.0,
                                value: value.0,
                            })
                            .collect();
                        ContractDiff {
                            contract_address: contract_address.0,
                            nonce: ContractNonce::ZERO.0,
                            storage_diffs,
                        }
                    }),
            )
            .collect();

        BlockStateUpdate {
            contract_diffs,
            deployed_contracts,
            declared_cairo_classes: x.declared_cairo_classes.into_iter().map(|c| c.0).collect(),
            declared_classes: x
                .declared_sierra_classes
                .into_iter()
                .map(|(sierra_hash, casm_hash)| DeclaredClass {
                    sierra_hash: sierra_hash.0,
                    casm_hash: casm_hash.0,
                })
                .collect(),
            replaced_classes,
        }
    }
}
