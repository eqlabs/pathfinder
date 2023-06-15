//! Sync related data retrieval from other peers

// TODO temporary hybrid p2p/gw client goes here

/// Workaround for the orphan rule - implement conversion traits for types ourside our crate.
mod body {
    use p2p_proto::common::{BlockBody, Receipt, Transaction};
    use pathfinder_common::{
        CallParam, CasmHash, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt,
        EntryPoint, Fee, TransactionHash, TransactionNonce, TransactionSignatureElem,
        TransactionVersion,
    };
    use primitive_types::H256;
    use stark_hash::Felt;
    use starknet_gateway_types::reply::transaction::{self as gw, EntryPointType};

    pub(super) fn try_from_p2p(
        body: BlockBody,
    ) -> anyhow::Result<(Vec<gw::Transaction>, Vec<gw::Receipt>)> {
        fn version(felt: Felt) -> u8 {
            felt.to_be_bytes()[31]
        }

        fn entry_point(
            entry_point: Option<p2p_proto::common::invoke_transaction::EntryPoint>,
        ) -> anyhow::Result<(EntryPoint, Option<EntryPointType>)> {
            match entry_point {
                Some(p2p_proto::common::invoke_transaction::EntryPoint::Unspecified(e)) => {
                    Ok((EntryPoint(e), None))
                }
                Some(p2p_proto::common::invoke_transaction::EntryPoint::External(e)) => {
                    Ok((EntryPoint(e), Some(EntryPointType::External)))
                }
                Some(p2p_proto::common::invoke_transaction::EntryPoint::L1Handler(e)) => {
                    Ok((EntryPoint(e), Some(EntryPointType::L1Handler)))
                }
                None => anyhow::bail!("Missing entry point selector for Invoke v0 transaction"),
            }
        }

        let (gw_t, gw_r) = body
            .transactions
            .into_iter()
            .zip(body.receipts.into_iter())
            .map(|(t, r)| {
                match (t, &r) {
                    (Transaction::Invoke(t), Receipt::Invoke(r)) => match version(t.version) {
                        0 => {
                            let (entry_point_selector, entry_point_type) =
                                entry_point(t.deprecated_entry_point_selector)?;

                            Ok(gw::Transaction::Invoke(gw::InvokeTransaction::V0(
                                gw::InvokeTransactionV0 {
                                    calldata: t.calldata.into_iter().map(CallParam).collect(),
                                    sender_address: ContractAddress::new_or_panic(t.sender_address),
                                    entry_point_selector,
                                    entry_point_type,
                                    max_fee: Fee(t.max_fee),
                                    signature: t
                                        .signature
                                        .into_iter()
                                        .map(TransactionSignatureElem)
                                        .collect(),
                                    transaction_hash: TransactionHash(r.common.transaction_hash),
                                },
                            )))
                        }
                        1 => Ok(gw::Transaction::Invoke(gw::InvokeTransaction::V1(
                            gw::InvokeTransactionV1 {
                                calldata: t.calldata.into_iter().map(CallParam).collect(),
                                sender_address: ContractAddress::new_or_panic(t.sender_address),
                                max_fee: Fee(t.max_fee),
                                signature: t
                                    .signature
                                    .into_iter()
                                    .map(TransactionSignatureElem)
                                    .collect(),
                                nonce: TransactionNonce(t.nonce),
                                transaction_hash: TransactionHash(r.common.transaction_hash),
                            },
                        ))),
                        _ => anyhow::bail!("Invalid invoke transaction version {}", t.version),
                    },
                    (Transaction::Declare(t), Receipt::Declare(r)) => match version(t.version) {
                        0 => Ok(gw::Transaction::Declare(gw::DeclareTransaction::V0(
                            gw::DeclareTransactionV0V1 {
                                class_hash: ClassHash(t.class_hash),
                                max_fee: Fee(t.max_fee),
                                nonce: TransactionNonce(t.nonce),
                                sender_address: ContractAddress::new_or_panic(t.sender_address),
                                signature: t
                                    .signature
                                    .into_iter()
                                    .map(TransactionSignatureElem)
                                    .collect(),
                                transaction_hash: TransactionHash(r.common.transaction_hash),
                            },
                        ))),
                        1 => Ok(gw::Transaction::Declare(gw::DeclareTransaction::V1(
                            gw::DeclareTransactionV0V1 {
                                class_hash: ClassHash(t.class_hash),
                                max_fee: Fee(t.max_fee),
                                nonce: TransactionNonce(t.nonce),
                                sender_address: ContractAddress::new_or_panic(t.sender_address),
                                signature: t
                                    .signature
                                    .into_iter()
                                    .map(TransactionSignatureElem)
                                    .collect(),
                                transaction_hash: TransactionHash(r.common.transaction_hash),
                            },
                        ))),
                        2 => Ok(gw::Transaction::Declare(gw::DeclareTransaction::V2(
                            gw::DeclareTransactionV2 {
                                class_hash: ClassHash(t.class_hash),
                                max_fee: Fee(t.max_fee),
                                nonce: TransactionNonce(t.nonce),
                                sender_address: ContractAddress::new_or_panic(t.sender_address),
                                signature: t
                                    .signature
                                    .into_iter()
                                    .map(TransactionSignatureElem)
                                    .collect(),
                                transaction_hash: TransactionHash(r.common.transaction_hash),
                                compiled_class_hash: CasmHash(t.casm_hash),
                            },
                        ))),
                        _ => anyhow::bail!("Invalid declare transaction version {}", t.version),
                    },
                    (Transaction::Deploy(t), Receipt::Deploy(r)) => {
                        Ok(gw::Transaction::Deploy(gw::DeployTransaction {
                            contract_address: ContractAddress::new_or_panic(r.contract_address),
                            contract_address_salt: ContractAddressSalt(t.contract_address_salt),
                            class_hash: ClassHash(t.class_hash),
                            constructor_calldata: t
                                .constructor_calldata
                                .into_iter()
                                .map(ConstructorParam)
                                .collect(),
                            transaction_hash: TransactionHash(r.common.transaction_hash),
                            version: TransactionVersion(H256::from_slice(t.version.as_be_bytes())),
                        }))
                    }
                    (Transaction::L1Handler(t), Receipt::L1Handler(r)) => {
                        Ok(gw::Transaction::L1Handler(gw::L1HandlerTransaction {
                            contract_address: ContractAddress::new_or_panic(t.contract_address),
                            entry_point_selector: EntryPoint(t.entry_point_selector),
                            nonce: TransactionNonce(t.nonce),
                            calldata: t.calldata.into_iter().map(CallParam).collect(),
                            transaction_hash: TransactionHash(r.common.transaction_hash),
                            version: TransactionVersion(H256::from_slice(t.version.as_be_bytes())),
                        }))
                    }
                    (Transaction::DeployAccount(t), Receipt::DeployAccount(r)) => Ok(
                        gw::Transaction::DeployAccount(gw::DeployAccountTransaction {
                            contract_address: ContractAddress::new_or_panic(r.contract_address),
                            transaction_hash: TransactionHash(r.common.transaction_hash),
                            max_fee: Fee(t.max_fee),
                            version: TransactionVersion(H256::from_slice(t.version.as_be_bytes())),
                            signature: t
                                .signature
                                .into_iter()
                                .map(TransactionSignatureElem)
                                .collect(),
                            nonce: TransactionNonce(t.nonce),
                            contract_address_salt: ContractAddressSalt(t.contract_address_salt),
                            constructor_calldata: t
                                .constructor_calldata
                                .into_iter()
                                .map(CallParam)
                                .collect(),
                            class_hash: ClassHash(t.class_hash),
                        }),
                    ),
                    _ => anyhow::bail!(
                        "Transaction receipt type differs from its respective transaction type"
                    ),
                }
                .map(|t| (t, receipt::from_p2p(r)))
            })
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .unzip();

        Ok((gw_t, gw_r))
    }

    mod receipt {
        use super::gw;
        use p2p_proto::common::{
            DeclareTransactionReceipt, DeployAccountTransactionReceipt, DeployTransactionReceipt,
            InvokeTransactionReceipt, L1HandlerTransactionReceipt, Receipt,
        };
        use pathfinder_common::{
            event::Event, ContractAddress, EntryPoint, EthereumAddress, EventData, EventKey, Fee,
            L1ToL2MessageNonce, L1ToL2MessagePayloadElem, L2ToL1MessagePayloadElem,
            TransactionHash, TransactionIndex,
        };

        pub(super) fn from_p2p(r: Receipt) -> gw::Receipt {
            match r {
                Receipt::Declare(DeclareTransactionReceipt { common })
                | Receipt::Deploy(DeployTransactionReceipt { common, .. })
                | Receipt::DeployAccount(DeployAccountTransactionReceipt { common, .. })
                | Receipt::Invoke(InvokeTransactionReceipt { common })
                | Receipt::L1Handler(L1HandlerTransactionReceipt { common }) => gw::Receipt {
                    actual_fee: Some(Fee(common.actual_fee)),
                    events: common
                        .events
                        .into_iter()
                        .map(|e| Event {
                            data: e.data.into_iter().map(EventData).collect(),
                            from_address: ContractAddress::new_or_panic(e.from_address),
                            keys: e.keys.into_iter().map(EventKey).collect(),
                        })
                        .collect(),
                    execution_resources: Some(gw::ExecutionResources {
                        builtin_instance_counter: {
                            let b = common.execution_resources.builtin_instance_counter;
                            gw::execution_resources::BuiltinInstanceCounter::Normal(
                                gw::execution_resources::NormalBuiltinInstanceCounter {
                                    bitwise_builtin: b.bitwise_builtin,
                                    ecdsa_builtin: b.ecdsa_builtin,
                                    ec_op_builtin: b.ec_op_builtin,
                                    output_builtin: b.output_builtin,
                                    pedersen_builtin: b.pedersen_builtin,
                                    range_check_builtin: b.range_check_builtin,
                                },
                            )
                        },
                        n_steps: common.execution_resources.n_steps,
                        n_memory_holes: common.execution_resources.n_memory_holes,
                    }),
                    l1_to_l2_consumed_message: common.consumed_message.map(|x| gw::L1ToL2Message {
                        from_address: EthereumAddress(x.from_address),
                        payload: x
                            .payload
                            .into_iter()
                            .map(L1ToL2MessagePayloadElem)
                            .collect(),
                        selector: EntryPoint(x.entry_point_selector),
                        to_address: ContractAddress::new_or_panic(x.to_address),
                        nonce: Some(L1ToL2MessageNonce(x.nonce)),
                    }),
                    l2_to_l1_messages: common
                        .messages_sent
                        .into_iter()
                        .map(|m| gw::L2ToL1Message {
                            from_address: ContractAddress::new_or_panic(m.from_address),
                            payload: m
                                .payload
                                .into_iter()
                                .map(L2ToL1MessagePayloadElem)
                                .collect(),
                            to_address: EthereumAddress(m.to_address),
                        })
                        .collect(),
                    transaction_hash: TransactionHash(common.transaction_hash),
                    transaction_index: TransactionIndex::new_or_panic(
                        common.transaction_index.into(),
                    ),
                },
            }
        }
    }
}
