//! Sync related data retrieval from other peers
//!
//! This is a temporary wrapper around proper p2p sync|propagation api that fits into
//! current sequential sync logic and will be removed when __proper__ sync algo is
//! integrated. What it does is just split methods between a bootstrap node
//! that syncs from the gateway and a "proper" p2p node which only syncs via p2p.

use p2p::HeadReceiver;
use pathfinder_common::{
    BlockHash, BlockHeader, BlockId, BlockNumber, CallParam, CasmHash, ClassHash, ContractAddress,
    ContractAddressSalt, Fee, SequencerAddress, StateCommitment, StateUpdate, TransactionHash,
    TransactionNonce, TransactionSignatureElem, TransactionVersion,
};
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::error::SequencerError;
use starknet_gateway_types::reply::{self, Block};
use starknet_gateway_types::request::add_transaction::ContractDefinition;

/// Hybrid, as it uses either p2p or the gateway depending on role
/// and api call
#[derive(Clone, Debug)]
pub enum HybridClient {
    /// Syncs from the feeder gateway, propagates new headers via p2p
    /// Proxies blockchain data to non propagating nodes via p2p
    ///
    /// Ofc bootstrapping can be split from proxying but let's keep two types
    /// of nodes for PoC
    Bootstrap {
        p2p_client: p2p::SyncClient,
        sequencer: starknet_gateway_client::Client,
    },
    /// Syncs from p2p network
    NonPropagating {
        p2p_client: p2p::SyncClient,
        sequencer: starknet_gateway_client::Client,
        head_receiver: HeadReceiver,
    },
}

impl HybridClient {
    pub fn new(
        i_am_boot: bool,
        p2p_client: p2p::SyncClient,
        sequencer: starknet_gateway_client::Client,
        head_receiver: HeadReceiver,
    ) -> Self {
        if i_am_boot {
            Self::Bootstrap {
                p2p_client,
                sequencer,
            }
        } else {
            Self::NonPropagating {
                p2p_client,
                sequencer,
                head_receiver,
            }
        }
    }

    fn as_sequencer(&self) -> &starknet_gateway_client::Client {
        match self {
            HybridClient::Bootstrap { sequencer, .. } => sequencer,
            HybridClient::NonPropagating { sequencer, .. } => sequencer,
        }
    }
}

/// A hacky temporary way to wrap p2p related errors
mod error {
    use starknet_gateway_types::error::{
        KnownStarknetErrorCode, SequencerError, StarknetError, StarknetErrorCode,
    };

    pub fn block_not_found(message: impl ToString) -> SequencerError {
        SequencerError::StarknetError(StarknetError {
            code: StarknetErrorCode::Known(KnownStarknetErrorCode::BlockNotFound),
            message: message.to_string(),
        })
    }

    pub fn class_not_found(message: impl ToString) -> SequencerError {
        SequencerError::StarknetError(StarknetError {
            code: StarknetErrorCode::Known(KnownStarknetErrorCode::UndeclaredClass),
            message: message.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl GatewayApi for HybridClient {
    async fn block(&self, block: BlockId) -> Result<reply::MaybePendingBlock, SequencerError> {
        use error::block_not_found;

        match self {
            HybridClient::Bootstrap { sequencer, .. } => sequencer.block(block).await,
            HybridClient::NonPropagating { p2p_client, .. } => match block {
                BlockId::Number(n) => {
                    let mut headers = p2p_client
                        .block_headers(n, 1)
                        .await
                        .map_err(block_not_found)?;

                    if headers.len() != 1 {
                        return Err(block_not_found(format!(
                            "Headers len for block {n} is {}, expected 1",
                            headers.len()
                        )));
                    }

                    let header = headers.swap_remove(0);

                    let mut bodies = p2p_client
                        .block_bodies(BlockHash(header.hash), 1)
                        .await
                        .map_err(block_not_found)?;

                    if bodies.len() != 1 {
                        return Err(block_not_found(format!(
                            "Bodies len for block {n} is {}, expected 1",
                            headers.len()
                        )));
                    }

                    let body = bodies.swap_remove(0);
                    let (transactions, transaction_receipts) =
                        conv::body::try_from_p2p(body).map_err(block_not_found)?;
                    let header = conv::header::try_from_p2p(header).map_err(block_not_found)?;

                    Ok(reply::MaybePendingBlock::Block(Block {
                        block_hash: header.hash,
                        block_number: header.number,
                        gas_price: Some(header.gas_price),
                        parent_block_hash: header.parent_hash,
                        sequencer_address: Some(header.sequencer_address),
                        state_commitment: header.state_commitment,
                        // FIXME
                        status: starknet_gateway_types::reply::Status::AcceptedOnL2,
                        timestamp: header.timestamp,
                        transaction_receipts,
                        transactions,
                        starknet_version: header.starknet_version,
                    }))
                }
                BlockId::Latest => {
                    unreachable!("GatewayApi.head() is used in sync and sync status instead")
                }
                BlockId::Hash(_) => unreachable!("not used in sync"),
                BlockId::Pending => {
                    unreachable!("pending should be disabled when p2p is enabled")
                }
            },
        }
    }

    async fn block_without_retry(
        &self,
        block: BlockId,
    ) -> Result<reply::MaybePendingBlock, SequencerError> {
        match self {
            HybridClient::Bootstrap { sequencer, .. } => sequencer.block_without_retry(block).await,
            HybridClient::NonPropagating { .. } => {
                unreachable!("used for gas price and not in sync")
            }
        }
    }

    async fn class_by_hash(&self, class_hash: ClassHash) -> Result<bytes::Bytes, SequencerError> {
        use error::class_not_found;

        match self {
            HybridClient::Bootstrap { sequencer, .. } => sequencer.class_by_hash(class_hash).await,
            HybridClient::NonPropagating { p2p_client, .. } => {
                let classes = p2p_client
                    .contract_classes(vec![class_hash])
                    .await
                    .map_err(class_not_found)?;
                let mut classes = classes.classes;

                if classes.len() != 1 {
                    return Err(class_not_found(format!(
                        "Classes len is {}, expected 1",
                        classes.len()
                    )));
                }

                let p2p_proto::common::RawClass { class } = classes.swap_remove(0);
                Ok(class.into())
            }
        }
    }

    async fn pending_class_by_hash(
        &self,
        class_hash: ClassHash,
    ) -> Result<bytes::Bytes, SequencerError> {
        match self {
            HybridClient::Bootstrap { sequencer, .. } => {
                sequencer.pending_class_by_hash(class_hash).await
            }
            HybridClient::NonPropagating { .. } => {
                unreachable!("pending should be disabled when p2p is enabled")
            }
        }
    }

    async fn transaction(
        &self,
        transaction_hash: TransactionHash,
    ) -> Result<reply::Transaction, SequencerError> {
        self.as_sequencer().transaction(transaction_hash).await
    }

    async fn state_update(&self, block: BlockId) -> Result<StateUpdate, SequencerError> {
        use error::block_not_found;

        match self {
            HybridClient::Bootstrap { sequencer, .. } => sequencer.state_update(block).await,
            HybridClient::NonPropagating { p2p_client, .. } => match block {
                BlockId::Hash(hash) => {
                    let mut state_updates = p2p_client
                        .state_updates(hash, 1)
                        .await
                        .map_err(block_not_found)?;

                    if state_updates.len() != 1 {
                        return Err(block_not_found(format!(
                            "State updates len is {}, expected 1",
                            state_updates.len()
                        )));
                    }

                    let state_update = state_updates.swap_remove(0);

                    let state_update =
                        conv::state_update::try_from_p2p(state_update).map_err(block_not_found)?;

                    if state_update.block_hash == hash {
                        Ok(state_update.into())
                    } else {
                        Err(block_not_found("Block hash mismatch"))
                    }
                }
                _ => unreachable!("not used in sync"),
            },
        }
    }

    async fn eth_contract_addresses(&self) -> Result<reply::EthContractAddresses, SequencerError> {
        self.as_sequencer().eth_contract_addresses().await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_invoke_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_address: ContractAddress,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::InvokeResponse, SequencerError> {
        self.as_sequencer()
            .add_invoke_transaction(
                version,
                max_fee,
                signature,
                nonce,
                contract_address,
                calldata,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_declare_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_definition: ContractDefinition,
        sender_address: ContractAddress,
        compiled_class_hash: Option<CasmHash>,
        token: Option<String>,
    ) -> Result<reply::add_transaction::DeclareResponse, SequencerError> {
        self.as_sequencer()
            .add_declare_transaction(
                version,
                max_fee,
                signature,
                nonce,
                contract_definition,
                sender_address,
                compiled_class_hash,
                token,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_deploy_account(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_address_salt: ContractAddressSalt,
        class_hash: ClassHash,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::DeployAccountResponse, SequencerError> {
        self.as_sequencer()
            .add_deploy_account(
                version,
                max_fee,
                signature,
                nonce,
                contract_address_salt,
                class_hash,
                calldata,
            )
            .await
    }

    /// This is a **temporary** measure to keep the sync logic unchanged
    ///
    /// TODO remove me when sync is changed to use the high level (ie. peer unaware) p2p API
    /// TODO use a block header type which should be in pathfinder_common (?)
    async fn propagate_block_header(
        &self,
        header: &BlockHeader,
        transaction_count: usize,
        event_count: usize,
    ) {
        match self {
            HybridClient::Bootstrap { p2p_client, .. } => {
                match p2p_client
                    .propagate_new_header(p2p_proto::common::BlockHeader {
                        hash: header.hash.0,
                        parent_hash: header.parent_hash.0,
                        number: header.number.get(),
                        state_commitment: header.state_commitment.0,
                        class_commitment: header.class_commitment.0,
                        storage_commitment: header.storage_commitment.0,
                        sequencer_address: header.sequencer_address.0,
                        timestamp: header.timestamp.get(),
                        gas_price: header.gas_price.0.into(),
                        // FIXME
                        transaction_count: todo!(),
                        transaction_commitment: header.state_commitment.0,

                        // FIXME
                        event_count: todo!(),
                        event_commitment: header.event_commitment.0,
                        starknet_version: header.starknet_version.take_inner(),
                    })
                    .await
                {
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "Propagating block header failed"),
                }
            }
            HybridClient::NonPropagating { .. } => {
                // This is why it's called non-propagating
            }
        }
    }

    /// This is a **temporary** measure to keep the sync logic unchanged
    ///
    /// TODO remove me when sync is changed to use the high level (ie. peer unaware) p2p API
    async fn head(&self) -> Result<(BlockNumber, BlockHash), SequencerError> {
        match self {
            HybridClient::Bootstrap { sequencer, .. } => Ok(sequencer.head().await?),
            HybridClient::NonPropagating { head_receiver, .. } => (*head_receiver.borrow()).ok_or(
                error::block_not_found("Haven't received any gossiped block headers yet"),
            ),
        }
    }
}

/// Workaround for the orphan rule - implement conversion fns for types ourside our crate.
pub mod conv {
    pub mod header {
        use pathfinder_common::{
            BlockHash, BlockHeader, BlockNumber, BlockTimestamp, ClassCommitment, EventCommitment,
            GasPrice, SequencerAddress, StarknetVersion, StateCommitment, StorageCommitment,
            TransactionCommitment,
        };

        #[allow(unused)]
        pub fn try_from_p2p(header: p2p_proto::common::BlockHeader) -> anyhow::Result<BlockHeader> {
            Ok(BlockHeader {
                hash: BlockHash(header.hash),
                parent_hash: BlockHash(header.parent_hash),
                number: BlockNumber::new(header.number).ok_or(anyhow::anyhow!(
                    "Out of range block number {}",
                    header.number
                ))?,
                timestamp: BlockTimestamp::new(header.timestamp).ok_or(anyhow::anyhow!(
                    "Out of range timestamp in block {}",
                    header.number
                ))?,
                gas_price: GasPrice::from_be_slice(&header.gas_price.as_be_bytes()[16..])
                    .expect("larger to smaller array is ok"),
                sequencer_address: SequencerAddress(header.sequencer_address),
                starknet_version: StarknetVersion::from(header.starknet_version),
                class_commitment: ClassCommitment(header.class_commitment),
                event_commitment: EventCommitment(header.event_commitment),
                state_commitment: StateCommitment(header.state_commitment),
                storage_commitment: StorageCommitment(header.storage_commitment),
                transaction_commitment: TransactionCommitment(header.transaction_commitment),
            })
        }
    }

    pub mod body {
        use anyhow::Context;
        use p2p_proto::common::{BlockBody, Receipt, Transaction};
        use pathfinder_common::{
            CallParam, CasmHash, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt,
            EntryPoint, Fee, TransactionHash, TransactionNonce, TransactionSignatureElem,
            TransactionVersion,
        };
        use primitive_types::H256;
        use stark_hash::Felt;
        use starknet_gateway_types::reply::transaction::{self as gw, EntryPointType};

        #[allow(unused)]
        pub fn try_from_p2p(
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
                .enumerate()
                .map(|(i, (t, r))| {
                    match (t, &r) {
                        (Transaction::Invoke(t), Receipt::Invoke(r)) => match version(t.version) {
                            0 => {
                                let (entry_point_selector, entry_point_type) =
                                    entry_point(t.deprecated_entry_point_selector)
                                        .context(r.common.transaction_hash)?;

                                anyhow::Ok(gw::Transaction::Invoke(gw::InvokeTransaction::V0(
                                    gw::InvokeTransactionV0 {
                                        calldata: t.calldata.into_iter().map(CallParam).collect(),
                                        sender_address: ContractAddress::new(t.sender_address)
                                            .ok_or(anyhow::anyhow!(
                                                "Out of range sender address {}",
                                                t.sender_address
                                            ))?,
                                        entry_point_selector,
                                        entry_point_type,
                                        max_fee: Fee(t.max_fee),
                                        signature: t
                                            .signature
                                            .into_iter()
                                            .map(TransactionSignatureElem)
                                            .collect(),
                                        transaction_hash: TransactionHash(
                                            r.common.transaction_hash,
                                        ),
                                    },
                                )))
                            }
                            1 => Ok(gw::Transaction::Invoke(gw::InvokeTransaction::V1(
                                gw::InvokeTransactionV1 {
                                    calldata: t.calldata.into_iter().map(CallParam).collect(),
                                    sender_address: ContractAddress::new(t.sender_address).ok_or(
                                        anyhow::anyhow!(
                                            "Out of range sender address {}",
                                            t.sender_address
                                        ),
                                    )?,
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
                            _ => anyhow::bail!(
                                "Invalid version {} of invoke transaction {}",
                                t.version,
                                r.common.transaction_hash
                            ),
                        },
                        (Transaction::Declare(t), Receipt::Declare(r)) => {
                            match version(t.version) {
                                0 => Ok(gw::Transaction::Declare(gw::DeclareTransaction::V0(
                                    gw::DeclareTransactionV0V1 {
                                        class_hash: ClassHash(t.class_hash),
                                        max_fee: Fee(t.max_fee),
                                        nonce: TransactionNonce(t.nonce),
                                        sender_address: ContractAddress::new(t.sender_address)
                                            .ok_or(anyhow::anyhow!(
                                                "Out of range sender address {}",
                                                t.sender_address
                                            ))?,
                                        signature: t
                                            .signature
                                            .into_iter()
                                            .map(TransactionSignatureElem)
                                            .collect(),
                                        transaction_hash: TransactionHash(
                                            r.common.transaction_hash,
                                        ),
                                    },
                                ))),
                                1 => Ok(gw::Transaction::Declare(gw::DeclareTransaction::V1(
                                    gw::DeclareTransactionV0V1 {
                                        class_hash: ClassHash(t.class_hash),
                                        max_fee: Fee(t.max_fee),
                                        nonce: TransactionNonce(t.nonce),
                                        sender_address: ContractAddress::new(t.sender_address)
                                            .ok_or(anyhow::anyhow!(
                                                "Out of range sender address {}",
                                                t.sender_address
                                            ))?,
                                        signature: t
                                            .signature
                                            .into_iter()
                                            .map(TransactionSignatureElem)
                                            .collect(),
                                        transaction_hash: TransactionHash(
                                            r.common.transaction_hash,
                                        ),
                                    },
                                ))),
                                2 => Ok(gw::Transaction::Declare(gw::DeclareTransaction::V2(
                                    gw::DeclareTransactionV2 {
                                        class_hash: ClassHash(t.class_hash),
                                        max_fee: Fee(t.max_fee),
                                        nonce: TransactionNonce(t.nonce),
                                        sender_address: ContractAddress::new(t.sender_address)
                                            .ok_or(anyhow::anyhow!(
                                                "Out of range sender address {}",
                                                t.sender_address
                                            ))?,
                                        signature: t
                                            .signature
                                            .into_iter()
                                            .map(TransactionSignatureElem)
                                            .collect(),
                                        transaction_hash: TransactionHash(
                                            r.common.transaction_hash,
                                        ),
                                        compiled_class_hash: CasmHash(t.casm_hash),
                                    },
                                ))),
                                _ => anyhow::bail!(
                                    "Invalid version {} of declare transaction {}",
                                    t.version,
                                    r.common.transaction_hash
                                ),
                            }
                        }
                        (Transaction::Deploy(t), Receipt::Deploy(r)) => {
                            Ok(gw::Transaction::Deploy(gw::DeployTransaction {
                                contract_address: ContractAddress::new(r.contract_address).ok_or(
                                    anyhow::anyhow!(
                                        "Out of range contract address {}",
                                        r.contract_address
                                    ),
                                )?,
                                contract_address_salt: ContractAddressSalt(t.contract_address_salt),
                                class_hash: ClassHash(t.class_hash),
                                constructor_calldata: t
                                    .constructor_calldata
                                    .into_iter()
                                    .map(ConstructorParam)
                                    .collect(),
                                transaction_hash: TransactionHash(r.common.transaction_hash),
                                version: TransactionVersion(H256::from_slice(
                                    t.version.as_be_bytes(),
                                )),
                            }))
                        }
                        (Transaction::L1Handler(t), Receipt::L1Handler(r)) => {
                            Ok(gw::Transaction::L1Handler(gw::L1HandlerTransaction {
                                contract_address: ContractAddress::new(t.contract_address).ok_or(
                                    anyhow::anyhow!(
                                        "Out of range contract address {}",
                                        t.contract_address
                                    ),
                                )?,
                                entry_point_selector: EntryPoint(t.entry_point_selector),
                                nonce: TransactionNonce(t.nonce),
                                calldata: t.calldata.into_iter().map(CallParam).collect(),
                                transaction_hash: TransactionHash(r.common.transaction_hash),
                                version: TransactionVersion(H256::from_slice(
                                    t.version.as_be_bytes(),
                                )),
                            }))
                        }
                        (Transaction::DeployAccount(t), Receipt::DeployAccount(r)) => Ok(
                            gw::Transaction::DeployAccount(gw::DeployAccountTransaction {
                                contract_address: ContractAddress::new(r.contract_address).ok_or(
                                    anyhow::anyhow!(
                                        "Out of range contract address {}",
                                        r.contract_address
                                    ),
                                )?,
                                transaction_hash: TransactionHash(r.common.transaction_hash),
                                max_fee: Fee(t.max_fee),
                                version: TransactionVersion(H256::from_slice(
                                    t.version.as_be_bytes(),
                                )),
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
                        _ => anyhow::bail!("Receipt vs transaction type mismatch at pos {}", i),
                    }
                    .map(|t| Ok((t, receipt::try_from_p2p(r)?)))?
                })
                .collect::<anyhow::Result<Vec<_>>>()?
                .into_iter()
                .unzip();

            Ok((gw_t, gw_r))
        }

        mod receipt {
            use super::gw;
            use p2p_proto::common::{
                DeclareTransactionReceipt, DeployAccountTransactionReceipt,
                DeployTransactionReceipt, InvokeTransactionReceipt, L1HandlerTransactionReceipt,
                Receipt,
            };
            use pathfinder_common::{
                event::Event, ContractAddress, EntryPoint, EthereumAddress, EventData, EventKey,
                Fee, L1ToL2MessageNonce, L1ToL2MessagePayloadElem, L2ToL1MessagePayloadElem,
                TransactionHash, TransactionIndex,
            };

            pub(super) fn try_from_p2p(r: Receipt) -> anyhow::Result<gw::Receipt> {
                match r {
                    Receipt::Declare(DeclareTransactionReceipt { common })
                    | Receipt::Deploy(DeployTransactionReceipt { common, .. })
                    | Receipt::DeployAccount(DeployAccountTransactionReceipt { common, .. })
                    | Receipt::Invoke(InvokeTransactionReceipt { common })
                    | Receipt::L1Handler(L1HandlerTransactionReceipt { common }) => {
                        Ok(gw::Receipt {
                            actual_fee: Some(Fee(common.actual_fee)),
                            events: common
                                .events
                                .into_iter()
                                .map(|e| {
                                    Ok(Event {
                                        data: e.data.into_iter().map(EventData).collect(),
                                        from_address: ContractAddress::new(e.from_address).ok_or(
                                            anyhow::anyhow!(
                                                "Out of range 'from' address {}",
                                                e.from_address
                                            ),
                                        )?,
                                        keys: e.keys.into_iter().map(EventKey).collect(),
                                    })
                                })
                                .collect::<anyhow::Result<Vec<_>>>()?,
                            execution_resources: Some(gw::ExecutionResources {
                                builtin_instance_counter: {
                                    let b = common.execution_resources.builtin_instance_counter;
                                    gw::BuiltinCounters {
                                        bitwise_builtin: b.bitwise_builtin,
                                        ecdsa_builtin: b.ecdsa_builtin,
                                        ec_op_builtin: b.ec_op_builtin,
                                        output_builtin: b.output_builtin,
                                        pedersen_builtin: b.pedersen_builtin,
                                        range_check_builtin: b.range_check_builtin,
                                        // FIXME once p2p has these builtins.
                                        keccak_builtin: Default::default(),
                                        poseidon_builtin: Default::default(),
                                        segment_arena_builtin: Default::default(),
                                    }
                                },
                                n_steps: common.execution_resources.n_steps,
                                n_memory_holes: common.execution_resources.n_memory_holes,
                            }),
                            l1_to_l2_consumed_message: match common.consumed_message {
                                Some(x) => Some(gw::L1ToL2Message {
                                    from_address: EthereumAddress(x.from_address),
                                    payload: x
                                        .payload
                                        .into_iter()
                                        .map(L1ToL2MessagePayloadElem)
                                        .collect(),
                                    selector: EntryPoint(x.entry_point_selector),
                                    to_address: ContractAddress::new(x.to_address).ok_or(
                                        anyhow::anyhow!(
                                            "Out of range 'to' address {}",
                                            x.to_address
                                        ),
                                    )?,
                                    nonce: Some(L1ToL2MessageNonce(x.nonce)),
                                }),
                                None => None,
                            },
                            l2_to_l1_messages: common
                                .messages_sent
                                .into_iter()
                                .map(|m| {
                                    Ok(gw::L2ToL1Message {
                                        from_address: ContractAddress::new(m.from_address).ok_or(
                                            anyhow::anyhow!(
                                                "Out of range 'from' address {}",
                                                m.from_address
                                            ),
                                        )?,
                                        payload: m
                                            .payload
                                            .into_iter()
                                            .map(L2ToL1MessagePayloadElem)
                                            .collect(),
                                        to_address: EthereumAddress(m.to_address),
                                    })
                                })
                                .collect::<anyhow::Result<Vec<_>>>()?,
                            transaction_hash: TransactionHash(common.transaction_hash),
                            transaction_index: TransactionIndex::new(
                                common.transaction_index.into(),
                            )
                            .expect("u32::MAX is always smaller than i64::MAX"),
                            // FIXME: once p2p supports reverted
                            execution_status: Default::default(),
                            revert_error: Default::default(),
                        })
                    }
                }
            }
        }
    }

    pub mod state_update {
        use std::collections::HashMap;

        use p2p_proto::sync::BlockStateUpdateWithHash;
        use pathfinder_common::{
            BlockHash, CasmHash, ClassHash, ContractAddress, ContractNonce, SierraHash,
            StateCommitment, StorageAddress, StorageValue,
        };
        use starknet_gateway_types::reply as gw;

        #[allow(unused)]
        pub fn try_from_p2p(su: BlockStateUpdateWithHash) -> anyhow::Result<gw::StateUpdate> {
            Ok(gw::StateUpdate {
                block_hash: BlockHash(su.block_hash),
                new_root: StateCommitment(su.state_commitment),
                old_root: StateCommitment(su.parent_state_commitment),
                state_diff: gw::state_update::StateDiff {
                    storage_diffs: su
                        .state_update
                        .contract_diffs
                        .iter()
                        .map(|contract_diff| {
                            Ok((
                                ContractAddress::new(contract_diff.contract_address).ok_or(
                                    anyhow::anyhow!(
                                        "Out of range contract address {}",
                                        contract_diff.contract_address
                                    ),
                                )?,
                                contract_diff
                                    .storage_diffs
                                    .iter()
                                    .map(|x| {
                                        Ok(gw::state_update::StorageDiff {
                                            key: StorageAddress::new(x.key).ok_or(
                                                anyhow::anyhow!("Out of range key {}", x.key),
                                            )?,
                                            value: StorageValue(x.value),
                                        })
                                    })
                                    .collect::<anyhow::Result<_>>()?,
                            ))
                        })
                        .collect::<anyhow::Result<HashMap<_, _>>>()?,
                    deployed_contracts: su
                        .state_update
                        .deployed_contracts
                        .into_iter()
                        .map(|x| {
                            Ok(gw::state_update::DeployedContract {
                                address: ContractAddress::new(x.contract_address).ok_or(
                                    anyhow::anyhow!(
                                        "Out of range contract address {}",
                                        x.contract_address
                                    ),
                                )?,
                                class_hash: ClassHash(x.class_hash),
                            })
                        })
                        .collect::<anyhow::Result<_>>()?,
                    old_declared_contracts: su
                        .state_update
                        .declared_cairo_classes
                        .into_iter()
                        .map(ClassHash)
                        .collect(),
                    declared_classes: su
                        .state_update
                        .declared_classes
                        .into_iter()
                        .map(|x| gw::state_update::DeclaredSierraClass {
                            class_hash: SierraHash(x.sierra_hash),
                            compiled_class_hash: CasmHash(x.casm_hash),
                        })
                        .collect(),
                    nonces: su
                        .state_update
                        .contract_diffs
                        .iter()
                        // Filter out the zero nonce, which does not indicate an update.
                        .filter(|contract_diff| contract_diff.nonce != ContractNonce::ZERO.0)
                        .map(|contract_diff| {
                            Ok((
                                ContractAddress::new(contract_diff.contract_address).ok_or(
                                    anyhow::anyhow!(
                                        "Out of range contract address {}",
                                        contract_diff.contract_address
                                    ),
                                )?,
                                ContractNonce(contract_diff.nonce),
                            ))
                        })
                        .collect::<anyhow::Result<HashMap<_, _>>>()?,
                    replaced_classes: su
                        .state_update
                        .replaced_classes
                        .into_iter()
                        .map(|x| {
                            Ok(gw::state_update::ReplacedClass {
                                address: ContractAddress::new(x.contract_address).ok_or(
                                    anyhow::anyhow!(
                                        "Out of range contract address {}",
                                        x.contract_address
                                    ),
                                )?,
                                class_hash: ClassHash(x.class_hash),
                            })
                        })
                        .collect::<anyhow::Result<_>>()?,
                },
            })
        }
    }
}
