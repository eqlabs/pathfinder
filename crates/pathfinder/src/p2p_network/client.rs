//! Sync related data retrieval from other peers
//!
//! This is a temporary wrapper around proper p2p sync|propagation api that fits into
//! current sequential sync logic and will be removed when __proper__ sync algo is
//! integrated. What it does is just split methods between a "proxy" node
//! that syncs from the gateway and propagates new headers and a
//! "proper" p2p node which only syncs via p2p.

use anyhow::Context;
use p2p::client::types::{BlockHeader, MaybeSignedBlockHeader, StateUpdateWithDefinitions};
use p2p::{client::peer_agnostic, HeadRx};
use p2p_proto::state::{Cairo0Class, Cairo1Class, Class};
use pathfinder_common::state_update::{ContractClassUpdate, ContractUpdate};
use pathfinder_common::transaction::Transaction;
use pathfinder_common::{
    BlockCommitmentSignature, BlockCommitmentSignatureElem, BlockHash, BlockId, BlockNumber,
    ByteCodeOffset, CasmHash, ClassHash, EntryPoint, SierraHash, StateCommitment,
    StateDiffCommitment, StateUpdate, TransactionHash, TransactionIndex,
};
use pathfinder_crypto::Felt;
use serde::Deserialize;
use serde_json::value::RawValue;
use starknet_gateway_client::{GatewayApi, GossipApi};
use starknet_gateway_types::class_definition::{self, SierraEntryPoints};
use starknet_gateway_types::class_hash::from_parts::{
    compute_cairo_class_hash, compute_sierra_class_hash,
};
use starknet_gateway_types::reply::{self as gw, BlockSignature};
use starknet_gateway_types::request::add_transaction::{Declare, DeployAccount, InvokeFunction};
use starknet_gateway_types::request::contract::{SelectorAndFunctionIndex, SelectorAndOffset};
use starknet_gateway_types::trace;
use starknet_gateway_types::{error::SequencerError, reply::Block};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

pub mod types;

/// Hybrid, as it uses either p2p or the gateway depending on role and api call
#[derive(Clone, Debug)]
pub enum HybridClient {
    /// Syncs from the feeder gateway, propagates new headers via p2p/gossipsub
    /// Proxies blockchain data to non propagating nodes via p2p
    GatewayProxy {
        p2p_client: peer_agnostic::Client,
        sequencer: starknet_gateway_client::Client,
    },
    /// Syncs from p2p network, does not propagate
    NonPropagatingP2P {
        p2p_client: peer_agnostic::Client,
        sequencer: starknet_gateway_client::Client,
        head_rx: HeadRx,
        /// We need to cache the last two fetched blocks via p2p otherwise sync logic will
        /// produce a false reorg from genesis when we loose connection to other p2p nodes.
        /// This was we can stay at the same height while we are disconnected.
        cache: Cache,
    },
}

/// We only need to cache 2 blocks: the last one and its parent.
const CACHE_SIZE: usize = 2;

#[derive(Clone, Debug)]
pub struct Cache {
    inner: Arc<Mutex<VecDeque<CacheEntry>>>,
}

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub block: Block,
    pub signature: BlockCommitmentSignature,
    pub class_definitions: HashMap<ClassHash, Vec<u8>>,
    pub casm_definitions: HashMap<ClassHash, Vec<u8>>,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

impl Cache {
    fn get_block(&self, number: BlockNumber) -> Option<Block> {
        let locked = self.inner.lock().unwrap();
        locked
            .iter()
            .find_map(|v| (v.block.block_number == number).then_some(v.block.clone()))
    }

    fn get_signature(&self, block_hash: BlockHash) -> Option<BlockSignature> {
        let locked = self.inner.lock().unwrap();
        locked.iter().find_map(|entry| {
            (entry.block.block_hash == block_hash).then_some(BlockSignature {
                // Not used in sync
                block_number: entry.block.block_number,
                // Only this field is used in sync
                signature: [
                    BlockCommitmentSignatureElem(entry.signature.r.0),
                    BlockCommitmentSignatureElem(entry.signature.s.0),
                ],
                // Not used in sync
                signature_input: gw::BlockSignatureInput {
                    block_hash,
                    state_diff_commitment: StateDiffCommitment::default(), // This is fine
                },
            })
        })
    }

    fn get_state_commitment(&self, block_hash: BlockHash) -> Option<StateCommitment> {
        let locked = self.inner.lock().unwrap();
        locked.iter().find_map(|entry| {
            (entry.block.block_hash == block_hash).then_some(entry.block.state_commitment)
        })
    }

    fn get_definition(&self, class_hash: ClassHash) -> Option<Vec<u8>> {
        let locked = self.inner.lock().unwrap();
        locked
            .iter()
            .find_map(|entry| entry.class_definitions.get(&class_hash).cloned())
    }

    fn get_casm(&self, class_hash: ClassHash) -> Option<Vec<u8>> {
        let locked = self.inner.lock().unwrap();
        locked
            .iter()
            .find_map(|entry| entry.casm_definitions.get(&class_hash).cloned())
    }

    fn clear_if_reorg(&self, header: &BlockHeader) {
        if let Some(parent_number) = header.number.get().checked_sub(1) {
            let mut locked = self.inner.lock().unwrap();
            if let Some(cached_parent_hash) = locked.iter().find_map(|entry| {
                (entry.block.block_number.get() == parent_number).then_some(entry.block.block_hash)
            }) {
                // If there's a reorg, purge the cache or we'll be stuck
                //
                // There's a risk we'll falsely reorg to genesis if all other peers get disconnected
                // just after the cache is purged
                // TODO: consider increasing the cache and just purging the last block
                if cached_parent_hash.0 != header.parent_hash.0 {
                    locked.clear();
                }
            }
        }
    }

    fn insert_block_and_signature(&self, block: Block, signature: BlockCommitmentSignature) {
        let mut locked_inner = self.inner.lock().unwrap();
        locked_inner.push_front(CacheEntry {
            block,
            signature,
            class_definitions: Default::default(),
            casm_definitions: Default::default(),
        });
        if locked_inner.len() > CACHE_SIZE {
            locked_inner.pop_back();
        }
    }

    fn insert_definitions(
        &self,
        block_hash: BlockHash,
        class_definitions: HashMap<ClassHash, Vec<u8>>,
        casm_definitions: HashMap<ClassHash, Vec<u8>>,
    ) {
        let mut locked = self.inner.lock().unwrap();
        let entry = locked
            .iter_mut()
            .find(|entry| entry.block.block_hash == block_hash)
            .expect("block is already cached");
        entry.class_definitions = class_definitions;
        entry.casm_definitions = casm_definitions;
    }
}

impl HybridClient {
    pub fn new(
        i_am_proxy: bool,
        p2p_client: peer_agnostic::Client,
        sequencer: starknet_gateway_client::Client,
        head_rx: HeadRx,
    ) -> Self {
        if i_am_proxy {
            Self::GatewayProxy {
                p2p_client,
                sequencer,
            }
        } else {
            Self::NonPropagatingP2P {
                p2p_client,
                sequencer,
                head_rx,
                cache: Default::default(),
            }
        }
    }

    fn as_sequencer(&self) -> &starknet_gateway_client::Client {
        match self {
            HybridClient::GatewayProxy { sequencer, .. } => sequencer,
            HybridClient::NonPropagatingP2P { sequencer, .. } => sequencer,
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
    async fn block(&self, block: BlockId) -> Result<gw::MaybePendingBlock, SequencerError> {
        use error::block_not_found;

        match self {
            HybridClient::GatewayProxy { sequencer, .. } => sequencer.block(block).await,
            HybridClient::NonPropagatingP2P {
                p2p_client, cache, ..
            } => {
                match block {
                    BlockId::Number(n) => {
                        if let Some(block) = cache.get_block(n) {
                            tracing::trace!(number=%n, "HybridClient: using cached block");
                            return Ok(block.into());
                        }

                        let headers = p2p_client.block_headers(n, 1).await.map_err(|error| {
                            block_not_found(format!("getting headers failed: block {n}, {error}",))
                        })?;

                        if headers.len() != 1 {
                            return Err(block_not_found(format!(
                                "headers len for block {n} is {}, expected 1",
                                headers.len()
                            )));
                        }

                        let MaybeSignedBlockHeader { header, signatures } =
                            headers.into_iter().next().expect("len is 1");

                        if header.number != n {
                            return Err(block_not_found("block number mismatch"));
                        }

                        if signatures.len() != 1 {
                            return Err(block_not_found("expected 1 block header signature"));
                        }

                        let signature = signatures.into_iter().next().expect("len is 1");

                        cache.clear_if_reorg(&header);

                        let block_hash = header.hash;

                        let mut transactions = p2p_client
                            .transactions(header.hash, 1)
                            .await
                            .map_err(|error| {
                                block_not_found(format!(
                                    "getting transactions failed: block {n}: {error}",
                                ))
                            })?;

                        let transactions = transactions.remove(&block_hash).ok_or_else(|| {
                            block_not_found(format!("no peers with transactions for block {n}",))
                        })?;

                        let receipts =
                            p2p_client.receipts(header.hash, 1).await.map_err(|error| {
                                block_not_found(format!(
                                    "getting receipts failed: block {n}: {error}",
                                ))
                            })?;

                        use crate::p2p_network::client::types::Receipt;

                        let mut receipts = receipts
                            .into_iter()
                            .map(|(k, v)| {
                                v.into_iter()
                                    .map(Receipt::try_from)
                                    .collect::<Result<Vec<_>, _>>()
                                    .map(|r| (k, r))
                            })
                            .collect::<Result<HashMap<_, _>, _>>()
                            .map_err(|error| {
                                block_not_found(format!(
                                    "failed to parse receipts for block {n}: {error}",
                                ))
                            })?;

                        let receipts = receipts.remove(&block_hash).ok_or_else(|| {
                            block_not_found(format!("no peers with receipts for block {n}",))
                        })?;

                        debug_assert_eq!(transactions.len(), receipts.len());

                        let mut events =
                            p2p_client.event(header.hash, 1).await.map_err(|error| {
                                block_not_found(format!(
                                    "getting events failed: block {n}: {error}",
                                ))
                            })?;

                        let mut events = events.remove(&block_hash).ok_or_else(|| {
                            block_not_found(format!("no peers with events for block {n}",))
                        })?;

                        // TODO: assume order is the same because proto::transaction does not carry transaction hash
                        let (transactions, receipts): (Vec<_>, Vec<_>) = transactions
                            .into_iter()
                            .zip(receipts)
                            .enumerate()
                            .map(|(i, (t, r))| {
                                let (execution_status, revert_error) = if r.revert_error.is_empty()
                                {
                                    (gw::transaction::ExecutionStatus::Succeeded, None)
                                } else {
                                    (
                                        gw::transaction::ExecutionStatus::Reverted,
                                        Some(r.revert_error),
                                    )
                                };

                                (
                                    gw::transaction::Transaction::from(Transaction {
                                        hash: r.transaction_hash,
                                        variant: t,
                                    }),
                                    gw::transaction::Receipt {
                                        actual_fee: Some(r.actual_fee),
                                        events: events
                                            .remove(&r.transaction_hash)
                                            .unwrap_or_default(),
                                        execution_resources: Some(r.execution_resources),
                                        l1_to_l2_consumed_message: r.l1_to_l2_consumed_message,
                                        l2_to_l1_messages: r.l2_to_l1_messages,
                                        transaction_hash: r.transaction_hash,
                                        transaction_index: TransactionIndex::new_or_panic(i as u64),
                                        execution_status,
                                        revert_error,
                                    },
                                )
                            })
                            .unzip();

                        let block = gw::Block {
                            block_hash: header.hash,
                            block_number: header.number,
                            eth_l1_gas_price: Some(header.eth_l1_gas_price),
                            strk_l1_gas_price: None,
                            parent_block_hash: header.parent_hash,
                            sequencer_address: Some(header.sequencer_address),
                            state_commitment: header.state_commitment,
                            // FIXME
                            status: gw::Status::AcceptedOnL2,
                            timestamp: header.timestamp,
                            transaction_receipts: receipts,
                            transactions,
                            starknet_version: header.starknet_version,
                        };

                        cache.insert_block_and_signature(block.clone(), signature);

                        Ok(block.into())
                    }
                    BlockId::Latest => {
                        unreachable!("GatewayApi.head() is used in sync and sync status instead")
                    }
                    BlockId::Hash(_) => unreachable!("not used in sync"),
                    BlockId::Pending => {
                        unreachable!("pending should be disabled when p2p is enabled")
                    }
                }
            }
        }
    }

    async fn block_without_retry(
        &self,
        block: BlockId,
    ) -> Result<gw::MaybePendingBlock, SequencerError> {
        match self {
            HybridClient::GatewayProxy { sequencer, .. } => {
                sequencer.block_without_retry(block).await
            }
            HybridClient::NonPropagatingP2P { .. } => {
                unreachable!("used for gas price and not in sync")
            }
        }
    }

    async fn pending_class_by_hash(
        &self,
        class_hash: ClassHash,
    ) -> Result<bytes::Bytes, SequencerError> {
        use error::class_not_found;

        match self {
            HybridClient::GatewayProxy { sequencer, .. } => {
                sequencer.pending_class_by_hash(class_hash).await
            }
            HybridClient::NonPropagatingP2P { cache, .. } => {
                let def = cache
                    .get_definition(class_hash)
                    .ok_or_else(|| class_not_found(format!("No peers with class {class_hash}")))?;
                Ok(def.into())
            }
        }
    }

    async fn pending_casm_by_hash(
        &self,
        class_hash: ClassHash,
    ) -> Result<bytes::Bytes, SequencerError> {
        use error::class_not_found;

        match self {
            HybridClient::GatewayProxy { sequencer, .. } => {
                sequencer.pending_casm_by_hash(class_hash).await
            }
            HybridClient::NonPropagatingP2P { cache, .. } => {
                let def = cache.get_casm(class_hash).ok_or_else(|| {
                    class_not_found(format!("No peers with casm for class {class_hash}"))
                })?;
                Ok(def.into())
            }
        }
    }

    async fn transaction(
        &self,
        transaction_hash: TransactionHash,
    ) -> Result<gw::TransactionStatus, SequencerError> {
        self.as_sequencer().transaction(transaction_hash).await
    }

    async fn state_update(&self, block: BlockId) -> Result<StateUpdate, SequencerError> {
        use error::block_not_found;

        match self {
            HybridClient::GatewayProxy { sequencer, .. } => sequencer.state_update(block).await,
            HybridClient::NonPropagatingP2P {
                p2p_client, cache, ..
            } => match block {
                BlockId::Hash(hash) => {
                    let mut state_updates =
                        p2p_client.state_updates(hash, 1).await.map_err(|error| {
                            block_not_found(format!(
                                "No peers with state update for block {hash}: {error}"
                            ))
                        })?;

                    if state_updates.len() != 1 {
                        return Err(block_not_found(format!(
                            "State updates len is {}, expected 1",
                            state_updates.len()
                        )));
                    }

                    let StateUpdateWithDefinitions {
                        block_hash,
                        state_update,
                        classes,
                    } = state_updates.swap_remove(0);

                    if block_hash != hash {
                        return Err(block_not_found("Block hash mismatch"));
                    }

                    let mut declared_cairo_classes = HashSet::new();
                    let mut declared_sierra_classes = HashMap::new();
                    let mut class_definitions = HashMap::new();
                    let mut casm_definitions = HashMap::new();

                    for class in classes {
                        match class {
                            Class::Cairo0(c0) => {
                                let jh = tokio::task::spawn_blocking(move || {
                                    cairo_hash_and_def_from_dto(c0)
                                });
                                let (class_hash, class_def) = jh
                                    .await
                                    .map_err(block_not_found)?
                                    .map_err(block_not_found)?;
                                declared_cairo_classes.insert(class_hash);
                                class_definitions.insert(class_hash, class_def);
                            }
                            Class::Cairo1(c1) => {
                                let jh = tokio::task::spawn_blocking(move || {
                                    sierra_defs_and_hashes_from_dto(c1)
                                });
                                let (sierra_hash, sierra_def, casm_hash, casm) = jh
                                    .await
                                    .map_err(block_not_found)?
                                    .map_err(block_not_found)?;
                                declared_sierra_classes.insert(sierra_hash, casm_hash);
                                let class_hash = ClassHash(sierra_hash.0);
                                class_definitions.insert(class_hash, sierra_def);
                                casm_definitions.insert(class_hash, casm);
                            }
                        }
                    }

                    cache.insert_definitions(hash, class_definitions, casm_definitions);

                    let state_commitment =
                        cache.get_state_commitment(block_hash).unwrap_or_default();

                    Ok(StateUpdate {
                        block_hash,
                        // Luckily this field is only used when polling pending which is disabled with p2p
                        parent_state_commitment: StateCommitment::default(),
                        state_commitment,
                        contract_updates: state_update
                            .contract_updates
                            .into_iter()
                            .map(|(k, v)| {
                                (
                                    k,
                                    ContractUpdate {
                                        storage: v.storage,
                                        // It does not matter if we mark class updates as "deploy" or "replace"
                                        // as the way those updates are inserted into our storage is "deploy/replace-agnostic"
                                        class: v.class.map(ContractClassUpdate::Deploy),
                                        nonce: v.nonce,
                                    },
                                )
                            })
                            .collect(),
                        system_contract_updates: state_update.system_contract_updates,
                        declared_cairo_classes,
                        declared_sierra_classes,
                    })
                }
                _ => unreachable!("not used in sync"),
            },
        }
    }

    async fn eth_contract_addresses(&self) -> Result<gw::EthContractAddresses, SequencerError> {
        self.as_sequencer().eth_contract_addresses().await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_invoke_transaction(
        &self,
        invoke_function: InvokeFunction,
    ) -> Result<gw::add_transaction::InvokeResponse, SequencerError> {
        self.as_sequencer()
            .add_invoke_transaction(invoke_function)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_declare_transaction(
        &self,
        declare: Declare,
        token: Option<String>,
    ) -> Result<gw::add_transaction::DeclareResponse, SequencerError> {
        self.as_sequencer()
            .add_declare_transaction(declare, token)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_deploy_account(
        &self,
        deploy_account: DeployAccount,
    ) -> Result<gw::add_transaction::DeployAccountResponse, SequencerError> {
        self.as_sequencer().add_deploy_account(deploy_account).await
    }

    /// This is a **temporary** measure to keep the sync logic unchanged
    ///
    /// TODO remove me when sync is changed to use the high level (ie. peer unaware) p2p API
    async fn head(&self) -> Result<(BlockNumber, BlockHash), SequencerError> {
        match self {
            HybridClient::GatewayProxy { sequencer, .. } => sequencer.head().await,
            HybridClient::NonPropagatingP2P { head_rx, .. } => {
                let head = *head_rx.borrow();
                tracing::trace!(?head, "HybridClient::head");
                head.ok_or(error::block_not_found(
                    "Haven't received any gossiped head yet",
                ))
            }
        }
    }

    async fn block_traces(&self, block: BlockId) -> Result<trace::BlockTrace, SequencerError> {
        // Not used in sync, so we can just always proxy
        self.as_sequencer().block_traces(block).await
    }

    async fn transaction_trace(
        &self,
        transaction: TransactionHash,
    ) -> Result<trace::TransactionTrace, SequencerError> {
        // Not used in sync, so we can just always proxy
        self.as_sequencer().transaction_trace(transaction).await
    }

    async fn signature(&self, block: BlockId) -> Result<gw::BlockSignature, SequencerError> {
        match self {
            HybridClient::GatewayProxy { sequencer, .. } => sequencer.signature(block).await,
            HybridClient::NonPropagatingP2P { cache, .. } => cache
                .get_signature(match block {
                    BlockId::Hash(hash) => hash,
                    _ => unreachable!("not used in sync"),
                })
                .ok_or_else(|| {
                    error::block_not_found(format!("No peers with signature for block {block:?}"))
                }),
        }
    }
}

fn cairo_hash_and_def_from_dto(c0: Cairo0Class) -> anyhow::Result<(ClassHash, Vec<u8>)> {
    let from_dto = |x: Vec<p2p_proto::state::EntryPoint>| {
        x.into_iter()
            .map(|e| SelectorAndOffset {
                selector: EntryPoint(e.selector),
                offset: ByteCodeOffset(e.offset),
            })
            .collect::<Vec<_>>()
    };

    let abi = c0.abi;
    let program = c0.program;
    let external = from_dto(c0.externals);
    let l1_handler = from_dto(c0.l1_handlers);
    let constructor = from_dto(c0.constructors);

    let external_entry_points = external.clone();
    let l1_handler_entry_points = l1_handler.clone();
    let constructor_entry_points = constructor.clone();

    let class_hash = compute_cairo_class_hash(
        &abi,
        &program,
        external_entry_points,
        l1_handler_entry_points,
        constructor_entry_points,
    )
    .context("compute cairo class hash")?;

    #[derive(Debug, Deserialize)]
    struct Abi<'a>(#[serde(borrow)] &'a RawValue);

    let class_def = class_definition::Cairo {
        abi: Cow::Borrowed(serde_json::from_slice::<Abi<'_>>(&abi).unwrap().0),
        program: serde_json::from_slice(&program)
            .context("verify that cairo class program is UTF-8")?,
        entry_points_by_type: class_definition::CairoEntryPoints {
            external,
            l1_handler,
            constructor,
        },
    };
    let class_def = serde_json::to_vec(&class_def).context("serialize cairo class definition")?;
    Ok((class_hash, class_def))
}

fn sierra_defs_and_hashes_from_dto(
    c1: Cairo1Class,
) -> Result<(SierraHash, Vec<u8>, CasmHash, Vec<u8>), SequencerError> {
    let from_dto = |x: Vec<p2p_proto::state::SierraEntryPoint>| {
        x.into_iter()
            .map(|e| SelectorAndFunctionIndex {
                selector: EntryPoint(e.selector),
                function_idx: e.index,
            })
            .collect::<Vec<_>>()
    };

    let abi = std::str::from_utf8(&c1.abi)
        .map_err(|e| error::block_not_found(format!("Sierra class abi is not valid UTF-8: {e}")))?;
    let entry_points = SierraEntryPoints {
        external: from_dto(c1.entry_points.externals),
        l1_handler: from_dto(c1.entry_points.l1_handlers),
        constructor: from_dto(c1.entry_points.constructors),
    };
    let program = c1.program;
    let contract_class_version = c1.contract_class_version;
    let compiled = c1.compiled;

    let program_clone = program.clone();
    let entry_points_clone = entry_points.clone();
    let sierra_hash = SierraHash(
        compute_sierra_class_hash(
            abi,
            program_clone,
            &contract_class_version,
            entry_points_clone,
        )
        .map_err(|e| error::block_not_found(format!("Failed to compute sierra class hash: {e}")))?
        .0,
    );

    use cairo_lang_starknet::casm_contract_class::CasmContractClass;

    let ccc: CasmContractClass = serde_json::from_slice(&compiled).map_err(|e| {
        error::block_not_found(format!("Sierra class compiled is not valid UTF-8: {e}"))
    })?;

    let casm_hash = CasmHash(
        Felt::from_be_bytes(ccc.compiled_class_hash().to_be_bytes()).map_err(|e| {
            error::block_not_found(format!("Failed to compute casm class hash: {e}"))
        })?,
    );

    let class_def = class_definition::Sierra {
        abi: Cow::Borrowed(abi),
        sierra_program: program,
        contract_class_version: contract_class_version.into(),
        entry_points_by_type: entry_points,
    };

    let class_def = serde_json::to_vec(&class_def).map_err(|e| {
        error::block_not_found(format!("Failed to serialize sierra class definition: {e}"))
    })?;

    Ok((sierra_hash, class_def, casm_hash, compiled))
}

#[async_trait::async_trait]
impl GossipApi for HybridClient {
    async fn propagate_head(&self, block_number: BlockNumber, block_hash: BlockHash) {
        use p2p_proto::common::{BlockId, Hash};
        match self {
            HybridClient::GatewayProxy { p2p_client, .. } => {
                match p2p_client
                    .propagate_new_head(BlockId {
                        number: block_number.get(),
                        hash: Hash(block_hash.0),
                    })
                    .await
                {
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "Propagating head failed"),
                }
            }
            HybridClient::NonPropagatingP2P { .. } => {
                // This is why it's called non-propagating
            }
        }
    }
}
