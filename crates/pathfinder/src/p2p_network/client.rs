//! Sync related data retrieval from other peers
//!
//! This is a temporary wrapper around proper p2p sync|propagation api that fits into
//! current sequential sync logic and will be removed when __proper__ sync algo is
//! integrated. What it does is just split methods between a "proxy" node
//! that syncs from the gateway and propagates new headers and a
//! "proper" p2p node which only syncs via p2p.

use lru::LruCache;
use p2p::client::types::BlockHeader;
use p2p::{client::peer_agnostic, client::types::StateUpdateWithDefs, HeadRx};
use pathfinder_common::SierraHash;
use pathfinder_common::{
    state_update::{ContractClassUpdate, ContractUpdate},
    TransactionIndex,
};
use pathfinder_common::{
    transaction::Transaction, BlockHash, BlockId, BlockNumber, CallParam, CasmHash, ClassHash,
    ContractAddress, ContractAddressSalt, EntryPoint, Fee, StateCommitment, StateUpdate,
    TransactionHash, TransactionNonce, TransactionSignatureElem, TransactionVersion,
};
use starknet_gateway_client::{GatewayApi, GossipApi};
use starknet_gateway_types::reply as gw;
use starknet_gateway_types::request::add_transaction::ContractDefinition;
use starknet_gateway_types::{error::SequencerError, reply::Block};
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

pub mod v0;
pub mod v1;

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

#[derive(Clone, Debug)]
pub struct Cache {
    inner: Arc<Mutex<LruCache<BlockHash, CacheEntry>>>,
}

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub block: Block,
    pub definitions: HashMap<ClassHash, Vec<u8>>,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            // We only need 2 blocks: the last one and its parent
            inner: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(2).unwrap()))),
        }
    }
}

impl Cache {
    fn get_block(&self, number: BlockNumber) -> Option<Block> {
        let locked = self.inner.lock().unwrap();
        locked
            .iter()
            .find_map(|(_, v)| (v.block.block_number == number).then_some(v.block.clone()))
    }

    fn get_definition(&self, class_hash: ClassHash) -> Option<Vec<u8>> {
        let locked = self.inner.lock().unwrap();
        locked
            .iter()
            .find_map(|(_, v)| v.definitions.get(&class_hash).cloned())
    }

    fn clear_if_reorg(&self, header: &BlockHeader) {
        if let Some(parent_number) = header.number.get().checked_sub(1) {
            let mut locked = self.inner.lock().unwrap();
            if let Some(cached_parent_hash) = locked
                .iter()
                .find_map(|(k, v)| (v.block.block_number.get() == parent_number).then_some(k))
            {
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

    fn insert_block(&self, block: Block) {
        let mut locked_inner = self.inner.lock().unwrap();
        locked_inner.put(
            block.block_hash,
            CacheEntry {
                block,
                definitions: Default::default(),
            },
        );
    }

    fn insert_definitions(&self, block_hash: BlockHash, definitions: HashMap<ClassHash, Vec<u8>>) {
        let mut locked = self.inner.lock().unwrap();
        locked
            .get_mut(&block_hash)
            .expect("block is already cached")
            .definitions = definitions;
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

                        let mut headers =
                            p2p_client.block_headers(n, 1).await.map_err(|error| {
                                block_not_found(format!(
                                    "getting headers failed: block {n}, {error}",
                                ))
                            })?;

                        if headers.len() != 1 {
                            return Err(block_not_found(format!(
                                "headers len for block {n} is {}, expected 1",
                                headers.len()
                            )));
                        }

                        let header = headers.swap_remove(0);

                        if header.number != n {
                            return Err(block_not_found("block number mismatch"));
                        }

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

                        use crate::p2p_network::client::v1::types::Receipt;

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
                            gas_price: Some(header.gas_price),
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

                        cache.insert_block(block.clone());

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
                let jh = tokio::task::spawn_blocking(move || zstd::decode_all(def.as_slice()));
                let def = jh
                    .await
                    .map_err(|error| {
                        class_not_found(format!(
                            "class decompression task ended unexpectedly: {error}"
                        ))
                    })?
                    .map_err(|error| {
                        class_not_found(format!("class decompression failed: {error}"))
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
        use error::{block_not_found, class_not_found};

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

                    let StateUpdateWithDefs {
                        block_hash,
                        state_update,
                        classes,
                    } = state_updates.swap_remove(0);

                    if block_hash != hash {
                        return Err(block_not_found("Block hash mismatch"));
                    }

                    #[derive(serde::Deserialize)]
                    #[serde(untagged)]
                    enum SierraOrCairo<'a> {
                        Sierra {
                            #[allow(unused)]
                            #[serde(borrow)]
                            sierra_program: &'a serde_json::value::RawValue,
                        },
                        Cairo {
                            #[allow(unused)]
                            #[serde(borrow)]
                            program: &'a serde_json::value::RawValue,
                        },
                    }

                    let jh = tokio::task::spawn_blocking(move || {
                        let mut declared_cairo_classes = HashSet::new();
                        let mut declared_sierra_classes = HashMap::new();
                        let mut definitions = HashMap::new();

                        for class in classes {
                            let definition = zstd::decode_all(class.definition.as_slice())
                                .map_err(|_| class_not_found("zstd failed"))?;

                            match serde_json::from_slice::<SierraOrCairo<'_>>(definition.as_slice())
                            {
                                Ok(SierraOrCairo::Sierra { .. }) => {
                                    // We don't verify the class hash so casm hash is not needed (?)
                                    declared_sierra_classes
                                        .insert(SierraHash(class.hash.0), CasmHash::ZERO);
                                    definitions.insert(class.hash, definition);
                                }
                                Ok(SierraOrCairo::Cairo { .. }) => {
                                    declared_cairo_classes.insert(class.hash);
                                    definitions.insert(class.hash, definition);
                                }
                                Err(_) => {
                                    return Err(class_not_found("invalid class definition"));
                                }
                            }
                        }

                        Ok((declared_cairo_classes, declared_sierra_classes, definitions))
                    });

                    let (declared_cairo_classes, declared_sierra_classes, definitions) =
                        jh.await.map_err(|error| {
                            class_not_found(format!(
                                "class definition decompression task ended unexpectedly: {error}"
                            ))
                        })??;

                    cache.insert_definitions(hash, definitions);

                    Ok(StateUpdate {
                        block_hash: hash,
                        // We don't verify the state commitment so both commitments are 0
                        parent_state_commitment: StateCommitment::default(),
                        state_commitment: StateCommitment::default(),
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
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: Option<TransactionNonce>,
        contract_address: ContractAddress,
        entry_point_selector: Option<EntryPoint>,
        calldata: Vec<CallParam>,
    ) -> Result<gw::add_transaction::InvokeResponse, SequencerError> {
        self.as_sequencer()
            .add_invoke_transaction(
                version,
                max_fee,
                signature,
                nonce,
                contract_address,
                entry_point_selector,
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
    ) -> Result<gw::add_transaction::DeclareResponse, SequencerError> {
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
    ) -> Result<gw::add_transaction::DeployAccountResponse, SequencerError> {
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
}

#[async_trait::async_trait]
impl GossipApi for HybridClient {
    async fn propagate_head(&self, block_number: BlockNumber, block_hash: BlockHash) {
        use p2p_proto_v1::common::{BlockId, Hash};
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
