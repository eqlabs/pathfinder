//! Sync related data retrieval from other peers
//!
//! This is a temporary wrapper around proper p2p sync|propagation api that fits into
//! current sequential sync logic and will be removed when __proper__ sync algo is
//! integrated. What it does is just split methods between a "proxy" node
//! that syncs from the gateway and propagates new headers and a
//! "proper" p2p node which only syncs via p2p.

use anyhow::Context;
use p2p::{client::peer_agnostic, HeadRx};
use p2p_proto::class::{Cairo0Class, Cairo1Class};
use pathfinder_common::{
    BlockCommitmentSignature, BlockCommitmentSignatureElem, BlockHash, BlockHeader, BlockId,
    BlockNumber, ByteCodeOffset, CasmHash, ClassHash, EntryPoint, SierraHash, StateCommitment,
    StateDiffCommitment, StateUpdate, TransactionHash,
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
use std::collections::{HashMap, VecDeque};
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
        match self {
            HybridClient::GatewayProxy { sequencer, .. } => sequencer.block(block).await,
            HybridClient::NonPropagatingP2P {
                p2p_client, cache, ..
            } => match block {
                BlockId::Number(_) => {
                    todo!()
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

    async fn state_update(&self, _: BlockId) -> Result<StateUpdate, SequencerError> {
        todo!()
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
