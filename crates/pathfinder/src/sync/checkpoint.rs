#![allow(dead_code, unused_variables)]
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use anyhow::Context;
use futures::{pin_mut, Stream, StreamExt, TryStreamExt};
use p2p::client::conv::TryFromDto;
use p2p::client::peer_agnostic::{
    ClassDefinition,
    Client as P2PClient,
    EventsForBlockByTransaction,
    SignedBlockHeader as P2PSignedBlockHeader,
    UnverifiedStateUpdateData,
    UnverifiedTransactionData,
};
use p2p::PeerData;
use p2p_proto::common::{BlockNumberOrHash, Direction, Iteration};
use p2p_proto::transaction::{TransactionWithReceipt, TransactionsRequest, TransactionsResponse};
use pathfinder_common::receipt::Receipt;
use pathfinder_common::state_update::StateUpdateData;
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{
    BlockHash,
    BlockNumber,
    Chain,
    ChainId,
    ClassHash,
    PublicKey,
    TransactionIndex,
};
use pathfinder_ethereum::EthereumStateUpdate;
use pathfinder_storage::Storage;
use primitive_types::H160;
use serde_json::de;
use starknet_gateway_client::{Client, GatewayApi};
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;
use tracing::Instrument;

use crate::state::block_hash::{
    calculate_transaction_commitment,
    TransactionCommitmentFinalHashType,
};
use crate::sync::error::SyncError;
use crate::sync::stream::{InfallibleSource, Source, SyncReceiver, SyncResult};
use crate::sync::{class_definitions, events, headers, state_updates, transactions};

/// Provides P2P sync capability for blocks secured by L1.
#[derive(Clone)]
pub struct Sync {
    pub storage: Storage,
    pub p2p: P2PClient,
    // TODO: merge these two inside the client.
    pub eth_client: pathfinder_ethereum::EthereumClient,
    pub eth_address: H160,
    pub fgw_client: Client,
    pub chain: Chain,
    pub chain_id: ChainId,
    pub public_key: PublicKey,
}

impl Sync {
    pub fn new(
        storage: Storage,
        p2p: P2PClient,
        ethereum: (pathfinder_ethereum::EthereumClient, H160),
        fgw_client: Client,
        chain: Chain,
        chain_id: ChainId,
        public_key: PublicKey,
    ) -> Self {
        Self {
            storage,
            p2p,
            eth_client: ethereum.0,
            eth_address: ethereum.1,
            fgw_client,
            chain,
            chain_id,
            public_key,
        }
    }

    /// Syncs using p2p until the given Ethereum checkpoint.
    pub async fn run(&self, checkpoint: EthereumStateUpdate) -> Result<(), SyncError> {
        use pathfinder_ethereum::EthereumApi;

        let local_state = LocalState::from_db(self.storage.clone(), checkpoint.clone())
            .await
            .context("Querying local state")?;

        // Ensure our local state is consistent with the L1 checkpoint.
        CheckpointAnalysis::analyse(&local_state, &checkpoint)
            .handle(self.storage.clone())
            .await
            .context("Analysing local storage against L1 checkpoint")?;

        // Persist checkpoint as new L1 anchor. This must be done first to protect
        // against an interrupted sync process. Subsequent syncs will use this
        // value to rollback against. Persisting it later would result in more data than
        // necessary being rolled back (potentially all data if the header sync process
        // is frequently interrupted), so this ensures sync will progress even
        // under bad conditions.
        let anchor = checkpoint;
        persist_anchor(self.storage.clone(), anchor.clone())
            .await
            .context("Persisting new Ethereum anchor")?;

        let head = anchor.block_number;

        // Sync missing headers in reverse chronological order, from the new anchor to
        // genesis.
        self.sync_headers(anchor).await?;

        // Sync the rest of the data in chronological order.
        self.sync_transactions(head, self.chain_id).await?;
        self.sync_state_updates(head).await?;
        self.sync_class_definitions(head).await?;
        self.sync_events(head).await?;

        Ok(())
    }

    /// Syncs all headers in reverse chronological order, from the anchor point
    /// back to genesis. Fills in any gaps left by previous header syncs.
    ///
    /// As sync goes backwards from a known L1 anchor block, this method can
    /// guarantee that all sync'd headers are secured by L1.
    ///
    /// No guarantees are made about any headers newer than the anchor.
    #[tracing::instrument(level = "debug", skip(self))]
    async fn sync_headers(&self, anchor: EthereumStateUpdate) -> Result<(), SyncError> {
        while let Some(gap) =
            headers::next_gap(self.storage.clone(), anchor.block_number, anchor.block_hash)
                .await
                .context("Finding next gap in header chain")?
        {
            tracing::info!(?gap, "Syncing headers");

            handle_header_stream(
                self.p2p.clone().header_stream(gap.tail, gap.head, true),
                gap.head(),
                self.chain,
                self.chain_id,
                self.public_key,
                self.storage.clone(),
            )
            .instrument(tracing::debug_span!("sync_headers", ?gap))
            .await?;
        }

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self))]
    async fn sync_transactions(
        &self,
        stop: BlockNumber,
        chain_id: ChainId,
    ) -> Result<(), SyncError> {
        let Some(start) = transactions::next_missing(self.storage.clone(), stop)
            .await
            .context("Finding next block with missing transaction(s)")?
        else {
            return Ok(());
        };

        let transaction_stream = self.p2p.clone().transaction_stream(
            start,
            stop,
            transactions::counts_and_commitments_stream(self.storage.clone(), start, stop),
        );

        handle_transaction_stream(
            transaction_stream,
            self.storage.connection()?,
            chain_id,
            start,
        )
        .await?;

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self))]
    async fn sync_state_updates(&self, stop: BlockNumber) -> Result<(), SyncError> {
        let Some(start) = state_updates::next_missing(self.storage.clone(), stop)
            .await
            .context("Finding next missing state update")?
        else {
            return Ok(());
        };

        let stream = self.p2p.clone().state_diff_stream(
            start,
            stop,
            state_updates::length_and_commitment_stream(self.storage.clone(), start, stop),
        );

        handle_state_diff_stream(stream, self.storage.connection()?, start).await?;

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self))]
    async fn sync_class_definitions(&self, stop: BlockNumber) -> Result<(), SyncError> {
        let Some(start) = class_definitions::next_missing(self.storage.clone(), stop)
            .await
            .context("Finding next block with missing class definition(s)")?
        else {
            return Ok(());
        };

        let class_stream = self.p2p.clone().class_definition_stream(
            start,
            stop,
            class_definitions::declared_class_counts_stream(self.storage.clone(), start, stop),
        );

        let declared_classes_stream =
            class_definitions::declared_classes_at_block_stream(self.storage.clone(), start, stop);

        handle_class_stream(
            class_stream,
            self.storage.clone(),
            self.fgw_client.clone(),
            declared_classes_stream,
        )
        .await?;

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self))]
    async fn sync_events(&self, stop: BlockNumber) -> Result<(), SyncError> {
        let Some(start) = events::next_missing(self.storage.clone(), stop)
            .await
            .context("Finding next block with missing events")?
        else {
            return Ok(());
        };

        let event_stream = self.p2p.clone().event_stream(
            start,
            stop,
            events::counts_stream(self.storage.clone(), start, stop),
        );

        handle_event_stream(event_stream, self.storage.clone()).await?;

        Ok(())
    }
}

async fn handle_header_stream(
    stream: impl Stream<Item = PeerData<P2PSignedBlockHeader>> + Send + 'static,
    head: (BlockNumber, BlockHash),
    chain: Chain,
    chain_id: ChainId,
    public_key: PublicKey,
    storage: Storage,
) -> Result<(), SyncError> {
    tracing::info!("Syncing headers");
    InfallibleSource::from_stream(stream)
        .spawn()
        .pipe(headers::BackwardContinuity::new(head.0, head.1), 10)
        .pipe(
            headers::VerifyHashAndSignature::new(chain, chain_id, public_key),
            10,
        )
        .try_chunks(1024, 10)
        .pipe(
            headers::Persist {
                connection: storage.connection()?,
            },
            10,
        )
        .into_stream()
        .try_fold((), |_state, _x| std::future::ready(Ok(())))
        .await
        .map_err(SyncError::from_v2)?;
    Ok(())
}

async fn handle_transaction_stream(
    stream: impl Stream<Item = Result<PeerData<UnverifiedTransactionData>, PeerData<anyhow::Error>>>
        + Send
        + 'static,
    db_connection: pathfinder_storage::Connection,
    chain_id: ChainId,
    start: BlockNumber,
) -> Result<(), SyncError> {
    Source::from_stream(stream.map_err(|e| e.map(Into::into)))
        .spawn()
        .pipe(transactions::CalculateHashes(chain_id), 10)
        .pipe(transactions::VerifyCommitment, 10)
        .pipe(transactions::Store::new(db_connection, start), 10)
        .into_stream()
        .inspect_ok(|x| tracing::info!(tail=%x.data, "Transactions chunk synced"))
        .try_fold((), |_, _| std::future::ready(Ok(())))
        .await
        .map_err(SyncError::from_v2)?;
    Ok(())
}

async fn handle_state_diff_stream(
    stream: impl Stream<Item = Result<PeerData<UnverifiedStateUpdateData>, PeerData<anyhow::Error>>>
        + Send
        + 'static,
    db_connection: pathfinder_storage::Connection,
    start: BlockNumber,
) -> Result<(), SyncError> {
    Source::from_stream(stream.map_err(|e| e.map(Into::into)))
        .spawn()
        .pipe(state_updates::VerifyCommitment, 10)
        .pipe(state_updates::Store::new(db_connection, start), 10)
        .into_stream()
        .inspect_ok(|x| tracing::info!(tail=%x.data, "State diff synced"))
        .try_fold((), |_, _| std::future::ready(Ok(())))
        .await
        .map_err(SyncError::from_v2)?;
    Ok(())
}

async fn handle_class_stream<SequencerClient: GatewayApi + Clone + Send>(
    stream: impl Stream<Item = anyhow::Result<PeerData<ClassDefinition>>>,
    storage: Storage,
    fgw: SequencerClient,
    declared_classes_at_block_stream: impl Stream<
        Item = Result<(BlockNumber, HashSet<ClassHash>), SyncError>,
    >,
) -> Result<(), SyncError> {
    let a = stream
        .map_err(Into::into)
        .and_then(class_definitions::verify_layout)
        .and_then(class_definitions::compute_hash);

    pin_mut!(a, declared_classes_at_block_stream);

    let b = class_definitions::verify_declared_at(declared_classes_at_block_stream, a);

    b.and_then(|x| class_definitions::compile_sierra_to_casm_or_fetch(x, fgw.clone()))
        .try_chunks(10)
        .map_err(|e| e.1)
        .and_then(|x| class_definitions::persist(storage.clone(), x))
        .inspect_ok(|x| tracing::info!(tail=%x, "Class definitions chunk synced"))
        // Drive stream to completion.
        .try_fold((), |_, _| std::future::ready(Ok(())))
        .await?;
    Ok(())
}

async fn handle_event_stream(
    stream: impl Stream<Item = anyhow::Result<PeerData<EventsForBlockByTransaction>>>,
    storage: Storage,
) -> Result<(), SyncError> {
    stream
        .map_err(Into::into)
        .and_then(|x| events::verify_commitment(x, storage.clone()))
        .try_chunks(100)
        .map_err(|e| e.1)
        .and_then(|x| events::persist(storage.clone(), x))
        .inspect_ok(|x| tracing::info!(tail=%x, "Events chunk synced"))
        // Drive stream to completion.
        .try_fold((), |_, _| std::future::ready(Ok(())))
        .await?;
    Ok(())
}

/// Performs [analysis](Self::analyse) of the [LocalState] by comparing it with
/// a given L1 checkpoint, and [handles](Self::handle) the result.
enum CheckpointAnalysis {
    /// The checkpoint hash does not match the local L1 anchor, indicating an
    /// inconsistency with the Ethereum source with the one used by the
    /// previous sync.
    HashMismatchWithAnchor {
        block: BlockNumber,
        checkpoint: BlockHash,
        anchor: BlockHash,
    },
    /// The checkpoint is older than the local anchor, indicating an
    /// inconsistency in the Ethereum source between this sync and the
    /// previous sync.
    PredatesAnchor {
        checkpoint: BlockNumber,
        anchor: BlockNumber,
    },
    /// The checkpoint exceeds the local chain. As such, the local chain should
    /// be rolled back to its anchor as we cannot be confident in any of the
    /// local data not verified by L1.
    ExceedsLocalChain {
        local: BlockNumber,
        checkpoint: BlockNumber,
        anchor: Option<BlockNumber>,
    },
    /// The checkpoint hash does not match the local chain data. The local chain
    /// should be rolled back to its anchor.
    HashMismatchWithLocalChain {
        block: BlockNumber,
        local: BlockHash,
        checkpoint: BlockHash,
        anchor: Option<BlockNumber>,
    },
    /// Local data is consistent with the checkpoint, no action required.
    Consistent,
}

impl CheckpointAnalysis {
    /// Analyse [LocalState] by checking it for consistency against the given L1
    /// checkpoint.
    ///
    /// For more information on the potential inconsistencies see the
    /// [CheckpointAnalysis] variants.
    fn analyse(local_state: &LocalState, checkpoint: &EthereumStateUpdate) -> CheckpointAnalysis {
        // Checkpoint is older than or inconsistent with our local L1 anchor.
        if let Some(anchor) = &local_state.anchor {
            if checkpoint.block_number < anchor.block_number {
                return CheckpointAnalysis::PredatesAnchor {
                    checkpoint: checkpoint.block_number,
                    anchor: anchor.block_number,
                };
            }
            if checkpoint.block_number == anchor.block_number
                && checkpoint.block_hash != anchor.block_hash
            {
                return CheckpointAnalysis::HashMismatchWithAnchor {
                    block: anchor.block_number,
                    checkpoint: checkpoint.block_hash,
                    anchor: anchor.block_hash,
                };
            }
        }

        // Is local data not secured by an anchor potentially invalid?
        if let Some(latest) = local_state.latest_header {
            if checkpoint.block_number > latest.0 {
                return CheckpointAnalysis::ExceedsLocalChain {
                    local: latest.0,
                    checkpoint: checkpoint.block_number,
                    anchor: local_state.anchor.as_ref().map(|x| x.block_number),
                };
            }
            if let Some((_, hash)) = local_state.checkpoint {
                if hash != checkpoint.block_hash {
                    return CheckpointAnalysis::HashMismatchWithLocalChain {
                        block: checkpoint.block_number,
                        local: hash,
                        checkpoint: checkpoint.block_hash,
                        anchor: local_state.anchor.as_ref().map(|x| x.block_number),
                    };
                }
            }
        }

        CheckpointAnalysis::Consistent
    }

    /// Handles the [checkpoint analysis](Self::analyse) [result](Self).
    ///
    /// Returns an error for [PredatesAnchor](Self::PredatesAnchor) and
    /// [HashMismatchWithAnchor](Self::HashMismatchWithAnchor) since these
    /// indicate an inconsistency with the Ethereum source - making all data
    /// suspect.
    ///
    /// Rolls back local state to the anchor for
    /// [ExceedsLocalChain](Self::ExceedsLocalChain) and
    /// [HashMismatchWithLocalChain](Self::HashMismatchWithLocalChain)
    /// conditions.
    ///
    /// Does nothing for [Consistent](Self::Consistent). This leaves any
    /// insecure local data intact. Always rolling back to the L1 anchor
    /// would result in a poor user experience if restarting frequently as each
    /// restart would purge new data.
    async fn handle(self, storage: Storage) -> anyhow::Result<()> {
        match self {
            CheckpointAnalysis::HashMismatchWithAnchor {
                block,
                checkpoint,
                anchor,
            } => {
                tracing::error!(
                    %block, %checkpoint, %anchor,
                    "Ethereum checkpoint's hash did not match the local Ethereum anchor. This indicates a serious inconsistency in the Ethereum source used by this sync and the previous sync."
                );
                anyhow::bail!("Ethereum checkpoint hash did not match local anchor.");
            }
            CheckpointAnalysis::PredatesAnchor { checkpoint, anchor } => {
                // TODO: or consider this valid. If so, then we should continue sync but use the
                // local anchor instead of the checkpoint.
                tracing::error!(
                    %checkpoint, %anchor,
                    "Ethereum checkpoint is older than the local anchor. This indicates a serious inconsistency in the Ethereum source used by this sync and the previous sync."
                );
                anyhow::bail!("Ethereum checkpoint hash did not match local anchor.");
            }
            CheckpointAnalysis::ExceedsLocalChain {
                local,
                checkpoint,
                anchor,
            } => {
                tracing::info!(
                    %local, anchor=%anchor.unwrap_or_default(), %checkpoint,
                    "Rolling back local chain to latest anchor point. Local data is potentially invalid as the Ethereum checkpoint is newer the local chain."
                );
                rollback_to_anchor(storage, anchor)
                    .await
                    .context("Rolling back chain state to L1 anchor")?;
            }
            CheckpointAnalysis::HashMismatchWithLocalChain {
                block,
                local,
                checkpoint,
                anchor,
            } => {
                tracing::info!(
                    %block, %local, %checkpoint, ?anchor,
                    "Rolling back local chain to latest anchor point. Local data is invalid as it did not match the Ethereum checkpoint's hash."
                );
                rollback_to_anchor(storage, anchor)
                    .await
                    .context("Rolling back chain state to L1 anchor")?;
            }
            CheckpointAnalysis::Consistent => {
                tracing::info!("Ethereum checkpoint is consistent with local data");
            }
        };

        Ok(())
    }
}

struct LocalState {
    latest_header: Option<(BlockNumber, BlockHash)>,
    anchor: Option<EthereumStateUpdate>,
    checkpoint: Option<(BlockNumber, BlockHash)>,
}

impl LocalState {
    async fn from_db(storage: Storage, checkpoint: EthereumStateUpdate) -> anyhow::Result<Self> {
        // TODO: this should include header gaps.
        spawn_blocking(move || {
            let mut db = storage
                .connection()
                .context("Creating database connection")?;
            let db = db.transaction().context("Creating database transaction")?;

            let latest_header = db
                .block_id(pathfinder_storage::BlockId::Latest)
                .context("Querying latest header")?;

            let checkpoint = db
                .block_id(checkpoint.block_number.into())
                .context("Querying checkpoint header")?;

            let anchor = db.latest_l1_state().context("Querying latest L1 anchor")?;

            Ok(LocalState {
                latest_header,
                checkpoint,
                anchor,
            })
        })
        .await
        .context("Joining blocking task")?
    }
}

/// Rolls back local chain-state until the given anchor point, making it the tip
/// of the local chain. If this is ['None'] then all data will be rolled back.
async fn rollback_to_anchor(storage: Storage, anchor: Option<BlockNumber>) -> anyhow::Result<()> {
    spawn_blocking(move || {
        todo!("Rollback storage to anchor point");
    })
    .await
    .context("Joining blocking task")?
}

async fn persist_anchor(storage: Storage, anchor: EthereumStateUpdate) -> anyhow::Result<()> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
        db.upsert_l1_state(&anchor).context("Inserting anchor")?;
        // TODO: this is a bit dodgy, but is used by the sync process. However it
        // destroys       some RPC assumptions which we should be aware of.
        db.update_l1_l2_pointer(Some(anchor.block_number))
            .context("Updating L1-L2 pointer")?;
        db.commit().context("Committing database transaction")?;
        Ok(())
    })
    .await
    .context("Joining blocking task")?
}

#[cfg(test)]
mod tests {
    use super::*;

    mod handle_header_stream {
        use assert_matches::assert_matches;
        use fake::{Dummy, Fake, Faker};
        use futures::stream;
        use p2p::client::peer_agnostic::BlockHeader as P2PBlockHeader;
        use p2p::libp2p::PeerId;
        use p2p_proto::header;
        use pathfinder_common::{
            public_key,
            BlockCommitmentSignature,
            BlockCommitmentSignatureElem,
            BlockHash,
            BlockHeader,
            BlockTimestamp,
            EventCommitment,
            SequencerAddress,
            StarknetVersion,
            StateCommitment,
            StateDiffCommitment,
            TransactionCommitment,
        };
        use pathfinder_storage::fake::{self as fake_storage, Block};
        use pathfinder_storage::StorageBuilder;
        use serde::Deserialize;
        use serde_with::{serde_as, DisplayFromStr};

        use super::super::handle_header_stream;
        use super::*;

        struct Setup {
            pub streamed_headers: Vec<PeerData<P2PSignedBlockHeader>>,
            pub expected_headers: Vec<P2PSignedBlockHeader>,
            pub storage: Storage,
            pub head: (BlockNumber, BlockHash),
            pub public_key: PublicKey,
        }

        #[serde_as]
        #[derive(Clone, Copy, Debug, Deserialize)]
        pub struct Fixture {
            pub block_hash: BlockHash,
            pub block_number: BlockNumber,
            pub parent_block_hash: BlockHash,
            pub sequencer_address: SequencerAddress,
            pub state_root: StateCommitment,
            pub timestamp: BlockTimestamp,
            pub transaction_commitment: TransactionCommitment,
            pub transaction_count: usize,
            pub event_commitment: EventCommitment,
            pub event_count: usize,
            pub signature: [BlockCommitmentSignatureElem; 2],
            pub state_diff_commitment: StateDiffCommitment,
        }

        impl From<Fixture> for P2PSignedBlockHeader {
            fn from(dto: Fixture) -> Self {
                Self {
                    header: P2PBlockHeader {
                        hash: dto.block_hash,
                        number: dto.block_number,
                        parent_hash: dto.parent_block_hash,
                        sequencer_address: dto.sequencer_address,
                        state_commitment: dto.state_root,
                        timestamp: dto.timestamp,
                        transaction_commitment: dto.transaction_commitment,
                        transaction_count: dto.transaction_count,
                        event_commitment: dto.event_commitment,
                        event_count: dto.event_count,
                        ..Default::default()
                    },
                    signature: BlockCommitmentSignature {
                        r: dto.signature[0],
                        s: dto.signature[1],
                    },
                    state_diff_commitment: dto.state_diff_commitment,
                    ..Default::default()
                }
            }
        }

        async fn setup() -> Setup {
            let expected_headers =
                serde_json::from_str::<Vec<Fixture>>(include_str!("fixtures/sepolia_headers.json"))
                    .unwrap()
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<P2PSignedBlockHeader>>();

            let hdr = &expected_headers.last().unwrap().header;
            Setup {
                head: (hdr.number, hdr.hash),
                streamed_headers: expected_headers
                    .iter()
                    .rev()
                    .cloned()
                    .map(PeerData::for_tests)
                    .collect::<Vec<_>>(),
                expected_headers,
                storage: StorageBuilder::in_memory().unwrap(),
                // https://alpha-sepolia.starknet.io/feeder_gateway/get_public_key
                public_key: public_key!(
                    "0x1252b6bce1351844c677869c6327e80eae1535755b611c66b8f46e595b40eea"
                ),
            }
        }

        #[tokio::test]
        async fn happy_path() {
            let Setup {
                streamed_headers,
                expected_headers,
                storage,
                head,
                public_key,
            } = setup().await;

            handle_header_stream(
                stream::iter(streamed_headers),
                head,
                Chain::SepoliaTestnet,
                ChainId::SEPOLIA_TESTNET,
                public_key,
                storage.clone(),
            )
            .await
            .unwrap();

            let actual_headers = tokio::task::spawn_blocking(move || {
                let mut conn = storage.connection().unwrap();
                let db = conn.transaction().unwrap();
                (0..=head.0.get())
                    .map(|n| {
                        let block_number = BlockNumber::new_or_panic(n);
                        let block_id = block_number.into();
                        let (state_diff_commitment, state_diff_length) = db
                            .state_diff_commitment_and_length(block_number)
                            .unwrap()
                            .unwrap();
                        P2PSignedBlockHeader {
                            header: db.block_header(block_id).unwrap().unwrap().into(),
                            signature: db.signature(block_id).unwrap().unwrap(),
                            state_diff_commitment,
                            state_diff_length: state_diff_length as u64,
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap();

            pretty_assertions_sorted::assert_eq!(expected_headers, actual_headers);
        }

        #[tokio::test]
        async fn discontinuity() {
            let Setup {
                mut streamed_headers,
                storage,
                head,
                public_key,
                ..
            } = setup().await;

            streamed_headers.last_mut().unwrap().data.header.number = BlockNumber::new_or_panic(3);

            assert_matches!(
                handle_header_stream(
                    stream::iter(streamed_headers),
                    head,
                    Chain::SepoliaTestnet,
                    ChainId::SEPOLIA_TESTNET,
                    public_key,
                    storage.clone(),
                )
                .await,
                Err(SyncError::Discontinuity(_))
            );
        }

        #[tokio::test]
        async fn bad_hash() {
            let Setup {
                streamed_headers,
                storage,
                head,
                public_key,
                ..
            } = setup().await;

            assert_matches!(
                handle_header_stream(
                    stream::iter(streamed_headers),
                    head,
                    // Causes mismatches for all block hashes because setup assumes Sepolia
                    Chain::Mainnet,
                    ChainId::MAINNET,
                    public_key,
                    storage.clone(),
                )
                .await,
                Err(SyncError::BadBlockHash(_))
            );
        }

        // TODO readd once the signature verification is enabled
        // #[tokio::test]
        // async fn bad_signature() {
        //     let Setup {
        //         streamed_headers,
        //         storage,
        //         head,
        //         ..
        //     } = setup().await;

        //     assert_matches!(
        //         handle_header_stream(
        //             stream::iter(streamed_headers),
        //             head,
        //             Chain::SepoliaTestnet,
        //             ChainId::SEPOLIA_TESTNET,
        //             PublicKey::ZERO, // Invalid public key
        //             storage.clone(),
        //         )
        //         .await,
        //         Err(SyncError::BadHeaderSignature(_))
        //     );
        // }

        #[tokio::test]
        async fn db_failure() {
            let Setup {
                mut streamed_headers,
                storage,
                head,
                public_key,
                ..
            } = setup().await;

            let mut db = storage.connection().unwrap();
            let db = db.transaction().unwrap();
            let genesis = BlockHeader {
                number: BlockNumber::GENESIS,
                ..Default::default()
            };
            db.insert_block_header(&genesis).unwrap();
            db.commit().unwrap();

            assert_matches!(
                handle_header_stream(
                    stream::iter(streamed_headers),
                    head,
                    Chain::SepoliaTestnet,
                    ChainId::SEPOLIA_TESTNET,
                    public_key,
                    storage.clone(),
                )
                .await,
                Err(SyncError::Other(_))
            );
        }
    }

    mod handle_transaction_stream {
        use assert_matches::assert_matches;
        use fake::{Dummy, Faker};
        use futures::stream;
        use p2p::client::peer_agnostic::UnverifiedTransactionData;
        use p2p::libp2p::PeerId;
        use pathfinder_common::receipt::Receipt;
        use pathfinder_common::transaction::TransactionVariant;
        use pathfinder_common::TransactionHash;
        use pathfinder_crypto::Felt;
        use pathfinder_storage::fake::{self as fake_storage, Block};
        use pathfinder_storage::StorageBuilder;

        use super::super::handle_transaction_stream;
        use super::*;

        struct Setup {
            pub streamed_transactions:
                Vec<Result<PeerData<UnverifiedTransactionData>, PeerData<anyhow::Error>>>,
            pub expected_transactions: Vec<Vec<(Transaction, Receipt)>>,
            pub storage: Storage,
        }

        async fn setup(num_blocks: usize) -> Setup {
            tokio::task::spawn_blocking(move || {
                let mut blocks = fake_storage::init::with_n_blocks(num_blocks);
                let streamed_transactions = blocks
                    .iter_mut()
                    .map(|block| {
                        let transaction_commitment = calculate_transaction_commitment(
                            block
                                .transaction_data
                                .iter()
                                .map(|(t, _, _)| t.clone())
                                .collect::<Vec<_>>()
                                .as_slice(),
                            TransactionCommitmentFinalHashType::Normal,
                        )
                        .unwrap();
                        block.header.header.transaction_commitment = transaction_commitment;

                        anyhow::Result::Ok(PeerData::for_tests(UnverifiedTransactionData {
                            expected_commitment: transaction_commitment,
                            transactions: block
                                .transaction_data
                                .iter()
                                .map(|x| (x.0.variant.clone(), x.1.clone().into()))
                                .collect::<Vec<_>>(),
                        }))
                    })
                    .collect::<Vec<_>>();
                let expected_transactions = blocks
                    .iter()
                    .map(|block| {
                        block
                            .transaction_data
                            .iter()
                            .map(|x| (x.0.clone(), x.1.clone()))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                blocks.iter_mut().for_each(|b| {
                    // Purge transaction data.
                    b.transaction_data = Default::default();
                });

                let storage = StorageBuilder::in_memory().unwrap();
                fake_storage::fill(&storage, &blocks);
                Setup {
                    streamed_transactions,
                    expected_transactions,
                    storage,
                }
            })
            .await
            .unwrap()
        }

        #[tokio::test]
        async fn happy_path() {
            const NUM_BLOCKS: usize = 10;
            let Setup {
                streamed_transactions,
                expected_transactions,
                storage,
            } = setup(NUM_BLOCKS).await;

            let x = expected_transactions
                .iter()
                .map(|x| x.iter().map(|y| y.0.hash).collect::<Vec<_>>())
                .collect::<Vec<_>>();

            handle_transaction_stream(
                stream::iter(streamed_transactions),
                storage.connection().unwrap(),
                ChainId::SEPOLIA_TESTNET,
                BlockNumber::GENESIS,
            )
            .await
            .unwrap();

            let actual_transactions = tokio::task::spawn_blocking(move || {
                let mut conn = storage.connection().unwrap();
                let db_tx = conn.transaction().unwrap();
                (0..NUM_BLOCKS)
                    .map(|n| {
                        db_tx
                            .transactions_with_receipts_for_block(
                                BlockNumber::new_or_panic(n as u64).into(),
                            )
                            .unwrap()
                            .unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap();
            pretty_assertions_sorted::assert_eq!(expected_transactions, actual_transactions);
        }

        #[tokio::test]
        async fn commitment_mismatch() {
            let Setup {
                streamed_transactions,
                storage,
                ..
            } = setup(1).await;
            assert_matches!(
                handle_transaction_stream(
                    stream::iter(streamed_transactions),
                    storage.connection().unwrap(),
                    // Causes mismatches for all transaction hashes because setup assumes
                    // ChainId::SEPOLIA_TESTNET
                    ChainId::MAINNET,
                    BlockNumber::GENESIS,
                )
                .await,
                Err(SyncError::TransactionCommitmentMismatch(_))
            );
        }

        #[tokio::test]
        async fn stream_failure() {
            assert_matches!(
                handle_transaction_stream(
                    stream::once(std::future::ready(Err(PeerData::for_tests(
                        anyhow::anyhow!("")
                    )))),
                    StorageBuilder::in_memory().unwrap().connection().unwrap(),
                    ChainId::SEPOLIA_TESTNET,
                    BlockNumber::GENESIS,
                )
                .await,
                Err(SyncError::Other(_))
            );
        }

        #[tokio::test]
        async fn header_missing() {
            let Setup {
                streamed_transactions,
                ..
            } = setup(1).await;
            assert_matches!(
                handle_transaction_stream(
                    stream::iter(streamed_transactions),
                    StorageBuilder::in_memory().unwrap().connection().unwrap(),
                    ChainId::SEPOLIA_TESTNET,
                    BlockNumber::GENESIS,
                )
                .await,
                Err(SyncError::Other(_))
            );
        }
    }

    mod handle_state_diff_stream {
        use assert_matches::assert_matches;
        use fake::{Dummy, Fake, Faker};
        use futures::stream;
        use p2p::libp2p::PeerId;
        use pathfinder_common::state_update::{ContractClassUpdate, StateUpdateData};
        use pathfinder_common::transaction::DeployTransactionV0;
        use pathfinder_common::TransactionHash;
        use pathfinder_crypto::Felt;
        use pathfinder_storage::fake::{self as fake_storage, Block};
        use pathfinder_storage::StorageBuilder;

        use super::super::handle_state_diff_stream;
        use super::*;

        struct Setup {
            pub streamed_state_diffs:
                Vec<Result<PeerData<UnverifiedStateUpdateData>, PeerData<anyhow::Error>>>,
            pub expected_state_diffs: Vec<StateUpdateData>,
            pub storage: Storage,
        }

        async fn setup(num_blocks: usize) -> Setup {
            tokio::task::spawn_blocking(move || {
                let mut blocks = fake_storage::init::with_n_blocks(num_blocks);
                let streamed_state_diffs = blocks
                    .iter()
                    .map(|block| {
                        Result::<PeerData<_>, PeerData<_>>::Ok(PeerData::for_tests(
                            UnverifiedStateUpdateData {
                                expected_commitment: block.header.state_diff_commitment,
                                state_diff: block.state_update.clone().into(),
                            },
                        ))
                    })
                    .collect::<Vec<_>>();
                let expected_state_diffs = blocks
                    .iter()
                    .map(|block| {
                        // Cairo0 Deploy should also count as implicit declaration
                        let mut state_diff: StateUpdateData = block.state_update.clone().into();
                        block
                            .state_update
                            .contract_updates
                            .iter()
                            .for_each(|(_, v)| {
                                v.class.as_ref().inspect(|class_update| {
                                    if let ContractClassUpdate::Deploy(class_hash) = class_update {
                                        state_diff.declared_cairo_classes.insert(*class_hash);
                                    }
                                });
                            });
                        state_diff
                    })
                    .collect::<Vec<_>>();
                blocks.iter_mut().for_each(|block| {
                    // Purge state diff data and class definitions.
                    block.state_update = Default::default();
                    block.sierra_defs = Default::default();
                    block.cairo_defs = Default::default();
                });

                let storage = StorageBuilder::in_memory().unwrap();
                fake_storage::fill(&storage, &blocks);
                Setup {
                    streamed_state_diffs,
                    expected_state_diffs,
                    storage,
                }
            })
            .await
            .unwrap()
        }

        #[tokio::test]
        async fn happy_path() {
            const NUM_BLOCKS: usize = 10;
            let Setup {
                streamed_state_diffs,
                expected_state_diffs,
                storage,
            } = setup(NUM_BLOCKS).await;

            handle_state_diff_stream(
                stream::iter(streamed_state_diffs),
                storage.connection().unwrap(),
                BlockNumber::GENESIS,
            )
            .await
            .unwrap();

            let actual_state_diffs = tokio::task::spawn_blocking(move || {
                let mut db = storage.connection().unwrap();
                let db = db.transaction().unwrap();
                (0..NUM_BLOCKS)
                    .map(|n| {
                        db.state_update(BlockNumber::new_or_panic(n as u64).into())
                            .unwrap()
                            .unwrap()
                            .into()
                    })
                    .collect::<Vec<StateUpdateData>>()
            })
            .await
            .unwrap();

            pretty_assertions_sorted::assert_eq!(expected_state_diffs, actual_state_diffs);
        }

        #[tokio::test]
        async fn commitment_mismatch() {
            let Setup {
                mut streamed_state_diffs,
                storage,
                ..
            } = setup(1).await;

            streamed_state_diffs[0]
                .as_mut()
                .unwrap()
                .data
                .state_diff
                .declared_cairo_classes
                .insert(Faker.fake());

            assert_matches!(
                handle_state_diff_stream(
                    stream::iter(streamed_state_diffs),
                    StorageBuilder::in_memory().unwrap().connection().unwrap(),
                    BlockNumber::GENESIS,
                )
                .await,
                Err(SyncError::StateDiffCommitmentMismatch(_))
            );
        }

        #[tokio::test]
        async fn stream_failure() {
            assert_matches!(
                handle_state_diff_stream(
                    stream::once(std::future::ready(Err(PeerData::for_tests(
                        anyhow::anyhow!("")
                    )))),
                    StorageBuilder::in_memory().unwrap().connection().unwrap(),
                    BlockNumber::GENESIS,
                )
                .await,
                Err(SyncError::Other(_))
            );
        }

        #[tokio::test]
        async fn header_missing() {
            let Setup {
                streamed_state_diffs,
                ..
            } = setup(1).await;
            assert_matches!(
                handle_state_diff_stream(
                    stream::iter(streamed_state_diffs),
                    StorageBuilder::in_memory().unwrap().connection().unwrap(),
                    BlockNumber::GENESIS,
                )
                .await,
                Err(SyncError::Other(_))
            );
        }
    }

    mod handle_class_stream {
        use std::collections::HashMap;
        use std::future;

        use assert_matches::assert_matches;
        use fake::{Dummy, Fake, Faker};
        use futures::{stream, SinkExt};
        use p2p::libp2p::PeerId;
        use pathfinder_common::event::Event;
        use pathfinder_common::transaction::TransactionVariant;
        use pathfinder_common::{felt, CasmHash, ClassHash, SierraHash, TransactionHash};
        use pathfinder_crypto::Felt;
        use pathfinder_storage::fake::{self as fake_storage, Block};
        use pathfinder_storage::StorageBuilder;
        use starknet_gateway_test_fixtures::class_definitions::{
            CAIRO_0_10_TUPLES_INTEGRATION,
            CAIRO_0_11_SIERRA,
            CAIRO_2_0_0_STACK_OVERFLOW,
        };
        use starknet_gateway_types::error::SequencerError;

        use super::super::handle_class_stream;
        use super::*;
        use crate::state::block_hash::calculate_event_commitment;

        #[derive(Clone)]
        struct FakeFgw;

        #[async_trait::async_trait]
        impl GatewayApi for FakeFgw {
            async fn pending_casm_by_hash(
                &self,
                class_hash: ClassHash,
            ) -> Result<bytes::Bytes, SequencerError> {
                Ok(bytes::Bytes::from_static(b"I'm from the fgw!"))
            }
        }

        #[derive(Clone, Copy, Debug, Dummy)]
        struct DeclaredClass {
            pub block: BlockNumber,
            pub class: ClassHash,
        }

        #[derive(Clone, Debug)]
        struct DeclaredClasses(Vec<DeclaredClass>);

        impl DeclaredClasses {
            pub fn to_stream(
                &self,
            ) -> impl Stream<Item = Result<(BlockNumber, HashSet<ClassHash>), SyncError>>
            {
                let mut all = HashMap::<_, HashSet<ClassHash>>::new();
                self.0
                    .iter()
                    .copied()
                    .for_each(|DeclaredClass { block, class }| {
                        all.entry(block).or_default().insert(class);
                    });
                stream::iter(all.into_iter().map(Ok))
            }
        }

        impl<T> Dummy<T> for DeclaredClasses {
            fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &T, rng: &mut R) -> Self {
                DeclaredClasses(fake::vec![DeclaredClass; 1..10])
            }
        }

        struct Setup {
            pub streamed_classes: Vec<anyhow::Result<PeerData<ClassDefinition>>>,
            pub declared_classes: DeclaredClasses,
            pub expected_defs: Vec<Vec<u8>>,
            pub storage: Storage,
        }

        const ONE: BlockNumber = BlockNumber::new_or_panic(1);

        /// The genesis block contains no declared classes
        async fn setup(expect_correct_class_hashes: bool) -> Setup {
            tokio::task::spawn_blocking(move || {
                let mut blocks = fake_storage::init::with_n_blocks(2);

                blocks[0].state_update.declared_cairo_classes = Default::default();
                blocks[0].state_update.declared_sierra_classes = Default::default();
                blocks[0].cairo_defs = Default::default();
                blocks[0].sierra_defs = Default::default();

                let (cairo_hash, sierra_hash, sierra_hash2) = if expect_correct_class_hashes {
                    (
                        ClassHash(felt!(
                            "0x542460935cea188d21e752d8459d82d60497866aaad21f873cbb61621d34f7f"
                        )),
                        SierraHash(felt!(
                            "0x4e70b19333ae94bd958625f7b61ce9eec631653597e68645e13780061b2136c"
                        )),
                        SierraHash(felt!(
                            "0x03dd9347d22f1ea2d5fbc7bd1f0860c6c334973499f9f1989fcb81bfff5191da"
                        )),
                    )
                } else {
                    Default::default()
                };
                blocks[1].state_update.declared_cairo_classes = [cairo_hash].into();
                blocks[1].state_update.declared_sierra_classes = [
                    (sierra_hash, Default::default()),
                    (sierra_hash2, Default::default()),
                ]
                .into();
                blocks[1].cairo_defs = vec![(cairo_hash, CAIRO_0_10_TUPLES_INTEGRATION.to_vec())];
                blocks[1].sierra_defs = vec![
                    // Does not compile
                    (sierra_hash, CAIRO_0_11_SIERRA.to_vec(), Default::default()),
                    // Compiles just fine
                    (
                        sierra_hash2,
                        CAIRO_2_0_0_STACK_OVERFLOW.to_vec(),
                        Default::default(),
                    ),
                ];

                let (declared_classes, streamed_classes) = blocks[1]
                    .cairo_defs
                    .iter()
                    .cloned()
                    .map(|(hash, definition)| {
                        let block_number = blocks[1].header.header.number;
                        (
                            DeclaredClass {
                                block: block_number,
                                class: hash,
                            },
                            anyhow::Result::Ok(PeerData::for_tests(ClassDefinition::Cairo {
                                block_number,
                                definition,
                            })),
                        )
                    })
                    .chain(blocks[1].sierra_defs.iter().cloned().map(
                        |(sierra_hash, sierra_definition, _)| {
                            let block_number = blocks[1].header.header.number;
                            (
                                DeclaredClass {
                                    block: block_number,
                                    class: ClassHash(sierra_hash.0),
                                },
                                anyhow::Result::Ok(PeerData::for_tests(ClassDefinition::Sierra {
                                    block_number,
                                    sierra_definition,
                                })),
                            )
                        },
                    ))
                    .unzip::<_, _, Vec<_>, Vec<_>>();
                let expected_defs = streamed_classes
                    .iter()
                    .map(|class| {
                        let class = &class.as_ref().unwrap().data;
                        class.class_definition()
                    })
                    .collect::<Vec<Vec<u8>>>();

                let storage = StorageBuilder::in_memory().unwrap();
                fake_storage::fill(&storage, &blocks);
                Setup {
                    streamed_classes,
                    declared_classes: DeclaredClasses(declared_classes),
                    expected_defs,
                    storage,
                }
            })
            .await
            .unwrap()
        }

        #[tokio::test]
        async fn happy_path() {
            let Setup {
                streamed_classes,
                declared_classes,
                expected_defs,
                storage,
            } = setup(true).await;

            handle_class_stream(
                stream::iter(streamed_classes),
                storage.clone(),
                FakeFgw,
                declared_classes.to_stream(),
            )
            .await
            .unwrap();

            let actual_defs = tokio::task::spawn_blocking(move || {
                let mut conn = storage.connection().unwrap();
                let db_tx = conn.transaction().unwrap();
                declared_classes
                    .0
                    .into_iter()
                    .map(|x| {
                        (
                            db_tx
                                .class_definition_at(x.block.into(), x.class)
                                .unwrap()
                                .unwrap(),
                            db_tx.casm_definition_at(x.block.into(), x.class).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap();

            // Cairo0
            assert_eq!(actual_defs[0].0, expected_defs[0]);
            assert!(actual_defs[0].1.is_none());
            // Cairo1
            assert_eq!(actual_defs[1].0, expected_defs[1]);
            // Compilation failed
            assert_eq!(actual_defs[1].1, Some(b"I'm from the fgw!".to_vec()));
            // Cairo1
            assert_eq!(actual_defs[2].0, expected_defs[2]);
            // Compilation succeeded, poor man's sanity check
            assert!(serde_json::from_slice::<serde_json::Value>(
                actual_defs[2].1.as_ref().unwrap()
            )
            .unwrap()["compiler_version"]
                .is_string());
        }

        #[rstest::rstest]
        #[case::cairo(ClassDefinition::Cairo {
            block_number: ONE,
            definition: Default::default()
        })]
        #[case::sierra(ClassDefinition::Sierra {
            block_number: ONE,
            sierra_definition: Default::default(),
        })]
        #[tokio::test]
        async fn bad_layout(#[case] class: ClassDefinition) {
            let storage = StorageBuilder::in_memory().unwrap();
            let data = PeerData::for_tests(class);
            let expected_peer_id = data.peer;

            assert_matches!(
                handle_class_stream(stream::once(std::future::ready(Ok(data))), storage, FakeFgw, Faker.fake::<DeclaredClasses>().to_stream())
                    .await,
                Err(SyncError::BadClassLayout(x)) => assert_eq!(x, expected_peer_id)
            );
        }

        #[tokio::test]
        async fn unexpected_class() {
            let Setup {
                streamed_classes,
                mut declared_classes,
                storage,
                ..
            } = setup(true).await;

            declared_classes.0.last_mut().unwrap().class = Faker.fake();
            let expected_peer_id = streamed_classes.last().unwrap().as_ref().unwrap().peer;

            assert_matches!(
                handle_class_stream(stream::iter(streamed_classes), storage, FakeFgw, declared_classes.to_stream())
                    .await,
                Err(SyncError::UnexpectedClass(x)) => assert_eq!(x, expected_peer_id)
            );
        }

        #[tokio::test]
        async fn stream_failure() {
            assert_matches!(
                handle_class_stream(
                    stream::once(std::future::ready(Err(anyhow::anyhow!("")))),
                    StorageBuilder::in_memory().unwrap(),
                    FakeFgw,
                    Faker.fake::<DeclaredClasses>().to_stream()
                )
                .await,
                Err(SyncError::Other(_))
            );
        }
    }

    mod handle_event_stream {
        use assert_matches::assert_matches;
        use fake::{Fake, Faker};
        use futures::stream;
        use p2p::libp2p::PeerId;
        use pathfinder_common::event::Event;
        use pathfinder_common::transaction::TransactionVariant;
        use pathfinder_common::TransactionHash;
        use pathfinder_crypto::Felt;
        use pathfinder_storage::{fake as fake_storage, StorageBuilder};

        use super::super::handle_event_stream;
        use super::*;
        use crate::state::block_hash::calculate_event_commitment;

        struct Setup {
            pub streamed_events: Vec<anyhow::Result<PeerData<EventsForBlockByTransaction>>>,
            pub expected_events: Vec<Vec<(TransactionHash, Vec<Event>)>>,
            pub storage: Storage,
        }

        async fn setup(num_blocks: usize, compute_event_commitments: bool) -> Setup {
            tokio::task::spawn_blocking(move || {
                let mut blocks = fake_storage::init::with_n_blocks(num_blocks);
                let streamed_events = blocks
                    .iter()
                    .map(|block| {
                        anyhow::Result::Ok(PeerData::for_tests((
                            block.header.header.number,
                            block
                                .transaction_data
                                .iter()
                                .map(|x| x.2.clone())
                                .collect::<Vec<_>>(),
                        )))
                    })
                    .collect::<Vec<_>>();
                let expected_events = blocks
                    .iter()
                    .map(|block| {
                        block
                            .transaction_data
                            .iter()
                            .map(|x| (x.0.hash, x.2.clone()))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                let storage = StorageBuilder::in_memory().unwrap();
                blocks.iter_mut().for_each(|block| {
                    if compute_event_commitments {
                        block.header.header.event_commitment = calculate_event_commitment(
                            &block
                                .transaction_data
                                .iter()
                                .flat_map(|(_, _, events)| events)
                                .collect::<Vec<_>>(),
                        )
                        .unwrap();
                    }
                    // Purge events
                    block
                        .transaction_data
                        .iter_mut()
                        .for_each(|(_, _, events)| events.clear());
                    block.cairo_defs.iter_mut().for_each(|(_, def)| def.clear());
                });
                fake_storage::fill(&storage, &blocks);
                Setup {
                    streamed_events,
                    expected_events,
                    storage,
                }
            })
            .await
            .unwrap()
        }

        #[tokio::test]
        async fn happy_path() {
            const NUM_BLOCKS: usize = 10;
            let Setup {
                streamed_events,
                expected_events,
                storage,
            } = setup(NUM_BLOCKS, true).await;

            handle_event_stream(stream::iter(streamed_events), storage.clone())
                .await
                .unwrap();

            let actual_events = tokio::task::spawn_blocking(move || {
                let mut conn = storage.connection().unwrap();
                let db_tx = conn.transaction().unwrap();
                (0..NUM_BLOCKS)
                    .map(|n| {
                        db_tx
                            .events_for_block(BlockNumber::new_or_panic(n as u64).into())
                            .unwrap()
                            .unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap();

            pretty_assertions_sorted::assert_eq!(expected_events, actual_events);
        }

        #[tokio::test]
        async fn commitment_mismatch() {
            const NUM_BLOCKS: usize = 1;
            let Setup {
                streamed_events,
                expected_events,
                storage,
            } = setup(NUM_BLOCKS, false).await;
            let expected_peer_id = streamed_events[0].as_ref().unwrap().peer;

            assert_matches::assert_matches!(
                handle_event_stream(stream::iter(streamed_events), storage.clone())
                    .await
                    .unwrap_err(),
                SyncError::EventCommitmentMismatch(x) => assert_eq!(x, expected_peer_id)
            );
        }

        #[tokio::test]
        async fn stream_failure() {
            assert_matches::assert_matches!(
                handle_event_stream(
                    stream::once(std::future::ready(Err(anyhow::anyhow!("")))),
                    StorageBuilder::in_memory().unwrap()
                )
                .await
                .unwrap_err(),
                SyncError::Other(_)
            );
        }

        #[tokio::test]
        async fn header_missing() {
            assert_matches::assert_matches!(
                handle_event_stream(
                    stream::once(std::future::ready(Ok(Faker.fake()))),
                    StorageBuilder::in_memory().unwrap()
                )
                .await
                .unwrap_err(),
                SyncError::Other(_)
            );
        }
    }
}
