pub(crate) trait ParserState {
    type Dto;
    type Inner;
    type Out;

    fn advance(&mut self, item: Self::Dto) -> anyhow::Result<()>
    where
        Self: Default + Sized,
    {
        let current_state = std::mem::take(self);
        let next_state = current_state.transition(item)?;

        *self = next_state;

        if self.should_stop() {
            anyhow::bail!("no data or premature end of response")
        } else {
            Ok(())
        }
    }

    fn transition(self, item: Self::Dto) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn from_inner(inner: Self::Inner) -> Self::Out;

    fn take_parsed(self) -> Option<Self::Out>;

    fn should_stop(&self) -> bool;
}

macro_rules! impl_take_parsed_and_should_stop {
    ($inner_collection: ident) => {
        fn take_parsed(self) -> Option<<Self as super::ParserState>::Out> {
            match self {
                Self::Delimited { $inner_collection }
                | Self::DelimitedWithError {
                    $inner_collection, ..
                } => {
                    debug_assert!(!$inner_collection.is_empty());
                    Some(Self::from_inner($inner_collection))
                }
                _ => None,
            }
        }

        fn should_stop(&self) -> bool {
            matches!(self, Self::Empty { .. } | Self::DelimitedWithError { .. })
        }
    };
}

pub(crate) mod block_header {
    use crate::client::types::{BlockHeader, MaybeSignedBlockHeader};
    use anyhow::Context;
    use p2p_proto::block::BlockHeadersResponsePart;
    use p2p_proto::common::{Error, Fin};
    use pathfinder_common::{
        signature::BlockCommitmentSignature, BlockCommitmentSignatureElem, BlockHash,
    };
    use std::collections::HashMap;

    #[derive(Debug, Default)]
    pub enum State {
        #[default]
        Uninitialized,
        Header {
            current: BlockHash,
            headers: HashMap<BlockHash, MaybeSignedBlockHeader>,
        },
        Signatures {
            headers: HashMap<BlockHash, MaybeSignedBlockHeader>,
        },
        Delimited {
            headers: HashMap<BlockHash, MaybeSignedBlockHeader>,
        },
        DelimitedWithError {
            error: Error,
            headers: HashMap<BlockHash, MaybeSignedBlockHeader>,
        },
        Empty {
            error: Option<Error>,
        },
    }

    impl super::ParserState for State {
        type Dto = BlockHeadersResponsePart;
        type Inner = HashMap<BlockHash, MaybeSignedBlockHeader>;
        type Out = Vec<MaybeSignedBlockHeader>;

        fn transition(self, next: Self::Dto) -> anyhow::Result<Self> {
            Ok(match (self, next) {
                (State::Uninitialized, BlockHeadersResponsePart::Header(header)) => {
                    let header = BlockHeader::try_from(*header).context("parsing header")?;
                    Self::Header {
                        current: header.hash,
                        headers: [(header.hash, header.into())].into(),
                    }
                }
                (State::Uninitialized, BlockHeadersResponsePart::Fin(Fin { error })) => {
                    Self::Empty { error }
                }
                (
                    State::Header {
                        current,
                        mut headers,
                    },
                    BlockHeadersResponsePart::Signatures(signatures),
                ) => {
                    if current != BlockHash(signatures.block.hash.0) {
                        anyhow::bail!("unexpected part");
                    }

                    headers
                        .get_mut(&current)
                        .expect("header for this hash is present")
                        .signatures
                        .extend(signatures.signatures.into_iter().map(|signature| {
                            BlockCommitmentSignature {
                                r: BlockCommitmentSignatureElem(signature.r),
                                s: BlockCommitmentSignatureElem(signature.s),
                            }
                        }));
                    Self::Signatures { headers }
                }
                (
                    State::Header { headers, .. } | State::Signatures { headers },
                    BlockHeadersResponsePart::Fin(Fin { error }),
                ) => match error {
                    Some(error) => State::DelimitedWithError { error, headers },
                    None => State::Delimited { headers },
                },
                (State::Delimited { mut headers }, BlockHeadersResponsePart::Header(header)) => {
                    if headers.contains_key(&BlockHash(header.hash.0)) {
                        anyhow::bail!("unexpected part");
                    }

                    let current = BlockHash(header.hash.0);
                    let header = BlockHeader::try_from(*header).context("parsing header")?;
                    headers.insert(header.hash, header.into());
                    Self::Header { current, headers }
                }
                (_, _) => anyhow::bail!("unexpected part"),
            })
        }

        fn from_inner(inner: Self::Inner) -> Self::Out {
            inner.into_values().collect()
        }

        impl_take_parsed_and_should_stop!(headers);
    }
}

pub(crate) mod state_update {
    use crate::client::types::{StateUpdate, StateUpdateWithDefinitions};
    use p2p_proto::{
        block::{BlockBodiesResponse, BlockBodyMessage},
        common::{BlockId, Error, Fin},
        state::{Class, Classes},
    };
    use pathfinder_common::BlockHash;
    use std::collections::HashMap;

    #[derive(Debug, Default)]
    pub enum State {
        #[default]
        Uninitialized,
        Diff {
            last_id: BlockId,
            state_updates: HashMap<BlockId, (StateUpdate, Vec<Class>)>,
        },
        Classes {
            last_id: BlockId,
            state_updates: HashMap<BlockId, (StateUpdate, Vec<Class>)>,
        },
        _Proof, // TODO add proof support
        Delimited {
            state_updates: HashMap<BlockId, (StateUpdate, Vec<Class>)>,
        },
        DelimitedWithError {
            error: Error,
            state_updates: HashMap<BlockId, (StateUpdate, Vec<Class>)>,
        },
        Empty {
            error: Option<Error>,
        },
    }

    impl super::ParserState for State {
        type Dto = BlockBodiesResponse;
        type Inner = HashMap<BlockId, (StateUpdate, Vec<Class>)>;
        type Out = Vec<StateUpdateWithDefinitions>;

        fn transition(self, item: Self::Dto) -> anyhow::Result<Self> {
            let BlockBodiesResponse { id, body_message } = item;
            Ok(match (self, id, body_message) {
                (State::Uninitialized, Some(id), BlockBodyMessage::Diff(diff)) => State::Diff {
                    last_id: id,
                    state_updates: [(id, (diff.into(), Default::default()))].into(),
                },
                (State::Uninitialized, _, BlockBodyMessage::Fin(Fin { error })) => {
                    State::Empty { error }
                }
                (
                    State::Diff {
                        last_id,
                        state_updates,
                    }
                    | State::Classes {
                        last_id,
                        state_updates,
                    },
                    Some(id),
                    BlockBodyMessage::Fin(Fin { error }),
                ) if last_id == id => match error {
                    Some(error) => State::DelimitedWithError {
                        error,
                        state_updates,
                    },
                    None => State::Delimited { state_updates },
                },
                (
                    State::Diff {
                        last_id,
                        mut state_updates,
                    }
                    | State::Classes {
                        last_id,
                        mut state_updates,
                    },
                    Some(id),
                    BlockBodyMessage::Classes(Classes {
                        domain: _, // TODO
                        classes,
                    }),
                ) if last_id == id => {
                    let current = state_updates
                        .get_mut(&id)
                        .expect("state update for this id is present");
                    current.1.extend(classes);

                    State::Classes {
                        last_id,
                        state_updates,
                    }
                }
                (
                    State::Delimited { mut state_updates },
                    Some(id),
                    BlockBodyMessage::Diff(diff),
                ) => {
                    if state_updates.contains_key(&id) {
                        anyhow::bail!("unexpected response");
                    }

                    state_updates.insert(id, (diff.into(), Default::default()));

                    State::Diff {
                        last_id: id,
                        state_updates,
                    }
                }
                (_, _, _) => anyhow::bail!("unexpected response"),
            })
        }

        fn from_inner(inner: Self::Inner) -> Self::Out {
            inner
                .into_iter()
                .map(|(k, v)| StateUpdateWithDefinitions {
                    block_hash: BlockHash(k.hash.0),
                    state_update: v.0,
                    classes: v.1,
                })
                .collect()
        }

        impl_take_parsed_and_should_stop!(state_updates);
    }
}

pub(crate) mod transactions {
    use crate::client::types::TryFromDto;
    use anyhow::Context;
    use p2p_proto::common::{BlockId, Error, Fin};
    use p2p_proto::transaction::{Transactions, TransactionsResponse, TransactionsResponseKind};
    use pathfinder_common::transaction::TransactionVariant;
    use pathfinder_common::BlockHash;
    use std::collections::HashMap;

    #[derive(Debug, Default)]
    pub enum State {
        #[default]
        Uninitialized,
        Transactions {
            last_id: BlockId,
            transactions: HashMap<BlockId, Vec<TransactionVariant>>,
        },
        Delimited {
            transactions: HashMap<BlockId, Vec<TransactionVariant>>,
        },
        DelimitedWithError {
            error: Error,
            transactions: HashMap<BlockId, Vec<TransactionVariant>>,
        },
        Empty {
            error: Option<Error>,
        },
    }

    impl super::ParserState for State {
        type Dto = TransactionsResponse;
        type Inner = HashMap<BlockId, Vec<TransactionVariant>>;
        type Out = HashMap<BlockHash, Vec<TransactionVariant>>;

        fn transition(self, next: Self::Dto) -> anyhow::Result<Self> {
            let TransactionsResponse { id, kind } = next;
            Ok(match (self, id, kind) {
                // We've just started, accept any transactions from some block
                (
                    State::Uninitialized,
                    Some(id),
                    TransactionsResponseKind::Transactions(Transactions { items }),
                ) => State::Transactions {
                    last_id: id,
                    transactions: [(
                        id,
                        items
                            .into_iter()
                            .map(TransactionVariant::try_from_dto)
                            .collect::<anyhow::Result<Vec<_>>>()
                            .context("parsing transactions")?,
                    )]
                    .into(),
                },
                // The peer does not have anything we asked for
                (State::Uninitialized, _, TransactionsResponseKind::Fin(Fin { error })) => {
                    State::Empty { error }
                }
                // There's more transactions for the same block
                (
                    State::Transactions {
                        last_id,
                        mut transactions,
                    },
                    Some(id),
                    TransactionsResponseKind::Transactions(Transactions { items }),
                ) if last_id == id => {
                    transactions
                        .get_mut(&id)
                        .expect("transactions for this id is present")
                        .extend(
                            items
                                .into_iter()
                                .map(TransactionVariant::try_from_dto)
                                .collect::<anyhow::Result<Vec<_>>>()
                                .context("parsing transactions")?,
                        );

                    State::Transactions {
                        last_id,
                        transactions,
                    }
                }
                // This is the end of the current block
                (
                    State::Transactions {
                        last_id,
                        transactions,
                    },
                    Some(id),
                    TransactionsResponseKind::Fin(Fin { error }),
                ) if last_id == id => match error {
                    Some(error) => State::DelimitedWithError {
                        error,
                        transactions,
                    },
                    None => State::Delimited { transactions },
                },
                // Accepting transactions for some other block we've not seen yet
                (
                    State::Delimited { mut transactions },
                    Some(id),
                    TransactionsResponseKind::Transactions(Transactions { items }),
                ) => {
                    debug_assert!(!transactions.is_empty());

                    if transactions.contains_key(&id) {
                        anyhow::bail!("unexpected response");
                    }

                    transactions.insert(
                        id,
                        items
                            .into_iter()
                            .map(TransactionVariant::try_from_dto)
                            .collect::<anyhow::Result<Vec<_>>>()
                            .context("parsing transactions")?,
                    );

                    State::Transactions {
                        last_id: id,
                        transactions,
                    }
                }
                (_, _, _) => anyhow::bail!("unexpected response"),
            })
        }

        fn from_inner(inner: Self::Inner) -> Self::Out {
            inner
                .into_iter()
                .map(|(k, v)| (BlockHash(k.hash.0), v))
                .collect()
        }

        impl_take_parsed_and_should_stop!(transactions);
    }
}

pub(crate) mod receipts {
    use p2p_proto::common::{BlockId, Error, Fin};
    use p2p_proto::receipt::{Receipt, Receipts, ReceiptsResponse, ReceiptsResponseKind};
    use pathfinder_common::BlockHash;
    use std::collections::HashMap;

    #[derive(Debug, Default)]
    pub enum State {
        #[default]
        Uninitialized,
        Receipts {
            last_id: BlockId,
            receipts: HashMap<BlockId, Vec<Receipt>>,
        },
        Delimited {
            receipts: HashMap<BlockId, Vec<Receipt>>,
        },
        DelimitedWithError {
            error: Error,
            receipts: HashMap<BlockId, Vec<Receipt>>,
        },
        Empty {
            error: Option<Error>,
        },
    }

    impl super::ParserState for State {
        type Dto = ReceiptsResponse;
        type Inner = HashMap<BlockId, Vec<Receipt>>;
        type Out = HashMap<BlockHash, Vec<Receipt>>;

        fn transition(self, next: Self::Dto) -> anyhow::Result<Self> {
            let ReceiptsResponse { id, kind } = next;
            Ok(match (self, id, kind) {
                // We've just started, accept any receipts from some block
                (
                    State::Uninitialized,
                    Some(id),
                    ReceiptsResponseKind::Receipts(Receipts { items }),
                ) => State::Receipts {
                    last_id: id,
                    receipts: [(id, items)].into(),
                },
                // The peer does not have anything we asked for
                (State::Uninitialized, _, ReceiptsResponseKind::Fin(Fin { error })) => {
                    State::Empty { error }
                }
                // There's more receipts for the same block
                (
                    State::Receipts {
                        last_id,
                        mut receipts,
                    },
                    Some(id),
                    ReceiptsResponseKind::Receipts(Receipts { items }),
                ) if last_id == id => {
                    receipts
                        .get_mut(&id)
                        .expect("transactions for this id is present")
                        .extend(items);

                    State::Receipts { last_id, receipts }
                }
                // This is the end of the current block
                (
                    State::Receipts { last_id, receipts },
                    Some(id),
                    ReceiptsResponseKind::Fin(Fin { error }),
                ) if last_id == id => match error {
                    Some(error) => State::DelimitedWithError { error, receipts },
                    None => State::Delimited { receipts },
                },
                // Accepting receipts for some other block we've not seen yet
                (
                    State::Delimited { mut receipts },
                    Some(id),
                    ReceiptsResponseKind::Receipts(Receipts { items }),
                ) => {
                    debug_assert!(!receipts.is_empty());

                    if receipts.contains_key(&id) {
                        anyhow::bail!("unexpected response");
                    }

                    receipts.insert(id, items);

                    State::Receipts {
                        last_id: id,
                        receipts,
                    }
                }
                (_, _, _) => anyhow::bail!("unexpected response"),
            })
        }

        fn from_inner(inner: Self::Inner) -> Self::Out {
            inner
                .into_iter()
                .map(|(k, v)| (BlockHash(k.hash.0), v))
                .collect()
        }

        impl_take_parsed_and_should_stop!(receipts);
    }
}

pub(crate) mod events {
    use p2p_proto::common::{BlockId, Error, Fin};
    use p2p_proto::event::{Event, Events, EventsResponse, EventsResponseKind};
    use pathfinder_common::{BlockHash, TransactionHash};
    use std::collections::HashMap;

    #[derive(Debug, Default)]
    pub enum State {
        #[default]
        Uninitialized,
        Events {
            last_id: BlockId,
            events: HashMap<BlockId, Vec<Event>>,
        },
        Delimited {
            events: HashMap<BlockId, Vec<Event>>,
        },
        DelimitedWithError {
            error: Error,
            events: HashMap<BlockId, Vec<Event>>,
        },
        Empty {
            error: Option<Error>,
        },
    }

    impl super::ParserState for State {
        type Dto = EventsResponse;
        type Inner = HashMap<BlockId, Vec<Event>>;
        type Out =
            HashMap<BlockHash, HashMap<TransactionHash, Vec<pathfinder_common::event::Event>>>;

        fn transition(self, next: Self::Dto) -> anyhow::Result<Self> {
            let EventsResponse { id, kind } = next;
            Ok(match (self, id, kind) {
                // We've just started, accept any events from some block
                (State::Uninitialized, Some(id), EventsResponseKind::Events(Events { items })) => {
                    State::Events {
                        last_id: id,
                        events: [(id, items)].into(),
                    }
                }
                // The peer does not have anything we asked for
                (State::Uninitialized, _, EventsResponseKind::Fin(Fin { error })) => {
                    State::Empty { error }
                }
                // There's more events for the same block
                (
                    State::Events {
                        last_id,
                        mut events,
                    },
                    Some(id),
                    EventsResponseKind::Events(Events { items }),
                ) if last_id == id => {
                    events
                        .get_mut(&id)
                        .expect("transactions for this id is present")
                        .extend(items);

                    State::Events { last_id, events }
                }
                // This is the end of the current block
                (
                    State::Events { last_id, events },
                    Some(id),
                    EventsResponseKind::Fin(Fin { error }),
                ) if last_id == id => match error {
                    Some(error) => State::DelimitedWithError { error, events },
                    None => State::Delimited { events },
                },
                // Accepting events for some other block we've not seen yet
                (
                    State::Delimited { mut events },
                    Some(id),
                    EventsResponseKind::Events(Events { items }),
                ) => {
                    debug_assert!(!events.is_empty());

                    if events.contains_key(&id) {
                        anyhow::bail!("unexpected response");
                    }

                    events.insert(id, items);

                    State::Events {
                        last_id: id,
                        events,
                    }
                }
                (_, _, _) => anyhow::bail!("unexpected response"),
            })
        }

        fn from_inner(inner: Self::Inner) -> Self::Out {
            use pathfinder_common::{event::Event, ContractAddress, EventData, EventKey};

            inner
                .into_iter()
                .map(|(k, v)| {
                    let mut events = HashMap::<_, Vec<Event>>::new();
                    v.into_iter().for_each(|e| {
                        events
                            .entry(TransactionHash(e.transaction_hash.0))
                            .or_default()
                            .push(Event {
                                data: e.data.into_iter().map(EventData).collect(),
                                from_address: ContractAddress(e.from_address),
                                keys: e.keys.into_iter().map(EventKey).collect(),
                            })
                    });

                    (BlockHash(k.hash.0), events)
                })
                .collect()
        }

        impl_take_parsed_and_should_stop!(events);
    }
}
