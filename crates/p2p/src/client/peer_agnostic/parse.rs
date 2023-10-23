pub(crate) trait ParserState {
    type Item;
    type Inner;

    fn advance(&mut self, item: Self::Item) -> anyhow::Result<()>
    where
        Self: Default + Sized,
    {
        let current_state = std::mem::take(self);
        let next_state = current_state.transition(item)?;

        *self = next_state;
        // We need to stop parsing when a block is properly delimited but an error was signalled
        // as the peer is not going to send any more blocks.

        if self.should_stop() {
            anyhow::bail!("no data or premature end of response")
        } else {
            Ok(())
        }
    }

    fn transition(self, item: Self::Item) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn take_inner(self) -> Option<Self::Inner>;

    fn should_stop(&self) -> bool;
}

macro_rules! impl_take_inner_and_should_stop {
    ($inner_collection: ident) => {
        fn take_inner(self) -> Option<<Self as super::ParserState>::Inner> {
            match self {
                Self::Delimited { $inner_collection }
                | Self::DelimitedWithError {
                    $inner_collection, ..
                } => {
                    debug_assert!(!$inner_collection.is_empty());
                    Some($inner_collection)
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
    use crate::client::types::BlockHeader;
    use anyhow::Context;
    use p2p_proto_v1::block::BlockHeadersResponsePart;
    use p2p_proto_v1::common::{Error, Fin};

    #[derive(Debug, Default)]
    pub enum State {
        #[default]
        Uninitialized,
        Header {
            headers: Vec<BlockHeader>,
        },
        _Signatures, // TODO add signature support
        Delimited {
            headers: Vec<BlockHeader>,
        },
        DelimitedWithError {
            error: Error,
            headers: Vec<BlockHeader>,
        },
        Empty {
            error: Option<Error>,
        },
    }

    impl super::ParserState for State {
        type Item = BlockHeadersResponsePart;
        type Inner = Vec<BlockHeader>;

        fn transition(self, next: Self::Item) -> anyhow::Result<Self> {
            Ok(match (self, next) {
                (State::Uninitialized, BlockHeadersResponsePart::Header(header)) => {
                    let header = BlockHeader::try_from(*header).context("parsing header")?;
                    Self::Header {
                        headers: vec![header],
                    }
                }
                (State::Uninitialized, BlockHeadersResponsePart::Fin(Fin { error })) => {
                    Self::Empty { error }
                }
                (State::Header { headers }, BlockHeadersResponsePart::Fin(Fin { error })) => {
                    match error {
                        Some(error) => State::DelimitedWithError { error, headers },
                        None => State::Delimited { headers },
                    }
                }
                (State::Delimited { mut headers }, BlockHeadersResponsePart::Header(header)) => {
                    let header = BlockHeader::try_from(*header).context("parsing header")?;
                    headers.push(header);
                    Self::Header { headers }
                }
                (_, _) => anyhow::bail!("unexpected part"),
            })
        }

        impl_take_inner_and_should_stop!(headers);
    }
}

pub(crate) mod state_update {
    use crate::client::types::{Class, StateUpdateWithDefs};
    use p2p_proto_v1::{
        block::{BlockBodiesResponse, BlockBodyMessage},
        common::{BlockId, Error, Fin, Hash},
        consts::MAX_PARTS_PER_CLASS,
        state::Classes,
    };
    use pathfinder_common::{BlockHash, ClassHash};

    #[derive(Debug)]
    pub enum State {
        Uninitialized,
        Diff {
            last_id: BlockId,
            state_updates: Vec<StateUpdateWithDefs>,
        },
        Classes {
            last_id: BlockId,
            state_updates: Vec<StateUpdateWithDefs>,
        },
        _Proof, // TODO add proof support
        Delimited {
            state_updates: Vec<StateUpdateWithDefs>,
        },
        DelimitedWithError {
            error: Error,
            state_updates: Vec<StateUpdateWithDefs>,
        },
        Empty {
            error: Option<Error>,
        },
    }

    impl State {
        pub fn advance(&mut self, r: BlockBodiesResponse) -> anyhow::Result<()> {
            let current_state = std::mem::replace(self, State::Uninitialized);
            let BlockBodiesResponse { id, body_message } = r;
            let next_state = match (current_state, id, body_message) {
                (State::Uninitialized, Some(id), BlockBodyMessage::Diff(diff)) => State::Diff {
                    last_id: id,
                    state_updates: vec![StateUpdateWithDefs {
                        block_hash: BlockHash(id.hash.0),
                        state_update: diff.into(),
                        classes: Default::default(),
                    }],
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
                    State::Classes {
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
                        .last_mut()
                        .expect("state update for this id is present");
                    current.classes.extend(classes_from_dto(classes)?);

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
                    state_updates.push(StateUpdateWithDefs {
                        block_hash: BlockHash(id.hash.0),
                        state_update: diff.into(),
                        classes: Default::default(),
                    });

                    State::Diff {
                        last_id: id,
                        state_updates,
                    }
                }
                (_, _, _) => anyhow::bail!("unexpected response"),
            };

            *self = next_state;
            // We need to stop parsing when a block is properly delimited but an error was signalled
            // as the peer is not going to send any more blocks.

            if self.should_stop() {
                anyhow::bail!("no data or premature end of response")
            } else {
                Ok(())
            }
        }

        pub fn take_inner(self) -> Option<Vec<StateUpdateWithDefs>> {
            match self {
                State::Delimited { state_updates }
                | State::DelimitedWithError { state_updates, .. } => {
                    debug_assert!(!state_updates.is_empty());
                    Some(state_updates)
                }
                _ => None,
            }
        }

        pub fn should_stop(&self) -> bool {
            matches!(self, State::Empty { .. } | State::DelimitedWithError { .. })
        }
    }

    /// Merges partitoned classes if necessary
    fn classes_from_dto(classes: Vec<p2p_proto_v1::state::Class>) -> anyhow::Result<Vec<Class>> {
        #[derive(Copy, Clone, Debug, Default, PartialEq)]
        struct Ctx {
            hash: Hash,
            total_parts: u32,
            part_num: u32,
        }

        impl Ctx {
            fn matches_next_part(&self, hash: Hash, total_parts: u32, part_num: u32) -> bool {
                self.hash == hash
                    && self.total_parts == total_parts
                    && self.part_num + 1 == part_num
            }

            fn advance(mut self) -> Option<Self> {
                // This was the last part
                if self.part_num == self.total_parts {
                    None
                } else {
                    self.part_num += 1;
                    Some(self)
                }
            }
        }

        let mut converted = Vec::new();
        let mut ctx: Option<Ctx> = None;

        for class in classes {
            match (class.total_parts, class.part_num) {
                // Small class definition, not partitioned
                (None, None) => converted.push(Class {
                    hash: ClassHash(class.compiled_hash.0),
                    definition: class.definition,
                }),
                // Large class definition, partitioned. Immediately reject invalid values or
                // obvious attempts at DoS-ing us.
                (Some(total_parts), Some(part_num))
                    if total_parts > 0
                        && total_parts < MAX_PARTS_PER_CLASS
                        && part_num < total_parts =>
                {
                    match ctx {
                        // First part of a larger definition
                        None if part_num == 0 => {
                            converted.push(Class {
                                hash: ClassHash(class.compiled_hash.0),
                                definition: class.definition,
                            });
                            ctx = Some(Ctx {
                                hash: class.compiled_hash,
                                total_parts,
                                part_num,
                            });
                        }
                        // Another part of the same definition
                        Some(some_ctx)
                            if some_ctx.matches_next_part(
                                class.compiled_hash,
                                total_parts,
                                part_num,
                            ) =>
                        {
                            converted
                                .last_mut()
                                .expect("gathered is not empty")
                                .definition
                                .extend(class.definition);

                            ctx = some_ctx.advance();
                        }
                        None | Some(_) => {
                            anyhow::bail!("Invalid Class part: {:?}/{:?}", part_num, total_parts)
                        }
                    }
                }
                _ => anyhow::bail!(
                    "Invalid Class part: {:?}/{:?}",
                    class.part_num,
                    class.total_parts,
                ),
            }
        }

        Ok(converted)
    }
}

pub(crate) mod transactions {
    use crate::client::types::TryFromDto;
    use anyhow::Context;
    use p2p_proto_v1::common::{BlockId, Error, Fin};
    use p2p_proto_v1::transaction::{Transactions, TransactionsResponse, TransactionsResponseKind};
    use pathfinder_common::transaction::TransactionVariant;
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
        type Item = TransactionsResponse;
        type Inner = HashMap<BlockId, Vec<TransactionVariant>>;

        fn transition(self, next: Self::Item) -> anyhow::Result<Self> {
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

        impl_take_inner_and_should_stop!(transactions);
    }
}
