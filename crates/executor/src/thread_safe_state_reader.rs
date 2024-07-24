use std::sync::mpsc;

use blockifier::state::state_api::StateReader;

enum Request {
    GetStorageAt {
        contract_address: starknet_api::core::ContractAddress,
        key: starknet_api::state::StorageKey,
        response_tx: mpsc::SyncSender<
            blockifier::state::state_api::StateResult<starknet_types_core::felt::Felt>,
        >,
    },
    GetNonceAt {
        contract_address: starknet_api::core::ContractAddress,
        response_tx:
            mpsc::SyncSender<blockifier::state::state_api::StateResult<starknet_api::core::Nonce>>,
    },
    GetClassHashAt {
        contract_address: starknet_api::core::ContractAddress,
        response_tx: mpsc::SyncSender<
            blockifier::state::state_api::StateResult<starknet_api::core::ClassHash>,
        >,
    },
    GetCompiledContractClass {
        class_hash: starknet_api::core::ClassHash,
        response_tx: mpsc::SyncSender<
            blockifier::state::state_api::StateResult<
                blockifier::execution::contract_class::ContractClass,
            >,
        >,
    },
    GetCompiledClassHash {
        class_hash: starknet_api::core::ClassHash,
        response_tx: mpsc::SyncSender<
            blockifier::state::state_api::StateResult<starknet_api::core::CompiledClassHash>,
        >,
    },
}

pub(crate) struct RequestProcessor<S: StateReader> {
    state: S,
    requests: mpsc::Receiver<Request>,
}

impl<S: StateReader> RequestProcessor<S> {
    pub fn run(self) -> Result<(), anyhow::Error> {
        for request in self.requests {
            match request {
                Request::GetStorageAt {
                    contract_address,
                    key,
                    response_tx,
                } => {
                    let result = self.state.get_storage_at(contract_address, key);
                    response_tx.send(result)?;
                }
                Request::GetNonceAt {
                    contract_address,
                    response_tx,
                } => {
                    let result = self.state.get_nonce_at(contract_address);
                    response_tx.send(result)?;
                }
                Request::GetClassHashAt {
                    contract_address,
                    response_tx,
                } => {
                    let result = self.state.get_class_hash_at(contract_address);
                    response_tx.send(result)?;
                }
                Request::GetCompiledContractClass {
                    class_hash,
                    response_tx,
                } => {
                    let result = self.state.get_compiled_contract_class(class_hash);
                    response_tx.send(result)?;
                }
                Request::GetCompiledClassHash {
                    class_hash,
                    response_tx,
                } => {
                    let result = self.state.get_compiled_class_hash(class_hash);
                    response_tx.send(result)?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct ThreadSafeReader {
    tx: mpsc::SyncSender<Request>,
}

pub fn new<S: StateReader>(state_reader: S) -> (ThreadSafeReader, RequestProcessor<S>) {
    let (tx, rx) = mpsc::sync_channel(10);
    (
        ThreadSafeReader { tx },
        RequestProcessor {
            state: state_reader,
            requests: rx,
        },
    )
}

impl StateReader for ThreadSafeReader {
    fn get_storage_at(
        &self,
        contract_address: starknet_api::core::ContractAddress,
        key: starknet_api::state::StorageKey,
    ) -> blockifier::state::state_api::StateResult<cairo_vm::Felt252> {
        let (response_tx, response_rx) = mpsc::sync_channel(0);
        self.tx
            .send(Request::GetStorageAt {
                contract_address,
                key,
                response_tx,
            })
            .map_err(|e| blockifier::state::errors::StateError::StateReadError(e.to_string()))?;
        response_rx
            .recv()
            .map_err(|e| blockifier::state::errors::StateError::StateReadError(e.to_string()))?
    }

    fn get_nonce_at(
        &self,
        contract_address: starknet_api::core::ContractAddress,
    ) -> blockifier::state::state_api::StateResult<starknet_api::core::Nonce> {
        let (response_tx, response_rx) = mpsc::sync_channel(0);
        self.tx
            .send(Request::GetNonceAt {
                contract_address,
                response_tx,
            })
            .map_err(|e| blockifier::state::errors::StateError::StateReadError(e.to_string()))?;
        response_rx
            .recv()
            .map_err(|e| blockifier::state::errors::StateError::StateReadError(e.to_string()))?
    }

    fn get_class_hash_at(
        &self,
        contract_address: starknet_api::core::ContractAddress,
    ) -> blockifier::state::state_api::StateResult<starknet_api::core::ClassHash> {
        let (response_tx, response_rx) = mpsc::sync_channel(0);
        self.tx
            .send(Request::GetClassHashAt {
                contract_address,
                response_tx,
            })
            .map_err(|e| blockifier::state::errors::StateError::StateReadError(e.to_string()))?;
        response_rx
            .recv()
            .map_err(|e| blockifier::state::errors::StateError::StateReadError(e.to_string()))?
    }

    fn get_compiled_contract_class(
        &self,
        class_hash: starknet_api::core::ClassHash,
    ) -> blockifier::state::state_api::StateResult<
        blockifier::execution::contract_class::ContractClass,
    > {
        let (response_tx, response_rx) = mpsc::sync_channel(0);
        self.tx
            .send(Request::GetCompiledContractClass {
                class_hash,
                response_tx,
            })
            .map_err(|e| blockifier::state::errors::StateError::StateReadError(e.to_string()))?;
        response_rx
            .recv()
            .map_err(|e| blockifier::state::errors::StateError::StateReadError(e.to_string()))?
    }

    fn get_compiled_class_hash(
        &self,
        class_hash: starknet_api::core::ClassHash,
    ) -> blockifier::state::state_api::StateResult<starknet_api::core::CompiledClassHash> {
        let (response_tx, response_rx) = mpsc::sync_channel(0);
        self.tx
            .send(Request::GetCompiledClassHash {
                class_hash,
                response_tx,
            })
            .map_err(|e| blockifier::state::errors::StateError::StateReadError(e.to_string()))?;
        response_rx
            .recv()
            .map_err(|e| blockifier::state::errors::StateError::StateReadError(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::{
        felt,
        BlockHash,
        BlockHeader,
        BlockNumber,
        BlockTimestamp,
        StarknetVersion,
    };
    use starknet_api::core::{ContractAddress, PatriciaKey};

    use super::*;
    use crate::state_reader::PathfinderStateReader;
    use crate::IntoStarkFelt;

    #[test]
    fn test_multiple_threads() {
        let storage = pathfinder_storage::StorageBuilder::in_memory().unwrap();
        let mut db = storage.connection().unwrap();
        let tx = db.transaction().unwrap();

        // Empty genesis block
        let header = BlockHeader::builder()
            .with_number(BlockNumber::GENESIS)
            .with_timestamp(BlockTimestamp::new_or_panic(0))
            .with_starknet_version(StarknetVersion::new(0, 13, 1, 1))
            .finalize_with_hash(BlockHash(felt!("0xb00")));
        tx.insert_block_header(&header).unwrap();

        let state_reader =
            PathfinderStateReader::new(&tx, Some(BlockNumber::new_or_panic(0)), false);
        let (reader, processor) = new(state_reader);

        std::thread::scope(|s| {
            let r = reader.clone();
            s.spawn(move || {
                r.get_nonce_at(ContractAddress(
                    PatriciaKey::try_from(felt!("0x0").into_starkfelt()).unwrap(),
                ))
                .unwrap();
            });
            let r = reader.clone();
            s.spawn(move || {
                r.get_nonce_at(ContractAddress(
                    PatriciaKey::try_from(felt!("0x0").into_starkfelt()).unwrap(),
                ))
                .unwrap();
            });
            drop(reader);
            processor.run().unwrap();
        });
    }
}
