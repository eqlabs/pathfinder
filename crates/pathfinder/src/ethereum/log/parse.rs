use anyhow::Context;
use pedersen_hash::StarkHash;
use web3::{
    contract::tokens::Tokenizable,
    ethabi::{ethereum_types::BigEndianHash, LogParam, RawLog},
    types::H256,
};

use crate::{
    core::{GlobalRoot, StarknetBlockNumber},
    ethereum::{
        contract::{
            MEMORY_PAGE_FACT_CONTINUOUS_EVENT, MEMORY_PAGE_HASHES_EVENT,
            STATE_TRANSITION_FACT_EVENT, STATE_UPDATE_EVENT,
        },
        log::{
            MemoryPageFactContinuousLog, MemoryPagesHashesLog, StateTransitionFactLog,
            StateUpdateLog,
        },
        EthOrigin,
    },
};

impl TryFrom<web3::types::Log> for StateUpdateLog {
    type Error = anyhow::Error;

    fn try_from(value: web3::types::Log) -> Result<Self, Self::Error> {
        let (origin, raw_log) = parse_web3_log(value)?;

        let log = STATE_UPDATE_EVENT.parse_log(raw_log)?;

        let global_root = get_log_param(&log, "globalRoot")?
            .value
            .into_uint()
            .context("global root could not be parsed")?;
        let mut buf = [0u8; 32];
        global_root.to_big_endian(&mut buf);
        let global_root =
            StarkHash::from_be_bytes(buf).context("global root could not be parsed")?;
        let global_root = GlobalRoot(global_root);

        let block_number = get_log_param(&log, "blockNumber")?
            .value
            .into_int()
            .context("Starknet block number could not be parsed")?
            .as_u64();
        let block_number = StarknetBlockNumber(block_number);

        Ok(Self {
            global_root,
            block_number,
            origin,
        })
    }
}

impl TryFrom<web3::types::Log> for StateTransitionFactLog {
    type Error = anyhow::Error;

    fn try_from(value: web3::types::Log) -> Result<Self, Self::Error> {
        let (origin, raw_log) = parse_web3_log(value)?;

        let log = STATE_TRANSITION_FACT_EVENT.parse_log(raw_log)?;

        let fact_hash = H256::from_token(get_log_param(&log, "stateTransitionFact")?.value)
            .context("fact hash could not be parsed")?;

        Ok(Self { origin, fact_hash })
    }
}

impl TryFrom<web3::types::Log> for MemoryPagesHashesLog {
    type Error = anyhow::Error;

    fn try_from(value: web3::types::Log) -> Result<Self, Self::Error> {
        let (origin, raw_log) = parse_web3_log(value)?;

        let log = MEMORY_PAGE_HASHES_EVENT.parse_log(raw_log)?;

        let hash = get_log_param(&log, "factHash")
            .map(|param| H256::from_token(param.value))
            .context("fact hash could not be cast to hash")??;

        let mempage_hashes = get_log_param(&log, "pagesHashes")?;
        let mempage_hashes = mempage_hashes
            .value
            .into_array()
            .context("page hashes could not be cast to array")?
            .iter()
            .map(|token| H256::from_token(token.clone()))
            .collect::<Result<Vec<_>, _>>()
            .context("page hash could not be parsed")?;

        Ok(Self {
            origin,
            hash,
            mempage_hashes,
        })
    }
}

impl TryFrom<web3::types::Log> for MemoryPageFactContinuousLog {
    type Error = anyhow::Error;

    fn try_from(value: web3::types::Log) -> Result<Self, Self::Error> {
        let (origin, raw_log) = parse_web3_log(value)?;

        let log = MEMORY_PAGE_FACT_CONTINUOUS_EVENT.parse_log(raw_log)?;

        let hash = get_log_param(&log, "memoryHash")?
            .value
            .into_uint()
            .context("mempage hash could not be cast to uint")?;
        let hash = H256::from_uint(&hash);

        Ok(Self { origin, hash })
    }
}

/// Utility which extracts the [EthOrigin] and log index, and then converts to a [RawLog].
fn parse_web3_log(log: web3::types::Log) -> anyhow::Result<(EthOrigin, RawLog)> {
    let origin = EthOrigin::try_from(&log)?;

    let raw_log = RawLog {
        topics: log.topics,
        data: log.data.0,
    };

    Ok((origin, raw_log))
}

/// Utility function to retrieve a named parameter from a log.
fn get_log_param(log: &web3::ethabi::Log, param: &str) -> anyhow::Result<LogParam> {
    log.params
        .iter()
        .find(|p| p.name == param)
        .cloned()
        .with_context(|| format!("parameter {} not found", param))
}

#[cfg(test)]
mod tests {
    use hex::FromHex;
    use web3::types::{H160, U256, U64};

    use super::*;

    /// Create a web3 log with the given signature topic and data.
    fn create_test_log(signature: H256, data: Vec<u8>) -> web3::types::Log {
        web3::types::Log {
            address: H160::from_low_u64_le(123456),
            topics: vec![signature],
            data: web3::types::Bytes(data),
            block_hash: Some(H256::from_low_u64_le(654321)),
            block_number: Some(U64::from(101)),
            transaction_hash: Some(H256::from_low_u64_le(664433)),
            transaction_index: Some(U64::from(99)),
            log_index: Some(U256::from(13)),
            transaction_log_index: None,
            log_type: None,
            removed: None,
        }
    }

    mod state_update {
        use std::str::FromStr;

        use super::*;
        use pretty_assertions::assert_eq;

        /// Creates a valid web3 log containing a [StateUpdateLog]. Also returns the
        /// log's StarkNet `global_root` and `block_number`
        ///
        /// Data taken from https://goerli.etherscan.io/tx/0xb6ba98e34c60bb39785df907de3c41c0a9c95302e50f213606772817514714ce#eventlog
        fn test_data() -> (web3::types::Log, GlobalRoot, StarknetBlockNumber) {
            let data = Vec::from_hex("06bd197ccc199cc3be696635a482ff818a1f166ef91c5fd844aacafb15a12bcd0000000000000000000000000000000000000000000000000000000000003583").unwrap();
            let signature = H256::from_str(
                "0xe8012213bb931d3efa0a954cfb0d7b75f2a5e2358ba5f7d3edfb0154f6e7a568",
            )
            .unwrap();
            let global_root = GlobalRoot(
                StarkHash::from_hex_str(
                    "06bd197ccc199cc3be696635a482ff818a1f166ef91c5fd844aacafb15a12bcd",
                )
                .unwrap(),
            );
            let sequence_number = StarknetBlockNumber(13699);

            (
                create_test_log(signature, data),
                global_root,
                sequence_number,
            )
        }

        #[test]
        fn ok() {
            let (log, root, sequence) = test_data();
            let origin = EthOrigin::try_from(&log).unwrap();

            let result = StateUpdateLog::try_from(log).unwrap();
            assert_eq!(result.origin, origin);
            assert_eq!(result.global_root, root);
            assert_eq!(result.block_number, sequence);
        }

        #[test]
        fn bad_data() {
            let (mut log, _, _) = test_data();
            log.data.0.pop();
            StateUpdateLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_block_hash() {
            let (mut log, _, _) = test_data();
            log.block_hash = None;
            StateUpdateLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_block_number() {
            let (mut log, _, _) = test_data();
            log.block_number = None;
            StateUpdateLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_tx_hash() {
            let (mut log, _, _) = test_data();
            log.transaction_hash = None;
            StateUpdateLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_tx_index() {
            let (mut log, _, _) = test_data();
            log.transaction_index = None;
            StateUpdateLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_log_index() {
            let (mut log, _, _) = test_data();
            log.log_index = None;
            StateUpdateLog::try_from(log).unwrap_err();
        }
    }

    mod state_transition_fact {
        use std::str::FromStr;

        use super::*;
        use pretty_assertions::assert_eq;

        /// Creates a valid web3 log containing a [StateTransitionFactLog]. Also returns the
        /// log's `fact_hash`.
        ///
        /// Data taken from https://goerli.etherscan.io/tx/0xb6ba98e34c60bb39785df907de3c41c0a9c95302e50f213606772817514714ce#eventlog
        fn test_data() -> (web3::types::Log, H256) {
            let data =
                Vec::from_hex("dc6194a6f096f55bea405c62196520299060ee13e405b1cdd442a20ab97fd226")
                    .unwrap();
            let signature = H256::from_str(
                "0x9866f8ddfe70bb512b2f2b28b49d4017c43f7ba775f1a20c61c13eea8cdac111",
            )
            .unwrap();
            let fact_hash =
                H256::from_str("DC6194A6F096F55BEA405C62196520299060EE13E405B1CDD442A20AB97FD226")
                    .unwrap();

            (create_test_log(signature, data), fact_hash)
        }

        #[test]
        fn ok() {
            let (log, fact_hash) = test_data();
            let origin = EthOrigin::try_from(&log).unwrap();

            let result = StateTransitionFactLog::try_from(log).unwrap();
            assert_eq!(result.origin, origin);
            assert_eq!(result.fact_hash, fact_hash);
        }

        #[test]
        fn bad_data() {
            let (mut log, _) = test_data();
            log.data.0.pop();
            StateTransitionFactLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_block_hash() {
            let (mut log, _) = test_data();
            log.block_hash = None;
            StateTransitionFactLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_block_number() {
            let (mut log, _) = test_data();
            log.block_number = None;
            StateTransitionFactLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_tx_hash() {
            let (mut log, _) = test_data();
            log.transaction_hash = None;
            StateTransitionFactLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_tx_index() {
            let (mut log, _) = test_data();
            log.transaction_index = None;
            StateTransitionFactLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_log_index() {
            let (mut log, _) = test_data();
            log.log_index = None;
            StateTransitionFactLog::try_from(log).unwrap_err();
        }
    }

    mod mempage_hashes {
        use std::str::FromStr;

        use super::*;
        use pretty_assertions::assert_eq;

        /// Creates a valid web3 log containing a [MemoryPagesHashesLog]. Also returns the
        /// log's `fact_hash` and `page_hashes`.
        ///
        /// Data taken from https://goerli.etherscan.io/tx/0x45852ddb65f209137a6966bc9efa7484e58a351619787dfa20e7fa8cc996d118#eventlog, log 30.
        fn test_data() -> (web3::types::Log, H256, Vec<H256>) {
            let data =
                Vec::from_hex("c4a36c5055545c20f1c4bcd0c0fb0f281d14f045b5d1e347810e5a0c1006c4310000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000298814cac4375766d0dbc4e571de92fc8e0ee9287e282b0d3130478b053f6398cf8f4bdc57b81e3eb36a0587454a2b391358970664428b92cbf0bd14ca408bbdf")
                    .unwrap();
            let signature = H256::from_str(
                "0x73b132cb33951232d83dc0f1f81c2d10f9a2598f057404ed02756716092097bb",
            )
            .unwrap();
            let fact_hash =
                H256::from_str("C4A36C5055545C20F1C4BCD0C0FB0F281D14F045B5D1E347810E5A0C1006C431")
                    .unwrap();
            let pages_hashes = vec![
                H256::from_str("98814CAC4375766D0DBC4E571DE92FC8E0EE9287E282B0D3130478B053F6398C")
                    .unwrap(),
                H256::from_str("F8F4BDC57B81E3EB36A0587454A2B391358970664428B92CBF0BD14CA408BBDF")
                    .unwrap(),
            ];

            (create_test_log(signature, data), fact_hash, pages_hashes)
        }

        #[test]
        fn ok() {
            // Data taken from https://goerli.etherscan.io/tx/0x45852ddb65f209137a6966bc9efa7484e58a351619787dfa20e7fa8cc996d118#eventlog
            // (this must match MEMPAGE_HASHES_LOG).
            let (log, fact_hash, pages_hashes) = test_data();
            let origin = EthOrigin::try_from(&log).unwrap();

            let result = MemoryPagesHashesLog::try_from(log).unwrap();
            assert_eq!(result.origin, origin);
            assert_eq!(result.hash, fact_hash);
            assert_eq!(result.mempage_hashes, pages_hashes);
        }

        #[test]
        fn bad_data() {
            let (mut log, _, _) = test_data();
            log.data.0.pop();
            MemoryPagesHashesLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_block_hash() {
            let (mut log, _, _) = test_data();
            log.block_hash = None;
            MemoryPagesHashesLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_block_number() {
            let (mut log, _, _) = test_data();
            log.block_number = None;
            MemoryPagesHashesLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_tx_hash() {
            let (mut log, _, _) = test_data();
            log.transaction_hash = None;
            MemoryPagesHashesLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_tx_index() {
            let (mut log, _, _) = test_data();
            log.transaction_index = None;
            MemoryPagesHashesLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_log_index() {
            let (mut log, _, _) = test_data();
            log.log_index = None;
            MemoryPagesHashesLog::try_from(log).unwrap_err();
        }
    }

    mod memory_page_fact_continuous {
        use std::str::FromStr;

        use super::*;
        use pretty_assertions::assert_eq;
        use web3::ethabi::ethereum_types::BigEndianHash;

        /// Creates a valid web3 log containing a [MemoryPageFactContinuousLog]. Also returns the
        /// log's `memory_hash`.
        ///
        /// Data taken from https://goerli.etherscan.io/tx/0x6690a78c3284b1c825925021211a3ffa8c31b92bc0e00c57e0e1306d6425fc36#eventlog
        fn test_data() -> (web3::types::Log, H256) {
            let data =
                Vec::from_hex("507971b8590e0b4572c1349ad19a3a0991ee95d025269672979f6c2673206664422c4adc2ee6fb0f296713ec48463605627b5a8088293f8a2fa3140ac21ef916050ff01b2b1248efde79fa86a669959b2e8e6ab35d697d464d450bcca2dcb9a1")
                    .unwrap();
            let signature = H256::from_str(
                "0xb8b9c39aeba1cfd98c38dfeebe11c2f7e02b334cbe9f05f22b442a5d9c1ea0c5",
            )
            .unwrap();
            let memory_hash = U256::from_dec_str(
                "29930905942703145183422509603072990525560324234256575117823357479962472806678",
            )
            .unwrap();
            let memory_hash = H256::from_uint(&memory_hash);

            (create_test_log(signature, data), memory_hash)
        }

        #[test]
        fn ok() {
            // Data taken from https://goerli.etherscan.io/tx/0x6690a78c3284b1c825925021211a3ffa8c31b92bc0e00c57e0e1306d6425fc36#eventlog
            // (this must match MEMPAGE_FACT_LOG).
            let (log, memory_hash) = test_data();
            let origin = EthOrigin::try_from(&log).unwrap();

            let result = MemoryPageFactContinuousLog::try_from(log).unwrap();
            assert_eq!(result.origin, origin);
            assert_eq!(result.hash, memory_hash);
        }

        #[test]
        fn bad_data() {
            let (mut log, _) = test_data();
            log.data.0.pop();
            MemoryPageFactContinuousLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_block_hash() {
            let (mut log, _) = test_data();
            log.block_hash = None;
            MemoryPageFactContinuousLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_block_number() {
            let (mut log, _) = test_data();
            log.block_number = None;
            MemoryPageFactContinuousLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_tx_hash() {
            let (mut log, _) = test_data();
            log.transaction_hash = None;
            MemoryPageFactContinuousLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_tx_index() {
            let (mut log, _) = test_data();
            log.transaction_index = None;
            MemoryPageFactContinuousLog::try_from(log).unwrap_err();
        }

        #[test]
        fn missing_log_index() {
            let (mut log, _) = test_data();
            log.log_index = None;
            MemoryPageFactContinuousLog::try_from(log).unwrap_err();
        }
    }
}
