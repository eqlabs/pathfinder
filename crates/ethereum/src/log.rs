use crate::{contract::STATE_UPDATE_EVENT, EthOrigin};
use anyhow::Context;
use pathfinder_common::{GlobalRoot, StarknetBlockNumber};
use stark_hash::StarkHash;
use web3::ethabi::{LogParam, RawLog};

/// Describes a state update log event.
///
/// This is emitted by the Starknet core contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateUpdateLog {
    pub origin: EthOrigin,
    pub global_root: GlobalRoot,
    pub block_number: StarknetBlockNumber,
}

impl StateUpdateLog {
    pub fn signature() -> web3::types::H256 {
        STATE_UPDATE_EVENT.signature()
    }
}

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
        let block_number = StarknetBlockNumber::new(block_number)
            .ok_or_else(|| anyhow::anyhow!("Starknet block number out of range"))?;

        Ok(Self {
            global_root,
            block_number,
            origin,
        })
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
    use web3::types::{H160, H256, U256, U64};

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
            let sequence_number = StarknetBlockNumber::new_or_panic(13699);

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
}
