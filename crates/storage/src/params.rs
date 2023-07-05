use pathfinder_common::trie::TrieNode;
use pathfinder_common::{
    BlockHash, BlockNumber, BlockTimestamp, ByteCodeOffset, CallParam, CallResultValue, CasmHash,
    ClassCommitment, ClassCommitmentLeafHash, ClassHash, ConstructorParam, ContractAddress,
    ContractAddressSalt, ContractNonce, ContractRoot, ContractStateHash, EntryPoint,
    EventCommitment, EventData, EventKey, Fee, GasPrice, L1ToL2MessageNonce,
    L1ToL2MessagePayloadElem, L2ToL1MessagePayloadElem, SequencerAddress, SierraHash,
    StarknetVersion, StateCommitment, StorageAddress, StorageCommitment, StorageValue,
    TransactionCommitment, TransactionHash, TransactionNonce, TransactionSignatureElem,
};
use rusqlite::types::{FromSqlError, ToSqlOutput};
use rusqlite::RowIndex;
use stark_hash::Felt;

pub trait ToSql {
    fn to_sql(&self) -> ToSqlOutput<'_>;
}

impl<Inner: ToSql> ToSql for Option<Inner> {
    fn to_sql(&self) -> ToSqlOutput<'_> {
        use rusqlite::types::Value;

        match self {
            Some(value) => value.to_sql(),
            None => ToSqlOutput::Owned(Value::Null),
        }
    }
}

impl ToSql for StarknetVersion {
    fn to_sql(&self) -> ToSqlOutput<'_> {
        use rusqlite::types::ValueRef;
        ToSqlOutput::Borrowed(ValueRef::Text(self.as_str().as_bytes()))
    }
}

impl ToSql for TrieNode {
    fn to_sql(&self) -> ToSqlOutput<'_> {
        use bitvec::order::Msb0;
        use bitvec::view::BitView;
        use rusqlite::types::Value;

        let mut buffer = Vec::with_capacity(65);

        match self {
            TrieNode::Binary { left, right } => {
                buffer.extend_from_slice(left.as_be_bytes());
                buffer.extend_from_slice(right.as_be_bytes());
            }
            TrieNode::Edge { child, path } => {
                buffer.extend_from_slice(child.as_be_bytes());
                // Bit path must be written in MSB format. This means that the LSB
                // must be in the last bit position. Since we write a fixed number of
                // bytes (32) but the path length may vary, we have to ensure we are writing
                // to the end of the slice.
                buffer.resize(65, 0);
                buffer[32..][..32].view_bits_mut::<Msb0>()[256 - path.len()..]
                    .copy_from_bitslice(path);

                buffer[64] = path.len() as u8;
            }
        }

        ToSqlOutput::Owned(Value::Blob(buffer))
    }
}

to_sql_felt!(
    BlockHash,
    ByteCodeOffset,
    CallParam,
    CallResultValue,
    CasmHash,
    ClassCommitment,
    ClassCommitmentLeafHash,
    ClassHash,
    ConstructorParam,
    ContractAddress,
    ContractAddressSalt,
    ContractStateHash,
    ContractRoot,
    EntryPoint,
    EventCommitment,
    EventData,
    EventKey,
    Fee,
    L1ToL2MessageNonce,
    L1ToL2MessagePayloadElem,
    L2ToL1MessagePayloadElem,
    SequencerAddress,
    SierraHash,
    TransactionHash,
    StateCommitment,
    StorageAddress,
    StorageCommitment,
    TransactionCommitment,
    TransactionSignatureElem,
);

to_sql_compressed_felt!(ContractNonce, StorageValue, TransactionNonce);

to_sql_int!(BlockNumber, BlockTimestamp);

// TODO: check if these can fail in rusqlite.
to_sql_builtin!(
    String,
    &str,
    Vec<u8>,
    &[u8],
    isize,
    i64,
    i32,
    i16,
    i8,
    usize,
    u64,
    u32,
    u16,
    u8
);

/// Extends [rusqlite::Row] to provide getters for our own foreign types. This is a work-around
/// for the orphan rule -- our types live in a separate crate and can therefore not implement the
/// rusqlite traits.
pub trait RowExt {
    fn get_blob<I: RowIndex>(&self, index: I) -> rusqlite::Result<&[u8]>;

    fn get_i64<I: RowIndex>(&self, index: I) -> rusqlite::Result<i64>;

    fn get_optional_i64<I: RowIndex>(&self, index: I) -> rusqlite::Result<Option<i64>>;

    fn get_optional_str<I: RowIndex>(&self, index: I) -> rusqlite::Result<Option<&str>>;

    fn get_optional_blob<I: RowIndex>(&self, index: I) -> rusqlite::Result<Option<&[u8]>>;

    fn get_felt<Index: RowIndex>(&self, index: Index) -> rusqlite::Result<Felt> {
        let blob = self.get_blob(index)?;
        let felt = Felt::from_be_slice(blob)
            .map_err(|e| rusqlite::types::FromSqlError::Other(e.into()))?;
        Ok(felt)
    }

    fn get_optional_felt<Index: RowIndex>(&self, index: Index) -> rusqlite::Result<Option<Felt>> {
        let Some(blob) = self.get_optional_blob(index)? else {
            return Ok(None);
        };

        let felt = Felt::from_be_slice(blob)
            .map_err(|e| rusqlite::types::FromSqlError::Other(e.into()))?;
        Ok(Some(felt))
    }

    fn get_optional_block_number<Index: RowIndex>(
        &self,
        index: Index,
    ) -> rusqlite::Result<Option<BlockNumber>> {
        let num = self
            .get_optional_i64(index)?
            // Always safe since we are fetching an i64
            .map(|x| BlockNumber::new_or_panic(x as u64));
        Ok(num)
    }

    fn get_optional_casm_hash<Index: RowIndex>(
        &self,
        index: Index,
    ) -> rusqlite::Result<Option<CasmHash>> {
        Ok(self.get_optional_felt(index)?.map(CasmHash))
    }

    fn get_optional_storage_commitment<Index: RowIndex>(
        &self,
        index: Index,
    ) -> rusqlite::Result<Option<StorageCommitment>> {
        Ok(self.get_optional_felt(index)?.map(StorageCommitment))
    }

    fn get_optional_class_commitment<Index: RowIndex>(
        &self,
        index: Index,
    ) -> rusqlite::Result<Option<ClassCommitment>> {
        Ok(self.get_optional_felt(index)?.map(ClassCommitment))
    }

    fn get_block_number<Index: RowIndex>(&self, index: Index) -> rusqlite::Result<BlockNumber> {
        let num = self.get_i64(index)?;
        // Always safe since we are fetching an i64
        Ok(BlockNumber::new_or_panic(num as u64))
    }

    fn get_gas_price<Index: RowIndex>(&self, index: Index) -> rusqlite::Result<GasPrice> {
        let blob = self.get_blob(index)?;
        let gas_price = GasPrice::from_be_slice(blob).map_err(|e| FromSqlError::Other(e.into()))?;
        Ok(gas_price)
    }

    fn get_timestamp<Index: RowIndex>(&self, index: Index) -> rusqlite::Result<BlockTimestamp> {
        let num = self.get_i64(index)?;
        // Always safe since we are fetching an i64
        Ok(BlockTimestamp::new_or_panic(num as u64))
    }

    fn get_starknet_version<Index: RowIndex>(
        &self,
        index: Index,
    ) -> rusqlite::Result<StarknetVersion> {
        // Older starknet versions were stored as null, map those to empty string.
        let s = self
            .get_optional_str(index)?
            .unwrap_or_default()
            .to_string();

        Ok(StarknetVersion::from(s))
    }

    fn get_transaction_commitment<Index: RowIndex>(
        &self,
        index: Index,
    ) -> rusqlite::Result<TransactionCommitment> {
        Ok(self
            .get_optional_felt(index)?
            .map(TransactionCommitment)
            .unwrap_or_default())
    }

    fn get_event_commitment<Index: RowIndex>(
        &self,
        index: Index,
    ) -> rusqlite::Result<EventCommitment> {
        Ok(self
            .get_optional_felt(index)?
            .map(EventCommitment)
            .unwrap_or_default())
    }

    fn get_class_commitment<Index: RowIndex>(
        &self,
        index: Index,
    ) -> rusqlite::Result<ClassCommitment> {
        Ok(self
            .get_optional_felt(index)?
            .map(ClassCommitment)
            .unwrap_or_default())
    }

    fn get_contract_address<Index: RowIndex>(
        &self,
        index: Index,
    ) -> rusqlite::Result<ContractAddress> {
        let felt = self.get_felt(index)?;

        let addr = ContractAddress::new(felt).ok_or(rusqlite::types::FromSqlError::Other(
            anyhow::anyhow!("contract address out of range").into(),
        ))?;

        Ok(addr)
    }

    fn get_storage_address<Index: RowIndex>(
        &self,
        index: Index,
    ) -> rusqlite::Result<StorageAddress> {
        let felt = self.get_felt(index)?;

        let addr = StorageAddress::new(felt).ok_or(rusqlite::types::FromSqlError::Other(
            anyhow::anyhow!("storage address out of range").into(),
        ))?;

        Ok(addr)
    }

    row_felt_wrapper!(get_block_hash, BlockHash);
    row_felt_wrapper!(get_class_hash, ClassHash);
    row_felt_wrapper!(get_state_commitment, StateCommitment);
    row_felt_wrapper!(get_storage_commitment, StorageCommitment);
    row_felt_wrapper!(get_sequencer_address, SequencerAddress);
    row_felt_wrapper!(get_contract_root, ContractRoot);
    row_felt_wrapper!(get_contract_nonce, ContractNonce);
    row_felt_wrapper!(get_storage_value, StorageValue);
    row_felt_wrapper!(get_transaction_hash, TransactionHash);

    fn get_trie_node<I: RowIndex>(&self, index: I) -> rusqlite::Result<TrieNode> {
        use anyhow::Context;
        use bitvec::order::Msb0;

        let data = self.get_blob(index)?;

        match data.len() {
            64 => {
                // unwraps and indexing are safe due to length check == 64.
                let left: [u8; 32] = data[..32].try_into().unwrap();
                let right: [u8; 32] = data[32..].try_into().unwrap();

                let left = Felt::from_be_bytes(left)
                    .context("Binary node's left hash is corrupt")
                    .map_err(|e| FromSqlError::Other(e.into()))?;
                let right = Felt::from_be_bytes(right)
                    .context("Binary node's right hash is corrupt")
                    .map_err(|e| FromSqlError::Other(e.into()))?;

                Ok(TrieNode::Binary { left, right })
            }
            65 => {
                // unwraps and indexing are safe due to length check == 65.
                let child: [u8; 32] = data[..32].try_into().unwrap();
                let path = data[32..64].to_vec();
                let length = data[64] as usize;

                // Grab the __last__ `length` bits. Path is stored in MSB format, which means LSB
                // is always stored in the last bit. Since the path may vary in length we must take
                // the last bits.
                use bitvec::view::BitView;
                let path = path.view_bits::<Msb0>()[256 - length..].to_bitvec();

                let child = Felt::from_be_bytes(child)
                    .context("Edge node's child hash is corrupt.")
                    .map_err(|e| FromSqlError::Other(e.into()))?;

                anyhow::Result::Ok(TrieNode::Edge { path, child })
            }
            other => {
                Err(FromSqlError::Other(anyhow::anyhow!("Bad node length: {other}").into()).into())
            }
        }
    }
}

impl<'a> RowExt for &rusqlite::Row<'a> {
    fn get_blob<I: RowIndex>(&self, index: I) -> rusqlite::Result<&[u8]> {
        self.get_ref(index)?.as_blob().map_err(|e| e.into())
    }

    fn get_optional_blob<I: RowIndex>(&self, index: I) -> rusqlite::Result<Option<&[u8]>> {
        self.get_ref(index)?.as_blob_or_null().map_err(|e| e.into())
    }

    fn get_i64<I: RowIndex>(&self, index: I) -> rusqlite::Result<i64> {
        self.get_ref(index)?.as_i64().map_err(|e| e.into())
    }

    fn get_optional_i64<I: RowIndex>(&self, index: I) -> rusqlite::Result<Option<i64>> {
        self.get_ref(index)?.as_i64_or_null().map_err(|e| e.into())
    }

    fn get_optional_str<I: RowIndex>(&self, index: I) -> rusqlite::Result<Option<&str>> {
        self.get_ref(index)?.as_str_or_null().map_err(|e| e.into())
    }
}

/// Implements [ToSql] for the target [Felt](stark_hash::Felt) newtype.
///
/// Writes the full underlying bytes (no compression).
macro_rules! to_sql_felt {
    ($target:ty) => {
        impl ToSql for $target {
            fn to_sql(&self) -> rusqlite::types::ToSqlOutput<'_> {
                use rusqlite::types::{ToSqlOutput, ValueRef};
                ToSqlOutput::Borrowed(ValueRef::Blob(self.as_inner().as_be_bytes()))
            }
        }
    };
    ($head:ty, $($rest:ty),+  $(,)?) => {
        to_sql_felt!($head);
        to_sql_felt!($($rest),+);
    }
}

/// Implements [ToSql] for the target [Felt] newtype.
///
/// Same as [to_sql_felt!] except it compresses the [Felt] by skipping leading zeros.
///
/// [Felt]: stark_hash::Felt
macro_rules! to_sql_compressed_felt {
    ($target:ty) => {
        impl ToSql for $target {
            fn to_sql(&self) -> rusqlite::types::ToSqlOutput<'_> {
                use rusqlite::types::{ToSqlOutput, ValueRef};
                let bytes = self.0.as_be_bytes();
                let num_zeroes = bytes.iter().take_while(|v| **v == 0).count();
                ToSqlOutput::Borrowed(ValueRef::Blob(&bytes[num_zeroes..]))
            }
        }
    };
    ($head:ty, $($rest:ty),+  $(,)?) => {
        to_sql_compressed_felt!($head);
        to_sql_compressed_felt!($($rest),+);
    }
}

/// Implements [ToSql] for the target integer newtype.
macro_rules! to_sql_int {
    ($target:ty) => {
        impl ToSql for $target {
            fn to_sql(&self) -> rusqlite::types::ToSqlOutput<'_> {
                use rusqlite::types::{ToSqlOutput, Value};
                ToSqlOutput::Owned(Value::Integer(self.get() as i64))
            }
        }
    };
    ($head:ty, $($rest:ty),+  $(,)?) => {
        to_sql_int!($head);
        to_sql_int!($($rest),+);
    }
}

macro_rules! to_sql_builtin {
    ($target:ty) => {
        impl ToSql for $target {
            fn to_sql(&self) -> rusqlite::types::ToSqlOutput<'_> {
                rusqlite::ToSql::to_sql(self).unwrap()
            }
        }
    };
    ($head:ty, $($rest:ty),+  $(,)?) => {
        to_sql_builtin!($head);
        to_sql_builtin!($($rest),+);
    }
}

macro_rules! row_felt_wrapper {
    ($fn_name:ident, $Type:ident) => {
        fn $fn_name<I: RowIndex>(&self, index: I) -> rusqlite::Result<$Type> {
            let felt = self.get_felt(index)?;
            Ok($Type(felt))
        }
    };
}

use {row_felt_wrapper, to_sql_builtin, to_sql_compressed_felt, to_sql_felt, to_sql_int};

/// Used in combination with our own [ToSql] trait to provide functionality equivalent to
/// [rusqlite::params!] for our own foreign types.
macro_rules! params {
    [] => {
        rusqlite::params![]
    };
    [$($param:expr),+ $(,)?] => {
        rusqlite::params![$(&$crate::params::ToSql::to_sql($param)),+]
    };
}

macro_rules! named_params {
    () => {
        rusqlite::named_params![]
    };
    // Note: It's a lot more work to support this as part of the same macro as
    // `params!`, unfortunately.
    ($($param_name:literal: $param_val:expr),+ $(,)?) => {
        rusqlite::named_params![$($param_name: $crate::params::ToSql::to_sql($param_val)),+]
    };
}

pub(crate) use {named_params, params};

#[cfg(test)]
mod tests {
    use super::*;

    use pathfinder_common::macro_prelude::*;

    #[test]
    fn to_sql() {
        // Exercises to_sql! and params! in a roundtrip to and from storage trip.

        let original = class_hash!("0xdeadbeef");

        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute("CREATE TABLE test (data BLOB)", []).unwrap();
        db.execute("INSERT INTO test VALUES(?)", params![&original])
            .unwrap();

        let result = db
            .query_row("SELECT data FROM test", [], |row| row.get_class_hash(0))
            .unwrap();

        assert_eq!(result, original);
    }
}
