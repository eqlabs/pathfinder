use pathfinder_common::{
    BlockHash, BlockNumber, BlockTimestamp, ByteCodeOffset, CallParam, CallResultValue, CasmHash,
    ClassCommitment, ClassCommitmentLeafHash, ClassHash, ConstructorParam, ContractAddress,
    ContractAddressSalt, ContractNonce, ContractRoot, ContractStateHash, EntryPoint,
    EventCommitment, EventData, EventKey, Fee, L1ToL2MessageNonce, L1ToL2MessagePayloadElem,
    L2ToL1MessagePayloadElem, SequencerAddress, SierraHash, StateCommitment, StorageAddress,
    StorageCommitment, StorageValue, TransactionCommitment, TransactionHash, TransactionNonce,
    TransactionSignatureElem,
};
use rusqlite::RowIndex;
use stark_hash::Felt;

pub trait ToSql: Sized {
    fn to_sql(&self) -> rusqlite::types::ToSqlOutput<'_>;
}

impl<Inner: ToSql> ToSql for Option<Inner> {
    fn to_sql(&self) -> rusqlite::types::ToSqlOutput<'_> {
        use rusqlite::types::{ToSqlOutput, Value};

        match self {
            Some(value) => value.to_sql(),
            None => ToSqlOutput::Owned(Value::Null),
        }
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
    i64,
    i32,
    i16,
    i8,
    u64,
    u32,
    u16,
    u8
);

/// Extends [rusqlite::Row] to provide getters for our own foreign types. This is a work-around
/// for the orphan rule -- our types live in a separate crate and can therefore not implement the
/// rusqlite traits.
pub trait RowExt {
    fn get_felt<I: RowIndex>(&self, index: I) -> rusqlite::Result<Felt>;

    fn get_class_hash<I: RowIndex>(&self, index: I) -> rusqlite::Result<ClassHash> {
        let felt = self.get_felt(index)?;
        Ok(ClassHash(felt))
    }
}

impl<'a> RowExt for &rusqlite::Row<'a> {
    fn get_felt<Index: RowIndex>(&self, index: Index) -> rusqlite::Result<Felt> {
        let bytes = self.get_ref(index)?.as_blob()?;
        let felt = Felt::from_be_slice(bytes)
            .map_err(|e| rusqlite::types::FromSqlError::Other(e.into()))?;
        Ok(felt)
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
/// Same as [to_sql!] except it compresses the [Felt] by skipping leading zeros.
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

use {to_sql_builtin, to_sql_compressed_felt, to_sql_felt, to_sql_int};

/// Used in combination with our own [ToSql] trait to provide functionality equivalent to
/// [rusqlite::params!] for our own foreign types.
#[macro_export]
macro_rules! params {
    [] => {
        rusqlite::params![]
    };
    [$($param:expr),+ $(,)?] => {
        rusqlite::params![$(&crate::params::ToSql::to_sql($param)),+]
    };
}

#[macro_export]
macro_rules! named_params {
    () => {
        rusqlite::named_params![]
    };
    // Note: It's a lot more work to support this as part of the same macro as
    // `params!`, unfortunately.
    ($($param_name:literal: $param_val:expr),+ $(,)?) => {
        rusqlite::named_params![$($param_name: crate::params::ToSql::to_sql($param_val)),+]
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::felt;

    #[test]
    fn to_sql() {
        // Exercises to_sql! and params! in a roundtrip to and from storage trip.

        let original = ClassHash(felt!("0xdeadbeef"));

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
