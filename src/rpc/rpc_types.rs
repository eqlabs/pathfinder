//! Definitions of JSON-RPC types.

/// __TODO__ The ultimate RPC reply structures are TBD.
/// Reexporting sequencer replies for transparent forwarding.
/// This will change once we have storage.
pub use crate::sequencer::reply;

/// Special tag values used in the RPC API.
pub mod tags {
    pub const LATEST: &str = "latest";
    pub const EARLIEST: &str = "earliest";
}
