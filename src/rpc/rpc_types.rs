/// __TODO__ The ultimate RPC reply structures are TBD.
/// Reexporting sequencer replies for transparent forwarding.
/// This will change once we have storage.
pub use crate::sequencer::reply;

pub mod tags {
    pub const LATEST: &str = "latest";
    pub const EARLIEST: &str = "earliest";
}
