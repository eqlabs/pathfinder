//! Consensus behaviour and other related utilities for the consensus p2p
//! network.
mod behaviour;

pub use behaviour::Behaviour;

/// Commands for the consensus behaviour.
pub enum Command {}

/// Events emitted by the consensus behaviour.
pub enum Event {}

/// State of the consensus behaviour.
pub struct State {}

pub struct Config {}
