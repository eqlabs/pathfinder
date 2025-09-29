pub(crate) mod rate_limit;

use std::num::NonZeroU32;

use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::OrTransport;
use libp2p::core::{upgrade, Transport};
use libp2p::{dns, noise, PeerId};
use rate_limit::RateLimit;

/// Creates a libp2p protocol pathfinder uses.
///
/// TCP with Noise and Yamux on top.
pub fn create(
    keypair: &libp2p::identity::Keypair,
    relay_transport: libp2p::relay::client::Transport,
) -> libp2p::core::transport::Boxed<(PeerId, StreamMuxerBox)> {
    let transport = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::new());
    let transport = OrTransport::new(transport, relay_transport);
    let transport = dns::tokio::Transport::system(transport).unwrap();

    let noise_config =
        noise::Config::new(keypair).expect("Signing libp2p-noise static DH keypair failed.");

    transport
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_config)
        .multiplex(libp2p::yamux::Config::default())
        .boxed()
}

/// Creates a libp2p protocol pathfinder uses with rate limited IO.
///
/// TCP with Noise and Yamux on top.
pub fn create_with_rate_limit(
    keypair: &libp2p::identity::Keypair,
    relay_transport: libp2p::relay::client::Transport,
    max_read_bytes_per_sec: NonZeroU32,
    max_write_bytes_per_sec: NonZeroU32,
) -> libp2p::core::transport::Boxed<(PeerId, StreamMuxerBox)> {
    let transport = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::new());
    let transport = OrTransport::new(transport, relay_transport);
    let transport = dns::tokio::Transport::system(transport).unwrap();
    let transport = RateLimit::new(transport, max_read_bytes_per_sec, max_write_bytes_per_sec);

    let noise_config =
        noise::Config::new(keypair).expect("Signing libp2p-noise static DH keypair failed.");

    transport
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_config)
        .multiplex(libp2p::yamux::Config::default())
        .boxed()
}
