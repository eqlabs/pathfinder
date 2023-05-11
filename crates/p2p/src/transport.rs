use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::OrTransport;
use libp2p::core::{upgrade, Transport};
use libp2p::noise;
use libp2p::{dns, PeerId};

/// Creates a libp2p protocol pathfinder uses.
///
/// TCP with Noise and Yamux on top.
pub fn create(
    keypair: &libp2p::identity::Keypair,
    relay_transport: libp2p::relay::client::Transport,
) -> libp2p::core::transport::Boxed<(PeerId, StreamMuxerBox)> {
    let transport = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::new());
    let transport = OrTransport::new(transport, relay_transport);
    let transport = dns::TokioDnsConfig::system(transport).unwrap();

    let noise_config =
        noise::Config::new(keypair).expect("Signing libp2p-noise static DH keypair failed.");

    transport
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_config)
        .multiplex(libp2p::yamux::Config::default())
        .boxed()
}
