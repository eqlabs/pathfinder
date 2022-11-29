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
    relay_transport: libp2p::relay::v2::client::transport::ClientTransport,
) -> libp2p::core::transport::Boxed<(PeerId, StreamMuxerBox)> {
    let transport = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::new());
    let transport = OrTransport::new(transport, relay_transport);
    let transport = dns::TokioDnsConfig::system(transport).unwrap();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(keypair)
        .expect("Signing libp2p-noise static DH keypair failed.");
    transport
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(libp2p::yamux::YamuxConfig::default())
        .boxed()
}
