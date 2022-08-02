use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::{upgrade, Transport};
use libp2p::noise;
use libp2p::tcp::{GenTcpConfig, TokioTcpTransport};
use libp2p::{dns, PeerId};

/// Creates a libp2p protocol pathfinder uses.
///
/// TCP with Noise and Yamux on top.
pub fn create(
    keypair: &libp2p::identity::Keypair,
) -> libp2p::core::transport::Boxed<(PeerId, StreamMuxerBox)> {
    let transport = TokioTcpTransport::new(GenTcpConfig::new());
    let transport = dns::TokioDnsConfig::system(transport).unwrap();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&keypair)
        .expect("Signing libp2p-noise static DH keypair failed.");
    let transport = transport
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(libp2p::yamux::YamuxConfig::default())
        .boxed();

    transport
}
