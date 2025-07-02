#![deny(rust_2018_idioms)]

use libp2p::identity::Keypair;
use libp2p::PeerId;

fn main() -> anyhow::Result<()> {
    let keypair = Keypair::generate_ed25519();

    let private_key = keypair.to_protobuf_encoding()?;
    let encoded_private_key = base64::encode(private_key);

    let peer_id = PeerId::from_public_key(&keypair.public());

    // Peer id is here just for convenience/debugging.
    println!(r#"{{"private_key":"{encoded_private_key}","peer_id":"{peer_id}"}}"#);

    Ok(())
}
