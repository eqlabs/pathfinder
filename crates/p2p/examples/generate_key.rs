#![deny(rust_2018_idioms)]

use libp2p::identity::Keypair;

fn main() -> anyhow::Result<()> {
    let keypair = Keypair::Ed25519(libp2p::identity::ed25519::Keypair::generate());

    let private_key = keypair.to_protobuf_encoding()?;
    let encoded_private_key = base64::encode(private_key);

    println!("{encoded_private_key}");

    Ok(())
}
