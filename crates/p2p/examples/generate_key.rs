#![deny(rust_2018_idioms)]

use libp2p::identity::Keypair;

fn main() -> anyhow::Result<()> {
    let keypair = Keypair::generate_ed25519();

    let private_key = keypair.to_protobuf_encoding()?;
    let encoded_private_key = base64::encode(private_key);

    println!("{encoded_private_key}");

    Ok(())
}
