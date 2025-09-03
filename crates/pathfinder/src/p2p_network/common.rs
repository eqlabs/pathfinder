use std::time::Duration;

use anyhow::{Context, Result};
use p2p::core::Client;
use p2p::libp2p::multiaddr::Protocol;
use p2p::libp2p::{Multiaddr, PeerId};

pub async fn dial_bootnodes<C>(
    bootstrap_addresses: Vec<Multiaddr>,
    core_client: &Client<C>,
) -> bool {
    if bootstrap_addresses.is_empty() {
        return true;
    }

    let mut success = false;
    for bootstrap_address in bootstrap_addresses {
        let peer_id = match ensure_peer_id_in_multiaddr(
            &bootstrap_address,
            "Bootstrap addresses must include peer ID",
        ) {
            Ok(id) => id,
            Err(error) => {
                tracing::warn!(?error, "Invalid bootstrap address {bootstrap_address}");
                continue;
            }
        };

        // TODO: Use exponential backoff with a max retry limit, at least one boot node
        // needs to be reachable for the node to be useful.
        // https://github.com/eqlabs/pathfinder/issues/2937
        for _ in 0..5 {
            match core_client.dial(peer_id, bootstrap_address.clone()).await {
                Ok(_) => {
                    success = true;
                }
                Err(error) => {
                    tracing::warn!(
                        %bootstrap_address,
                        %error,
                        "Failed to dial bootstrap node, retrying",
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }

        let relay_listener_address = bootstrap_address.clone().with(Protocol::P2pCircuit);
        if let Err(error) = core_client
            .start_listening(relay_listener_address.clone())
            .await
        {
            tracing::warn!(
                ?error,
                "Failed starting relay listener on {relay_listener_address}"
            );
        }
    }
    success
}

pub fn ensure_peer_id_in_multiaddr(
    addr: &Multiaddr,
    msg: &'static str,
) -> Result<PeerId, anyhow::Error> {
    addr.iter()
        .find_map(|p| match p {
            Protocol::P2p(peer_id) => Some(peer_id),
            _ => None,
        })
        .context(msg)
}
