use p2p::{
    core::Client,
    libp2p::{multiaddr::Protocol, Multiaddr, PeerId},
};

pub async fn dial_bootnodes<C>(
    bootstrap_addresses: Vec<Multiaddr>,
    core_client: &Client<C>,
) -> bool {
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
        loop {
            let dial_result = core_client.dial(peer_id, bootstrap_address.clone()).await;

            match dial_result {
                Ok(_) => {
                    success = true;
                    break;
                }
                Err(error) => {
                    tracing::warn!(
                        %bootstrap_address,
                        %error,
                        "Failed to dial bootstrap node, retrying",
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
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
        .ok_or_else(|| anyhow::anyhow!(msg))
}
