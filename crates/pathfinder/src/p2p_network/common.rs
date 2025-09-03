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

        match core_client.dial(peer_id, bootstrap_address.clone()).await {
            Ok(_) => {
                success = true;
            }
            Err(error) => {
                tracing::warn!(?error, "Failed dialing {bootstrap_address}");
                continue;
            }
        };

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
