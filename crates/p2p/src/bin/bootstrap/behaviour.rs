use std::time::Duration;

use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{autonat, dcutr, identify, identity, ping, relay};
use p2p::core::kademlia_protocol_name;
use pathfinder_common::ChainId;

#[derive(NetworkBehaviour)]
pub struct BootstrapBehaviour {
    relay: relay::Behaviour,
    autonat: autonat::Behaviour,
    dcutr: dcutr::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<MemoryStore>,
}

impl BootstrapBehaviour {
    pub fn new(pub_key: identity::PublicKey, chain_id: ChainId) -> Self {
        let peer_id = pub_key.to_peer_id();
        let mut kad_config = kad::Config::new(kademlia_protocol_name(chain_id));
        kad_config.set_periodic_bootstrap_interval(Some(Duration::from_secs(5)));

        Self {
            relay: relay::Behaviour::new(peer_id, Default::default()),
            autonat: autonat::Behaviour::new(peer_id, Default::default()),
            dcutr: dcutr::Behaviour::new(peer_id),
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(
                identify::Config::new(identify::PROTOCOL_NAME.to_string(), pub_key)
                    .with_agent_version(format!("pathfinder/{}", env!("CARGO_PKG_VERSION"))),
            ),
            kademlia: kad::Behaviour::with_config(peer_id, MemoryStore::new(peer_id), kad_config),
        }
    }
}
