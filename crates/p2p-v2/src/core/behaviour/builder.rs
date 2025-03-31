use libp2p::kad::store::MemoryStore;
use libp2p::relay::client::Transport;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{autonat, dcutr, identify, identity, kad, ping, relay, StreamProtocol};
use pathfinder_common::ChainId;

use crate::config::Config;
use crate::core::behaviour::{kademlia_protocol_name, Behaviour, Inner};
use crate::peers::PeerSet;
use crate::secret::Secret;

pub struct Builder<B> {
    identity: identity::Keypair,
    chain_id: ChainId,
    cfg: Config,
    enable_kademlia: bool,
    app_behaviour: Option<B>,
}

impl<B> Builder<B> {
    pub fn new(identity: identity::Keypair, chain_id: ChainId, cfg: Config) -> Self {
        Self {
            identity,
            chain_id,
            cfg,
            enable_kademlia: true,
            app_behaviour: None,
        }
    }

    #[allow(unused)]
    pub fn app_behaviour(mut self, behaviour: B) -> Self {
        self.app_behaviour = Some(behaviour);
        self
    }

    /// Disable Kademlia for in-crate tests. Kademlia is always enabled in
    /// production.
    #[allow(unused)]
    #[cfg(test)]
    pub(crate) fn disable_kademlia_for_test(mut self) -> Self {
        self.enable_kademlia = false;
        self
    }

    pub fn build(self) -> (Behaviour<B>, Transport)
    where
        B: NetworkBehaviour + Default,
    {
        let Self {
            identity,
            chain_id,
            cfg,
            enable_kademlia,
            app_behaviour,
        } = self;

        let peer_id = identity.public().to_peer_id();
        let secret = Secret::new(&identity);
        let public_key = identity.public();

        #[cfg(not(test))]
        assert!(enable_kademlia, "Kademlia must be enabled in production");

        let kademlia = Toggle::from(enable_kademlia.then_some({
            // This makes sure that the DHT we're implementing is incompatible with the
            // "default" IPFS DHT from libp2p.
            let protocol_name = cfg
                .kad_name
                .clone()
                .map(|x| StreamProtocol::try_from_owned(x).expect("Valid protocol name"))
                .unwrap_or_else(|| kademlia_protocol_name(chain_id));
            let config = kad::Config::new(protocol_name);
            kad::Behaviour::with_config(peer_id, MemoryStore::new(peer_id), config)
        }));

        let (relay_transport, relay) = relay::client::new(peer_id);

        let application = app_behaviour.unwrap_or_default();

        (
            Behaviour {
                peers: PeerSet::new(cfg.eviction_timeout),
                cfg,
                secret,
                pending_events: Default::default(),
                inner: Inner {
                    relay,
                    autonat: autonat::Behaviour::new(peer_id, Default::default()),
                    dcutr: dcutr::Behaviour::new(peer_id),
                    ping: ping::Behaviour::new(ping::Config::new()),
                    identify: identify::Behaviour::new(
                        identify::Config::new(identify::PROTOCOL_NAME.to_string(), public_key)
                            .with_agent_version(format!(
                                "pathfinder/{}",
                                env!("CARGO_PKG_VERSION")
                            )),
                    ),
                    kademlia,
                    application,
                },
            },
            relay_transport,
        )
    }
}
