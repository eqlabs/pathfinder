use std::marker::PhantomData;

use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::relay::client::Transport;
use libp2p::swarm::behaviour::toggle::Toggle;
#[cfg(test)]
use libp2p::swarm::dummy;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{autonat, dcutr, identify, identity, kad, ping, relay, StreamProtocol};
use pathfinder_common::ChainId;

use crate::core::behaviour::{kademlia_protocol_name, Behaviour, Inner};
use crate::core::Config;
use crate::peers::PeerSet;
use crate::secret::Secret;

pub struct AppBehaviourUnset;
pub struct AppBehaviourSet;

pub struct Builder<B, Phase = AppBehaviourUnset> {
    keypair: Keypair,
    chain_id: ChainId,
    cfg: Config,
    enable_kademlia: bool,
    app_behaviour: Option<B>,
    _phase: PhantomData<Phase>,
}

impl<B> Builder<B, AppBehaviourUnset> {
    pub fn new(keypair: identity::Keypair, chain_id: ChainId, cfg: Config) -> Self {
        Self {
            keypair,
            chain_id,
            cfg,
            enable_kademlia: true,
            app_behaviour: None,
            _phase: PhantomData,
        }
    }

    pub fn app_behaviour(self, app_behaviour: B) -> Builder<B, AppBehaviourSet> {
        Builder {
            keypair: self.keypair,
            chain_id: self.chain_id,
            cfg: self.cfg,
            enable_kademlia: self.enable_kademlia,
            app_behaviour: Some(app_behaviour),
            _phase: PhantomData,
        }
    }
}

#[cfg(test)]
impl<B, AnyPhase> Builder<B, AnyPhase> {
    pub(crate) fn disable_kademlia_for_test(mut self) -> Self {
        self.enable_kademlia = false;
        self
    }
}

#[cfg(test)]
impl Builder<dummy::Behaviour, AppBehaviourUnset> {
    pub fn dummy_app_behaviour_for_test(self) -> Builder<dummy::Behaviour, AppBehaviourSet> {
        self.app_behaviour(dummy::Behaviour)
    }
}

impl<B> Builder<B, AppBehaviourSet>
where
    B: NetworkBehaviour,
{
    pub fn build(self) -> (Behaviour<B>, Transport) {
        let Self {
            keypair,
            chain_id,
            cfg,
            enable_kademlia,
            app_behaviour,
            ..
        } = self;

        let peer_id = keypair.public().to_peer_id();
        let secret = Secret::new(&keypair);
        let public_key = keypair.public();

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
                    application: app_behaviour.expect("App behaviour is set in this phase"),
                },
            },
            relay_transport,
        )
    }
}
