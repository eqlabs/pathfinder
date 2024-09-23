use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::Duration;

use libp2p::gossipsub::{MessageAuthenticity, MessageId};
use libp2p::kad::store::MemoryStore;
use libp2p::{autonat, dcutr, gossipsub, identify, identity, kad, ping, relay, StreamProtocol};
use pathfinder_common::ChainId;

use super::{Behaviour, BehaviourWithRelayTransport};
use crate::behaviour::Inner;
use crate::peers::PeerSet;
use crate::secret::Secret;
use crate::sync::codec;
use crate::{kademlia_protocol_name, Config};

pub struct Builder {
    identity: identity::Keypair,
    chain_id: ChainId,
    cfg: Config,
    header_sync: Option<p2p_stream::Behaviour<codec::Headers>>,
    class_sync: Option<p2p_stream::Behaviour<codec::Classes>>,
    state_diff_sync: Option<p2p_stream::Behaviour<codec::StateDiffs>>,
    transaction_sync: Option<p2p_stream::Behaviour<codec::Transactions>>,
    event_sync: Option<p2p_stream::Behaviour<codec::Events>>,
}

impl Builder {
    pub fn new(identity: identity::Keypair, chain_id: ChainId, cfg: Config) -> Self {
        Self {
            identity,
            chain_id,
            cfg,
            header_sync: None,
            class_sync: None,
            state_diff_sync: None,
            transaction_sync: None,
            event_sync: None,
        }
    }

    #[allow(unused)]
    pub fn header_sync_behaviour(
        mut self,
        behaviour: p2p_stream::Behaviour<codec::Headers>,
    ) -> Self {
        self.header_sync = Some(behaviour);
        self
    }

    #[allow(unused)]
    pub fn class_sync_behaviour(
        mut self,
        behaviour: p2p_stream::Behaviour<codec::Classes>,
    ) -> Self {
        self.class_sync = Some(behaviour);
        self
    }

    #[allow(unused)]
    pub fn state_diff_sync_behaviour(
        mut self,
        behaviour: p2p_stream::Behaviour<codec::StateDiffs>,
    ) -> Self {
        self.state_diff_sync = Some(behaviour);
        self
    }

    #[allow(unused)]
    pub fn transaction_sync_behaviour(
        mut self,
        behaviour: p2p_stream::Behaviour<codec::Transactions>,
    ) -> Self {
        self.transaction_sync = Some(behaviour);
        self
    }

    #[allow(unused)]
    pub fn event_sync_behaviour(mut self, behaviour: p2p_stream::Behaviour<codec::Events>) -> Self {
        self.event_sync = Some(behaviour);
        self
    }

    pub fn build(self, client: crate::Client) -> BehaviourWithRelayTransport {
        let Self {
            identity,
            chain_id,
            cfg,
            header_sync,
            class_sync,
            state_diff_sync,
            transaction_sync,
            event_sync,
        } = self;

        const PROVIDER_PUBLICATION_INTERVAL: Duration = Duration::from_secs(600);

        // This makes sure that the DHT we're implementing is incompatible with the
        // "default" IPFS DHT from libp2p.
        let protocol_name = cfg
            .kad_name
            .clone()
            .map(|x| StreamProtocol::try_from_owned(x).expect("valid protocol name"))
            .unwrap_or_else(|| kademlia_protocol_name(chain_id));

        let mut kademlia_config = kad::Config::new(protocol_name);
        kademlia_config.set_record_ttl(Some(Duration::from_secs(0)));
        kademlia_config.set_provider_record_ttl(Some(PROVIDER_PUBLICATION_INTERVAL * 3));
        kademlia_config.set_provider_publication_interval(Some(PROVIDER_PUBLICATION_INTERVAL));
        kademlia_config.set_periodic_bootstrap_interval(Some(cfg.bootstrap_period));

        let peer_id = identity.public().to_peer_id();
        let secret = Secret::new(&identity);
        let public_key = identity.public();

        let kademlia =
            kad::Behaviour::with_config(peer_id, MemoryStore::new(peer_id), kademlia_config);

        // FIXME: find out how we should derive message id
        let message_id_fn = |message: &gossipsub::Message| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            MessageId::from(s.finish().to_string())
        };
        let gossipsub_config = libp2p::gossipsub::ConfigBuilder::default()
            .message_id_fn(message_id_fn)
            .build()
            .expect("valid gossipsub config");
        let gossipsub =
            gossipsub::Behaviour::new(MessageAuthenticity::Signed(identity), gossipsub_config)
                .expect("valid gossipsub params");

        let (relay_transport, relay) = relay::client::new(peer_id);

        let p2p_stream_cfg = p2p_stream::Config::default()
            .request_timeout(cfg.stream_timeout)
            .max_concurrent_streams(cfg.max_concurrent_streams);

        let header_sync = header_sync
            .unwrap_or_else(|| p2p_stream::Behaviour::<codec::Headers>::new(p2p_stream_cfg));
        let class_sync = class_sync
            .unwrap_or_else(|| p2p_stream::Behaviour::<codec::Classes>::new(p2p_stream_cfg));
        let state_diff_sync = state_diff_sync
            .unwrap_or_else(|| p2p_stream::Behaviour::<codec::StateDiffs>::new(p2p_stream_cfg));
        let transaction_sync = transaction_sync
            .unwrap_or_else(|| p2p_stream::Behaviour::<codec::Transactions>::new(p2p_stream_cfg));
        let event_sync = event_sync
            .unwrap_or_else(|| p2p_stream::Behaviour::<codec::Events>::new(p2p_stream_cfg));

        (
            Behaviour {
                peers: PeerSet::new(cfg.eviction_timeout),
                cfg,
                swarm: client,
                secret,
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
                    gossipsub,
                    header_sync,
                    class_sync,
                    state_diff_sync,
                    transaction_sync,
                    event_sync,
                },
            },
            relay_transport,
        )
    }
}
