use libp2p::identity::Keypair;
use libp2p::{swarm, Swarm};
use pathfinder_common::ChainId;
use tokio::sync::mpsc;

use crate::behaviour::{self, Behaviour};
use crate::client::peer_aware::Client;
use crate::main_loop::MainLoop;
use crate::{transport, Config, EventReceiver};

pub struct Builder {
    keypair: Keypair,
    cfg: Config,
    chain_id: ChainId,
    behaviour_builder: Option<behaviour::Builder>,
    enable_kademlia: bool,
}

impl Builder {
    pub fn new(keypair: Keypair, cfg: Config, chain_id: ChainId) -> Self {
        Self {
            keypair,
            cfg,
            chain_id,
            behaviour_builder: None,
            enable_kademlia: true,
        }
    }
}

impl Builder {
    #[allow(unused)]
    pub fn behaviour_builder(mut self, behaviour_builder: behaviour::Builder) -> Self {
        self.behaviour_builder = Some(behaviour_builder);
        self
    }

    #[cfg(test)]
    pub(crate) fn disable_kademlia_for_test(mut self) -> Self {
        self.enable_kademlia = false;
        self
    }

    pub fn build(self) -> (Client, EventReceiver, MainLoop) {
        let Self {
            keypair,
            cfg,
            chain_id,
            behaviour_builder,
            enable_kademlia,
        } = self;

        let local_peer_id = keypair.public().to_peer_id();

        let (command_sender, command_receiver) = mpsc::channel(1);
        let client = Client::new(command_sender, local_peer_id);

        let behaviour_builder =
            behaviour_builder.unwrap_or_else(|| Behaviour::builder(keypair.clone(), chain_id, cfg));

        #[cfg(not(test))]
        assert!(enable_kademlia, "Kademlia must be enabled in production");

        #[cfg(test)]
        let behaviour_builder = if enable_kademlia {
            behaviour_builder
        } else {
            behaviour_builder.disable_kademlia_for_test()
        };

        let (behaviour, relay_transport) = behaviour_builder.build();

        let swarm = Swarm::new(
            transport::create(&keypair, relay_transport),
            behaviour,
            local_peer_id,
            swarm::Config::with_tokio_executor(),
        );

        let (event_sender, event_receiver) = mpsc::channel(1);

        (
            client,
            event_receiver,
            MainLoop::new(swarm, command_receiver, event_sender),
        )
    }
}
