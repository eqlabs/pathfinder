use std::time::Duration;

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
}

impl Builder {
    pub fn new(keypair: Keypair, cfg: Config, chain_id: ChainId) -> Self {
        Self {
            keypair,
            cfg,
            chain_id,
            behaviour_builder: None,
        }
    }
}

impl Builder {
    #[allow(unused)]
    pub fn behaviour_builder(mut self, behaviour_builder: behaviour::Builder) -> Self {
        self.behaviour_builder = Some(behaviour_builder);
        self
    }

    pub fn build(self) -> (Client, EventReceiver, MainLoop) {
        let Self {
            keypair,
            cfg,
            chain_id,
            behaviour_builder,
        } = self;

        let local_peer_id = keypair.public().to_peer_id();

        let (command_sender, command_receiver) = mpsc::channel(1);
        let client = Client::new(command_sender, local_peer_id);

        let (behaviour, relay_transport) = behaviour_builder
            .unwrap_or_else(|| Behaviour::builder(keypair.clone(), chain_id, cfg))
            .build(client.clone());

        let swarm = Swarm::new(
            transport::create(&keypair, relay_transport),
            behaviour,
            local_peer_id,
            swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(3600 * 365)), // A YEAR
        );

        let (event_sender, event_receiver) = mpsc::channel(1);

        (
            client,
            event_receiver,
            MainLoop::new(swarm, command_receiver, event_sender),
        )
    }
}
