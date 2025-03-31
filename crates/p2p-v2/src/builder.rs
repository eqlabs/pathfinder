use libp2p::identity::Keypair;
use libp2p::swarm::{dummy, NetworkBehaviour};
use libp2p::{swarm, Swarm};
use pathfinder_common::ChainId;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::core::client::Client;
use crate::main_loop::MainLoop;
use crate::{core, transport, P2PApplicationBehaviour};

pub struct Builder {
    keypair: Keypair,
    cfg: Config,
    chain_id: ChainId,
    enable_kademlia: bool,
    behaviour_builder: Option<core::behaviour::Builder>,
}

impl Builder {
    pub fn new(keypair: Keypair, cfg: Config, chain_id: ChainId) -> Self {
        Self {
            keypair,
            cfg,
            chain_id,
            enable_kademlia: true,
            behaviour_builder: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn disable_kademlia_for_test(mut self) -> Self {
        self.enable_kademlia = false;
        self
    }

    #[allow(unused)]
    pub fn behaviour_builder<B>(mut self, behaviour_builder: core::behaviour::Builder) -> Self {
        self.behaviour_builder = Some(behaviour_builder);
        self
    }

    pub fn build(
        self,
    ) -> (
        Client<<dummy::Behaviour as P2PApplicationBehaviour>::Command>,
        mpsc::Receiver<<dummy::Behaviour as P2PApplicationBehaviour>::Event>,
        MainLoop<dummy::Behaviour>,
    )
    where
        dummy::Behaviour: P2PApplicationBehaviour,
        <dummy::Behaviour as NetworkBehaviour>::ToSwarm: std::fmt::Debug,
        <dummy::Behaviour as P2PApplicationBehaviour>::State: Default,
    {
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

        // FIXME no way to get a default behaviour built here
        let behaviour_builder = behaviour_builder.unwrap_or_else(|| {
            core::behaviour::Behaviour::<dummy::Behaviour>::builder(keypair.clone(), chain_id, cfg)
        });

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

impl P2PApplicationBehaviour for dummy::Behaviour {
    type Command = ();
    type Event = ();
    type State = ();

    fn handle_command(
        &mut self,
        _: Self::Command,
        _: &mut Self::State,
    ) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }

    fn handle_event(
        &mut self,
        _: <Self as NetworkBehaviour>::ToSwarm,
        _: &mut Self::State,
        _: mpsc::Sender<Self::Event>,
    ) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}
