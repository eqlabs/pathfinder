use std::marker::PhantomData;

use libp2p::identity::Keypair;
#[cfg(test)]
use libp2p::swarm::dummy;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{swarm, Swarm};
use pathfinder_common::ChainId;
use tokio::sync::mpsc;

use crate::core::{Client, Config};
use crate::main_loop::MainLoop;
use crate::{core, transport, ApplicationBehaviour};

pub struct AppBehaviourUnset;
pub struct AppBehaviourSet;

/// Builder for the p2p network.
pub struct Builder<B, Phase> {
    keypair: Keypair,
    cfg: Config,
    chain_id: ChainId,
    enable_kademlia: bool,
    app_behaviour: Option<B>,
    _phase: PhantomData<Phase>,
}

impl<B> Builder<B, AppBehaviourUnset> {
    pub fn new(keypair: Keypair, cfg: Config, chain_id: ChainId) -> Self {
        Self {
            keypair,
            cfg,
            chain_id,
            enable_kademlia: true,
            app_behaviour: None,
            _phase: PhantomData,
        }
    }

    pub fn app_behaviour(self, app_behaviour: B) -> Builder<B, AppBehaviourSet> {
        Builder {
            keypair: self.keypair,
            cfg: self.cfg,
            chain_id: self.chain_id,
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

impl<B> Builder<B, AppBehaviourSet> {
    pub fn build(
        self,
    ) -> (
        Client<<B as ApplicationBehaviour>::Command>,
        mpsc::Receiver<<B as ApplicationBehaviour>::Event>,
        MainLoop<B>,
    )
    where
        B: ApplicationBehaviour,
        <B as NetworkBehaviour>::ToSwarm: std::fmt::Debug,
        <B as ApplicationBehaviour>::State: Default,
    {
        let Self {
            keypair,
            cfg,
            chain_id,
            enable_kademlia,
            app_behaviour,
            ..
        } = self;

        let local_peer_id = keypair.public().to_peer_id();

        let (command_sender, command_receiver) = mpsc::channel(1);
        let client = Client::new(command_sender, local_peer_id);

        #[cfg(not(test))]
        assert!(enable_kademlia, "Kademlia must be enabled in production");

        let core_behaviour_builder = core::Behaviour::builder(keypair.clone(), chain_id, cfg);

        #[cfg(test)]
        let core_behaviour_builder = if enable_kademlia {
            core_behaviour_builder
        } else {
            core_behaviour_builder.disable_kademlia_for_test()
        };

        let (behaviour, relay_transport) = core_behaviour_builder
            .app_behaviour(app_behaviour.expect("App behaviour is set in this phase"))
            .build();

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

#[cfg(test)]
impl ApplicationBehaviour for dummy::Behaviour {
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
