use std::marker::PhantomData;

use libp2p::identity::Keypair;
#[cfg(test)]
use libp2p::swarm::dummy;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{swarm, Swarm};
use pathfinder_common::ChainId;
use tokio::sync::mpsc;

use crate::builder_phase::*;
use crate::core::{Client, Config};
use crate::main_loop::MainLoop;
use crate::{core, transport, ApplicationBehaviour};

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

impl<B> Builder<B, AppBehaviourSet> {
    pub fn build(
        self,
    ) -> (
        Client<<B as ApplicationBehaviour>::Command>,
        mpsc::UnboundedReceiver<<B as ApplicationBehaviour>::Event>,
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

        #[cfg(not(test))]
        assert!(enable_kademlia, "Kademlia must be enabled in production");

        let max_read_bytes_per_sec = cfg.max_read_bytes_per_sec;
        let max_write_bytes_per_sec = cfg.max_write_bytes_per_sec;
        let data_directory = cfg.data_directory.clone();

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

        let transport = match (max_read_bytes_per_sec, max_write_bytes_per_sec) {
            (None, None) => transport::create(&keypair, relay_transport),
            (Some(max_read), Some(max_write)) => {
                tracing::info!(
                    "Enabling transport rate limit: read={} B/s, write={} B/s",
                    max_read,
                    max_write
                );
                transport::create_with_rate_limit(&keypair, relay_transport, max_read, max_write)
            }
            // This is enforced through CLI args.
            _ => panic!("Both read and write limits must be set to enable transport rate limiting"),
        };

        let swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            swarm::Config::with_tokio_executor(),
        );

        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        let (main_loop, command_sender) = MainLoop::new(swarm, event_sender, data_directory);
        let client = Client::new(command_sender, local_peer_id);

        (client, event_receiver, main_loop)
    }
}

#[cfg(test)]
impl ApplicationBehaviour for dummy::Behaviour {
    type Command = ();
    type Event = ();
    type State = ();

    async fn handle_command(&mut self, _: Self::Command, _: &mut Self::State) {}
    async fn handle_event(
        &mut self,
        _: <Self as NetworkBehaviour>::ToSwarm,
        _: &mut Self::State,
        _: mpsc::UnboundedSender<Self::Event>,
    ) {
    }
    fn domain() -> &'static str {
        "p2p_dummy"
    }
}
