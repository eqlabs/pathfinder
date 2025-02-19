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

        let max_concurrent_streams = cfg.max_concurrent_streams;

        let (behaviour, relay_transport) = behaviour_builder
            .unwrap_or_else(|| Behaviour::builder(keypair.clone(), chain_id, cfg))
            .build();

        let swarm = Swarm::new(
            transport::create(&keypair, relay_transport),
            behaviour,
            local_peer_id,
            swarm::Config::with_tokio_executor()
                // The swarm will stall if the length of the event buffer is too small.
                // https://github.com/libp2p/rust-libp2p/blob/a966f626af5f3243a67207856c6a79df846d316a/swarm/src/connection/pool.rs#L1014
                //
                // See PR https://github.com/eqlabs/pathfinder/pull/2594 for more details.
                //
                // In the worst case, for each stream, we need to accommodate for at least:
                // - 1x `InboundRequest` event
                // - 1x `OutboundResponseStreamClosed` event, in case the older streams are closed
                //   and immediately replaced by new ones from the very same client
                // - a number of other events, that could happen in the meantime from other
                //   behaviors: identify, kad, ping, gossipsub, etc.
                //
                // Stress tests show that 3x should be sufficient, so we're using 4x just to be
                // safe.
                //
                // We also add a base value of 7, which is the default size of this buffer, in case
                // `max_concurrent_streams` is 1.
                .with_per_connection_event_buffer_size(7 + max_concurrent_streams * 4),
        );

        let (event_sender, event_receiver) = mpsc::channel(1);

        (
            client,
            event_receiver,
            MainLoop::new(swarm, command_receiver, event_sender),
        )
    }
}
