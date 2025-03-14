use std::fmt::Debug;

use libp2p::{Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot};

pub mod behaviour;
pub mod main_loop;

use crate::{EmptyResultSender, TestCommand, TestEvent};

pub trait ApplicationMainLoopHandler {
    type Command;
    type Event;
    type PendingStuff;

    async fn handle_command(&mut self, command: Self::Command, pending: &mut Self::PendingStuff);

    async fn handle_event(&mut self, event: Self::Event, pending: &mut Self::PendingStuff);
}

#[derive(Debug)]
pub enum Command<ApplicationCommand> {
    StarListening {
        addr: Multiaddr,
        sender: EmptyResultSender,
    },
    Dial {
        peer_id: PeerId,
        addr: Multiaddr,
        sender: EmptyResultSender,
    },
    Disconnect {
        peer_id: PeerId,
        sender: EmptyResultSender,
    },
    GetClosestPeers {
        peer: PeerId,
        sender: mpsc::Sender<anyhow::Result<Vec<PeerId>>>,
    },
    NotUseful {
        peer_id: PeerId,
        sender: oneshot::Sender<()>,
    },
    /// Application behaviour commands go here
    Application(ApplicationCommand),
    /// For testing purposes only
    // TODO test commands could also be split into core and application specific although I'm not
    // sure if it's necessary, maybe this comment should just be removed
    _Test(TestCommand),
}

#[derive(Debug)]
pub enum Event<ApplicationEvent> {
    /// Application behaviour events (notifications) go here
    Application(ApplicationEvent),
    /// For testing purposes only
    Test(TestEvent),
}
