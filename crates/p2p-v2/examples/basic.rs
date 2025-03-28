use p2p_v2::P2PApplicationBehaviour;

use p2p_v2::MainLoop;

use p2p_v2::sync::Behaviour as SyncBehaviour;




fn main() {


    let sync = SyncBehaviour::new();


    let p2p = MainLoop::new(
        sync,
        command_tx,
        event_rx,
    );

}

