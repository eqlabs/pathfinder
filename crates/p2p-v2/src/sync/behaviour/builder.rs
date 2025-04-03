use crate::sync::behaviour::Behaviour;
use crate::sync::protocol::codec;
use crate::sync::Config;

/// Builder for the sync P2P network behaviour.
pub struct Builder {
    cfg: Config,
    header_sync: Option<p2p_stream::Behaviour<codec::Headers>>,
    class_sync: Option<p2p_stream::Behaviour<codec::Classes>>,
    state_diff_sync: Option<p2p_stream::Behaviour<codec::StateDiffs>>,
    transaction_sync: Option<p2p_stream::Behaviour<codec::Transactions>>,
    event_sync: Option<p2p_stream::Behaviour<codec::Events>>,
}

impl Builder {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            header_sync: None,
            class_sync: None,
            state_diff_sync: None,
            transaction_sync: None,
            event_sync: None,
        }
    }

    pub fn header_sync_behaviour(
        mut self,
        behaviour: p2p_stream::Behaviour<codec::Headers>,
    ) -> Self {
        self.header_sync = Some(behaviour);
        self
    }

    pub fn class_sync_behaviour(
        mut self,
        behaviour: p2p_stream::Behaviour<codec::Classes>,
    ) -> Self {
        self.class_sync = Some(behaviour);
        self
    }

    pub fn state_diff_sync_behaviour(
        mut self,
        behaviour: p2p_stream::Behaviour<codec::StateDiffs>,
    ) -> Self {
        self.state_diff_sync = Some(behaviour);
        self
    }

    pub fn transaction_sync_behaviour(
        mut self,
        behaviour: p2p_stream::Behaviour<codec::Transactions>,
    ) -> Self {
        self.transaction_sync = Some(behaviour);
        self
    }

    pub fn event_sync_behaviour(mut self, behaviour: p2p_stream::Behaviour<codec::Events>) -> Self {
        self.event_sync = Some(behaviour);
        self
    }

    pub fn build(self) -> Behaviour {
        let Self {
            cfg,
            header_sync,
            class_sync,
            state_diff_sync,
            transaction_sync,
            event_sync,
        } = self;

        let p2p_stream_cfg = p2p_stream::Config::default()
            .stream_timeout(cfg.stream_timeout)
            .response_timeout(cfg.response_timeout)
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

        Behaviour {
            header_sync,
            class_sync,
            state_diff_sync,
            transaction_sync,
            event_sync,
        }
    }
}
