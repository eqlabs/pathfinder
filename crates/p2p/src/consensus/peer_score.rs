use libp2p::gossipsub;

/// Initial value of the application-specific portion of the peer score.
pub const INTIAL_APPLICATION_SCORE: f64 = 0.0;

/// Application-specific weight for peer scoring.  
///
/// When calculating overall peer score, libp2p multiplies the application score
/// by this weight. The penalty values should be picked with this in
/// mind.
///
/// The value is the same as the default in libp2p (at the time) but we expose
/// it here to have something to base our penalty values on.
const APP_SPECIFIC_WEIGHT: f64 = 10.0;

/// Graylist threshold for peer scoring. Peers with a score below this value
/// will have their message processing suppressed altogether.
///
/// The value is the same as the default in libp2p (at the time) but we expose
/// it here to have something to base our penalty values on.
const GRAYLIST_THRESHOLD: f64 = -80.0;

// This is the only penalty we have at the moment and the whole peer scoring
// system still needs to be tested in a realistic environment before we can be
// confident these values make sense.
//
// For now we'll set this to a value that requires quite a lot of offenses to
// graylist a peer, in order to avoid affecting the network.
pub const OUTDATED_MESSAGE_PENALTY: f64 = penalty(1000);

pub fn default_params() -> gossipsub::PeerScoreParams {
    gossipsub::PeerScoreParams {
        app_specific_weight: APP_SPECIFIC_WEIGHT,
        ..Default::default()
    }
}

pub fn default_thresholds() -> gossipsub::PeerScoreThresholds {
    gossipsub::PeerScoreThresholds {
        graylist_threshold: GRAYLIST_THRESHOLD,
        ..Default::default()
    }
}

/// Calculate a penalty value. Penalties are defined in terms of the number of
/// times the error that is being penalized should occur to reach the graylist
/// threshold.
///
/// ### Reference
///
/// <https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md?plain=1#L236-L237>
const fn penalty(err_count: u16) -> f64 {
    (INTIAL_APPLICATION_SCORE - GRAYLIST_THRESHOLD) / APP_SPECIFIC_WEIGHT / (err_count as f64)
}
