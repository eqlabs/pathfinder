pub mod core;
pub mod main_loop;
pub mod peer;
pub mod sync;

use std::fmt::Debug;

use tokio::sync::mpsc;

/// [`MainLoop`](p2p::MainLoop)'s event channel size is 1, so we need to consume
/// all events as soon as they're sent otherwise the main loop will stall.
/// `f` should return `Some(data)` where `data` is extracted from
/// the event type of interest. For other events that should be ignored
/// `f` should return `None`. This function returns a receiver to the filtered
/// events' data channel.
pub(crate) fn filter_events<Event, Data>(
    mut event_receiver: mpsc::UnboundedReceiver<Event>,
    f: impl FnOnce(Event) -> Option<Data> + Copy + Send + 'static,
) -> mpsc::Receiver<Data>
where
    Event: Send + 'static,
    Data: Debug + Send + 'static,
{
    let (tx, rx) = mpsc::channel(1000);

    tokio::spawn(async move {
        while let Some(event) = event_receiver.recv().await {
            if let Some(data) = f(event) {
                tx.try_send(data).unwrap();
            }
        }
    });

    rx
}

/// Wait for a specific event to happen.
pub(crate) async fn wait_for_event<Event, Data>(
    event_receiver: &mut mpsc::UnboundedReceiver<Event>,
    mut f: impl FnMut(Event) -> Option<Data>,
) -> Option<Data>
where
    Event: Send + 'static,
    Data: Debug + Send + 'static,
{
    while let Some(event) = event_receiver.recv().await {
        if let Some(data) = f(event) {
            return Some(data);
        }
    }
    None
}
