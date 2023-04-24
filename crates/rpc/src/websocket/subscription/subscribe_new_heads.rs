use crate::context::RpcContext;
use jsonrpsee::core::error::SubscriptionClosed;
use jsonrpsee::types::error::SubscriptionEmptyError;
use jsonrpsee::SubscriptionSink;
use starknet_gateway_types::websocket::WebsocketEventNewHead;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

pub fn subscribe_new_heads(
    _context: RpcContext,
    mut sink: SubscriptionSink,
    ws_new_heads_tx: &broadcast::Sender<WebsocketEventNewHead>,
) -> Result<(), SubscriptionEmptyError> {
    let ws_new_heads_tx = BroadcastStream::new(ws_new_heads_tx.subscribe());

    tokio::spawn(async move {
        match sink.pipe_from_try_stream(ws_new_heads_tx).await {
            SubscriptionClosed::Success => {
                sink.close(SubscriptionClosed::Success);
            }
            SubscriptionClosed::RemotePeerAborted => (),
            SubscriptionClosed::Failed(err) => {
                sink.close(err);
            }
        };
    });
    Ok(())
}
