use crate::module::Module;

use starknet_gateway_types::websocket::WebsocketSenders;

pub mod subscription;

pub fn register_subscriptions(
    module: Module,
    ws_broadcast_txs: WebsocketSenders,
) -> anyhow::Result<Module> {
    let module = module.register_subscription(
        "pathfinder_subscribe_newHeads",
        "pathfinder_subscription_newHead",
        "pathfinder_unsubscribe_newHeads",
        subscription::subscribe_new_heads::subscribe_new_heads,
        ws_broadcast_txs.new_head,
    )?;

    Ok(module)
}
