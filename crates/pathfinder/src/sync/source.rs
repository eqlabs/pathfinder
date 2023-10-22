mod block;
mod ethereum;
mod head;
mod pending;
mod watcher;

pub trait Gateway: GatewayApi + Send + 'static {}
impl<G> Gateway for G where G: GatewayApi + Send + 'static {}
