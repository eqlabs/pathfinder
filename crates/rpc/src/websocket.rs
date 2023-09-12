use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::Response;

use crate::context::RpcContext;
use crate::jsonrpc::{RpcError, RpcRequest, RpcResponse};
use crate::websocket::types::BlockHeader;

pub mod types;

pub async fn websocket_handler(ws: WebSocketUpgrade, State(state): State<RpcContext>) -> Response {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: RpcContext) {
    let mut next_id = 0;
    let mut header_subscription: Option<u32> = None;

    let mut new_headers = state.websocket.new_head.0.subscribe();

    loop {
        tokio::select! {
            request = socket.recv() => {
                let request = match request {
                    Some(Ok(Message::Text(text))) => text.into_bytes(),
                    Some(Ok(Message::Binary(data))) => data,
                    Some(Ok(Message::Close(frame))) => {
                        tracing::trace!(?frame, "Websocket close request received");
                        break;
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                        // Replies to pings are automatically handled by axum already.
                        continue;
                    }
                    Some(Err(e)) => {
                        tracing::debug!(error=%e, "Error while receiving websocket message");
                        continue;
                    }
                    None => {
                        tracing::trace!("Websocket connection closed by client");
                        break;
                    }
                };

                let Ok(request) = serde_json::from_slice::<RpcRequest>(&request) else {
                    if send_response(&mut socket, &RpcResponse::INVALID_REQUEST).await.is_err() {
                        break;
                    } else {
                        continue;
                    }
                };

                let response = match request.method.as_ref() {
                    // TODO: this should be a formal error in the spec instead of an internal error.
                    "pathfinder_subscribe_newHeads" if header_subscription.is_some() => Err(
                        RpcError::InternalError(anyhow::anyhow!("Header subscription already active")),
                    ),
                    "pathfinder_subscribe_newHeads" => {
                        // Params must be empty.
                        if request.params.is_empty() {
                            let id = next_id;
                            next_id += 1;
                            header_subscription = Some(id);

                            Ok(serde_json::Value::Number(id.into()))
                        } else {
                            Err(RpcError::InvalidParams)
                        }
                    }
                    "pathfinder_unsubscribe_newHeads" => {
                        match request.params.deserialize::<u32>() {
                            Ok(id) if Some(id) == header_subscription => Ok(serde_json::Value::Bool(true)),
                            Ok(_) => Ok(serde_json::Value::Bool(false)),
                            Err(_) => Err(RpcError::InvalidParams)
                        }
                    }
                    _ => Err(RpcError::MethodNotFound),
                };

                if !request.id.is_notification() {
                    let response = RpcResponse {
                        output: response,
                        id: request.id,
                    };

                    if send_response(&mut socket, &response).await.is_err() {
                        break;
                    }
                }
            }
            header = new_headers.recv() => {
                use tokio::sync::broadcast::error::RecvError;
                if let Some(id) = header_subscription {
                    match header {
                        Ok(header) => {
                            if send_header(&mut socket, header, id).await.is_err() {
                                break;
                            }
                        }
                        // TODO: should one send an internal error in the event of failure here? Definitely all
                        // subscriptions will be invalid from here onwards..
                        Err(err) => match err {
                            RecvError::Closed => todo!(),
                            RecvError::Lagged(_) => todo!(),
                        },
                    }
                }
            }
        }
    }
}

/// Encodes and sends the response over the socket.
///
/// Intentionally hides the actual error as this function already does the logging.
async fn send_response(socket: &mut WebSocket, response: &RpcResponse<'_>) -> Result<(), ()> {
    let response = match serde_json::to_vec(response) {
        Ok(x) => x,
        Err(e) => {
            tracing::error!(error=%e, "Failed to encode websocket response");
            return Err(());
        }
    };

    if let Err(e) = socket.send(Message::Binary(response)).await {
        tracing::debug!(error=%e, "Failed to send websocket message");
        return Err(());
    }

    Ok(())
}

/// Encodes and sends the block header over the socket.
///
/// Intentionally hides the actual error as this function already does the logging.
async fn send_header(
    socket: &mut WebSocket,
    header: BlockHeader,
    subscription_id: u32,
) -> Result<(), ()> {
    #[derive(serde::Serialize)]
    struct HeaderOutput {
        subscription_id: u32,
        header: BlockHeader,
    }

    let output = HeaderOutput {
        subscription_id,
        header,
    };

    let output = match serde_json::to_value(&output) {
        Ok(x) => x,
        Err(e) => {
            tracing::error!(error=%e, "Failed to encode header");
            return Err(());
        }
    };

    let response = RpcResponse {
        output: Ok(output),
        id: crate::jsonrpc::RequestId::Null,
    };

    let response = match serde_json::to_vec(&response) {
        Ok(x) => x,
        Err(e) => {
            tracing::error!(error=%e, "Failed to encode header response");
            return Err(());
        }
    };

    if let Err(e) = socket.send(Message::Binary(response)).await {
        tracing::debug!(error=%e, "Failed to send header");
        return Err(());
    }

    Ok(())
}
