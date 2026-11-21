//! The live event stream for front ends, over WebSocket.
//!
//! WebSockets are not covered by the same-origin policy, so the Origin check in [`crate::security::guard`]
//! is what stops a target page from opening this socket with the user's cookie. Viewers and up may subscribe.

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use bosun_store::Role;
use tokio::sync::broadcast::error::RecvError;

use crate::AppState;
use crate::auth::Caller;

pub async fn events(
    State(st): State<AppState>,
    caller: Caller,
    ws: WebSocketUpgrade,
) -> Result<Response, Response> {
    caller.require(Role::Viewer)?;
    let rx = st.inner.events.subscribe();
    Ok(ws
        .max_message_size(64 * 1024)
        .on_upgrade(move |socket| pump(socket, rx)))
}

async fn pump(mut socket: WebSocket, mut rx: tokio::sync::broadcast::Receiver<bosun_proxy::ProxyEvent>) {
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(ev) => {
                    let Ok(text) = serde_json::to_string(&ev) else { continue };
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        return;
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    // The client fell behind; tell it to reload instead of silently missing events.
                    let msg = serde_json::json!({ "type": "lagged", "missed": n }).to_string();
                    if socket.send(Message::Text(msg.into())).await.is_err() {
                        return;
                    }
                }
                Err(RecvError::Closed) => return,
            },
            incoming = socket.recv() => match incoming {
                // Clients only send pings/close; anything else is ignored.
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                Some(Ok(_)) => {}
            },
        }
    }
}
