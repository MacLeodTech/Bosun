//! The live event stream for front ends, over WebSocket.
//!
//! WebSockets are not covered by the same-origin policy, so the Origin check in [`crate::security::guard`]
//! is what stops a target page from opening this socket with the user's cookie. Viewers and up may subscribe.
//!
//! Every event carries a sequence number. The first message on a connection is
//! `{"type":"hello","epoch":"…","seq":N}`: the engine run's name and the latest number. A client that reconnects
//! passes `?since=N&epoch=E` and is sent what it missed. If that is no longer possible (too much happened, or the
//! engine restarted) it gets `{"type":"reload"}` and should fetch its data again.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use bosun_proxy::{EventBus, EventReceiver, Resume};
use bosun_store::Role;
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;

use crate::AppState;
use crate::auth::Caller;

#[derive(Deserialize, Default)]
pub struct Since {
    since: Option<u64>,
    epoch: Option<String>,
}

pub async fn events(
    State(st): State<AppState>,
    caller: Caller,
    Query(q): Query<Since>,
    ws: WebSocketUpgrade,
) -> Result<Response, Response> {
    caller.require(Role::Viewer)?;
    let bus = st.inner.events.clone();
    Ok(ws
        .max_message_size(64 * 1024)
        .on_upgrade(move |socket| pump(socket, bus, q)))
}

async fn send_json(socket: &mut WebSocket, v: &impl serde::Serialize) -> bool {
    match serde_json::to_string(v) {
        Ok(text) => socket.send(Message::Text(text.into())).await.is_ok(),
        Err(_) => true,
    }
}

async fn pump(mut socket: WebSocket, bus: EventBus, q: Since) {
    // Subscribe first, then say where the stream stands, so nothing falls between the two.
    let (mut rx, mut last, replay, reload) = match (q.since, q.epoch.as_deref()) {
        (Some(since), Some(epoch)) => match bus.resume_in(epoch, since) {
            Resume::Replay { missed, rx } => (rx, since, missed, false),
            Resume::Reload { rx } => {
                let seq = bus.current_seq();
                (rx, seq, Vec::new(), true)
            }
        },
        // A client from another run (or one that gave no position) starts from here; a stale position is
        // told to reload.
        (since, _) => {
            let rx = bus.subscribe();
            (rx, bus.current_seq(), Vec::new(), since.is_some())
        }
    };
    let hello = serde_json::json!({ "type": "hello", "epoch": bus.epoch(), "seq": last });
    if !send_json(&mut socket, &hello).await {
        return;
    }
    if reload && !send_json(&mut socket, &serde_json::json!({ "type": "reload" })).await {
        return;
    }
    for e in replay {
        last = e.seq;
        if !send_json(&mut socket, &e).await {
            return;
        }
    }
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(e) => {
                    // The replay and the live channel may overlap by an event or two.
                    if e.seq <= last {
                        continue;
                    }
                    last = e.seq;
                    if !send_json(&mut socket, &e).await {
                        return;
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    // Fell behind the live channel: catch up from the recent events, or say to reload.
                    match catch_up(&mut socket, &bus, &mut rx, &mut last).await {
                        Some(true) => {}
                        _ => return,
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

/// After a lag: send what was missed, or tell the client to reload. `Some(true)` to carry on.
async fn catch_up(
    socket: &mut WebSocket,
    bus: &EventBus,
    rx: &mut EventReceiver,
    last: &mut u64,
) -> Option<bool> {
    match bus.resume(*last) {
        Resume::Replay { missed, rx: fresh } => {
            *rx = fresh;
            for e in missed {
                *last = e.seq;
                if !send_json(socket, &e).await {
                    return None;
                }
            }
        }
        Resume::Reload { rx: fresh } => {
            *rx = fresh;
            *last = bus.current_seq();
            if !send_json(socket, &serde_json::json!({ "type": "reload" })).await {
                return None;
            }
        }
    }
    Some(true)
}
