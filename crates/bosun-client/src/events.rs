//! The event stream with resume (see `bosun-api`'s `events.rs` for the protocol).

use std::sync::Arc;

use futures_util::StreamExt;
use reqwest::Url;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::client::Client;
use crate::error::{Error, Result};
use crate::types::Event;

/// Where a stream stood: the engine run and the last event number seen. Hand it to
/// [`Client::events`] to carry on after a disconnect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Position {
    pub epoch: String,
    pub seq: u64,
}

/// An event and its place in the stream. `seq` is `None` for the stream's own `hello` and `reload` messages.
#[derive(Debug, Clone)]
pub struct Sequenced {
    pub seq: Option<u64>,
    pub event: Event,
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A live connection to `/api/v1/events`.
///
/// [`EventStream::next`] returns events in order. When the connection drops, call [`EventStream::reconnect`]: it
/// resumes from [`EventStream::position`], and you will get a [`Event::Reload`] if the engine could not replay
/// what you missed (fetch your data again then).
pub struct EventStream {
    client: Client,
    ws: Socket,
    position: Option<Position>,
}

impl std::fmt::Debug for EventStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventStream")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl EventStream {
    pub(crate) async fn connect(client: Client, resume: Option<Position>) -> Result<Self> {
        let ws = open(&client, resume.as_ref()).await?;
        Ok(Self {
            client,
            ws,
            position: resume,
        })
    }

    /// The latest position seen. `None` until the engine's `hello` has arrived.
    pub fn position(&self) -> Option<&Position> {
        self.position.as_ref()
    }

    /// The next event, or `None` when the engine closed the stream.
    pub async fn next(&mut self) -> Option<Result<Sequenced>> {
        loop {
            let msg = match self.ws.next().await? {
                Ok(m) => m,
                Err(e) => return Some(Err(Error::Events(e.to_string()))),
            };
            let text = match msg {
                Message::Text(t) => t,
                Message::Close(_) => return None,
                _ => continue,
            };
            return Some(self.parse(text.as_str()));
        }
    }

    fn parse(&mut self, text: &str) -> Result<Sequenced> {
        #[derive(serde::Deserialize)]
        struct Seq {
            seq: Option<u64>,
        }
        let event: Event =
            serde_json::from_str(text).map_err(|e| Error::Events(format!("{e} in {text:.200}")))?;
        let seq = serde_json::from_str::<Seq>(text).ok().and_then(|s| s.seq);
        match &event {
            Event::Hello { epoch, seq } => {
                self.position = Some(Position {
                    epoch: epoch.clone(),
                    seq: *seq,
                })
            }
            _ => {
                if let (Some(p), Some(s)) = (&mut self.position, seq) {
                    p.seq = s;
                }
            }
        }
        Ok(Sequenced {
            seq: if matches!(event, Event::Hello { .. }) {
                None
            } else {
                seq
            },
            event,
        })
    }

    /// Open the connection again from where this stream got to.
    pub async fn reconnect(&mut self) -> Result<()> {
        self.ws = open(&self.client, self.position.as_ref()).await?;
        Ok(())
    }

    /// Close the connection politely.
    pub async fn close(mut self) {
        let _ = futures_util::SinkExt::close(&mut self.ws).await;
    }
}

async fn open(client: &Client, resume: Option<&Position>) -> Result<Socket> {
    let mut url: Url = client.inner.url.clone();
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .map_err(|()| Error::Setup("cannot use this address for a WebSocket".into()))?;
    url.set_path("/api/v1/events");
    if let Some(p) = resume {
        url.query_pairs_mut()
            .append_pair("since", &p.seq.to_string())
            .append_pair("epoch", &p.epoch);
    }
    let mut req = url
        .as_str()
        .into_client_request()
        .map_err(|e| Error::Events(e.to_string()))?;
    client.authorize(req.headers_mut());
    let connector = if scheme == "wss" && !client.inner.roots_pem.is_empty() {
        let mut roots = rustls::RootCertStore::empty();
        for pem in &client.inner.roots_pem {
            for der in CertificateDer::pem_slice_iter(pem) {
                let der = der.map_err(|e| Error::Setup(format!("bad CA certificate: {e}")))?;
                roots
                    .add(der)
                    .map_err(|e| Error::Setup(format!("bad CA certificate: {e}")))?;
            }
        }
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Some(Connector::Rustls(Arc::new(cfg)))
    } else {
        None
    };
    let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(req, None, false, connector)
        .await
        .map_err(|e| match e {
            tokio_tungstenite::tungstenite::Error::Http(r) => Error::Api {
                status: r.status().as_u16(),
                message: "the engine refused the event stream".into(),
            },
            e => Error::Events(e.to_string()),
        })?;
    Ok(ws)
}
