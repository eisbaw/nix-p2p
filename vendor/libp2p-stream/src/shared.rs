use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    sync::{Arc, Mutex, MutexGuard},
};

use futures::channel::mpsc;
use libp2p_identity::PeerId;
use libp2p_swarm::{ConnectionId, Stream, StreamProtocol};
use rand::seq::IteratorRandom as _;

use crate::{handler::NewStream, AlreadyRegistered, IncomingStreams};

pub(crate) struct Shared {
    /// Tracks the supported inbound protocols created via
    /// [`Control::accept`](crate::Control::accept).
    ///
    /// For each [`StreamProtocol`], we hold the [`mpsc::Sender`] corresponding to the
    /// [`mpsc::Receiver`] in [`IncomingStreams`].
    supported_inbound_protocols: HashMap<StreamProtocol, mpsc::Sender<(PeerId, Stream)>>,

    connections: HashMap<ConnectionId, PeerId>,
    senders: HashMap<ConnectionId, mpsc::Sender<NewStream>>,

    /// Tracks channel pairs for a peer whilst we are dialing them.
    pending_channels: HashMap<PeerId, (mpsc::Sender<NewStream>, mpsc::Receiver<NewStream>)>,

    /// Sender for peers we want to dial.
    ///
    /// We manage this through a channel to avoid locks as part of
    /// [`NetworkBehaviour::poll`](libp2p_swarm::NetworkBehaviour::poll).
    dial_sender: mpsc::Sender<PeerId>,
}

impl Shared {
    pub(crate) fn lock(shared: &Arc<Mutex<Shared>>) -> MutexGuard<'_, Shared> {
        shared.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Shared {
    pub(crate) fn new(dial_sender: mpsc::Sender<PeerId>) -> Self {
        Self {
            dial_sender,
            connections: Default::default(),
            senders: Default::default(),
            pending_channels: Default::default(),
            supported_inbound_protocols: Default::default(),
        }
    }

    pub(crate) fn accept(
        &mut self,
        protocol: StreamProtocol,
    ) -> Result<IncomingStreams, AlreadyRegistered> {
        self.supported_inbound_protocols
            .retain(|_, sender| !sender.is_closed());

        if self.supported_inbound_protocols.contains_key(&protocol) {
            return Err(AlreadyRegistered);
        }

        let (sender, receiver) = mpsc::channel(0);
        self.supported_inbound_protocols
            .insert(protocol.clone(), sender);

        Ok(IncomingStreams::new(receiver))
    }

    /// Lists the protocols for which we have an active [`IncomingStreams`] instance.
    pub(crate) fn supported_inbound_protocols(&mut self) -> Vec<StreamProtocol> {
        self.supported_inbound_protocols
            .retain(|_, sender| !sender.is_closed());

        self.supported_inbound_protocols.keys().cloned().collect()
    }

    pub(crate) fn on_inbound_stream(
        &mut self,
        remote: PeerId,
        stream: Stream,
        protocol: StreamProtocol,
    ) {
        match self.supported_inbound_protocols.entry(protocol.clone()) {
            Entry::Occupied(mut entry) => match entry.get_mut().try_send((remote, stream)) {
                Ok(()) => {}
                Err(e) if e.is_full() => {
                    tracing::debug!(%protocol, "Channel is full, dropping inbound stream");
                }
                Err(e) if e.is_disconnected() => {
                    tracing::debug!(%protocol, "Channel is gone, dropping inbound stream");
                    entry.remove();
                }
                _ => unreachable!(),
            },
            Entry::Vacant(_) => {
                tracing::debug!(%protocol, "channel is gone, dropping inbound stream");
            }
        }
    }

    pub(crate) fn on_connection_established(&mut self, conn: ConnectionId, peer: PeerId) {
        self.connections.insert(conn, peer);
    }

    pub(crate) fn on_connection_closed(&mut self, conn: ConnectionId) {
        self.connections.remove(&conn);
        self.senders.remove(&conn);
    }

    pub(crate) fn on_dial_failure(&mut self, peer: PeerId, reason: String) {
        let Some((_, mut receiver)) = self.pending_channels.remove(&peer) else {
            return;
        };

        while let Ok(new_stream) = receiver.try_recv() {
            let _ = new_stream
                .sender
                .send(Err(crate::OpenStreamError::Io(io::Error::new(
                    io::ErrorKind::NotConnected,
                    reason.clone(),
                ))));
        }
    }

    pub(crate) fn sender(&mut self, peer: PeerId) -> mpsc::Sender<NewStream> {
        let maybe_sender = self
            .connections
            .iter()
            .filter_map(|(c, p)| (p == &peer).then_some(c))
            .choose(&mut rand::thread_rng())
            .and_then(|c| self.senders.get(c));

        match maybe_sender {
            Some(sender) => {
                tracing::debug!("Returning sender to existing connection");

                sender.clone()
            }
            None => {
                tracing::debug!(%peer, "Not connected to peer, initiating dial");

                let (sender, _) = self
                    .pending_channels
                    .entry(peer)
                    .or_insert_with(|| mpsc::channel(0));

                let _ = self.dial_sender.try_send(peer);

                sender.clone()
            }
        }
    }

    /// Return only the sender owned by `connection`, after atomically verifying the ID is live
    /// and belongs to `peer`. There is deliberately no peer-wide selection or dial fallback.
    pub(crate) fn sender_on_connection(
        &self,
        peer: PeerId,
        connection: ConnectionId,
    ) -> io::Result<mpsc::Sender<NewStream>> {
        match self.connections.get(&connection) {
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("connection {connection} is stale; no live connection exists for {peer}"),
            )),
            Some(actual_peer) if *actual_peer != peer => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!(
                    "connection {connection} belongs to peer {actual_peer}, not requested peer {peer}"
                ),
            )),
            Some(_) => self.senders.get(&connection).cloned().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    format!(
                        "connection {connection} to peer {peer} has no live stream handler sender"
                    ),
                )
            }),
        }
    }

    pub(crate) fn receiver(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
    ) -> mpsc::Receiver<NewStream> {
        if let Some((sender, receiver)) = self.pending_channels.remove(&peer) {
            tracing::debug!(%peer, %connection, "Returning existing pending receiver");

            self.senders.insert(connection, sender);
            return receiver;
        }

        tracing::debug!(%peer, %connection, "Creating new channel pair");

        let (sender, receiver) = mpsc::channel(0);
        self.senders.insert(connection, sender);

        receiver
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt as _, StreamExt as _};

    use super::*;

    fn peer(id: &str) -> PeerId {
        id.parse().expect("fixed test PeerId is valid")
    }

    #[test]
    fn exact_sender_rejects_stale_and_wrong_peer_connection_ids() {
        let (dial_sender, _dial_receiver) = mpsc::channel(0);
        let mut shared = Shared::new(dial_sender);
        let owner = peer("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN");
        let wrong = peer("12D3KooWBr7cTGxmMhdiGNcbesEusWMR1VG26jEQQgFr6wwZkNNf");
        let connection = ConnectionId::new_unchecked(41);
        let _receiver = shared.receiver(owner, connection);
        shared.on_connection_established(connection, owner);

        let wrong_error = shared
            .sender_on_connection(wrong, connection)
            .expect_err("a connection ID cannot be borrowed by another peer");
        assert_eq!(wrong_error.kind(), io::ErrorKind::NotConnected);
        assert!(wrong_error.to_string().contains("belongs to peer"));

        shared.on_connection_closed(connection);
        let stale_error = shared
            .sender_on_connection(owner, connection)
            .expect_err("a closed connection ID cannot fall back to another route");
        assert_eq!(stale_error.kind(), io::ErrorKind::NotConnected);
        assert!(stale_error.to_string().contains("stale"));
    }

    #[test]
    fn exact_sender_targets_only_the_requested_connection() {
        futures::executor::block_on(async {
            let (dial_sender, _dial_receiver) = mpsc::channel(0);
            let mut shared = Shared::new(dial_sender);
            let peer = peer("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN");
            let first = ConnectionId::new_unchecked(51);
            let second = ConnectionId::new_unchecked(52);
            let mut first_receiver = shared.receiver(peer, first);
            let mut second_receiver = shared.receiver(peer, second);
            shared.on_connection_established(first, peer);
            shared.on_connection_established(second, peer);

            let mut selected = shared
                .sender_on_connection(peer, second)
                .expect("the exact second connection is live");
            let (stream_reply, _stream_result) = futures::channel::oneshot::channel();
            let message = NewStream {
                protocol: StreamProtocol::new("/exact-connection-test"),
                sender: stream_reply,
            };
            let (send_result, received) =
                futures::join!(selected.send(message), second_receiver.next());
            send_result.expect("selected connection accepts the request");
            assert!(
                received.is_some(),
                "the selected connection receives the request"
            );
            assert!(
                first_receiver.try_recv().is_err(),
                "the other connection must receive nothing; random peer-wide selection is forbidden"
            );
        });
    }

    #[test]
    fn dial_failure_reports_every_queued_open_request() {
        futures::executor::block_on(async {
            let (dial_sender, _dial_receiver) = mpsc::channel(0);
            let mut shared = Shared::new(dial_sender);
            let peer = peer("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN");
            let (mut pending_sender, pending_receiver) = mpsc::channel(2);
            let mut replies = Vec::new();

            for protocol in ["/dial-failure-test/1", "/dial-failure-test/2"] {
                let (reply_sender, reply_receiver) = futures::channel::oneshot::channel();
                pending_sender
                    .try_send(NewStream {
                        protocol: StreamProtocol::new(protocol),
                        sender: reply_sender,
                    })
                    .expect("test request fits in the pending queue");
                replies.push(reply_receiver);
            }
            shared
                .pending_channels
                .insert(peer, (pending_sender, pending_receiver));

            shared.on_dial_failure(peer, "dial refused".to_string());

            assert!(
                !shared.pending_channels.contains_key(&peer),
                "a terminal dial failure removes the pending channel"
            );
            for reply in replies {
                let error = reply
                    .await
                    .expect("dial failure sends an explicit response")
                    .expect_err("queued open request fails when dialing fails");
                assert!(
                    error.to_string().contains("dial refused"),
                    "terminal error retains the dial-failure context: {error}"
                );
            }
        });
    }
}
