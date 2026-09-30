//! Bounded, named-key LAN metadata exchange. No inventory or public DHT writes.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::{PeerId, StreamProtocol};
use tokio::sync::Semaphore;

use crate::swarm::SwarmHandle;
pub use crate::swarm::abort::AbortOnDropHandle as LanMetadataServer;

pub(crate) const LAN_METADATA_FANOUT: usize = 8;
pub(crate) const MAX_LAN_METADATA_ADDRESSES: usize = 8;

pub const MAX_LAN_NARINFO: usize = 64 * 1024;
pub const LAN_METADATA_TIMEOUT: Duration = Duration::from_secs(20);

/// Implemented by the composition root, which owns local Nix metadata and trust.
#[async_trait]
pub trait LanMetadataSource: Send + Sync {
    async fn lookup(&self, peer: PeerId, store_hash: &str) -> Option<Vec<u8>>;
}

pub fn valid_store_hash(hash: &str) -> bool {
    hash.len() == 32
        && hash
            .bytes()
            .all(|b| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&b))
}

impl SwarmHandle {
    /// Install only on a LAN-confined node. Each accepted stream is authorized
    /// by its actual connection, before spending a bounded concurrency slot.
    pub fn serve_lan_metadata(
        &self,
        source: Arc<dyn LanMetadataSource>,
    ) -> Result<LanMetadataServer, String> {
        let protocol = self.lan_metadata_protocol()?;
        let mut incoming = self
            .metadata_control()
            .accept(protocol)
            .map_err(|e| e.to_string())?;
        let handle = self.clone();
        let slots = Arc::new(Semaphore::new(4));
        Ok(LanMetadataServer::new(tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                    item = incoming.next() => {
                        let Some((peer, connection, mut stream)) = item else { break };
                        if !handle.metadata_connection_permitted(peer, connection) { continue; }
                        let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                        let source = source.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            let exchange = async {
                                let mut hash = [0u8; 32];
                                stream.read_exact(&mut hash).await.ok()?;
                                let hash = std::str::from_utf8(&hash).ok()?;
                                if !valid_store_hash(hash) { return None; }
                                let bytes = source.lookup(peer, hash).await.unwrap_or_default();
                                if bytes.len() > MAX_LAN_NARINFO { return None; }
                                stream.write_all(&(bytes.len() as u32).to_be_bytes()).await.ok()?;
                                stream.write_all(&bytes).await.ok()?;
                                stream.close().await.ok()
                            };
                            let _ = tokio::time::timeout(LAN_METADATA_TIMEOUT, exchange).await;
                        });
                    }
                }
            }
        })))
    }

    /// Query at most eight routing peers on the confined LAN. The caller
    /// verifies signatures and can continue past an invalid first answer.
    pub async fn lan_metadata_candidates(&self) -> Vec<PeerId> {
        if self.lan_metadata_protocol().is_err() {
            return Vec::new();
        }
        self.metadata_peers().await
    }

    pub async fn fetch_lan_metadata(&self, peer: PeerId, hash: &str) -> Option<Vec<u8>> {
        if !valid_store_hash(hash) {
            return None;
        }
        let protocol: StreamProtocol = self.lan_metadata_protocol().ok()?;
        let exchange = async {
            let (live, addresses) = self.metadata_peer_route(peer).await;
            let connection = match live {
                Some(connection) => connection,
                None => self
                    .connect_lan_metadata(peer, addresses, LAN_METADATA_TIMEOUT)
                    .await
                    .ok()?,
            };
            let mut stream = self
                .metadata_control()
                .open_stream_on_connection(peer, connection, protocol)
                .await
                .ok()?;
            let mut size = [0u8; 4];
            stream.write_all(hash.as_bytes()).await.ok()?;
            stream.flush().await.ok()?;
            stream.read_exact(&mut size).await.ok()?;
            let size = u32::from_be_bytes(size) as usize;
            if size == 0 || size > MAX_LAN_NARINFO {
                return None;
            }
            let mut bytes = vec![0u8; size];
            stream.read_exact(&mut bytes).await.ok()?;
            let mut tail = [0u8; 1];
            if stream.read(&mut tail).await.ok()? != 0 {
                return None;
            }
            Some(bytes)
        };
        tokio::time::timeout(LAN_METADATA_TIMEOUT, exchange)
            .await
            .ok()
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swarm::{Node, NodeConfig};

    struct EchoMetadata;
    #[async_trait]
    impl LanMetadataSource for EchoMetadata {
        async fn lookup(&self, _: PeerId, hash: &str) -> Option<Vec<u8>> {
            Some(format!("metadata-for-{hash}").into_bytes())
        }
    }

    fn confined_node(seed: u8) -> Node {
        Node::start(
            NodeConfig::new([seed; 32])
                .with_network_scope("lan-metadata-reconnect-test")
                .with_lan_confinement(true)
                .with_relay_server(false),
        )
        .expect("confined test node")
    }

    #[tokio::test]
    async fn metadata_reconnects_to_known_lan_peer_after_connection_loss() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let consumer = confined_node(131);
            let provider = confined_node(132);
            provider
                .handle
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            let address = provider.handle.listen_addrs().await.remove(0);
            let peer = provider.peer_id;
            let server = provider
                .handle
                .serve_lan_metadata(Arc::new(EchoMetadata))
                .unwrap();
            consumer.handle.add_address(peer, address.clone()).await;
            let hash = "00000000000000000000000000000000";
            let expected = format!("metadata-for-{hash}").into_bytes();
            assert!(
                consumer
                    .handle
                    .lan_metadata_candidates()
                    .await
                    .contains(&peer)
            );
            assert_eq!(
                consumer.handle.fetch_lan_metadata(peer, hash).await,
                Some(expected.clone())
            );
            assert!(consumer.handle.is_connected(peer).await);

            // Real transport closure, retaining only the consumer's known LAN route.
            // Mutating candidate selection back to live connections loses this peer.
            drop(server);
            drop(provider);
            while consumer.handle.is_connected(peer).await {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                consumer
                    .handle
                    .lan_metadata_candidates()
                    .await
                    .contains(&peer),
                "a disconnected known LAN peer must remain a metadata candidate"
            );
            let (connection, addresses) = consumer.handle.metadata_peer_route(peer).await;
            assert!(connection.is_none());
            assert!(
                addresses
                    .iter()
                    .any(|known| known.to_string().starts_with(&address.to_string()))
            );

            let provider = confined_node(132);
            provider.handle.listen(address).await.unwrap();
            let _server = provider
                .handle
                .serve_lan_metadata(Arc::new(EchoMetadata))
                .unwrap();
            assert_eq!(
                consumer.handle.fetch_lan_metadata(peer, hash).await,
                Some(expected),
                "metadata lookup must reconnect using the retained LAN route"
            );
            let (connection, _) = consumer.handle.metadata_peer_route(peer).await;
            assert!(
                consumer
                    .handle
                    .metadata_connection_permitted(peer, connection.unwrap())
            );

            let rejected = consumer
                .handle
                .connect_lan_metadata(
                    peer,
                    vec!["/ip4/203.0.113.7/tcp/1234".parse().unwrap()],
                    Duration::from_secs(1),
                )
                .await;
            assert!(rejected.unwrap_err().contains("direct LAN addresses"));
        })
        .await
        .expect("metadata reconnect is bounded");
    }
}
