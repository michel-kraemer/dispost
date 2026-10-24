use std::{
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
};

use dashmap::DashMap;
use distruct::{Cluster, collections::DMultiMap};
use log::{debug, error, info};
use quinn::{
    ClientConfig, ConnectionError, Endpoint, Incoming, RecvStream, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    rustls::{
        self, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer},
    },
};
use rand::seq::IndexedRandom as _;
use tokio::{
    sync::{
        Mutex,
        mpsc::{UnboundedSender, unbounded_channel},
        oneshot,
    },
    task::JoinHandle,
};
use tracing::{Instrument, info_span};

use crate::{
    error::{ConfigError, CreateError, Error, Result, TransportError},
    message::Message,
    peer::Peer,
    subscribers::{OnceSubscriber, UnboundedSubscriber},
};

const ALPN_QUIC_EVENTBUS: &[u8] = b"eventbus";

/// [`EventBus`] configuration.
///
/// Create instances using [`EventBusConfigBuilder`].
pub struct EventBusConfig {
    bind_addr: SocketAddr,
    public_addr: Option<SocketAddr>,
    public_server_name: String,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

/// A builder for [`EventBusConfig`].
pub struct EventBusConfigBuilder {
    bind_addr: SocketAddr,
    public_addr: Option<SocketAddr>,
    public_server_name: String,
}

impl Default for EventBusConfigBuilder {
    fn default() -> Self {
        Self {
            bind_addr: (Ipv6Addr::LOCALHOST, 0).into(),
            public_addr: None,
            public_server_name: "::1".to_string(),
        }
    }
}

impl EventBusConfigBuilder {
    /// Sets the IP address and port to bind the node to.
    ///
    /// By default, the node binds to the loopback address (`::1`) on a random
    /// port.
    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Sets the public IP address and port that other nodes can use to reach
    /// this node.
    ///
    /// If not set, the public address defaults to the bind address.
    pub fn with_public_addr<S>(mut self, addr: SocketAddr, server_name: S) -> Self
    where
        S: Into<String>,
    {
        self.public_addr = Some(addr);
        self.public_server_name = server_name.into();
        self
    }

    /// Builds the [`EventBusConfig`] object using the current builder
    /// configuration and the given TLS certificates and private key.
    pub fn build(
        self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> EventBusConfig {
        EventBusConfig {
            bind_addr: self.bind_addr,
            public_addr: self.public_addr,
            public_server_name: self.public_server_name,
            certs,
            key,
        }
    }
}

enum SubscriberSender {
    Unbounded {
        id: u64,
        sender: UnboundedSender<Arc<Message>>,
    },
    Once {
        id: u64,
        address: Arc<str>,
        sender: oneshot::Sender<Arc<Message>>,
    },
}

struct SubscriberMaps {
    /// A Mutex that only needs to be locked on write operations where
    /// `local_subscribers` and `remote_subscribers` are changed at the same
    /// time.
    write_mutex: Mutex<()>,

    local_subscribers: DashMap<Arc<str>, Vec<SubscriberSender>>,
    remote_subscribers: DMultiMap<Arc<str>, Peer>,
}

impl SubscriberMaps {
    async fn add(&self, peer: Peer, address: Arc<str>, sender: SubscriberSender) -> Result<()> {
        let _lock = self.write_mutex.lock().await;

        let mut entry = self
            .local_subscribers
            .entry(Arc::clone(&address))
            .or_default();
        entry.push(sender);

        if let Err(e) = self.remote_subscribers.insert(address, peer).await {
            // make sure `entry` does not contain an orphaned item
            entry.pop();

            return Err(e.into());
        }

        Ok(())
    }

    async fn remove(
        &self,
        peer: &Peer,
        id: u64,
        address: Arc<str>,
    ) -> Result<Option<SubscriberSender>> {
        let _lock = self.write_mutex.lock().await;

        if let Some(mut subscribers) = self.local_subscribers.get_mut(&address)
            && let Some((index, _)) = subscribers.iter().enumerate().find(|(_, s)| {
                let sender_id = match s {
                    SubscriberSender::Unbounded { id: sender_id, .. } => *sender_id,
                    SubscriberSender::Once { id: sender_id, .. } => *sender_id,
                };
                id == sender_id
            })
        {
            let s = subscribers.swap_remove(index);

            if subscribers.is_empty() {
                // Drop `subscribers` so we can modify `local_subscribers`.
                // Otherwise, `remove` will deadlock.
                drop(subscribers);

                self.local_subscribers.remove(&address);
                self.remote_subscribers.remove(&address, peer).await?;
            }

            return Ok(Some(s));
        }

        Ok(None)
    }

    /// Removes all local subscribers and unregisters `peer` for their addresses.
    async fn remove_all(&self, peer: &Peer) -> Result<()> {
        let _lock = self.write_mutex.lock().await;

        let mut addresses = Vec::with_capacity(self.local_subscribers.len());
        self.local_subscribers.retain(|address, _| {
            addresses.push(Arc::clone(address));
            false
        });

        for address in addresses {
            self.remote_subscribers.remove(&address, peer).await?;
        }

        Ok(())
    }
}

/// A distributed event bus.
///
/// Use it to send messages between nodes in a `distruct::Cluster`.
pub struct EventBus {
    endpoint: Endpoint,
    peer: Peer,
    subscriber_maps: Arc<SubscriberMaps>,
    main_loop_handle: JoinHandle<()>,
}

impl EventBus {
    /// Creates a new event bus using the given `distruct::Cluster` and
    /// configuration.
    pub fn new(cluster: &Cluster, config: EventBusConfig) -> Result<Self, CreateError> {
        // create endpoint
        let endpoint = create_endpoint(config.bind_addr, config.certs, config.key)?;

        let local_addr = endpoint.local_addr().map_err(CreateError::CreateEndpoint)?;
        let public_addr = config.public_addr.unwrap_or(local_addr);

        let peer = Peer::new(public_addr, config.public_server_name);
        let local_subscribers = DashMap::new();
        let remote_subscribers = cluster.get_multi_map("__dispost_subscribers");
        let subscriber_maps = Arc::new(SubscriberMaps {
            write_mutex: Mutex::default(),
            local_subscribers,
            remote_subscribers,
        });

        // handle incoming messages
        let inner_endpoint = endpoint.clone();
        let inner_peer = Arc::new(peer.clone());
        let inner_subscriber_maps = Arc::clone(&subscriber_maps);
        let main_loop_handle = tokio::spawn(async move {
            while let Some(conn) = inner_endpoint.accept().await {
                if !conn.remote_address_validated() {
                    info!("requiring connection to validate its address");
                    conn.retry().unwrap();
                } else {
                    info!("accepting connection");
                    let fut = handle_connection(
                        conn,
                        Arc::clone(&inner_subscriber_maps),
                        Arc::clone(&inner_peer),
                    );
                    tokio::spawn(async move {
                        if let Err(e) = fut.await {
                            error!("connection failed: {e}");
                        }
                    });
                }
            }
        });

        info!("Event bus listening on {local_addr} ...");

        Ok(Self {
            endpoint,
            peer,
            subscriber_maps,
            main_loop_handle,
        })
    }

    /// Shuts down the event bus.
    pub async fn shutdown(self) -> Result<()> {
        self.subscriber_maps.remove_all(&self.peer).await?;
        self.endpoint.close(0u32.into(), b"shutdown");
        self.endpoint.wait_idle().await;
        self.main_loop_handle.await?;
        Ok(())
    }

    /// Subscribe to an address on the event bus.
    ///
    /// The method creates an unbounded in-memory message queue for messages
    /// that arrive at the given address. It returns a subscriber that can be
    /// used to take messages from the queue.
    pub async fn subscribe<A>(&self, address: A) -> Result<UnboundedSubscriber>
    where
        A: Into<String>,
    {
        let address = Arc::from(address.into());
        let (sender, receiver) = unbounded_channel();
        let receiver = UnboundedSubscriber::new(Arc::clone(&address), receiver);
        self.subscriber_maps
            .add(
                self.peer.clone(),
                address,
                SubscriberSender::Unbounded {
                    id: receiver.id,
                    sender,
                },
            )
            .await?;
        Ok(receiver)
    }

    /// Subscribe to receiving a single message at a certain event bus address.
    ///
    /// The method creates a subscriber that can be used to receive exactly one
    /// message at the given address. Once the message is received, the
    /// subscriber is automatically unregistered from the event bus and cannot
    /// be used anymore.
    pub async fn subscribe_once<A>(&self, address: A) -> Result<OnceSubscriber>
    where
        A: Into<String>,
    {
        let address = Arc::from(address.into());
        let (sender, receiver) = oneshot::channel();
        let receiver = OnceSubscriber::new(Arc::clone(&address), receiver);
        self.subscriber_maps
            .add(
                self.peer.clone(),
                Arc::clone(&address),
                SubscriberSender::Once {
                    id: receiver.id,
                    address,
                    sender,
                },
            )
            .await?;
        Ok(receiver)
    }

    async fn send_to(&self, c: &Peer, message: &Message) -> Result<()> {
        let payload = postcard::to_allocvec(message)?;

        // TODO add connection cache
        let connection = self
            .endpoint
            .connect(c.addr, &c.server_name)
            .map_err(TransportError::from)?
            .await
            .map_err(TransportError::from)?;

        let mut stream = connection.open_uni().await.map_err(TransportError::from)?;

        stream
            .write_all(&payload)
            .await
            .map_err(TransportError::from)?;

        let _ = stream.finish();

        // TODO this is not necessary if the connection is cached
        let _ = stream.stopped().await;

        Ok(())
    }

    /// Send a message to a single subscriber at a certain event bus address.
    ///
    /// If there is no subscriber at the given address, the method returns
    /// [`Error::NoSubscriber`]. If there are multiple subscribers, the current
    /// implementation selects one at random. This may change in the future.
    ///
    /// The method makes no guarantees about whether the message is actually
    /// received and processed by the subscriber.
    pub async fn send(&self, address: &str, message: &[u8]) -> Result<()> {
        let message = Message {
            address: address.to_string(),
            body: message.to_vec(),
            reply_address: None,
        };

        // select peer now and not in the `if let` statement below because `if
        // let` would borrow `rand::rng()` and we wouldn't be able to call
        // `.await` because `ThreadRng` is not `Send`
        let subscribers = self.subscriber_maps.remote_subscribers.get(address).await?;
        let peer = subscribers.choose(&mut rand::rng());

        // TODO implement proper round-robin and other strategies
        if let Some(s) = peer {
            self.send_to(s, &message).await
        } else {
            Err(Error::NoSubscriber {
                address: address.to_string(),
            })
        }
    }

    /// Send a message to all subscribers at a certain event bus address.
    ///
    /// If there is no subscriber at the given address at all, the method
    /// returns [`Error::NoSubscriber`].
    ///
    /// The method makes no guarantees about whether the message is actually
    /// received and processed by the subscribers.
    pub async fn publish(&self, address: &str, message: &[u8]) -> Result<()> {
        let message = Message {
            address: address.to_string(),
            body: message.to_vec(),
            reply_address: None,
        };

        let subscribers = self.subscriber_maps.remote_subscribers.get(address).await?;

        if subscribers.is_empty() {
            return Err(Error::NoSubscriber {
                address: address.to_string(),
            });
        }

        for s in subscribers {
            self.send_to(&s, &message).await?;
        }

        Ok(())
    }

    /// Send a request to a subscriber at a certain event bus address and return
    /// its reply.
    ///
    /// If there is no subscriber at the given address, the method returns
    /// [`Error::NoSubscriber`]. Otherwise, the method sends the message to
    /// exactly one subscriber and returns a new, temporary subscriber that can
    /// be used to receive the reply.
    ///
    /// If there are multiple subscribers, the current implementation selects
    /// one at random. This may change in the future.
    pub async fn request(&self, address: &str, message: &[u8]) -> Result<OnceSubscriber> {
        // TODO implement proper round-robin and other strategies
        let ss = self.subscriber_maps.remote_subscribers.get(address).await?;
        let Some(remote_subscriber) = ss.choose(&mut rand::rng()) else {
            return Err(Error::NoSubscriber {
                address: address.to_string(),
            });
        };

        let reply_address = format!("__dispost_reply_{}", ulid::Ulid::generate());
        let reply_subscriber = self.subscribe_once(&reply_address).await?;

        let message = Message {
            address: address.to_string(),
            body: message.to_vec(),
            reply_address: Some(reply_address),
        };

        // TODO unsubscribe if send fails!
        self.send_to(remote_subscriber, &message).await?;

        Ok(reply_subscriber)
    }

    pub(crate) async fn unsubscribe(&self, id: u64, address: Arc<str>) -> Result<()> {
        self.subscriber_maps.remove(&self.peer, id, address).await?;
        Ok(())
    }
}

fn create_endpoint(
    addr: SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Endpoint, CreateError> {
    // create client configuration
    let mut store = RootCertStore::empty();
    for cert in &certs {
        store.add(cert.clone()).map_err(ConfigError::from)?;
    }

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![ALPN_QUIC_EVENTBUS.to_vec()];

    let client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).map_err(ConfigError::from)?,
    ));

    // create server configuration
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(ConfigError::from)?;

    server_crypto.alpn_protocols = vec![ALPN_QUIC_EVENTBUS.to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).map_err(ConfigError::from)?,
    ));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_bidi_streams(0_u8.into());

    // create endpoint
    let mut endpoint =
        Endpoint::server(server_config, addr).map_err(CreateError::CreateEndpoint)?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

async fn handle_connection(
    conn: Incoming,
    subscriber_maps: Arc<SubscriberMaps>,
    peer: Arc<Peer>,
) -> Result<()> {
    let connection = conn.await.map_err(TransportError::from)?;

    let span = info_span!(
        "connection",
        remote = %connection.remote_address()
    );
    async {
        info!("connection established");

        loop {
            let stream = match connection.accept_uni().await {
                Err(
                    ConnectionError::ApplicationClosed { .. }
                    | ConnectionError::TimedOut
                    | ConnectionError::LocallyClosed,
                ) => {
                    debug!("connection closed");
                    return crate::error::Ok(());
                }
                Err(e) => return Err(TransportError::from(e).into()),
                Ok(s) => s,
            };

            let subscriber_maps = Arc::clone(&subscriber_maps);
            let peer = Arc::clone(&peer);
            tokio::spawn(
                async move {
                    handle_message(stream, subscriber_maps, peer).await;
                }
                .instrument(info_span!("handle_message")),
            );
        }
    }
    .instrument(span)
    .await?;
    Ok(())
}

async fn handle_message(
    mut stream: RecvStream,
    subscriber_maps: Arc<SubscriberMaps>,
    peer: Arc<Peer>,
) {
    let mut msg = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = stream.read(&mut buf).await;
        match read {
            Ok(Some(read)) => msg.extend(&buf[0..read]),
            Ok(None) => break,
            Err(e) => {
                error!("failed to read incoming message: {e}");
                return;
            }
        }
    }

    let msg = match postcard::from_bytes::<Message>(&msg) {
        Ok(msg) => Arc::new(msg),
        Err(e) => {
            error!("failed to deserialize incoming message: {e}");
            return;
        }
    };

    // find all one-shot subscribers
    let oneshot_subscriber_ids = subscriber_maps
        .local_subscribers
        .get_mut(msg.address.as_str())
        .map(|subscribers| {
            subscribers
                .iter()
                .filter_map(|s| {
                    if let SubscriberSender::Once { id, address, .. } = s {
                        Some((*id, Arc::clone(address)))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // unsubscribe all one-shot subscribers
    let mut oneshot_subscribers = Vec::new();
    for (id, address) in oneshot_subscriber_ids {
        match subscriber_maps.remove(&peer, id, address).await {
            Ok(Some(s)) => oneshot_subscribers.push(s),
            Ok(None) => {
                // subscription was already removed by someone else
            }
            Err(e) => error!("failed to unsubscribe one-shot subscriber: {e}"),
        }
    }

    // send to one-shot subscribers
    for s in oneshot_subscribers {
        match s {
            SubscriberSender::Once {
                address, sender, ..
            } => {
                if sender.send(Arc::clone(&msg)).is_err() {
                    error!(
                        "failed to forward incoming message to local one-shot \
                        subscriber at address {address}"
                    );
                }
            }
            _ => unreachable!("collection only contains one-shot subscribers"),
        }
    }

    // send to remaining subscribers
    if let Some(subscribers) = subscriber_maps.local_subscribers.get(msg.address.as_str()) {
        for s in subscribers.iter() {
            match s {
                SubscriberSender::Unbounded { sender, .. } => {
                    if let Err(e) = sender.send(Arc::clone(&msg)) {
                        error!("failed to forward incoming message to local subscriber: {e}");
                    }
                }
                SubscriberSender::Once { .. } => {
                    // A new one-shot subscriber was added in the meantime. It's
                    // too late. Ignore it.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use anyhow::{Context as _, Result, bail};
    use distruct::{Cluster, ClusterConfigBuilder};
    use quinn::rustls::pki_types::PrivateKeyDer;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use tokio::{select, time::timeout};

    use crate::{EventBus, EventBusConfigBuilder, error::Error, subscribers::Subscriber as _};

    async fn setup_single_node() -> Result<(Cluster, EventBus)> {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string(), "::1".to_string()]).unwrap();
        let certs = vec![cert.der().clone()];
        let key: PrivateKeyDer<'_> = signing_key.into();

        let cluster =
            Cluster::spawn(ClusterConfigBuilder::default().build(certs.clone(), key.clone_key()))
                .await?;
        let eventbus = EventBus::new(&cluster, EventBusConfigBuilder::default().build(certs, key))?;

        Ok((cluster, eventbus))
    }

    async fn setup_two_nodes() -> Result<((Cluster, EventBus), (Cluster, EventBus))> {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string(), "::1".to_string()]).unwrap();
        let certs = vec![cert.der().clone()];
        let key: PrivateKeyDer<'_> = signing_key.into();

        let cluster1 =
            Cluster::spawn(ClusterConfigBuilder::default().build(certs.clone(), key.clone_key()))
                .await?;
        let cluster2 = Cluster::spawn(
            ClusterConfigBuilder::default()
                .with_seed(cluster1.public_addr(), "localhost")
                .build(certs.clone(), key.clone_key()),
        )
        .await?;
        let eventbus1 = EventBus::new(
            &cluster1,
            EventBusConfigBuilder::default().build(certs.clone(), key.clone_key()),
        )?;
        let eventbus2 = EventBus::new(
            &cluster2,
            EventBusConfigBuilder::default().build(certs, key),
        )?;

        Ok(((cluster1, eventbus1), (cluster2, eventbus2)))
    }

    #[tokio::test]
    async fn send_no_subscriber() -> Result<()> {
        let (cluster, eventbus) = setup_single_node().await?;

        let Err(Error::NoSubscriber { address }) = eventbus.send("my_address", b"hello").await
        else {
            bail!("expected error")
        };
        assert_eq!(address, "my_address");

        eventbus.shutdown().await?;
        cluster.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn send_single_node() -> Result<()> {
        let (cluster, eventbus) = setup_single_node().await?;

        let mut subscriber = eventbus.subscribe("my_address").await?;
        let handle = tokio::spawn(async move { subscriber.recv().await });

        eventbus.send("my_address", b"hello").await?;

        let msg = handle.await?.context("no message received")?;
        assert_eq!("hello".as_bytes().to_vec(), msg.body);

        eventbus.shutdown().await?;
        cluster.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn send_two_nodes() -> Result<()> {
        let ((cluster1, eventbus1), (cluster2, eventbus2)) = setup_two_nodes().await?;

        let mut subscriber = eventbus2.subscribe("my_address").await?;
        let handle = tokio::spawn(async move { subscriber.recv().await });

        eventbus1.send("my_address", b"hello").await?;

        let msg = handle.await?.context("no message received")?;
        assert_eq!("hello".as_bytes().to_vec(), msg.body);

        eventbus1.shutdown().await?;
        eventbus2.shutdown().await?;
        cluster1.shutdown().await?;
        cluster2.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn send_multiple_subscribers() -> Result<()> {
        let ((cluster1, eventbus1), (cluster2, eventbus2)) = setup_two_nodes().await?;

        let mut subscriber1 = eventbus1.subscribe("my_address").await?;
        let mut subscriber2 = eventbus2.subscribe("my_address").await?;

        eventbus1.send("my_address", b"hello").await?;

        let (mut other, msg) = timeout(Duration::from_secs(5), async {
            select! {
                m = subscriber1.recv() => (subscriber2, m),
                m = subscriber2.recv() => (subscriber1, m),
            }
        })
        .await
        .context("no message received")?;

        let msg = msg.context("channel closed")?;
        assert_eq!(b"hello".to_vec(), msg.body);

        assert!(
            timeout(Duration::from_millis(200), other.recv())
                .await
                .is_err(),
            "message was delivered to both subscribers"
        );

        eventbus1.shutdown().await?;
        eventbus2.shutdown().await?;
        cluster1.shutdown().await?;
        cluster2.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn send_and_recv_after_shutdown() -> Result<()> {
        let ((cluster1, eventbus1), (cluster2, eventbus2)) = setup_two_nodes().await?;

        let mut subscriber = eventbus1.subscribe("my_address").await?;
        eventbus1.shutdown().await?;

        // receiving should not be possible
        assert!(subscriber.recv().await.is_none());

        // sending from another node should not be possible anymore (subscriber
        // should have been unregistered)
        let Err(Error::NoSubscriber { address }) = eventbus2.send("my_address", b"hello").await
        else {
            bail!("expected error")
        };
        assert_eq!(address, "my_address");

        eventbus2.shutdown().await?;
        cluster1.shutdown().await?;
        cluster2.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn publish_no_subscriber() -> Result<()> {
        let (cluster, eventbus) = setup_single_node().await?;

        let Err(Error::NoSubscriber { address }) = eventbus.publish("my_address", b"hello").await
        else {
            bail!("expected error")
        };
        assert_eq!(address, "my_address");

        eventbus.shutdown().await?;
        cluster.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn publish_single_node() -> Result<()> {
        let (cluster, eventbus) = setup_single_node().await?;

        let mut subscriber1 = eventbus.subscribe("my_address").await?;
        let mut subscriber2 = eventbus.subscribe("my_address").await?;
        let handle1 = tokio::spawn(async move { subscriber1.recv().await });
        let handle2 = tokio::spawn(async move { subscriber2.recv().await });

        eventbus.publish("my_address", b"hello").await?;

        let msg1 = handle1.await?.context("no message received")?;
        assert_eq!("hello".as_bytes().to_vec(), msg1.body);
        let msg2 = handle2.await?.context("no message received")?;
        assert_eq!("hello".as_bytes().to_vec(), msg2.body);

        eventbus.shutdown().await?;
        cluster.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn publish_two_nodes() -> Result<()> {
        let ((cluster1, eventbus1), (cluster2, eventbus2)) = setup_two_nodes().await?;

        let mut subscriber1 = eventbus1.subscribe("my_address").await?;
        let mut subscriber2 = eventbus2.subscribe("my_address").await?;
        let handle1 = tokio::spawn(async move { subscriber1.recv().await });
        let handle2 = tokio::spawn(async move { subscriber2.recv().await });

        eventbus1.publish("my_address", b"hello").await?;

        let msg1 = handle1.await?.context("no message received")?;
        assert_eq!("hello".as_bytes().to_vec(), msg1.body);
        let msg2 = handle2.await?.context("no message received")?;
        assert_eq!("hello".as_bytes().to_vec(), msg2.body);

        eventbus1.shutdown().await?;
        eventbus2.shutdown().await?;
        cluster1.shutdown().await?;
        cluster2.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn request_no_subscriber() -> Result<()> {
        let (cluster, eventbus) = setup_single_node().await?;

        let Err(Error::NoSubscriber { address }) = eventbus.request("my_address", b"hello").await
        else {
            bail!("expected error")
        };
        assert_eq!(address, "my_address");

        eventbus.shutdown().await?;
        cluster.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn request_single_node() -> Result<()> {
        let (cluster, eventbus) = setup_single_node().await?;
        let eventbus = Arc::new(eventbus);

        let inner_eventbus = Arc::clone(&eventbus);
        let mut subscriber = eventbus.subscribe("my_address").await?;
        let handle = tokio::spawn(async move {
            let msg = subscriber.recv().await.context("no message received")?;
            let reply = msg.body.to_ascii_uppercase();
            let reply_address = msg.reply_address.as_ref().context("no reply address")?;
            inner_eventbus.send(reply_address, &reply).await?;
            anyhow::Ok(())
        });

        let reply_subscriber = eventbus.request("my_address", b"hello").await?;

        handle.await??;

        let reply = reply_subscriber.await?;
        assert_eq!("HELLO".as_bytes().to_vec(), reply.body);

        Arc::into_inner(eventbus).unwrap().shutdown().await?;
        cluster.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn request_two_nodes() -> Result<()> {
        let ((cluster1, eventbus1), (cluster2, eventbus2)) = setup_two_nodes().await?;

        let mut subscriber = eventbus2.subscribe("my_address").await?;
        let handle = tokio::spawn(async move {
            let msg = subscriber.recv().await.context("no message received")?;
            let reply = msg.body.to_ascii_uppercase();
            let reply_address = msg.reply_address.as_ref().context("no reply address")?;
            eventbus2.send(reply_address, &reply).await?;
            eventbus2.shutdown().await?;
            anyhow::Ok(())
        });

        let reply_subscriber = eventbus1.request("my_address", b"hello").await?;

        handle.await??;

        let reply = reply_subscriber.await?;
        assert_eq!("HELLO".as_bytes().to_vec(), reply.body);

        eventbus1.shutdown().await?;
        cluster1.shutdown().await?;
        cluster2.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn subscribe_once_send() -> Result<()> {
        let (cluster, eventbus) = setup_single_node().await?;

        let subscriber = eventbus.subscribe_once("my_address").await?;
        let handle = tokio::spawn(subscriber);

        eventbus.send("my_address", b"hello").await?;

        let msg = handle.await?.context("no message received")?;
        assert_eq!("hello".as_bytes().to_vec(), msg.body);

        // subscriber should not be there anymore
        let Err(Error::NoSubscriber { address }) = eventbus.send("my_address", b"hello").await
        else {
            bail!("expected error")
        };
        assert_eq!(address, "my_address");

        eventbus.shutdown().await?;
        cluster.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn subscribe_once_publish() -> Result<()> {
        let (cluster, eventbus) = setup_single_node().await?;

        let subscriber = eventbus.subscribe_once("my_address").await?;
        let handle = tokio::spawn(subscriber);

        eventbus.publish("my_address", b"hello").await?;

        let msg = handle.await?.context("no message received")?;
        assert_eq!("hello".as_bytes().to_vec(), msg.body);

        // subscriber should not be there anymore
        let Err(Error::NoSubscriber { address }) = eventbus.publish("my_address", b"hello").await
        else {
            bail!("expected error")
        };
        assert_eq!(address, "my_address");

        eventbus.shutdown().await?;
        cluster.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn subscribe_once_request() -> Result<()> {
        let (cluster, eventbus) = setup_single_node().await?;
        let eventbus = Arc::new(eventbus);

        let subscriber = eventbus.subscribe_once("my_address").await?;
        let inner_eventbus = Arc::clone(&eventbus);
        let handle = tokio::spawn(async move {
            let msg = subscriber.await.context("no message received")?;
            let reply = msg.body.to_ascii_uppercase();
            let reply_address = msg.reply_address.as_ref().context("no reply address")?;
            inner_eventbus.send(reply_address, &reply).await?;
            anyhow::Ok(())
        });

        let reply_subscriber = eventbus.request("my_address", b"hello").await?;

        handle.await??;

        let reply = reply_subscriber.await?;
        assert_eq!("HELLO".as_bytes().to_vec(), reply.body);

        // subscriber should not be there anymore
        let Err(Error::NoSubscriber { address }) = eventbus.request("my_address", b"hello").await
        else {
            bail!("expected error")
        };
        assert_eq!(address, "my_address");

        Arc::into_inner(eventbus).unwrap().shutdown().await?;
        cluster.shutdown().await?;

        Ok(())
    }

    #[tokio::test]
    async fn unsubscribe() -> Result<()> {
        let (cluster, eventbus) = setup_single_node().await?;

        let subscriber = eventbus.subscribe("my_address").await?;
        subscriber.unsubscribe(&eventbus).await?;

        let Err(Error::NoSubscriber { address }) = eventbus.send("my_address", b"hello").await
        else {
            bail!("expected error")
        };
        assert_eq!(address, "my_address");

        eventbus.shutdown().await?;
        cluster.shutdown().await?;

        Ok(())
    }
}
