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
        mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
        oneshot,
    },
    task::JoinHandle,
};
use tracing::{Instrument, info_span};

use crate::{
    error::{ConfigError, CreateError, Result, ShutdownEventBusError, TransportError},
    message::Message,
    peer::Peer,
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

enum Subscriber {
    Unbounded(UnboundedSender<Arc<Message>>),
    Once(String, oneshot::Sender<Arc<Message>>),
}

/// A distributed event bus.
///
/// Use it to send messages between nodes in a `distruct::Cluster`.
pub struct EventBus {
    endpoint: Endpoint,
    peer: Peer,
    local_subscribers: Arc<DashMap<String, Vec<Subscriber>>>,
    remote_subscribers: Arc<DMultiMap<String, Peer>>,
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
        let local_subscribers = Arc::new(DashMap::new());
        let remote_subscribers = Arc::new(cluster.get_multi_map("__dispost_subscribers"));

        // handle incoming messages
        let inner_endpoint = endpoint.clone();
        let inner_peer = Arc::new(peer.clone());
        let inner_local_subscribers = Arc::clone(&local_subscribers);
        let inner_remote_subscribers = Arc::clone(&remote_subscribers);
        let main_loop_handle = tokio::spawn(async move {
            while let Some(conn) = inner_endpoint.accept().await {
                if !conn.remote_address_validated() {
                    info!("requiring connection to validate its address");
                    conn.retry().unwrap();
                } else {
                    info!("accepting connection");
                    let fut = handle_connection(
                        conn,
                        Arc::clone(&inner_local_subscribers),
                        Arc::clone(&inner_remote_subscribers),
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
            local_subscribers,
            remote_subscribers,
            main_loop_handle,
        })
    }

    /// Shuts down the event bus.
    pub async fn shutdown(self) -> Result<(), ShutdownEventBusError> {
        self.endpoint.close(0u32.into(), b"shutdown");
        self.endpoint.wait_idle().await;
        self.main_loop_handle.await?;
        Ok(())
    }

    async fn subscribe_internal<A, R>(
        &self,
        address: A,
        subscriber: Subscriber,
        receiver: R,
    ) -> Result<Option<R>>
    where
        A: Into<String>,
    {
        let address: String = address.into();

        let mut entry = self.local_subscribers.entry(address.clone()).or_default();
        entry.push(subscriber);

        let inserted = self
            .remote_subscribers
            .insert(address, self.peer.clone())
            .await?;

        if !inserted {
            // undo push into local_subscribers map - pop() is possible because
            // `entry` holds a lock internally and nobody else could have
            // modified local_subscribers in the meantime
            entry.pop();

            Ok(None)
        } else {
            Ok(Some(receiver))
        }
    }

    /// Subscribe to an address on the event bus.
    ///
    /// The method creates an unbounded in-memory message queue for messages
    /// that arrive at the given address. It returns a receiver that can be used
    /// to take messages from the queue.
    ///
    /// If the current cluster node already listens to the given address, the
    /// method returns `None`.
    pub async fn subscribe<A>(&self, address: A) -> Result<Option<UnboundedReceiver<Arc<Message>>>>
    where
        A: Into<String>,
    {
        let (sender, receiver) = unbounded_channel();
        self.subscribe_internal(address, Subscriber::Unbounded(sender), receiver)
            .await
    }

    /// Subscribe to receiving a single message at a certain event bus address.
    ///
    /// The method creates a one-shot receiver that can be used to receive
    /// exactly one message at the given address. Once the message is received,
    /// the receiver cannot be used anymore.
    ///
    /// If the current cluster node already listens to the given address, the
    /// method returns `None`.
    pub async fn subscribe_once<A>(
        &self,
        address: A,
    ) -> Result<Option<oneshot::Receiver<Arc<Message>>>>
    where
        A: Into<String>,
    {
        let address: String = address.into();
        let (sender, receiver) = oneshot::channel();
        self.subscribe_internal(address.clone(), Subscriber::Once(address, sender), receiver)
            .await
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
    /// If there is no subscriber at the given address, the method is a no-op.
    /// If there are multiple subscribers, the current implementation selects one
    /// at random. This may change in the future.
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
        let subscribers = self.remote_subscribers.get(address).await?;
        let peer = subscribers.choose(&mut rand::rng());

        // TODO implement proper round-robin and other strategies
        if let Some(s) = peer {
            self.send_to(s, &message).await
        } else {
            Ok(())
        }
    }

    /// Send a message to all subscribers at a certain event bus address.
    ///
    /// If there is no subscriber at the given address, the method is a no-op.
    ///
    /// The method makes no guarantees about whether the message is actually
    /// received and processed by the subscribers.
    pub async fn publish(&self, address: &str, message: &[u8]) -> Result<()> {
        let message = Message {
            address: address.to_string(),
            body: message.to_vec(),
            reply_address: None,
        };

        let subscribers = self.remote_subscribers.get(address).await?;
        for s in subscribers {
            self.send_to(&s, &message).await?;
        }

        Ok(())
    }

    /// Send a request to a subscriber at a certain event bus address and return
    /// its reply.
    ///
    /// If there is no subscriber at the given address, the method returns
    /// `None`. Otherwise, the method sends the message to exactly one
    /// subscriber and returns a one-shot receiver that can be used to receive
    /// the subscriber's reply.
    ///
    /// If there are multiple subscribers, the current implementation selects one
    /// at random. This may change in the future.
    pub async fn request(
        &self,
        address: &str,
        message: &[u8],
    ) -> Result<Option<oneshot::Receiver<Arc<Message>>>> {
        // TODO implement proper round-robin and other strategies
        let ss = self.remote_subscribers.get(address).await?;
        let Some(remote_subscriber) = ss.choose(&mut rand::rng()) else {
            return Ok(None);
        };

        let (reply_address, reply) = loop {
            let reply_address = format!("__dispost_reply_{}", ulid::Ulid::generate());
            if let Some(reply) = self.subscribe_once(&reply_address).await? {
                break (reply_address, reply);
            }
        };

        let message = Message {
            address: address.to_string(),
            body: message.to_vec(),
            reply_address: Some(reply_address),
        };

        // TODO unsubscribe if send fails!
        self.send_to(remote_subscriber, &message).await?;

        Ok(Some(reply))
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
    local_subscribers: Arc<DashMap<String, Vec<Subscriber>>>,
    remote_subscribers: Arc<DMultiMap<String, Peer>>,
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

            let local_subscribers = Arc::clone(&local_subscribers);
            let remote_subscribers = Arc::clone(&remote_subscribers);
            let peer = Arc::clone(&peer);
            tokio::spawn(
                async move {
                    handle_message(stream, local_subscribers, remote_subscribers, peer).await;
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
    local_subscribers: Arc<DashMap<String, Vec<Subscriber>>>,
    remote_subscribers: Arc<DMultiMap<String, Peer>>,
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

    if let Some(mut subscribers) = local_subscribers.get_mut(&msg.address) {
        let oneshot_subscribers = subscribers.extract_if(.., |s| matches!(s, Subscriber::Once(..)));

        for s in oneshot_subscribers {
            match s {
                Subscriber::Once(address, sender) => {
                    if sender.send(Arc::clone(&msg)).is_err() {
                        error!("failed to forward incoming message to local oneshot subscriber");
                    }
                    if let Err(e) = remote_subscribers.remove(&address, &peer).await {
                        error!("failed to unsubscribe oneshot subscriber: {e}");
                    }
                }
                _ => unreachable!("collection only contains oneshot subscribers"),
            }
        }

        for s in subscribers.iter() {
            match s {
                Subscriber::Unbounded(sender) => {
                    if let Err(e) = sender.send(Arc::clone(&msg)) {
                        error!("failed to forward incoming message to local subscriber: {e}");
                    }
                }
                Subscriber::Once(..) => unreachable!("already removed above"),
            }
        }
    }
}
