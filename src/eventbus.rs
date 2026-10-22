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
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tracing::{Instrument, info_span};

use crate::{
    error::{ConfigError, CreateError, InternalError, Result, TransportError},
    message::Message,
    peer::Peer,
};

const ALPN_QUIC_EVENTBUS: &[u8] = b"eventbus";

pub struct EventBusConfig {
    bind_addr: SocketAddr,
    public_addr: Option<SocketAddr>,
    public_server_name: String,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

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
    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    pub fn with_public_addr(mut self, addr: SocketAddr, server_name: String) -> Self {
        self.public_addr = Some(addr);
        self.public_server_name = server_name;
        self
    }

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

pub struct EventBus<'c> {
    endpoint: Endpoint,
    peer: Peer,
    local_subscribers: Arc<DashMap<String, Vec<UnboundedSender<Arc<Message>>>>>,
    remote_subscribers: DMultiMap<'c, String, Peer>,
}

impl<'c> EventBus<'c> {
    pub fn new(cluster: &'c Cluster, config: EventBusConfig) -> Result<Self, CreateError> {
        // create endpoint
        let endpoint = create_endpoint(config.bind_addr, config.certs, config.key)?;

        let local_addr = endpoint.local_addr().map_err(CreateError::CreateEndpoint)?;
        let public_addr = config.public_addr.unwrap_or(local_addr);

        let local_subscribers = Arc::new(DashMap::new());

        // handle incoming messages
        let inner_endpoint = endpoint.clone();
        let inner_local_subscribers = Arc::clone(&local_subscribers);
        tokio::spawn(async move {
            while let Some(conn) = inner_endpoint.accept().await {
                if !conn.remote_address_validated() {
                    info!("requiring connection to validate its address");
                    conn.retry().unwrap();
                } else {
                    info!("accepting connection");
                    let fut = handle_connection(conn, Arc::clone(&inner_local_subscribers));
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
            peer: Peer::new(public_addr, config.public_server_name),
            local_subscribers,
            remote_subscribers: cluster.get_multi_map("__disact_subscribers"),
        })
    }

    pub async fn subscribe<A>(&self, address: A) -> Result<Option<UnboundedReceiver<Arc<Message>>>>
    where
        A: Into<String>,
    {
        let address: String = address.into();

        let (sender, receiver) = unbounded_channel();
        let mut entry = self.local_subscribers.entry(address.clone()).or_default();
        entry.push(sender);

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

    async fn send_to(&self, c: &Peer, address: &str, message: &[u8]) -> Result<()> {
        let payload = postcard::to_allocvec(&Message {
            address: address.to_string(),
            body: message.to_vec(),
        })
        .map_err(InternalError::SerializeRequest)?;

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

    pub async fn send(&self, address: &str, message: &[u8]) -> Result<()> {
        // TODO implement round-robin or some other strategy
        if let Some(s) = self.remote_subscribers.get(address).await?.first() {
            self.send_to(s, address, message).await
        } else {
            Ok(())
        }
    }

    pub async fn publish(&self, address: &str, message: &[u8]) -> Result<()> {
        let subscribers = self.remote_subscribers.get(address).await?;
        for s in subscribers {
            self.send_to(&s, address, message).await?;
        }
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
    local_subscribers: Arc<DashMap<String, Vec<UnboundedSender<Arc<Message>>>>>,
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

            let fut = handle_message(stream, Arc::clone(&local_subscribers));
            tokio::spawn(
                async move {
                    if let Err(e) = fut.await {
                        error!("failed to handle incoming message: {e}");
                    }
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
    local_subscribers: Arc<DashMap<String, Vec<UnboundedSender<Arc<Message>>>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut msg = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    while let Some(read) = stream.read(&mut buf).await? {
        msg.extend(&buf[0..read]);
    }

    let msg: Arc<Message> = Arc::new(postcard::from_bytes(&msg)?);

    if let Some(subscribers) = local_subscribers.get(&msg.address) {
        for s in subscribers.iter() {
            s.send(Arc::clone(&msg))?;
        }
    }

    Ok(())
}
