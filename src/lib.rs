//! An event bus based on strongly consistent distributed data structures.
//!
//! The event bus can be used to send messages between nodes in a
//! `distruct::Cluster`.
//!
//! # Creating a distributed event bus
//!
//! First, you need to create a `distruct::Cluster`, so the individual nodes of
//! your application are connected to a cluster. Please refer to the [distruct
//! documentation](http://docs.rs/distruct) for more information.
//!
//! After this, you can use the cluster to set up an event bus:
//!
//! ```no_run
//! use dispost::{
//!     EventBusConfigBuilder,
//!     distruct::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
//! };
//! use std::net::{Ipv4Addr, Ipv6Addr};
//!
//! # fn config() -> Result<(), Box<dyn std::error::Error>> {
//! // load server certificate and private key
//! let certs: Vec<CertificateDer> =
//!     CertificateDer::pem_file_iter("cert.pem")?.collect::<Result<_, _>>()?;
//! let key = PrivateKeyDer::from_pem_file("key.pem")?;
//!
//! // build the configuration
//! let config = EventBusConfigBuilder::default()
//!     .with_bind_addr((Ipv6Addr::LOCALHOST, 36000).into())
//!     .with_public_addr((Ipv4Addr::new(192, 0, 2, 0), 36000).into(), "example.com")
//!     .build(certs, key);
//! # Ok(())
//! # }
//! ```
//!
//! Then, create the event bus. Remember that `cluster` is a `distruct::Cluster`
//! (see above).
//!
//! ```no_run
//! use dispost::EventBus;
//!
//! # fn new(config: dispost::EventBusConfig, cluster: distruct::Cluster) -> Result<(), Box<dyn std::error::Error>> {
//! let eventbus = EventBus::new(&cluster, config)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Sending and receiving messages
//!
//! Register a subscriber to receive messages at a given address on the event
//! bus:
//!
//! ```no_run
//! # async fn recv(eventbus: dispost::EventBus) -> Result<(), Box<dyn std::error::Error>> {
//! let mut subscriber = eventbus.subscribe("my_address").await?;
//! while let Some(message) = subscriber.recv().await {
//!     // do something with `message`, for example:
//!     println!("{}", std::str::from_utf8(&message.body)?);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Then, elsewhere in your distributed application, send a message to the
//! address:
//!
//! ```no_run
//! # async fn send(eventbus: dispost::EventBus) -> Result<(), Box<dyn std::error::Error>> {
//! eventbus.send("my_address", b"Hello world").await?;
//! # Ok(())
//! # }
//! ```
//!
//! If there are multiple subscribers listening on the same address, the current
//! implementation selects one at random. This behavior may change in the
//! future.
//!
//! # Sending messages to multiple subscribers at once
//!
//! You can perform a broadcast and send a message to multiple subscribers at
//! once using the [`publish`](crate::EventBus::publish) method:
//!
//! ```no_run
//! # async fn publ(eventbus: dispost::EventBus) -> Result<(), Box<dyn std::error::Error>> {
//! eventbus.publish("my_address", b"Hello world").await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Requesting information from a subscriber
//!
//! You may send a message to a single subscriber and wait for a reply from it
//! using the [`request`](crate::EventBus::request) method.
//!
//! First, register a subscriber that sends back a reply to the reply address
//! included in the message:
//!
//! ```no_run
//! # async fn recv(eventbus: dispost::EventBus) -> Result<(), Box<dyn std::error::Error>> {
//! let mut subscriber = eventbus.subscribe("uppercase").await?;
//! while let Some(message) = subscriber.recv().await {
//!     if let Some(reply_address) = &message.reply_address {
//!         let reply = message.body.to_ascii_uppercase();
//!         eventbus.send(&reply_address, &reply).await?;
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Then, elsewhere in your distributed application, send a message to the
//! address and wait for the reply:
//!
//! ```no_run
//! # async fn req(eventbus: dispost::EventBus) -> Result<(), Box<dyn std::error::Error>> {
//! let subscriber = eventbus.request("uppercase", b"Hello world").await?;
//! let reply = subscriber.await?;
//! assert_eq!("HELLO WORLD", std::str::from_utf8(&reply.body)?);
//! # Ok(())
//! # }
//! ```
//!
//! If there are multiple subscribers listening on the same address, the current
//! implementation selects one at random. This behavior may change in the
//! future.
pub mod error;
mod eventbus;
mod message;
mod peer;
pub mod subscribers;

pub use eventbus::{EventBus, EventBusConfig, EventBusConfigBuilder};
pub use message::Message;

pub use distruct;
