//! Error types exposed by this crate.
use quinn::rustls;
use tokio::task::JoinError;

/// Alias for a [`core::result::Result`] with the error type
/// [`dispost::Error`](Error).
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Equivalent to `Ok::<_, dispost::Error>(value)`.
#[allow(non_snake_case)]
#[inline]
pub fn Ok<T>(value: T) -> Result<T> {
    Result::Ok(value)
}

/// An error that can occur when working with an [`EventBus`](crate::EventBus).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cluster error: {0}")]
    Cluster(#[from] distruct::error::Error),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("failed to serialize or deserialize value: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("no subscriber for address `{address}'")]
    NoSubscriber { address: String },

    #[error("failed to join asynchronous task: {0}")]
    Join(#[from] JoinError),
}

/// An error that can happen when creating an [`EventBus`](crate::EventBus).
#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("failed to create endpoint: {0}")]
    CreateEndpoint(#[source] std::io::Error),
}

/// An error that can happen when configuring an [`EventBus`](crate::EventBus).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("TLS configuration error: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("no initial cipher suite: {0}")]
    NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
}

/// An error that can happen when cluster nodes communicate with each other.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("failed to connect: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("connection lost: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("failed to write to stream: {0}")]
    Write(#[from] quinn::WriteError),
}
