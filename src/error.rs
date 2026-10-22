use quinn::rustls;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[allow(non_snake_case)]
#[inline]
pub fn Ok<T>(value: T) -> Result<T> {
    Result::Ok(value)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cluster error: {0}")]
    Cluster(#[from] distruct::error::Error),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("internal error: {0}")]
    Internal(#[from] InternalError),
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("failed to create endpoint: {0}")]
    CreateEndpoint(#[source] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("TLS configuration error: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("no initial cipher suite: {0}")]
    NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("failed to connect: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("connection lost: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("failed to write to stream: {0}")]
    Write(#[from] quinn::WriteError),
}

#[derive(Debug, thiserror::Error)]
pub enum InternalError {
    #[error("request serialization failed: {0}")]
    SerializeRequest(#[source] postcard::Error),
}
