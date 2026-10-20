use std::{
    fmt::{Display, Formatter},
    net::SocketAddr,
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Peer {
    pub addr: SocketAddr,
    pub server_name: String,
}

impl Peer {
    pub(crate) fn new(addr: SocketAddr, server_name: String) -> Self {
        Self { addr, server_name }
    }
}

impl Display for Peer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.server_name, self.addr)
    }
}
