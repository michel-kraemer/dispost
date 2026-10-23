use serde::{Deserialize, Serialize};

/// A message received over the event bus.
#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    /// The address to which the message was sent.
    pub address: String,

    /// The message body.
    pub body: Vec<u8>,

    /// An optional address to send a reply to.
    pub reply_address: Option<String>,
}
