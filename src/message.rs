use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub address: String,
    pub body: Vec<u8>,
    pub reply_address: Option<String>,
}
