use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum WhisperPayload {
    Handshake(crate::protocol::handshake::HandshakeMessage),
    Message {
        sender_identity: [u8; 32],
        ciphertext: Vec<u8>,
    },
}

impl WhisperPayload {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn deserialize(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}
