use serde::{Serialize, Deserialize};
use x25519_dalek::PublicKey;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};

#[derive(Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub identity_key: PublicKey,
    pub ephemeral_key: PublicKey,
    pub signed_prekey_sig: Signature,
    pub ciphertext: Vec<u8>,
}

impl HandshakeMessage {
    pub fn serialize(&self) -> Vec<u8> { bincode::serialize(self).unwrap() }
    pub fn deserialize(data: &[u8]) -> Self { bincode::deserialize(data).unwrap() }
    pub fn verify_signature(&self, identity_vk: &VerifyingKey) -> bool {
        identity_vk.verify(self.ephemeral_key.as_bytes(), &self.signed_prekey_sig).is_ok()
    }
}
