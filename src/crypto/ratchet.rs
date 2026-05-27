use hkdf::Hkdf;
use sha2::Sha256;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use anyhow::{Result, anyhow};

pub struct RatchetState {
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
}

impl RatchetState {
    /// Initialize the Double Ratchet from the X3DH shared secret
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        // Extract and expand the raw shared secret into three distinct 32-byte keys
        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut okm = [0u8; 96];
        hk.expand(b"whispernet-ratchet-init", &mut okm).expect("HKDF expansion failed");

        let mut root = [0u8; 32];
        let mut send = [0u8; 32];
        let mut recv = [0u8; 32];

        root.copy_from_slice(&okm[0..32]);
        send.copy_from_slice(&okm[32..64]);
        recv.copy_from_slice(&okm[64..96]);

        Self {
            root_key: root,
            send_chain_key: send,
            recv_chain_key: recv,
        }
    }

    /// Symmetric Ratchet Step: Derives a new Message Key and advances the Send Chain
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let hk = Hkdf::<Sha256>::new(None, &self.send_chain_key);
        let mut okm = [0u8; 64];
        hk.expand(b"whispernet-message-key", &mut okm).expect("HKDF expansion failed");

        // 1. Split the output: First half becomes the *new* chain key, second half is the message key
        let mut msg_key = [0u8; 32];
        self.send_chain_key.copy_from_slice(&okm[0..32]);
        msg_key.copy_from_slice(&okm[32..64]);

        // 2. Encrypt the payload using ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        
        // For strict Double Ratchet compliance, the nonce is usually derived or sequence-based.
        // We use a static derivation here for the symmetric foundation.
        let nonce = Nonce::from_slice(b"whispernonce"); 
        
        cipher.encrypt(&nonce, plaintext).map_err(|e| anyhow!("Encryption failed: {:?}", e))
    }

    /// Symmetric Ratchet Step: Derives the expected Message Key and advances the Receive Chain
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let hk = Hkdf::<Sha256>::new(None, &self.recv_chain_key);
        let mut okm = [0u8; 64];
        hk.expand(b"whispernet-message-key", &mut okm).expect("HKDF expansion failed");

        let mut msg_key = [0u8; 32];
        self.recv_chain_key.copy_from_slice(&okm[0..32]);
        msg_key.copy_from_slice(&okm[32..64]);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let nonce = Nonce::from_slice(b"whispernonce");
        
        cipher.decrypt(&nonce, ciphertext).map_err(|e| anyhow!("Decryption failed: {:?}", e))
    }
}
