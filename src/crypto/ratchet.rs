use hkdf::Hkdf;
use sha2::Sha256;

pub struct RatchetState {
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub receive_chain_key: [u8; 32],
}

impl RatchetState {
    pub fn step_ratchet(&mut self, dh_output: [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(&self.root_key), &dh_output);
        let mut okm = [0u8; 96];
        hk.expand(b"WhisperNet_Ratchet", &mut okm).expect("HKDF expansion failed");
        self.root_key.copy_from_slice(&okm[0..32]);
        self.send_chain_key.copy_from_slice(&okm[32..64]);
        self.receive_chain_key.copy_from_slice(&okm[64..96]);
    }
}
