use x25519_dalek::{PublicKey, StaticSecret};
use ed25519_dalek::{Signer, SigningKey, Signature};
use rand_core::OsRng;

pub struct KeyBundle {
    pub identity_key: PublicKey,
    pub signed_prekey: PublicKey,
    pub signed_prekey_sig: Signature,
    pub ephemeral_prekey: PublicKey,
}

impl KeyBundle {
    pub fn generate() -> Self {
        let identity_secret = StaticSecret::random_from_rng(OsRng);
        let signed_prekey_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_prekey_secret = StaticSecret::random_from_rng(OsRng);
        
        let identity_public = PublicKey::from(&identity_secret);
        let signed_prekey_public = PublicKey::from(&signed_prekey_secret);

        // Sign the signed_prekey using the identity_secret
        // Note: For production, ensure correct conversion between X25519 and Ed25519
        let signing_key = SigningKey::from_bytes(identity_secret.to_bytes().as_slice().try_into().unwrap());
        let sig = signing_key.sign(signed_prekey_public.as_bytes());

        KeyBundle {
            identity_key: identity_public,
            signed_prekey: signed_prekey_public,
            signed_prekey_sig: sig,
            ephemeral_prekey: PublicKey::from(&ephemeral_prekey_secret),
        }
    }
}
