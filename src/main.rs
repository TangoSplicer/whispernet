mod crypto;
mod network;
mod storage;
mod protocol;

use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;
use std::io::Write;
use std::fs::File;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use storage::db_manager::DbManager;
use tor_hscrypto::pk::HsId; // Importing the type

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = DbManager::new("whispernet.db", "secure_passphrase")?;
    
    let signing_key = match db.get_local_identity() {
        Ok(bytes) => {
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&bytes[..32]);
            SigningKey::from_bytes(&sk_bytes)
        },
        Err(_) => {
            let sk = SigningKey::generate(&mut OsRng);
            db.set_local_identity(&sk.to_bytes())?;
            sk
        }
    };
    
    let verifying_key: VerifyingKey = (&signing_key).into();
    println!("[+] Node Identity: {}", hex::encode(verifying_key.as_bytes()));

    let config = TorClientConfig::default();
    let tor_client: TorClient<PreferredRuntime> = TorClient::create_bootstrapped(config).await?;
    let (service, _rend_requests) = network::hidden_service::launch_hidden_service(&tor_client, "whispernet").await?;
    
    if let Some(onion) = service.onion_address() {
        // Correct method to get the address as a string
        let addr = format!("{}.onion", onion.to_base32());
        let mut file = File::create("address.txt")?;
        file.write_all(addr.as_bytes())?;
        println!("[+] Address written: {}", addr);
    }
    
    println!("WhisperNet node running.");
    Ok(())
}
