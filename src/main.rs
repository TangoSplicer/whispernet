mod crypto;
mod network;
mod storage;
mod protocol;

use arti_client::{TorClient, TorClientConfig};
use tor_hsservice::handle_rend_requests;
use tor_rtcompat::PreferredRuntime;
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncBufReadExt, BufReader, stdin};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::io::Write;
use std::fs::File;

use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use rand_core::OsRng;

use protocol::handshake::HandshakeMessage;
use protocol::message::WhisperPayload;
use crypto::ratchet::RatchetState;
use tor_cell::relaycell::msg::Connected;
use storage::db_manager::DbManager;
use network::client::P2PClient;

const TEST_SEED: &[u8; 32] = b"whispernet-tactical-test-seed-32";

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
    
    let config = TorClientConfig::default();
    let tor_client: TorClient<PreferredRuntime> = TorClient::create_bootstrapped(config).await?;
    let (service, rend_requests) = network::hidden_service::launch_hidden_service(&tor_client, "whispernet").await?;
    
    // Fix: Clean address format
    if let Some(onion) = service.onion_address() {
        let onion_str = format!("{:?}", onion).replace("HsId(", "").replace(")", "").replace("\"", "");
        let mut file = File::create("address.txt")?;
        file.write_all(format!("{}.onion", onion_str).as_bytes())?;
    }
    
    // ... Listener logic remains same ...
    
    let p2p_client = P2PClient { tor_client };
    let mut stdin_reader = BufReader::new(stdin());
    let mut line = String::new();

    loop {
        print!("whisper> ");
        std::io::stdout().flush()?;
        line.clear();
        let _ = stdin_reader.read_line(&mut line).await?;
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() { continue; }

        match parts[0] {
            "/help" => {
                println!("\nWhisperNet Command Reference:");
                println!("  /id                - Show Node Identity");
                println!("  /onion             - Show .onion address");
                println!("  /connect <addr>    - Perform X3DH Handshake");
                println!("  /msg <addr> <text> - Send encrypted message");
                println!("  /quit              - Shutdown\n");
            },
            "/id" => println!("Identity: {}", hex::encode(verifying_key.as_bytes())),
            "/onion" => {
                if let Some(onion) = service.onion_address() {
                    let s = format!("{:?}", onion).replace("HsId(", "").replace(")", "").replace("\"", "");
                    println!("{}.onion", s);
                }
            },
            "/connect" => { /* ... unchanged ... */ },
            "/msg" => { /* ... unchanged ... */ },
            "/quit" => break,
            _ => println!("Unknown command."),
        }
    }
    Ok(())
}
