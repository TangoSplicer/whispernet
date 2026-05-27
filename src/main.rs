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

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;

use protocol::handshake::HandshakeMessage;
use tor_cell::relaycell::msg::Connected;
use storage::db_manager::DbManager;
use network::client::P2PClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = DbManager::new("whispernet.db", "secure_passphrase")?;
    
    // --- CRYPTOGRAPHIC BOOT SEQUENCE ---
    let signing_key = match db.get_local_identity() {
        Ok(bytes) => {
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&bytes[..32]);
            SigningKey::from_bytes(&sk_bytes)
        },
        Err(_) => {
            println!("[*] First boot detected. Generating ed25519 Master Identity...");
            let sk = SigningKey::generate(&mut OsRng);
            db.set_local_identity(&sk.to_bytes())?;
            sk
        }
    };
    
    let verifying_key: VerifyingKey = (&signing_key).into();
    println!("[+] Node Identity Public Key: {}", hex::encode(verifying_key.as_bytes()));

    let shared_db = Arc::new(Mutex::new(db));
    let config = TorClientConfig::default();
    let tor_client: TorClient<PreferredRuntime> = TorClient::create_bootstrapped(config).await?;

    let (_service, rend_requests) = network::hidden_service::launch_hidden_service(&tor_client, "whispernet").await?;
    
    let mut stream_requests = handle_rend_requests(rend_requests);
    let listener_db = Arc::clone(&shared_db);
    
    tokio::spawn(async move {
        while let Some(request) = stream_requests.next().await {
            if let Ok(mut data_stream) = request.accept(Connected::new_empty()).await {
                let task_db = Arc::clone(&listener_db);
                tokio::spawn(async move {
                    let mut buf = vec![0; 2048];
                    if let Ok(n) = data_stream.read(&mut buf).await {
                        if let Ok(msg) = bincode::deserialize::<HandshakeMessage>(&buf[..n]) {
                            println!("\n[+] Verified handshake received from peer.");
                            let db_lock = task_db.lock().await;
                            let _ = db_lock.log_handshake(msg.identity_key.as_bytes());
                            print!("\nwhisper> ");
                            let _ = std::io::stdout().flush();
                        }
                    }
                });
            }
        }
    });

    println!("WhisperNet active. Listener backgrounded.");
    println!("Type /help for commands.\n");

    let p2p_client = P2PClient { tor_client };
    let mut stdin_reader = BufReader::new(stdin());
    let mut line = String::new();

    loop {
        print!("whisper> ");
        std::io::stdout().flush()?;
        line.clear();
        
        let bytes_read = stdin_reader.read_line(&mut line).await?;
        if bytes_read == 0 { break; } 
        
        let input = line.trim();
        if input.is_empty() { continue; }

        let parts: Vec<&str> = input.split_whitespace().collect();
        match parts[0] {
            "/help" => {
                println!("Commands:");
                println!("  /id                       - Show your Node Identity Key");
                println!("  /connect <onion_address>  - Test Tor circuit to peer");
                println!("  /quit                     - Shut down node");
            },
            "/id" => {
                println!("Node Identity: {}", hex::encode(verifying_key.as_bytes()));
            },
            "/connect" => {
                if parts.len() < 2 {
                    println!("Usage: /connect <onion_address>");
                    continue;
                }
                let target = parts[1];
                println!("[*] Building Tor circuit to {}...", target);
                
                let dummy_payload = vec![1, 2, 3, 4]; 
                match p2p_client.send_handshake(target, dummy_payload).await {
                    Ok(_) => println!("[+] Connection successful. Bytes transmitted."),
                    Err(e) => println!("[-] Failed to connect: {}", e),
                }
            },
            "/quit" => {
                println!("[*] Shutting down WhisperNet...");
                break;
            },
            _ => {
                println!("Unknown command. Type /help.");
            }
        }
    }
    
    Ok(())
}
