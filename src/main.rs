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
            println!("[*] First boot detected. Generating ed25519 Master Identity...");
            let sk = SigningKey::generate(&mut OsRng);
            db.set_local_identity(&sk.to_bytes())?;
            sk
        }
    };
    
    let verifying_key: VerifyingKey = (&signing_key).into();
    println!("[+] Node Identity: {}", hex::encode(verifying_key.as_bytes()));

    let shared_db = Arc::new(Mutex::new(db));
    let config = TorClientConfig::default();
    let tor_client: TorClient<PreferredRuntime> = TorClient::create_bootstrapped(config).await?;

    let (service, rend_requests) = network::hidden_service::launch_hidden_service(&tor_client, "whispernet").await?;
    
    // By-pass the Display restriction using the Debug formatter and string stripping
    if let Some(onion) = service.onion_address() {
        let onion_str = format!("{:?}", onion);
        let clean = onion_str.replace("HsId(", "").replace(")", "").replace("\"", "");
        println!("[+] Node Onion Address: {}", clean);
    } else {
        println!("[-] Warning: Could not retrieve local Onion address.");
    }
    
    let mut stream_requests = handle_rend_requests(rend_requests);
    let listener_db = Arc::clone(&shared_db);
    
    let shared_ratchet = Arc::new(Mutex::new(RatchetState::new(TEST_SEED)));
    let listener_ratchet = Arc::clone(&shared_ratchet);

    tokio::spawn(async move {
        while let Some(request) = stream_requests.next().await {
            if let Ok(mut data_stream) = request.accept(Connected::new_empty()).await {
                let task_db = Arc::clone(&listener_db);
                let task_ratchet = Arc::clone(&listener_ratchet);
                
                tokio::spawn(async move {
                    let mut buf = vec![0; 2048];
                    if let Ok(n) = data_stream.read(&mut buf).await {
                        if let Some(payload) = WhisperPayload::deserialize(&buf[..n]) {
                            match payload {
                                WhisperPayload::Handshake(msg) => {
                                    if msg.verify_signature() {
                                        println!("\n[+] Verified handshake from peer: {}", hex::encode(msg.identity_key));
                                        let db_lock = task_db.lock().await;
                                        let _ = db_lock.log_handshake(&msg.identity_key);
                                    } else {
                                        println!("\n[!] Handshake signature invalid. Dropped.");
                                    }
                                },
                                WhisperPayload::Message { sender_identity, ciphertext } => {
                                    let mut ratchet = task_ratchet.lock().await;
                                    match ratchet.decrypt_message(&ciphertext) {
                                        Ok(plaintext) => {
                                            if let Ok(text) = String::from_utf8(plaintext) {
                                                println!("\n[Encrypted] {}: {}", hex::encode(&sender_identity[0..4]), text);
                                            }
                                        },
                                        Err(_) => println!("\n[!] Failed to decrypt incoming message."),
                                    }
                                }
                            }
                            print!("\nwhisper> ");
                            let _ = std::io::stdout().flush();
                        }
                    }
                });
            }
        }
    });

    println!("WhisperNet active. Listener backgrounded.\n");

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
            "/id" => println!("Identity: {}", hex::encode(verifying_key.as_bytes())),
            "/onion" => {
                if let Some(onion) = service.onion_address() {
                    let onion_str = format!("{:?}", onion);
                    let clean = onion_str.replace("HsId(", "").replace(")", "").replace("\"", "");
                    println!("{}", clean);
                }
            },
            "/connect" => {
                if parts.len() < 2 { continue; }
                println!("[*] Transmitting X3DH Handshake...");
                let ephemeral_secret = EphemeralSecret::random_from_rng(&mut OsRng);
                let handshake = HandshakeMessage::new(&signing_key, &X25519PublicKey::from(&ephemeral_secret));
                let payload = WhisperPayload::Handshake(handshake).serialize();
                let _ = p2p_client.send_handshake(parts[1], payload).await;
            },
            "/msg" => {
                if parts.len() < 3 {
                    println!("Usage: /msg <onion_address> <your message>");
                    continue;
                }
                let target = parts[1];
                let text = parts[2..].join(" ");
                
                let mut ratchet = shared_ratchet.lock().await;
                if let Ok(ciphertext) = ratchet.encrypt_message(text.as_bytes()) {
                    let payload = WhisperPayload::Message {
                        sender_identity: verifying_key.to_bytes(),
                        ciphertext,
                    }.serialize();
                    
                    match p2p_client.send_handshake(target, payload).await {
                        Ok(_) => println!("[+] Ciphertext routed through Tor."),
                        Err(e) => println!("[-] Failed to transmit: {}", e),
                    }
                }
            },
            "/quit" => break,
            _ => println!("Unknown command."),
        }
    }
    
    Ok(())
}
