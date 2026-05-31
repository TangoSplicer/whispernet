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
use std::sync::Mutex;
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

// Helper to encode HsId to a string manually to bypass Display trait restriction
fn format_onion(id: &tor_hscrypto::pk::HsId) -> String {
    let bytes = id.as_bytes();
    let encoded = data_encoding::BASE32_NOPAD.encode(bytes).to_lowercase();
    format!("{}.onion", encoded)
}

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

    let shared_db = Arc::new(Mutex::new(db));
    let config = TorClientConfig::default();
    let tor_client: TorClient<PreferredRuntime> = TorClient::create_bootstrapped(config).await?;

    let (service, rend_requests) = network::hidden_service::launch_hidden_service(&tor_client, "whispernet").await?;
    
    if let Some(onion) = service.onion_address() {
        let addr = format_onion(&onion);
        let mut file = File::create("address.txt")?;
        file.write_all(addr.as_bytes())?;
        println!("[+] Address written to address.txt: {}", addr);
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
                                        let _ = task_db.lock().unwrap().log_handshake(&msg.identity_key);
                                    }
                                },
                                WhisperPayload::Message { sender_identity, ciphertext } => {
                                    let mut ratchet = task_ratchet.lock().unwrap();
                                    if let Ok(plaintext) = ratchet.decrypt_message(&ciphertext) {
                                        if let Ok(text) = String::from_utf8(plaintext) {
                                            println!("\n[Encrypted] {}: {}", hex::encode(&sender_identity[0..4]), text);
                                            print!("\nwhisper> "); let _ = std::io::stdout().flush();
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }
    });

    let p2p_client = P2PClient { tor_client };
    let mut stdin_reader = BufReader::new(stdin());
    let mut line = String::new();

    loop {
        print!("whisper> "); std::io::stdout().flush()?;
        line.clear();
        if stdin_reader.read_line(&mut line).await? == 0 { break; }
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
                    println!("{}", format_onion(&onion));
                }
            },
            "/connect" => {
                if parts.len() > 1 {
                    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut OsRng);
                    let handshake = HandshakeMessage::new(&signing_key, &X25519PublicKey::from(&ephemeral_secret));
                    let _ = p2p_client.send_handshake(parts[1], WhisperPayload::Handshake(handshake).serialize()).await;
                }
            },
            "/msg" => {
                if parts.len() > 2 {
                    let mut ratchet = shared_ratchet.lock().unwrap();
                    if let Ok(ciphertext) = ratchet.encrypt_message(parts[2..].join(" ").as_bytes()) {
                        let payload = WhisperPayload::Message {
                            sender_identity: verifying_key.to_bytes(),
                            ciphertext,
                        }.serialize();
                        let _ = p2p_client.send_handshake(parts[1], payload).await;
                    }
                }
            },
            "/quit" => break,
            _ => println!("Unknown command."),
        }
    }
    Ok(())
}
