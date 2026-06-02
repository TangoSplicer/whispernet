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
use sha3::{Digest, Sha3_256};

use protocol::handshake::HandshakeMessage;
use protocol::message::WhisperPayload;
use crypto::ratchet::RatchetState;
use tor_cell::relaycell::msg::Connected;
use storage::db_manager::DbManager;
use network::client::P2PClient;

const TEST_SEED: &[u8; 32] = b"whispernet-tactical-test-seed-32";

fn encode_v3_onion(pubkey_bytes: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey_bytes);
    hasher.update(&[0x03]);
    let checksum = hasher.finalize();

    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(pubkey_bytes);
    payload[32..34].copy_from_slice(&checksum[..2]);
    payload[34] = 0x03;

    data_encoding::BASE32_NOPAD.encode(&payload).to_lowercase()
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
        let bytes: &[u8] = onion.as_ref();
        let encoded = encode_v3_onion(bytes);
        let full_addr = format!("{}.onion", encoded);
        let mut file = File::create("address.txt")?;
        file.write_all(full_addr.as_bytes())?;
        println!("[+] Address written to address.txt: {}", full_addr);
    }
    
    let mut stream_requests = handle_rend_requests(rend_requests);
    let listener_db = Arc::clone(&shared_db);
    let shared_ratchet = Arc::new(Mutex::new(RatchetState::new(TEST_SEED)));
    let listener_ratchet = Arc::clone(&shared_ratchet);

    tokio::spawn(async move {
        while let Some(request) = stream_requests.next().await {
            println!("\n[*] Inbound connection request received.");
            if let Ok(mut data_stream) = request.accept(Connected::new_empty()).await {
                println!("[*] Connection accepted. Reading stream...");
                let task_db = Arc::clone(&listener_db);
                let task_ratchet = Arc::clone(&listener_ratchet);
                tokio::spawn(async move {
                    let mut buf = vec![0; 2048];
                    match data_stream.read(&mut buf).await {
                        Ok(0) => eprintln!("[-] Stream closed by peer before data was sent."),
                        Ok(n) => {
                            println!("[*] Received {} bytes of payload.", n);
                            match WhisperPayload::deserialize(&buf[..n]) {
                                Some(payload) => {
                                    match payload {
                                        WhisperPayload::Handshake(msg) => {
                                            println!("[*] Payload identified as Handshake.");
                                            if msg.verify_signature() {
                                                let _ = task_db.lock().unwrap().log_handshake(&msg.identity_key);
                                                println!("[+] Verified handshake received from peer.");
                                                print!("\nwhisper> "); let _ = std::io::stdout().flush();
                                            } else {
                                                eprintln!("[-] CRITICAL: Handshake signature verification failed!");
                                            }
                                        },
                                        WhisperPayload::Message { sender_identity, ciphertext } => {
                                            println!("[*] Payload identified as Encrypted Message.");
                                            let mut ratchet = task_ratchet.lock().unwrap();
                                            match ratchet.decrypt_message(&ciphertext) {
                                                Ok(plaintext) => {
                                                    if let Ok(text) = String::from_utf8(plaintext) {
                                                        println!("\n[Encrypted] {}: {}", hex::encode(&sender_identity[0..4]), text);
                                                        print!("\nwhisper> "); let _ = std::io::stdout().flush();
                                                    } else {
                                                        eprintln!("[-] Decrypted payload is not valid UTF-8.");
                                                    }
                                                },
                                                Err(e) => eprintln!("[-] Decryption failed: {:?}", e),
                                            }
                                        }
                                    }
                                },
                                None => eprintln!("[-] Failed to deserialize payload. Data may be corrupted or version mismatched."),
                            }
                        },
                        Err(e) => eprintln!("[-] Error reading from stream: {:?}", e),
                    }
                });
            } else {
                eprintln!("[-] Failed to accept inbound connection.");
            }
            print!("\nwhisper> "); let _ = std::io::stdout().flush();
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
                    let bytes: &[u8] = onion.as_ref();
                    let encoded = encode_v3_onion(bytes);
                    println!("{}.onion", encoded);
                }
            },
            "/connect" => {
                if parts.len() > 1 {
                    println!("[*] Building Tor circuit to {}...", parts[1]);
                    println!("[*] NOTE: HSDir publishing takes 1-3 minutes. If this fails, wait and retry.");
                    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut OsRng);
                    let handshake = HandshakeMessage::new(&signing_key, &X25519PublicKey::from(&ephemeral_secret));
                    let res = p2p_client.send_handshake(parts[1], WhisperPayload::Handshake(handshake).serialize()).await;
                    println!("[*] Handshake transmission result: {:?}", res);
                } else {
                    println!("Usage: /connect <onion_address>");
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
                        let res = p2p_client.send_handshake(parts[1], payload).await;
                        println!("[*] Message transmission result: {:?}", res);
                    } else {
                        println!("[-] Encryption failed.");
                    }
                } else {
                    println!("Usage: /msg <onion_address> <text>");
                }
            },
            "/quit" => break,
            _ => println!("Unknown command."),
        }
    }
    Ok(())
}
