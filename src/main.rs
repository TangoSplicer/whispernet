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

use protocol::handshake::HandshakeMessage;
use tor_cell::relaycell::msg::Connected;
use storage::db_manager::DbManager;
use network::client::P2PClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = DbManager::new("whispernet.db", "secure_passphrase")?;
    let shared_db = Arc::new(Mutex::new(db));

    let config = TorClientConfig::default();
    let tor_client: TorClient<PreferredRuntime> = TorClient::create_bootstrapped(config).await?;

    let (_service, rend_requests) = network::hidden_service::launch_hidden_service(&tor_client, "whispernet").await?;
    
    // 1. ISOLATE THE LISTENER TO A BACKGROUND TASK
    let mut stream_requests = handle_rend_requests(rend_requests);
    let listener_db = Arc::clone(&shared_db);
    
    tokio::spawn(async move {
        while let Some(request) = stream_requests.next().await {
            if let Ok(mut data_stream) = request.accept(Connected::new_empty()).await {
                let task_db = Arc::clone(&listener_db);
                tokio::spawn(async move {
                    let mut buf = vec![0; 2048];
                    if let Ok(n) = data_stream.read(&mut buf).await {
                        // The receiver tries to parse the incoming bytes as a Handshake
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

    // 2. FOREGROUND TERMINAL INTERFACE
    let p2p_client = P2PClient { tor_client };
    let mut stdin_reader = BufReader::new(stdin());
    let mut line = String::new();

    loop {
        print!("whisper> ");
        std::io::stdout().flush()?;
        line.clear();
        
        let bytes_read = stdin_reader.read_line(&mut line).await?;
        if bytes_read == 0 { break; } // Handle EOF (Ctrl+D)
        
        let input = line.trim();
        if input.is_empty() { continue; }

        let parts: Vec<&str> = input.split_whitespace().collect();
        match parts[0] {
            "/help" => {
                println!("Commands:");
                println!("  /connect <onion_address>  - Test Tor circuit to peer");
                println!("  /quit                     - Shut down node");
            },
            "/connect" => {
                if parts.len() < 2 {
                    println!("Usage: /connect <onion_address>");
                    continue;
                }
                let target = parts[1];
                println!("[*] Building Tor circuit to {}...", target);
                
                // Transmit a raw byte sequence to test the circuit (X3DH wiring comes next)
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
