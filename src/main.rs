mod crypto;
mod network;
mod storage;
mod protocol;

use arti_client::{TorClient, TorClientConfig};
use tor_hsservice::handle_rend_requests;
use tor_rtcompat::PreferredRuntime;
use futures::StreamExt;
use tokio::io::AsyncReadExt;
use protocol::handshake::HandshakeMessage;
use tor_cell::relaycell::msg::Connected;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TorClientConfig::default();
    let tor_client: TorClient<PreferredRuntime> = TorClient::create_bootstrapped(config).await?;

    let (_service, rend_requests) = network::hidden_service::launch_hidden_service(&tor_client, "whispernet").await?;
    println!("WhisperNet active. Listening for connections...");

    let mut stream_requests = handle_rend_requests(rend_requests);
    
    while let Some(request) = stream_requests.next().await {
        // Send an empty Connected cell back to the client to finalize the circuit
        if let Ok(mut data_stream) = request.accept(Connected::new_empty()).await {
            tokio::spawn(async move {
                let mut buf = vec![0; 2048];
                if let Ok(n) = data_stream.read(&mut buf).await {
                    if let Ok(_msg) = bincode::deserialize::<HandshakeMessage>(&buf[..n]) {
                        println!("Verified handshake received from peer.");
                    }
                }
            });
        }
    }
    
    Ok(())
}
