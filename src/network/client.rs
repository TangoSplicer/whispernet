use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;
use tokio::io::AsyncWriteExt;
use anyhow::Result;

pub struct P2PClient {
    pub tor_client: TorClient<PreferredRuntime>,
}

impl P2PClient {
    // Initiates an outbound Tor connection to another hidden service
    pub async fn send_handshake(&self, target_onion: &str, msg: Vec<u8>) -> Result<()> {
        // Hidden services typically route traffic over port 80 virtually
        let mut stream = self.tor_client.connect((target_onion, 80)).await?;
        stream.write_all(&msg).await?;
        
        // Ensure all bytes are pushed through the circuit before closing
        stream.flush().await?;
        Ok(())
    }
}
