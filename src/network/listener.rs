use tokio::io::AsyncReadExt;
use crate::protocol::handshake::HandshakeMessage;

pub async fn start_listener(mut stream: tokio::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = vec![0; 1024];
    let n = stream.read(&mut buffer).await?;
    
    // Deserialize the incoming packet
    let msg = HandshakeMessage::deserialize(&buffer[..n]);
    
    // Logic: 
    // 1. Verify msg.identity_key signature
    // 2. Perform X3DH shared secret derivation
    // 3. Initialize Double Ratchet state
    println!("Received handshake from: {:?}", msg.identity_key);
    
    Ok(())
}
