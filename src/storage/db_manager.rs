use rusqlite::{Connection, Result, params};

pub struct DbManager {
    pub conn: Connection,
}

impl DbManager {
    pub fn new(path: &str, passphrase: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        
        // Use execute_batch to safely ignore the confirmation row returned by SQLCipher
        conn.execute_batch(&format!("PRAGMA key = '{}';", passphrase))?;
        
        // Create a schema for tracking handshakes and peers
        conn.execute(
            "CREATE TABLE IF NOT EXISTS handshakes (
                id INTEGER PRIMARY KEY,
                peer_key BLOB NOT NULL,
                received_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );",
            [],
        )?;
        Ok(DbManager { conn })
    }

    // Safely insert the peer's public identity key into the local ledger
    pub fn log_handshake(&self, peer_key: &[u8]) -> Result<usize> {
        self.conn.execute(
            "INSERT INTO handshakes (peer_key) VALUES (?1)",
            params![peer_key],
        )
    }
}
