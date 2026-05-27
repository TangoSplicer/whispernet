use rusqlite::{Connection, Result, params};

pub struct DbManager {
    pub conn: Connection,
}

impl DbManager {
    pub fn new(path: &str, passphrase: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        
        conn.execute_batch(&format!("
            PRAGMA key = '{}';
            
            CREATE TABLE IF NOT EXISTS handshakes (
                id INTEGER PRIMARY KEY,
                peer_key BLOB NOT NULL,
                received_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS local_config (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
        ", passphrase))?;
        
        Ok(DbManager { conn })
    }

    pub fn log_handshake(&self, peer_key: &[u8]) -> Result<usize> {
        self.conn.execute(
            "INSERT INTO handshakes (peer_key) VALUES (?1)",
            params![peer_key],
        )
    }

    pub fn get_local_identity(&self) -> Result<Vec<u8>> {
        self.conn.query_row(
            "SELECT value FROM local_config WHERE key = 'identity_sk'",
            [],
            |row| row.get(0),
        )
    }

    pub fn set_local_identity(&self, sk_bytes: &[u8]) -> Result<usize> {
        self.conn.execute(
            "INSERT OR REPLACE INTO local_config (key, value) VALUES ('identity_sk', ?1)",
            params![sk_bytes],
        )
    }
}
