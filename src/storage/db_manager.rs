use rusqlite::{Connection, Result};

pub struct DbManager {
    pub conn: Connection,
}

impl DbManager {
    pub fn new(path: &str, passphrase: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute(&format!("PRAGMA key = '{}';", passphrase), [])?;
        conn.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, content BLOB);", [])?;
        Ok(DbManager { conn })
    }
}
