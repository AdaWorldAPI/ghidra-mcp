//! Durable token storage.
//!
//! # Why this is not a HashMap
//!
//! The Python reference implementation keeps `_tokens = {}` — an in-process
//! dict. That is fine for a reference implementation and wrong for anything
//! fronting a decompiler:
//!
//! - every restart silently invalidates every issued token, so a deploy
//!   looks to clients exactly like a credential compromise;
//! - a second replica shares nothing, so tokens work or fail depending on
//!   which instance the load balancer picked;
//! - authorization codes are one-time by definition, and single-use cannot
//!   be enforced across processes by a per-process map.
//!
//! # Why redb and not sqlite
//!
//! `redb` is a pure-Rust embedded key-value store. `rusqlite` would drag a C
//! dependency into a runtime this workspace deliberately keeps C-free (the
//! `tesseract-rs` precedent: *zero C at runtime*, so the deploy image is a
//! glibc binary and nothing else). The storage need here — a handful of
//! keyed records with expiry — does not justify importing a C library.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};

/// Authorization codes: short-lived, single-use.
const CODES: TableDefinition<&str, &[u8]> = TableDefinition::new("auth_codes");
/// Access and refresh tokens.
const TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("tokens");

/// RFC 6749 §4.1.2 recommends a maximum authorization-code lifetime of 10
/// minutes. Short by design: the code is a bearer credential in transit
/// through a user agent.
pub const CODE_TTL_SECS: u64 = 600;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("storage: {0}")]
    Db(String),
    #[error("record encoding: {0}")]
    Codec(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    /// The PKCE challenge recorded at authorization time. `None` means the
    /// request carried none — which `pkce::verify` treats as a hard error,
    /// never as "PKCE not required".
    pub code_challenge: Option<String>,
    pub code_challenge_method: String,
    pub scope: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub client_id: String,
    pub scope: String,
    pub expires_at: u64,
    pub is_refresh: bool,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct Store {
    db: Database,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(|e| StoreError::Db(e.to_string()))?;
        // Create both tables up front so a read on a fresh database is a
        // miss rather than a "table does not exist" error.
        let w = db
            .begin_write()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        {
            w.open_table(CODES)
                .map_err(|e| StoreError::Db(e.to_string()))?;
            w.open_table(TOKENS)
                .map_err(|e| StoreError::Db(e.to_string()))?;
        }
        w.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(Self { db })
    }

    pub fn put_code(&self, code: &str, rec: &AuthCode) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(rec)?;
        let w = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        {
            let mut t = w
                .open_table(CODES)
                .map_err(|e| StoreError::Db(e.to_string()))?;
            t.insert(code, bytes.as_slice())
                .map_err(|e| StoreError::Db(e.to_string()))?;
        }
        w.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(())
    }

    /// Redeem an authorization code: read it and REMOVE it in one write
    /// transaction.
    ///
    /// Single-use is enforced here, atomically, rather than by a
    /// read-then-delete pair. RFC 6749 §4.1.2 requires the code be usable
    /// once; a non-atomic check-then-delete lets two concurrent redemptions
    /// both observe the code present and both succeed, which is exactly the
    /// race an attacker who has intercepted a code wants.
    pub fn take_code(&self, code: &str) -> Result<Option<AuthCode>, StoreError> {
        let w = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let found = {
            let mut t = w
                .open_table(CODES)
                .map_err(|e| StoreError::Db(e.to_string()))?;
            let taken = match t.remove(code).map_err(|e| StoreError::Db(e.to_string()))? {
                Some(v) => Some(serde_json::from_slice::<AuthCode>(v.value())?),
                None => None,
            };
            taken
        };
        w.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        // Expiry is checked AFTER removal: an expired code is still spent.
        Ok(found.filter(|c| c.expires_at > now_secs()))
    }

    pub fn put_token(&self, token: &str, rec: &TokenRecord) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(rec)?;
        let w = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        {
            let mut t = w
                .open_table(TOKENS)
                .map_err(|e| StoreError::Db(e.to_string()))?;
            t.insert(token, bytes.as_slice())
                .map_err(|e| StoreError::Db(e.to_string()))?;
        }
        w.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(())
    }

    pub fn get_token(&self, token: &str) -> Result<Option<TokenRecord>, StoreError> {
        let r = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let t = r
            .open_table(TOKENS)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let rec = match t.get(token).map_err(|e| StoreError::Db(e.to_string()))? {
            Some(v) => Some(serde_json::from_slice::<TokenRecord>(v.value())?),
            None => None,
        };
        Ok(rec.filter(|x| x.expires_at > now_secs()))
    }

    pub fn revoke_token(&self, token: &str) -> Result<(), StoreError> {
        let w = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        {
            let mut t = w
                .open_table(TOKENS)
                .map_err(|e| StoreError::Db(e.to_string()))?;
            t.remove(token).map_err(|e| StoreError::Db(e.to_string()))?;
        }
        w.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(())
    }
}
