//! Keeper Security (`keepersecurity`) vault provider.
//!
//! Owns the connection — the encrypted KSM config stored in
//! `vault_connection` — plus the per-workspace session and a small resolve cache.
//! Keeper is **not** a hostname-matched vault racer like Bitwarden; it is a
//! *value source* for explicit secrets. A secret with `value_source =
//! "keepersecurity"` carries an `keeper://<record-uid>/field/<name>` reference that the
//! The `PolicyEngine` (`context`) resolves here at request time
//! (instead of decrypting a stored `encrypted_value`).
//!
//! The actual Keeper SDK work (validate token, resolve `keeper://`, browse
//! vaults/items/fields for the picker) is delegated to the Node "Keeper SDK
//! service" via [`super::keepersecurity_api`]; the gateway never runs the `op` CLI.
//!
//! A cached session is re-checked against its `vault_connections` row on every
//! use (see the crate docs), so a disconnect or re-pair made through any
//! gateway instance retires the token everywhere on the next request.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use db::VaultGeneration;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{info, warn};

use super::keepersecurity_api::{self, KeeperSecurityError};
use super::{
    check_session, PairResult, ProviderStatus, SessionCheck, VaultCredential, VaultError,
    VaultProvider,
};
use crypto::CryptoService;

const PROVIDER: &str = "keepersecurity";
const RESOLVE_CACHE_TTL: Duration = Duration::from_secs(60);
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);
const ERROR_COOLDOWN: Duration = Duration::from_secs(60);
/// How long a successful `status` connectivity check is trusted before re-checking.
const STATUS_OK_TTL: Duration = Duration::from_secs(30);
const EVICTION_INTERVAL: Duration = Duration::from_secs(300);
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(1800);

// ── Config & session types ──────────────────────────────────────────────

/// Persisted in `vault_connection.connection_data`. Rows written before the
/// value-source refactor also carry a `mappings` key; serde ignores it.
///
/// Deliberately no `Debug`/`Clone`: the struct carries only a credential (the
/// encrypted KSM config), so it must not be `{:?}`-logged or cloned around.
#[derive(Serialize, Deserialize)]
pub struct KeeperSecurityConfig {
    pub encrypted_ksm_config: String,
}

/// What a `pair` request carries: a ready KSM config, or a single-use one-time
/// token (e.g. `US:xxxx`) that must be bound to a config first.
#[derive(Debug, PartialEq, Eq)]
enum PairInput<'a> {
    Config(&'a str),
    OneTimeToken(&'a str),
}

/// Pick the credential out of a `pair` body. A config wins over a token when both
/// are sent (the token would otherwise be spent for nothing). Blank or non-string
/// values count as absent, so a form submitted empty fails here with a clear
/// message instead of reaching the Keeper SDK.
fn parse_pair_input(params: &serde_json::Value) -> Result<PairInput<'_>> {
    let field = |name: &str| {
        params
            .get(name)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    if let Some(config) = field("ksm_config") {
        Ok(PairInput::Config(config))
    } else if let Some(token) = field("one_time_token") {
        Ok(PairInput::OneTimeToken(token))
    } else {
        Err(anyhow!("missing ksm_config or one_time_token"))
    }
}

/// A cached `keeper://` resolution. `value: None` is a negative cache entry (the
/// reference resolved to nothing / failed) held for a shorter TTL.
struct CachedRef {
    value: Option<String>,
    expires_at: Instant,
}

struct KeeperSecuritySession {
    decrypted_config: String,
    /// The row generation this session was loaded at: the session is valid
    /// only while the row still carries it.
    generation: VaultGeneration,
    /// `keeper://<record-uid>/field/<name>` → resolved value, with positive/negative TTLs.
    ref_cache: DashMap<String, CachedRef>,
    last_used: Mutex<Instant>,
    last_error: Mutex<Option<String>>,
    error_until: Mutex<Option<Instant>>,
    /// Timestamp of the last successful connectivity check (positive `status` cache).
    last_ok: Mutex<Option<Instant>>,
}

impl KeeperSecuritySession {
    /// Whether the session is still within its post-error cooldown window (set
    /// when a `Transient` Keeper failure was last seen).
    fn in_error_cooldown(&self) -> bool {
        self.error_until
            .lock()
            .expect("session lock poisoned")
            .is_some_and(|t| Instant::now() < t)
    }
}

pub struct KeeperSecurityVaultProvider {
    pool: PgPool,
    crypto: Arc<CryptoService>,
    sessions: Arc<DashMap<String, Arc<KeeperSecuritySession>>>,
}

// ── Constructor with idle-session eviction ──────────────────────────────

impl KeeperSecurityVaultProvider {
    pub fn new(pool: PgPool, crypto: Arc<CryptoService>) -> Self {
        let sessions: Arc<DashMap<String, Arc<KeeperSecuritySession>>> = Arc::new(DashMap::new());

        let sessions_clone = Arc::clone(&sessions);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(EVICTION_INTERVAL).await;
                let mut to_evict = Vec::new();
                for entry in sessions_clone.iter() {
                    let last = *entry
                        .value()
                        .last_used
                        .lock()
                        .expect("session lock poisoned");
                    if last.elapsed() > SESSION_IDLE_TIMEOUT {
                        to_evict.push(entry.key().clone());
                    }
                }
                for key in to_evict {
                    if let Some((_, session)) = sessions_clone.remove(&key) {
                        session.ref_cache.clear();
                        info!(workspace_id = %key, "evicted idle keepersecurity session");
                    }
                }
            }
        });

        Self {
            pool,
            crypto,
            sessions,
        }
    }

    /// Load the workspace's session, or `None` if it is not paired.
    ///
    /// A cached session is served only after its row confirms it: gone means
    /// disconnected (drop it, return `None`), a new generation means re-paired
    /// (drop it and load the new token). A database error fails the call and
    /// keeps the session — a credential is never served unverified.
    /// Decrypts the KSM config into memory (held for resolution).
    async fn load_session(
        &self,
        workspace_id: &str,
    ) -> Result<Option<Arc<KeeperSecuritySession>>, VaultError> {
        // Clone out of the map so no shard lock is held across the await.
        let cached = self
            .sessions
            .get(workspace_id)
            .map(|entry| Arc::clone(entry.value()));
        if let Some(session) = cached {
            let check = check_session(&self.pool, workspace_id, PROVIDER, Some(session.generation))
                .await
                .map_err(|e| {
                    warn!(workspace_id, error = %e, "keepersecurity: session check failed");
                    VaultError::Internal("failed to verify vault connection".into())
                })?;
            match check {
                SessionCheck::Current => {
                    *session.last_used.lock().expect("session lock poisoned") = Instant::now();
                    return Ok(Some(session));
                }
                SessionCheck::Gone => {
                    self.evict(workspace_id, &session);
                    info!(
                        workspace_id,
                        "keepersecurity: connection removed; session dropped"
                    );
                    return Ok(None);
                }
                SessionCheck::Superseded => {
                    self.evict(workspace_id, &session);
                    info!(
                        workspace_id,
                        "keepersecurity: connection re-paired; reloading session"
                    );
                }
            }
        }

        let row = match db::find_vault_connection(&self.pool, workspace_id, PROVIDER).await {
            Ok(Some(row)) => row,
            Ok(None) => return Ok(None),
            Err(e) => {
                return Err(VaultError::Internal(format!(
                    "failed to load vault connection: {e}"
                )))
            }
        };

        let connection_data = row.connection_data.ok_or_else(|| {
            VaultError::Internal("vault connection has no connection_data".into())
        })?;
        let config: KeeperSecurityConfig = serde_json::from_value(connection_data)
            .map_err(|e| VaultError::Internal(format!("malformed connection_data: {e}")))?;

        let ksm_config = self
            .crypto
            .decrypt(&config.encrypted_ksm_config)
            .await
            .map_err(|e| {
                warn!(workspace_id, "failed to decrypt KSM config: {e}");
                VaultError::Internal("token decryption failed; re-pair to fix".into())
            })?;

        let session = Arc::new(KeeperSecuritySession {
            decrypted_config: ksm_config,
            generation: row.generation,
            ref_cache: DashMap::new(),
            last_used: Mutex::new(Instant::now()),
            last_error: Mutex::new(None),
            error_until: Mutex::new(None),
            last_ok: Mutex::new(None),
        });
        self.sessions
            .insert(workspace_id.to_string(), Arc::clone(&session));
        Ok(Some(session))
    }

    /// Drop `session` from the map — only if it is still the one there, so a
    /// concurrent reload's fresh session is never removed in its place — and
    /// release its resolved values.
    fn evict(&self, workspace_id: &str, session: &Arc<KeeperSecuritySession>) {
        self.sessions
            .remove_if(workspace_id, |_, current| Arc::ptr_eq(current, session));
        session.ref_cache.clear();
    }

    // ── Value-source resolution (the secret-injection path) ──────────────

    /// Resolve an `keeper://<record-uid>/field/<name>` reference to its secret value for a
    /// workspace's Keeper connection. Cached by `keepersecurity_ref` with the same TTL /
    /// cooldown as before. Errors classify so the caller can skip the secret the
    /// same way it skips one whose stored value fails to decrypt.
    ///
    /// There is one Keeper connection per workspace, so the reference resolves
    /// via that workspace's connection (the `workspace_id` session).
    pub async fn resolve_ref(
        &self,
        workspace_id: &str,
        keepersecurity_ref: &str,
    ) -> Result<String, VaultError> {
        let session = self
            .load_session(workspace_id)
            .await?
            .ok_or_else(|| VaultError::NotFound("keepersecurity is not connected".into()))?;

        if let Some(cached) = session.ref_cache.get(keepersecurity_ref) {
            if cached.expires_at > Instant::now() {
                return cached.value.clone().ok_or_else(|| {
                    VaultError::BadRequest(format!("cannot resolve {keepersecurity_ref}"))
                });
            }
            drop(cached);
            session.ref_cache.remove(keepersecurity_ref);
        }

        if session.in_error_cooldown() {
            return Err(VaultError::Internal(
                "keepersecurity temporarily unavailable (cooldown)".into(),
            ));
        }

        match keepersecurity_api::resolve(&session.decrypted_config, keepersecurity_ref).await {
            Ok(value) if !value.is_empty() => {
                *session.last_error.lock().expect("session lock poisoned") = None;
                session.ref_cache.insert(
                    keepersecurity_ref.to_string(),
                    CachedRef {
                        value: Some(value.clone()),
                        expires_at: Instant::now() + RESOLVE_CACHE_TTL,
                    },
                );
                Ok(value)
            }
            Ok(_) => {
                self.cache_negative(&session, keepersecurity_ref);
                Err(VaultError::BadRequest(format!(
                    "{keepersecurity_ref} resolved to an empty value"
                )))
            }
            Err(KeeperSecurityError::NotFound(msg)) | Err(KeeperSecurityError::BadRequest(msg)) => {
                self.cache_negative(&session, keepersecurity_ref);
                Err(VaultError::BadRequest(msg))
            }
            Err(KeeperSecurityError::Transient(msg)) => {
                *session.last_error.lock().expect("session lock poisoned") = Some(msg.clone());
                *session.error_until.lock().expect("session lock poisoned") =
                    Some(Instant::now() + ERROR_COOLDOWN);
                Err(VaultError::Internal(msg))
            }
        }
    }

    fn cache_negative(&self, session: &KeeperSecuritySession, keepersecurity_ref: &str) {
        session.ref_cache.insert(
            keepersecurity_ref.to_string(),
            CachedRef {
                value: None,
                expires_at: Instant::now() + NEGATIVE_CACHE_TTL,
            },
        );
    }

    // ── Picker passthroughs (browse records → fields) ────────────────────
    // The browser never sees the KSM config or field values — it gets only the
    // titles/labels/refs the Node service returns.

    pub async fn list_records(&self, workspace_id: &str) -> Result<serde_json::Value, VaultError> {
        let session = self.picker_session(workspace_id).await?;
        keepersecurity_api::list_records(&session.decrypted_config)
            .await
            .map_err(keepersecurity_err_to_vault)
    }

    pub async fn list_fields(
        &self,
        workspace_id: &str,
        record_uid: &str,
    ) -> Result<serde_json::Value, VaultError> {
        let session = self.picker_session(workspace_id).await?;
        keepersecurity_api::list_fields(&session.decrypted_config, record_uid)
            .await
            .map_err(keepersecurity_err_to_vault)
    }

    /// Load a connected session for picker calls, or 404 if not paired.
    async fn picker_session(
        &self,
        workspace_id: &str,
    ) -> Result<Arc<KeeperSecuritySession>, VaultError> {
        self.load_session(workspace_id)
            .await?
            .ok_or_else(|| VaultError::NotFound("keepersecurity is not connected".into()))
    }
}

// ── VaultProvider implementation ─────────────────────────────────────────

#[async_trait]
impl VaultProvider for KeeperSecurityVaultProvider {
    fn provider_name(&self) -> &'static str {
        PROVIDER
    }

    async fn pair(&self, workspace_id: &str, params: &serde_json::Value) -> Result<PairResult> {
        // Only the config is ever stored: a one-time token is single-use, so it
        // is bound to a config first and then discarded.
        let bound;
        let ksm_config: &str = match parse_pair_input(params)? {
            PairInput::Config(cfg) => cfg,
            PairInput::OneTimeToken(token) => {
                bound = keepersecurity_api::bind(token)
                    .await
                    .map_err(|e| anyhow!("one-time token binding failed: {e}"))?;
                &bound
            }
        };

        // Validate the config via the Node SDK service before persisting it.
        keepersecurity_api::validate(ksm_config)
            .await
            .map_err(|e| anyhow!("config validation failed: {e}"))?;

        let encrypted = self
            .crypto
            .encrypt(ksm_config)
            .await
            .map_err(|e| anyhow!("encryption failed: {e}"))?;

        let config = KeeperSecurityConfig {
            encrypted_ksm_config: encrypted,
        };
        let cd = serde_json::to_value(&config)?;
        db::upsert_vault_connection(&self.pool, workspace_id, PROVIDER, "paired", Some(&cd))
            .await?;

        // Drop this instance's copy now; every other instance retires its own
        // on its next use, when the row's new generation no longer matches.
        if let Some((_, old)) = self.sessions.remove(workspace_id) {
            old.ref_cache.clear();
        }
        Ok(PairResult {
            display_name: Some("Keeper Secrets Manager".into()),
        })
    }

    /// Keeper is a value-source for explicit secrets (resolved via the
    /// PolicyEngine secret-injection path), not a hostname-matched vault racer,
    /// so it never participates in the Bitwarden-style credential race.
    async fn request_credential(
        &self,
        _workspace_id: &str,
        _hostname: &str,
    ) -> Option<VaultCredential> {
        None
    }

    async fn status(&self, workspace_id: &str) -> ProviderStatus {
        let session = match self.load_session(workspace_id).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                return ProviderStatus {
                    connected: false,
                    name: None,
                    status_data: None,
                }
            }
            Err(e) => {
                return ProviderStatus {
                    connected: false,
                    name: None,
                    status_data: Some(serde_json::json!({ "last_error": e.to_string() })),
                }
            }
        };

        let connected = live_check(&session).await;
        let last_err = session
            .last_error
            .lock()
            .expect("session lock poisoned")
            .clone();

        ProviderStatus {
            connected,
            name: None,
            status_data: Some(serde_json::json!({ "last_error": last_err })),
        }
    }

    async fn disconnect(&self, workspace_id: &str) -> Result<()> {
        if let Some((_, session)) = self.sessions.remove(workspace_id) {
            session.ref_cache.clear();
        }
        Ok(())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Live connectivity check for `status`, gated by the error cooldown and a
/// short positive TTL so dashboard polling doesn't hammer Keeper.
async fn live_check(session: &KeeperSecuritySession) -> bool {
    if session.in_error_cooldown() {
        return false;
    }
    if session
        .last_ok
        .lock()
        .expect("session lock poisoned")
        .is_some_and(|t| t.elapsed() < STATUS_OK_TTL)
    {
        return true;
    }
    match keepersecurity_api::validate(&session.decrypted_config).await {
        Ok(()) => {
            *session.last_error.lock().expect("session lock poisoned") = None;
            *session.last_ok.lock().expect("session lock poisoned") = Some(Instant::now());
            true
        }
        Err(e) => {
            *session.last_error.lock().expect("session lock poisoned") = Some(e.to_string());
            *session.error_until.lock().expect("session lock poisoned") =
                Some(Instant::now() + ERROR_COOLDOWN);
            false
        }
    }
}

fn keepersecurity_err_to_vault(e: KeeperSecurityError) -> VaultError {
    match e {
        KeeperSecurityError::NotFound(m) => VaultError::NotFound(m),
        KeeperSecurityError::BadRequest(m) => VaultError::BadRequest(m),
        KeeperSecurityError::Transient(m) => VaultError::Internal(m),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── pair input ──────────────────────────────────────────────────────

    #[test]
    fn pair_accepts_a_config() {
        let body = json!({ "ksm_config": "e30=" });
        assert_eq!(parse_pair_input(&body).unwrap(), PairInput::Config("e30="));
    }

    #[test]
    fn pair_accepts_a_one_time_token() {
        let body = json!({ "one_time_token": "US:abc_DEF-123" });
        assert_eq!(
            parse_pair_input(&body).unwrap(),
            PairInput::OneTimeToken("US:abc_DEF-123")
        );
    }

    #[test]
    fn pair_trims_surrounding_whitespace() {
        let body = json!({ "one_time_token": "  US:abc \n" });
        assert_eq!(
            parse_pair_input(&body).unwrap(),
            PairInput::OneTimeToken("US:abc")
        );
    }

    // A config wins: binding the token as well would spend a single-use token
    // for a connection that is already usable.
    #[test]
    fn pair_prefers_the_config_when_both_are_sent() {
        let body = json!({ "ksm_config": "cfg", "one_time_token": "US:abc" });
        assert_eq!(parse_pair_input(&body).unwrap(), PairInput::Config("cfg"));
    }

    #[test]
    fn pair_falls_back_to_the_token_when_the_config_is_blank() {
        let body = json!({ "ksm_config": "   ", "one_time_token": "US:abc" });
        assert_eq!(
            parse_pair_input(&body).unwrap(),
            PairInput::OneTimeToken("US:abc")
        );
    }

    #[test]
    fn pair_rejects_a_body_with_neither() {
        for body in [
            json!({}),
            json!({ "ksm_config": "" }),
            json!({ "one_time_token": "   " }),
            json!({ "ksm_config": 123 }),
            json!({ "one_time_token": null }),
            json!({ "service_account_token": "ops_1password_field" }),
            json!("just a string"),
            json!(null),
        ] {
            let err = parse_pair_input(&body).unwrap_err().to_string();
            assert_eq!(err, "missing ksm_config or one_time_token", "{body}");
        }
    }

    // The error must never echo what was sent: it may be a credential.
    #[test]
    fn pair_errors_do_not_echo_the_input() {
        let body = json!({ "ksm_config": 42, "secret": "hunter2" });
        let err = parse_pair_input(&body).unwrap_err().to_string();
        assert!(!err.contains("hunter2"));
    }

    #[test]
    fn config_round_trip() {
        let config = KeeperSecurityConfig {
            encrypted_ksm_config: "iv:tag:ct".into(),
        };
        let json = serde_json::to_value(&config).unwrap();
        let back: KeeperSecurityConfig = serde_json::from_value(json).unwrap();
        assert_eq!(back.encrypted_ksm_config, "iv:tag:ct");
    }

    #[test]
    fn config_ignores_legacy_mappings() {
        // Rows written before the value-source refactor carry a `mappings` key.
        // It must deserialize cleanly (ignored) so existing connections keep working.
        let json = serde_json::json!({
            "encrypted_ksm_config": "iv:tag:ct",
            "mappings": { "api.anthropic.com": "keeper://uid/field/password" },
        });
        let config: KeeperSecurityConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.encrypted_ksm_config, "iv:tag:ct");
    }

    // ── Cross-instance revocation, over a real Postgres ─────────────────
    //
    // Two providers over one database stand in for two gateway instances. The
    // pair/disconnect "through instance A" is the row write it performs, so
    // these drive the row directly (pairing itself dials the Keeper
    // service) and assert on what instance B serves.

    use crate::test_support::{seed_workspace, test_crypto, test_pool};
    use crate::VaultService;

    /// Write the connection row the way `pair` does, for `token`.
    async fn write_pairing(pool: &PgPool, crypto: &CryptoService, workspace_id: &str, token: &str) {
        let config = KeeperSecurityConfig {
            encrypted_ksm_config: crypto.encrypt(token).await.expect("encrypt"),
        };
        let cd = serde_json::to_value(&config).expect("serialize");
        db::upsert_vault_connection(pool, workspace_id, PROVIDER, "paired", Some(&cd))
            .await
            .expect("upsert");
    }

    async fn token_served(
        provider: &KeeperSecurityVaultProvider,
        workspace_id: &str,
    ) -> Option<String> {
        provider
            .load_session(workspace_id)
            .await
            .expect("load session")
            .map(|s| s.decrypted_config.clone())
    }

    #[tokio::test]
    async fn a_re_pair_on_another_instance_replaces_the_cached_token() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let ws = seed_workspace(&pool, "vkp1").await;
        let crypto = test_crypto();
        let b = KeeperSecurityVaultProvider::new(pool.clone(), Arc::clone(&crypto));

        write_pairing(&pool, &crypto, &ws, "token-one").await;
        assert_eq!(token_served(&b, &ws).await.as_deref(), Some("token-one"));

        // Re-paired through another instance: B's cached session is stale.
        write_pairing(&pool, &crypto, &ws, "token-two").await;
        assert_eq!(token_served(&b, &ws).await.as_deref(), Some("token-two"));
    }

    #[tokio::test]
    async fn a_disconnect_on_another_instance_drops_the_cached_session() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let ws = seed_workspace(&pool, "vkp2").await;
        let crypto = test_crypto();
        let a = Arc::new(KeeperSecurityVaultProvider::new(
            pool.clone(),
            Arc::clone(&crypto),
        ));
        let b = KeeperSecurityVaultProvider::new(pool.clone(), Arc::clone(&crypto));
        let service_a =
            VaultService::new(vec![Arc::clone(&a) as Arc<dyn VaultProvider>], pool.clone());

        write_pairing(&pool, &crypto, &ws, "token-one").await;
        assert_eq!(token_served(&b, &ws).await.as_deref(), Some("token-one"));

        service_a
            .disconnect(&ws, PROVIDER)
            .await
            .expect("disconnect");

        assert_eq!(token_served(&b, &ws).await, None);
        assert!(
            !b.sessions.contains_key(&ws),
            "the revoked token must not stay resident on B"
        );
        // And the resolve path refuses rather than reaching Keeper.
        assert!(matches!(
            b.resolve_ref(&ws, "keeper://v/i/f").await,
            Err(VaultError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn a_current_session_is_reused_not_reloaded() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let ws = seed_workspace(&pool, "vkp3").await;
        let crypto = test_crypto();
        let b = KeeperSecurityVaultProvider::new(pool.clone(), Arc::clone(&crypto));

        write_pairing(&pool, &crypto, &ws, "token-one").await;
        let first = b.load_session(&ws).await.expect("load").expect("session");
        let second = b.load_session(&ws).await.expect("load").expect("session");
        assert!(
            Arc::ptr_eq(&first, &second),
            "an unchanged row must keep its session"
        );
    }

    #[tokio::test]
    async fn a_disconnect_never_reaches_another_workspaces_session() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let ws_x = seed_workspace(&pool, "vkp5x").await;
        let ws_y = seed_workspace(&pool, "vkp5y").await;
        let crypto = test_crypto();
        let a = Arc::new(KeeperSecurityVaultProvider::new(
            pool.clone(),
            Arc::clone(&crypto),
        ));
        let b = KeeperSecurityVaultProvider::new(pool.clone(), Arc::clone(&crypto));
        let service_a =
            VaultService::new(vec![Arc::clone(&a) as Arc<dyn VaultProvider>], pool.clone());

        write_pairing(&pool, &crypto, &ws_x, "token-x").await;
        write_pairing(&pool, &crypto, &ws_y, "token-y").await;
        let y_before = b.load_session(&ws_y).await.expect("load").expect("session");
        assert_eq!(token_served(&b, &ws_x).await.as_deref(), Some("token-x"));

        // Workspace X disconnects; workspace Y's connection is untouched.
        service_a
            .disconnect(&ws_x, PROVIDER)
            .await
            .expect("disconnect");

        assert_eq!(token_served(&b, &ws_x).await, None);
        let y_after = b.load_session(&ws_y).await.expect("load").expect("session");
        assert_eq!(y_after.decrypted_config, "token-y");
        assert!(
            Arc::ptr_eq(&y_before, &y_after),
            "another workspace's session must not even be reloaded"
        );
    }

    #[tokio::test]
    async fn a_database_error_fails_closed_and_keeps_the_session() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let ws = seed_workspace(&pool, "vkp4").await;
        let crypto = test_crypto();
        write_pairing(&pool, &crypto, &ws, "token-one").await;

        // B on its own pool, so closing it simulates B losing the database.
        let url = std::env::var("GATEWAY_TEST_DATABASE_URL").expect("url");
        let b_pool = db::create_pool(&url).await.expect("pool");
        let b = KeeperSecurityVaultProvider::new(b_pool.clone(), Arc::clone(&crypto));
        assert_eq!(token_served(&b, &ws).await.as_deref(), Some("token-one"));

        b_pool.close().await;
        assert!(
            matches!(b.load_session(&ws).await, Err(VaultError::Internal(_))),
            "an unverifiable session must not be served"
        );
        assert!(
            b.sessions.contains_key(&ws),
            "a database blip must not tear the session down"
        );
    }
}
