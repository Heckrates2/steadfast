//! steadfast-auth: Per-App-Benutzer-Authentifizierung der REST-Engine.
//!
//! Aktivierung erfolgt ausschliesslich per Konfiguration (`[apps.<id>.auth]`
//! mit `enabled = true` in der `apps.toml`). Ohne aktive Auth bleibt eine App
//! beim bisherigen Modell (API-Key + Gateway-Header) — dieses Modul wird dann
//! weder initialisiert noch erreicht (abgesehen vom fehlenden `/_auth`-Pfad).
//!
//! Architektur:
//!
//! * [`AppAuth`] — Runtime-State einer aktivierten App-Auth: JWT-Keys,
//!   Refresh-Rotation, User-Store-Zugriff, Rate-Limiter. Benutzer und
//!   Refresh-Tokens liegen als gewoehnliche Dokumente im [`MemoryStore`]
//!   unter dem Namespace der jeweiligen App (Tenant-Isolation gratis,
//!   WAL-Persistenz inklusive) — in den reservierten Kollektionen
//!   `_auth_users` / `_auth_refresh`.
//! * [`password`] — Argon2id-Hashing plus Dummy-Hash fuer Timing-Paritaet.
//! * [`tokens`] — JWT (HS256, pro App-Secret) und opake Refresh-Tokens
//!   (Rotation mit Wiederverwendungs-Erkennung).
//! * [`endpoints`] — der `/{app_id}/_auth/*`-Subrouter (Login, Register,
//!   Refresh, Logout, Me, Admin-Verwaltung).
//! * [`rate_limit`] — Token-Bucket je Client-IP fuer die Auth-Endpunkte.
//! * [`cookies`] — optionaler Browser-Cookie-Modus (HttpOnly + CSRF).
//! * [`sweeper`] — periodische Bereinigung abgelaufener Tokens/Buckets.
//!
//! Passwort-Verifizierung (Argon2, ~100 ms CPU) laeuft bewusst synchron auf
//! dem Tokio-Worker — die Engine betreibt auch Rhai-Sandbox und WAL-Worker
//! synchron, und Login-Raten sind per Rate-Limit und Lockout gedeckelt.

mod cookies;
mod endpoints;
mod password;
mod rate_limit;
mod sweeper;
mod tokens;
mod users;

pub use endpoints::route;
pub use sweeper::{SWEEP_INTERVAL, spawn_sweeper};
pub use tokens::Claims;

use std::sync::Arc;
use std::sync::Mutex;

use axum::http::HeaderMap;
use steadfast_core::{AllowedOrigins, AuthSettings, CorsConfig, EngineError};
use steadfast_storage::MemoryStore;

/// Reservierte Kollektion fuer Benutzerdokumente (Namespace der App).
pub const USERS_COLLECTION: &str = "_auth_users";
/// Reservierte Kollektion fuer Refresh-Token-Dokumente (Namespace der App).
pub const REFRESH_COLLECTION: &str = "_auth_refresh";
/// Reserviertes Pfad-Segment: `/{app_id}/_auth/...` (Config-Validierung
/// verbietet Endpunkte auf `/_auth`, solange die App-Auth aktiv ist).
pub const AUTH_PATH_SEGMENT: &str = "_auth";

/// Fehlversuche bis zum Lockout (dann exponentielle Sperre, siehe
/// [`users`]).
pub const LOGIN_FAILURE_THRESHOLD: u64 = 10;

/// Frisch verifizierter Benutzer fuer den Hot Path: Bearer-Token geprueft
/// UND der Store-Stand (existiert, nicht deaktiviert) dazu gelesen — Rolle
/// aus dem Dokument, nicht aus den (bis zu 15 min alten) Claims.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub role: String,
}

/// Unix-Sekunden "jetzt" (Monotonie irrelevant: nur Ablaufvergleiche).
pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Runtime-State der App-Auth (pro aktivierter App genau einmal gebaut,
/// danach nur gelesen; billig via `Arc` geteilt).
pub struct AppAuth {
    app_id: Arc<str>,
    settings: AuthSettings,
    store: Arc<MemoryStore>,
    encode_key: jsonwebtoken::EncodingKey,
    decode_key: jsonwebtoken::DecodingKey,
    limiter: rate_limit::RateLimiter,
    dummy: password::DummyHash,
    /// Effektive Origins fuer den Cookie-Modus: `[auth].allowed_origins`,
    /// Rueckfall auf die konkreten `cors.allowed_origins` der App. `None`
    /// (oder CORS-Wildcard) deaktiviert den Cookie-Modus.
    cookie_origins: Option<Arc<[String]>>,
    /// Serialisiert Benutzer-Anlagen: Der Store erzwingt Eindeutigkeit nur
    /// je Dokument-ID, E-Mails sind aber eindeutig — Check-then-Create
    /// unter dieser Sperre macht die E-Mail-Eindeutigkeit atomar.
    user_write: Mutex<()>,
}

impl AppAuth {
    /// Baut die App-Auth: deklariert die Sekundaerindizes (E-Mail im
    /// User-Store, `user_id` im Refresh-Store — beides Lookup-Pfade),
    /// bootstrappt den Admin und berechnet den Dummy-Hash. Muss VOR dem
    /// ersten Request laufen (Aufruf aus `AppState::build_with_store`).
    pub fn init(
        app_id: &str,
        settings: AuthSettings,
        store: Arc<MemoryStore>,
        cors: Option<&CorsConfig>,
    ) -> Result<Self, EngineError> {
        store.declare_indexes(app_id, USERS_COLLECTION, &["email".to_string()]);
        store.declare_indexes(app_id, REFRESH_COLLECTION, &["user_id".to_string()]);

        // Cookie-Modus: eigene Origin-Liste, sonst konkrete CORS-Origins.
        // Eine CORS-Wildcard taugt nicht als CSRF-Herkunftsnachweis.
        let cookie_origins = match &settings.allowed_origins {
            Some(origins) => Some(Arc::clone(origins)),
            None => cors.and_then(|cors| match &cors.allowed_origins {
                AllowedOrigins::List(list) => Some(Arc::clone(list)),
                AllowedOrigins::Any => None,
            }),
        };

        let secret = settings.jwt_secret.as_bytes().to_vec();
        let auth = Self {
            app_id: app_id.into(),
            encode_key: jsonwebtoken::EncodingKey::from_secret(&secret),
            decode_key: jsonwebtoken::DecodingKey::from_secret(&secret),
            limiter: rate_limit::RateLimiter::new(),
            dummy: password::DummyHash::new(),
            cookie_origins,
            settings,
            store,
            user_write: Mutex::new(()),
        };

        if let Some(admin) = auth.settings.admin.clone() {
            auth.bootstrap_admin(&admin.email, &admin.password);
        }
        Ok(auth)
    }

    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    pub fn settings(&self) -> &AuthSettings {
        &self.settings
    }

    pub(crate) fn store(&self) -> &MemoryStore {
        &self.store
    }

    pub(crate) fn encode_key(&self) -> &jsonwebtoken::EncodingKey {
        &self.encode_key
    }

    /// Nur fuer Tests (Produktionspfad geht ueber [`AppAuth::verify_bearer`]).
    #[cfg(test)]
    pub(crate) fn decode_key(&self) -> &jsonwebtoken::DecodingKey {
        &self.decode_key
    }

    pub(crate) fn dummy(&self) -> &password::DummyHash {
        &self.dummy
    }

    pub(crate) fn limiter(&self) -> &rate_limit::RateLimiter {
        &self.limiter
    }

    /// Origins, deren Browser den Cookie-Modus nutzen duerfen (`None` =
    /// Cookie-Modus aus, nur Bearer).
    pub(crate) fn cookie_origins(&self) -> Option<&Arc<[String]>> {
        self.cookie_origins.as_ref()
    }

    /// Prueft `Authorization: Bearer <token>` gegen den JWT-Secret der App
    /// (Signatur HS256, `exp`, `iss`). Liefert die Claims — NICHT geprüft:
    /// ob der Benutzer noch existiert/aktiv ist (das macht der Aufrufer mit
    /// einem frischen Store-Lookup, damit Sperren/Rückstufungen sofort
    /// greifen und nicht erst beim nächsten Refresh).
    pub fn verify_bearer(&self, headers: &HeaderMap) -> Option<Claims> {
        let value = headers.get(axum::http::header::AUTHORIZATION)?;
        let raw = value.to_str().ok()?;
        let token = raw
            .strip_prefix("Bearer ")
            .or_else(|| raw.strip_prefix("bearer "))?;
        if token.is_empty() {
            return None;
        }
        tokens::decode_access(token, &self.decode_key, &self.app_id)
    }

    /// Hot-Path-Variante fuer `auth_mode = "jwt"`-Endpunkte: verifiziert
    /// das Bearer-Token UND liest den Benutzer frisch aus dem Store —
    /// geloeschte/gesperrte Kontos scheitern hier sofort, Rollenaenderungen
    /// greifen ohne Refresh-Abzug. Ein DashMap-Lookup pro Request.
    pub fn verify_bearer_user(&self, headers: &HeaderMap) -> Option<AuthenticatedUser> {
        let claims = self.verify_bearer(headers)?;
        let user = self.user_by_id(&claims.sub)?;
        if user
            .get("disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return None;
        }
        Some(AuthenticatedUser {
            user_id: claims.sub,
            role: user
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("user")
                .to_string(),
        })
    }

    /// Periodische Bereinigung (Sweeper-Task): abgelaufene Refresh-Tokens
    /// und leer gelaufene Rate-Limit-Buckets.
    pub(crate) fn sweep(&self) {
        self.sweep_refresh_tokens();
        self.limiter.sweep();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Test-Settings mit Policy, die Test-Passwoerter zulaesst.
    pub(crate) fn test_settings() -> AuthSettings {
        AuthSettings {
            jwt_secret: "test-jwt-secret-0123456789abcdef".into(),
            access_token_secs: 900,
            refresh_token_secs: 3_600,
            registration_open: true,
            allowed_origins: None,
            admin: None,
            password_policy: steadfast_core::PasswordPolicy {
                min_length: 8,
                ..steadfast_core::PasswordPolicy::default()
            },
            rate_limit: steadfast_core::AuthRateLimit::default(),
        }
    }

    pub(crate) fn test_app_auth() -> AppAuth {
        AppAuth::init("demo", test_settings(), Arc::new(MemoryStore::new()), None).expect("AppAuth")
    }

    #[test]
    fn init_declares_indexes_and_bootstrap_admin() {
        let settings = AuthSettings {
            admin: Some(steadfast_core::AdminBootstrap {
                email: "Admin@Example.com".into(),
                password: "Bootstrap-Passw0rt!".into(),
            }),
            ..test_settings()
        };
        let store = Arc::new(MemoryStore::new());
        let auth = AppAuth::init("demo", settings, Arc::clone(&store), None).unwrap();

        let user = auth.find_user_by_email("admin@example.com").expect("admin");
        assert_eq!(user["role"], json!("admin"));

        // Erneuter Init (Restart) legt den Admin NICHT erneut an und
        // ueberschreibt das Passwort nicht.
        let auth2 = AppAuth::init("demo", test_settings_with_admin(), store, None).unwrap();
        let again = auth2
            .find_user_by_email("admin@example.com")
            .expect("admin");
        assert_eq!(again["id"], user["id"]);
        let total = auth2.list_users(1, 100);
        assert_eq!(total.1, 1, "nur der eine Bootstrap-Admin");
    }

    fn test_settings_with_admin() -> AuthSettings {
        AuthSettings {
            admin: Some(steadfast_core::AdminBootstrap {
                email: "admin@example.com".into(),
                password: "Anderes-Passw0rt!".into(),
            }),
            ..test_settings()
        }
    }

    #[test]
    fn cookie_origins_fall_back_to_cors_list() {
        let cors = cors_list_config();
        let auth = AppAuth::init(
            "demo",
            test_settings(),
            Arc::new(MemoryStore::new()),
            Some(&cors),
        )
        .unwrap();
        assert_eq!(
            auth.cookie_origins().map(|o| o.to_vec()),
            Some(vec!["https://app.example.com".to_string()])
        );

        // Eigene Liste gewinnt ueber CORS.
        let settings = AuthSettings {
            allowed_origins: Some(vec!["https://auth.example.com".to_string()].into()),
            ..test_settings()
        };
        let auth =
            AppAuth::init("demo", settings, Arc::new(MemoryStore::new()), Some(&cors)).unwrap();
        assert_eq!(
            auth.cookie_origins().map(|o| o.to_vec()),
            Some(vec!["https://auth.example.com".to_string()])
        );
    }

    fn cors_list_config() -> CorsConfig {
        // CorsConfig direkt bauen: Validierung testet core; hier zaehlt nur
        // die List-Semantik fuer den Cookie-Fallback.
        CorsConfig {
            allowed_origins: AllowedOrigins::List(
                vec!["https://app.example.com".to_string()].into(),
            ),
            allowed_methods: vec![].into(),
            allowed_headers: vec![].into(),
            exposed_headers: vec!["location".to_string()].into(),
            allow_credentials: false,
            max_age_secs: None,
        }
    }
}
