//! Zentraler Engine-State: Route-Tabellen (beim Start gebaut, danach
//! read-only) plus der gemeinsame MemoryStore.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use steadfast_core::{CorsConfig, EndpointRuntime, EngineConfig, EngineError, HttpMethod};
use steadfast_storage::MemoryStore;

/// Alle Endpunkte eines konfigurierten Pfades einer App, nach HTTP-Methode.
/// `BTreeMap`, damit der `Allow`-Header bei 405 deterministisch sortiert ist.
#[derive(Debug, Default)]
pub struct PathRoutes {
    methods: BTreeMap<HttpMethod, Arc<EndpointRuntime>>,
}

impl PathRoutes {
    pub fn method(&self, method: HttpMethod) -> Option<&Arc<EndpointRuntime>> {
        self.methods.get(&method)
    }

    pub fn allowed_methods(&self) -> impl Iterator<Item = HttpMethod> + '_ {
        self.methods.keys().copied()
    }
}

/// Eine App: optionales API-Key-Secret, optionale CORS-Regeln plus
/// Pfad -> Endpunkt-Tabellen.
#[derive(Debug, Default)]
pub struct AppRoutes {
    secret: Option<Arc<str>>,
    cors: Option<Arc<CorsConfig>>,
    paths: HashMap<String, PathRoutes>,
}

impl AppRoutes {
    pub fn path(&self, path: &str) -> Option<&PathRoutes> {
        self.paths.get(path)
    }

    pub fn secret(&self) -> Option<&str> {
        self.secret.as_deref()
    }

    /// CORS-Regeln der App (`None` = keine `[cors]`-Sektion konfiguriert —
    /// Requests werden dann von der CORS-Middleware unangetastet
    /// durchgereicht).
    pub fn cors(&self) -> Option<&CorsConfig> {
        self.cors.as_deref()
    }
}

/// Von allen Tokio-Workern geteilter State (billig klonbar via `Arc`).
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    apps: HashMap<String, AppRoutes>,
    /// Geteilter Speicher als `Arc`, damit `main` denselben Store an die
    /// Persistenz (Replay + WAL-Worker) binden kann wie der HTTP-Hot-Path.
    store: Arc<MemoryStore>,
    /// H1': Optionales Shared Secret (`ENGINE_GATEWAY_SECRET`). Setzt es
    /// der Betreiber, werden `X-User-*`-Header nur noch honoring, wenn der
    /// Request per `X-Internal-Auth` seine Herkunft vom Gateway belegt.
    gateway_secret: Option<Arc<str>>,
    /// gzip-Komprimierung von JSON-Antworten (default an, `--no-compression`
    /// schaltet ab). AtomicBool, damit `main` den Schalter nach dem Build
    /// umlegen kann, ohne den Konstruktor-Signatur aller Tests zu aendern.
    compression_enabled: AtomicBool,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("apps", &self.inner.apps.len())
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// Baut den State aus einer geladenen Konfiguration. Alle Skripte sind zu
    /// diesem Zeitpunkt bereits vorkompiliert (Fail-Fast passiert in
    /// `EngineConfig::from_toml`/`load`). Der Store wird von aussen
    /// vorgegeben — `main` laesst Replay und WAL-Worker auf denselben Store
    /// arbeiten wie den HTTP-Hot-Path; ohne Persistenz einfach einen frischen
    /// `MemoryStore::new()` uebergeben. `gateway_secret` aktiviert (Some)
    /// die H1'-Provenienzpruefung fuer `X-User-*`-Header.
    pub fn build_with_store(
        config: EngineConfig,
        store: Arc<MemoryStore>,
        gateway_secret: Option<String>,
    ) -> Result<Self, EngineError> {
        if config.apps.is_empty() {
            return Err(EngineError::Config(
                "configuration defines no applications".into(),
            ));
        }

        let mut apps: HashMap<String, AppRoutes> = HashMap::new();
        for (app_id, app) in config.apps {
            let mut paths: HashMap<String, PathRoutes> = HashMap::new();
            // Union der filter_fields aller GET-Endpunkte je Pfad: Genau diese
            // Felder bekommt die Kollektion als Sekundaerindizes deklariert —
            // der Server kennt das Filterprofil der Konfiguration und der
            // Store kann gefilterte Listen damit selektiv beantworten.
            let mut filter_fields: BTreeMap<String, std::collections::BTreeSet<String>> =
                BTreeMap::new();
            let mut unauthenticated_writes: Vec<String> = Vec::new();
            for endpoint in app.endpoints.into_values() {
                // M6: Ein schreibender Endpoint ohne auth_required ist die
                // haeufigste Fehlkonfiguration (Default ist false) — beim
                // Start laut sichtbar machen, statt sie still zu erlauben.
                if endpoint.method != HttpMethod::Get && !endpoint.auth_required {
                    unauthenticated_writes.push(format!(
                        "{} {}",
                        endpoint.method.as_str(),
                        endpoint.path
                    ));
                }
                if endpoint.method == HttpMethod::Get {
                    if let Some(fields) = &endpoint.filter_fields {
                        filter_fields
                            .entry(endpoint.path.trim_start_matches('/').to_string())
                            .or_default()
                            .extend(fields.iter().cloned());
                    }
                }
                paths
                    .entry(endpoint.path.clone())
                    .or_default()
                    .methods
                    .insert(endpoint.method, endpoint);
            }
            for (collection, fields) in &filter_fields {
                store.declare_indexes(
                    &app_id,
                    collection,
                    &fields.iter().cloned().collect::<Vec<String>>(),
                );
            }
            if !unauthenticated_writes.is_empty() {
                tracing::warn!(
                    app = %app_id,
                    endpoints = %unauthenticated_writes.join(", "),
                    "write endpoints without auth_required = true — jeder Client darf hier unauthentifiziert schreiben"
                );
            }
            apps.insert(
                app_id,
                AppRoutes {
                    secret: app.api_key_secret,
                    cors: app.cors,
                    paths,
                },
            );
        }

        Ok(Self {
            inner: Arc::new(Inner {
                apps,
                store,
                gateway_secret: gateway_secret.map(Into::into),
                compression_enabled: AtomicBool::new(true),
            }),
        })
    }

    pub fn app(&self, app_id: &str) -> Option<&AppRoutes> {
        self.inner.apps.get(app_id)
    }

    pub fn store(&self) -> &MemoryStore {
        &self.inner.store
    }

    /// Konfiguriertes Gateway-Secret (H1'); `None` = Provenienzpruefung
    /// inaktiv, `X-User-*` werden wie im bisherigen Vertrauensmodell
    /// honoring.
    pub fn gateway_secret(&self) -> Option<&str> {
        self.inner.gateway_secret.as_deref()
    }

    /// Schaltet die gzip-Komprimierung ab (`--no-compression`). Vor
    /// `build_router` aufrufen — der Router liest den Schalter beim Aufbau.
    pub fn set_compression_enabled(&self, enabled: bool) {
        self.inner
            .compression_enabled
            .store(enabled, Ordering::Relaxed);
    }

    /// Ist die gzip-Komprimierung aktiv? (Default: ja.)
    pub fn compression_enabled(&self) -> bool {
        self.inner.compression_enabled.load(Ordering::Relaxed)
    }

    /// (Anzahl Apps, Anzahl Endpunkte) fuer Startup-Logging.
    pub fn summary(&self) -> (usize, usize) {
        let apps = self.inner.apps.len();
        let endpoints: usize = self
            .inner
            .apps
            .values()
            .map(|app| app.paths.values().map(|p| p.methods.len()).sum::<usize>())
            .sum();
        (apps, endpoints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use steadfast_storage::ListParams;

    const TEST_TOML: &str = r#"
[apps.todo_app]
api_key_secret = "test_secret_123_geheim"

  [apps.todo_app.endpoints.tasks_get]
  path = "/tasks"
  method = "GET"
"#;

    #[test]
    fn build_with_store_uses_the_prepopulated_store() {
        let store = Arc::new(MemoryStore::new());
        store.insert("todo_app", "tasks", "t1", json!({"title": "a"}));

        let config = EngineConfig::from_toml(TEST_TOML).expect("test config");
        let state = AppState::build_with_store(config, store, None).expect("state");

        let list = state.store().list(
            "todo_app",
            "tasks",
            ListParams {
                page: 1,
                limit: 10,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(
            list.total, 1,
            "Replay-Vorfuellung muss im Hot Path sichtbar sein"
        );
    }

    #[test]
    fn build_declares_filter_fields_as_secondary_indexes() {
        // Vorfuellung wie beim Replay: der Backfill in build_with_store muss
        // die Bestand dokumente in die deklarierten Indizes uebernehmen.
        let store = Arc::new(MemoryStore::new());
        store.insert(
            "todo_app",
            "tasks",
            "t1",
            json!({"title": "a", "status": "offen"}),
        );
        store.insert(
            "todo_app",
            "tasks",
            "t2",
            json!({"title": "b", "status": "erledigt"}),
        );

        let config = EngineConfig::from_toml(
            r#"
[apps.todo_app]
api_key_secret = "test_secret_123_geheim"

  [apps.todo_app.endpoints.tasks_get]
  path = "/tasks"
  method = "GET"
  filter_fields = ["status"]
"#,
        )
        .expect("test config");
        let state = AppState::build_with_store(config, Arc::clone(&store), None).expect("state");
        drop(state);

        let list = store.list(
            "todo_app",
            "tasks",
            ListParams {
                page: 1,
                limit: 10,
                filters: vec![("status".to_string(), "offen".to_string())],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(list.total, 1);
        assert_eq!(list.items[0]["id"], json!("t1"));
    }
}
