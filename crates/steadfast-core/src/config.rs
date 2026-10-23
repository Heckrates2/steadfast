//! Parsen und Validieren der `apps.toml` inkl. Vorkompilieren der
//! Rhai-Skripte. Alles passiert einmalig beim Engine-Start (Fail-Fast);
//! zur Laufzeit wird nur noch in den fertigen Runtime-Strukturen gelesen.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;

use crate::error::EngineError;
use crate::script::{CompiledScript, ScriptRuntime};

/// Default-Seitengroesse, wenn ein Endpunkt kein `paging_default` setzt.
pub const DEFAULT_PAGE_SIZE: usize = 20;
/// Harte Obergrenze fuer `?limit=` und `paging_default`.
pub const MAX_PAGE_SIZE: usize = 100;
/// Mindestlaenge fuer `api_key_secret` (nach `${ENV_VAR}`-Aufloesung) —
/// grob genug, um Brute-Force auf kurze Keys unattraktiv zu machen.
pub const MIN_API_KEY_SECRET_LEN: usize = 16;

/// Ober grenze fuer `cors.max_age_secs` (24 h). Browser deckeln den Preflight-
/// Cache ohnehin selbst; groessere Werte sind ein Config-Fehler.
pub const MAX_CORS_MAX_AGE_SECS: u64 = 86_400;

/// Alle vom Server unterstuetzten Methoden in kanonischer Reihenfolge —
/// der Default fuer `cors.allowed_methods` und die Sortierordnung des
/// `Access-Control-Allow-Methods`-Headers.
const ALL_HTTP_METHODS: [HttpMethod; 5] = [
    HttpMethod::Get,
    HttpMethod::Post,
    HttpMethod::Put,
    HttpMethod::Patch,
    HttpMethod::Delete,
];

/// Default-Allowlist fuer `Access-Control-Allow-Headers`: genau die Header,
/// die die Engine selbst aus Requests liest. (Bewusst OHNE `X-Internal-Auth`
/// — das ist ein Gateway-interner Header und gehoert nicht in Browser-
/// Preflights.)
const DEFAULT_CORS_HEADERS: [&str; 4] = ["content-type", "x-api-key", "x-user-id", "x-user-role"];

/// Default fuer `cors.exposed_headers`: `Location` auf 201 Created ist der
/// einzige eigene Header, den die Engine sendet — und er ist NICHT
/// CORS-safelisted, ohne Freigabe kann Browser-JS ihn nicht lesen. Alle
/// safelisted Header (Content-Type, Content-Length, ...) liest der Browser
/// ohnehin; alles Weitere traegt der Betreiber explizit nach.
const DEFAULT_CORS_EXPOSED_HEADERS: [&str; 1] = ["location"];

/// HTTP-Methoden, die die Engine generieren kann. Eigener Enum (statt
/// `axum::http::Method`), damit steadfast-core HTTP-frei bleibt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_uppercase().as_str() {
            "GET" => Some(HttpMethod::Get),
            "POST" => Some(HttpMethod::Post),
            "PUT" => Some(HttpMethod::Put),
            "PATCH" => Some(HttpMethod::Patch),
            "DELETE" => Some(HttpMethod::Delete),
            _ => None,
        }
    }
}

// --- Roh-Strukturen (Serde-Sicht der apps.toml) -----------------------------

#[derive(Debug, Deserialize)]
struct AppsFile {
    apps: HashMap<String, AppConfigRaw>,
}

#[derive(Debug, Deserialize)]
struct AppConfigRaw {
    api_key_secret: Option<String>,
    #[serde(default)]
    cors: Option<CorsConfigRaw>,
    #[serde(default)]
    endpoints: HashMap<String, EndpointRaw>,
}

#[derive(Debug, Deserialize)]
struct CorsConfigRaw {
    allowed_origins: Vec<String>,
    allowed_methods: Option<Vec<String>>,
    allowed_headers: Option<Vec<String>>,
    exposed_headers: Option<Vec<String>>,
    #[serde(default)]
    allow_credentials: bool,
    max_age_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct EndpointRaw {
    path: String,
    method: String,
    #[serde(default)]
    auth_required: bool,
    paging_default: Option<usize>,
    filter_fields: Option<Vec<String>>,
    business_logic: Option<String>,
}

// --- Runtime-Strukturen (fertig validiert + kompiliert) ----------------------

/// Ein fertig konfigurierter Endpunkt: validierte Felder plus das beim Start
/// vorkompilierte `rhai::AST`. Wird vom Server nur gelesen (read-only, `Arc`).
#[derive(Debug, Clone)]
pub struct EndpointRuntime {
    pub app_id: Arc<str>,
    pub name: String,
    /// Normalisierter Kollektions-Pfad, z. B. "/tasks".
    pub path: String,
    pub method: HttpMethod,
    pub auth_required: bool,
    /// Seitengroesse fuer GET-Listen ohne explizites `?limit=`.
    pub paging_default: usize,
    /// Optionale Allowlist filterbarer Felder.
    pub filter_fields: Option<Arc<[String]>>,
    pub script: Option<Arc<CompiledScript>>,
}

/// CORS-Ursprungsregel einer App (fertig validiert).
#[derive(Debug, Clone)]
pub enum AllowedOrigins {
    /// `allowed_origins = ["*"]`: jede Origin erlaubt (Antwort `*`).
    /// Nur ohne `allow_credentials` zulaessig — Browser lehnen
    /// `Access-Control-Allow-Origin: *` neben Credentials ab.
    Any,
    /// Exakte Origins, beim Laden lowercase normalisiert. Der
    /// Laufzeitvergleich ist case-insensitive (Header-Namen/Hosts sind es
    /// per Spezifikation), der Echo-Wert bleibt der Original-Header.
    List(Arc<[String]>),
}

/// Fertig validierte CORS-Einstellungen einer App. Der Server leitet daraus
/// Preflight-Antworten und die `Access-Control-*`-Header echter Responses
/// ab; Apps ohne `[cors]`-Sektion (`None`) bleiben unangetastet.
#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub allowed_origins: AllowedOrigins,
    /// Erlaubte (Preflight-)Methoden in kanonischer Reihenfolge.
    pub allowed_methods: Arc<[HttpMethod]>,
    /// Erlaubte Request-Header, lowercase normalisiert, sortiert.
    pub allowed_headers: Arc<[String]>,
    /// Response-Header, die Browser-JS via `Access-Control-Expose-Headers`
    /// lesen darf (safelisted Header ausgenommen — die darf es immer).
    /// Lowercase normalisiert, sortiert, nie leer.
    pub exposed_headers: Arc<[String]>,
    pub allow_credentials: bool,
    /// Preflight-Cachezeit in Sekunden (0..=MAX_CORS_MAX_AGE_SECS).
    pub max_age_secs: Option<u64>,
}

impl CorsConfig {
    /// Origin-Pruefung (case-insensitive Gesamtabgleich).
    pub fn origin_allowed(&self, origin: &str) -> bool {
        match &self.allowed_origins {
            AllowedOrigins::Any => true,
            AllowedOrigins::List(list) => {
                let lowered = origin.to_ascii_lowercase();
                list.iter().any(|allowed| allowed == &lowered)
            }
        }
    }

    /// Ist eine per `Access-Control-Request-Method` angefragte Methode
    /// erlaubt? (Methodennamen sind case-insensitive.)
    pub fn method_allowed(&self, method: &str) -> bool {
        self.allowed_methods
            .iter()
            .any(|m| m.as_str().eq_ignore_ascii_case(method))
    }

    /// Ist ein per `Access-Control-Request-Headers` angefragter Header
    /// erlaubt? (Header-Namen sind case-insensitive.)
    pub fn header_allowed(&self, name: &str) -> bool {
        self.allowed_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name))
    }

    /// `Access-Control-Allow-Methods`-Wert in kanonischer Reihenfolge.
    pub fn allow_methods_header(&self) -> String {
        self.allowed_methods
            .iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `Access-Control-Allow-Headers`-Wert (lowercase, sortiert).
    pub fn allow_headers_header(&self) -> String {
        self.allowed_headers.join(", ")
    }

    /// `Access-Control-Expose-Headers`-Wert (lowercase, sortiert). Gehoert
    /// nur auf echte Antworten, nicht auf Preflights (Fetch-Spec).
    pub fn expose_headers_header(&self) -> String {
        self.exposed_headers.join(", ")
    }
}

/// Eine Anwendung: Secret plus alle Endpunkte (Schluessel = Endpunktname).
#[derive(Debug, Clone)]
pub struct AppConfigRuntime {
    pub api_key_secret: Option<Arc<str>>,
    pub cors: Option<Arc<CorsConfig>>,
    pub endpoints: HashMap<String, Arc<EndpointRuntime>>,
}

/// Komplett geladene Engine-Konfiguration: App-ID -> Anwendung.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub apps: HashMap<String, AppConfigRuntime>,
}

impl EngineConfig {
    /// Laedt und validiert eine `apps.toml` von der Platte.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, EngineError> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .map_err(|e| EngineError::Config(format!("cannot read {}: {e}", path.display())))?;
        Self::from_toml(&raw)
    }

    /// Laedt und validiert eine `apps.toml` aus einem String (auch fuer Tests).
    pub fn from_toml(source: &str) -> Result<Self, EngineError> {
        let file: AppsFile = toml::from_str(source)
            .map_err(|e| EngineError::Config(format!("invalid apps.toml: {e}")))?;
        Self::validate_with(file, |name| std::env::var(name).ok())
    }

    /// Validierung + Kompilierung mit injizierbarem Umgebungsllookup
    /// (Produktion: `std::env`; Tests: fake Map, ohne globale Env-Mutation).
    fn validate_with(
        file: AppsFile,
        env_lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, EngineError> {
        validate_and_compile(file, env_lookup)
    }
}

// --- Validierung + Kompilierung ----------------------------------------------

fn validate_and_compile(
    file: AppsFile,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Result<EngineConfig, EngineError> {
    if file.apps.is_empty() {
        return Err(EngineError::Config(
            "apps.toml defines no [apps.*] sections".into(),
        ));
    }

    let mut apps = HashMap::new();
    for (app_id, raw_app) in file.apps {
        validate_app_id(&app_id)?;

        // Secret vor allen anderen Pruefungen aufloesen: `${ENV_VAR}`-Form
        // wird aus der Umgebung gelesen (Fail-Fast), alles andere bleibt
        // literal. Die Mindestlaenge gilt fuer den aufgeloesten Wert.
        let secret = match &raw_app.api_key_secret {
            None => None,
            Some(raw) => {
                let resolved = resolve_api_key_secret(&app_id, raw, &env_lookup)?;
                if resolved.chars().count() < MIN_API_KEY_SECRET_LEN {
                    return Err(EngineError::Config(format!(
                        "app `{app_id}`: api_key_secret must be at least {MIN_API_KEY_SECRET_LEN} characters"
                    )));
                }
                Some(resolved)
            }
        };
        if raw_app.endpoints.is_empty() {
            return Err(EngineError::Config(format!(
                "app `{app_id}` defines no endpoints"
            )));
        }

        let cors = match raw_app.cors {
            None => None,
            Some(raw_cors) => Some(Arc::new(validate_cors(&app_id, raw_cors)?)),
        };

        let mut endpoints = HashMap::new();
        // (Pfad, Methode) -> Endpunktname, um Doppelbelegungen zu finden.
        let mut seen_routes: HashMap<(String, HttpMethod), String> = HashMap::new();

        for (endpoint_name, raw_ep) in raw_app.endpoints {
            let path = normalize_collection_path(&raw_ep.path).map_err(|reason| {
                EngineError::Config(format!(
                    "app `{app_id}`, endpoint `{endpoint_name}`: {reason}"
                ))
            })?;
            let method = HttpMethod::parse(&raw_ep.method).ok_or_else(|| {
                EngineError::Config(format!(
                    "app `{app_id}`, endpoint `{endpoint_name}`: unsupported method `{}` \
                     (allowed: GET, POST, PUT, PATCH, DELETE)",
                    raw_ep.method
                ))
            })?;

            if let Some(previous) =
                seen_routes.insert((path.clone(), method), endpoint_name.clone())
            {
                return Err(EngineError::Config(format!(
                    "app `{app_id}`: endpoints `{previous}` and `{endpoint_name}` \
                     define the same route {} {path}",
                    method.as_str()
                )));
            }

            if raw_ep.auth_required && secret.is_none() {
                return Err(EngineError::Config(format!(
                    "app `{app_id}`, endpoint `{endpoint_name}`: auth_required = true \
                     requires api_key_secret on the app"
                )));
            }

            let paging_default = match raw_ep.paging_default {
                None => DEFAULT_PAGE_SIZE,
                Some(0) => {
                    return Err(EngineError::Config(format!(
                        "app `{app_id}`, endpoint `{endpoint_name}`: paging_default must be >= 1"
                    )));
                }
                Some(n) if n > MAX_PAGE_SIZE => {
                    return Err(EngineError::Config(format!(
                        "app `{app_id}`, endpoint `{endpoint_name}`: paging_default must be <= {MAX_PAGE_SIZE}"
                    )));
                }
                Some(n) => n,
            };

            let filter_fields = match raw_ep.filter_fields {
                None => None,
                Some(fields) if fields.is_empty() => None,
                Some(fields) => {
                    for field in &fields {
                        validate_field_name(field).map_err(|reason| {
                            EngineError::Config(format!(
                                "app `{app_id}`, endpoint `{endpoint_name}`: \
                                 invalid filter field `{field}`: {reason}"
                            ))
                        })?;
                    }
                    let mut unique = fields;
                    unique.sort();
                    unique.dedup();
                    Some(unique.into())
                }
            };

            let script = match &raw_ep.business_logic {
                None => None,
                Some(source) => Some(Arc::new(ScriptRuntime::compile(
                    &format!("{app_id}/{endpoint_name}"),
                    source,
                )?)),
            };

            endpoints.insert(
                endpoint_name.clone(),
                Arc::new(EndpointRuntime {
                    app_id: app_id.clone().into(),
                    name: endpoint_name,
                    path,
                    method,
                    auth_required: raw_ep.auth_required,
                    paging_default,
                    filter_fields,
                    script,
                }),
            );
        }

        apps.insert(
            app_id,
            AppConfigRuntime {
                api_key_secret: secret.map(Into::into),
                cors,
                endpoints,
            },
        );
    }

    Ok(EngineConfig { apps })
}

/// Löst die `${ENV_VAR}`-Indirection fuer `api_key_secret` auf: Exakt die
/// Form `${NAME}` wird beim Start aus der Umgebung gelesen (Fail-Fast bei
/// fehlender oder leerer Variable). Alles andere bleibt literal — Klartext
/// in der apps.toml ist weiterhin erlaubt (Demo/Dev), die Indirection ist
/// der empfohlene Weg fuer den Betrieb.
fn resolve_api_key_secret(
    app_id: &str,
    raw: &str,
    env_lookup: &impl Fn(&str) -> Option<String>,
) -> Result<String, EngineError> {
    let Some(inner) = raw
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return Ok(raw.to_string());
    };
    let name = inner.trim();
    if name.is_empty() {
        return Err(EngineError::Config(format!(
            "app `{app_id}`: api_key_secret `${{...}}` names an empty environment variable"
        )));
    }
    match env_lookup(name) {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_) => Err(EngineError::Config(format!(
            "app `{app_id}`: environment variable `{name}` (api_key_secret) is set but empty"
        ))),
        None => Err(EngineError::Config(format!(
            "app `{app_id}`: environment variable `{name}` (api_key_secret) is not set — \
             export it before starting the engine"
        ))),
    }
}

// --- CORS-Validierung ---------------------------------------------------------

/// Validiert die `[cors]`-Sektion einer App (Fail-Fast beim Start).
fn validate_cors(app_id: &str, raw: CorsConfigRaw) -> Result<CorsConfig, EngineError> {
    if raw.allowed_origins.is_empty() {
        return Err(EngineError::Config(format!(
            "app `{app_id}`: cors.allowed_origins must not be empty \
             (list explicit origins or exactly [\"*\"])"
        )));
    }
    let has_star = raw.allowed_origins.iter().any(|o| o == "*");
    if has_star && raw.allowed_origins.len() > 1 {
        return Err(EngineError::Config(format!(
            "app `{app_id}`: cors.allowed_origins `*` cannot be combined with explicit origins"
        )));
    }

    let allowed_origins = if has_star {
        // `Access-Control-Allow-Origin: *` neben Credentials ist per Spec
        // ungueltig — Browser lehnen solche Antworten ab. Also Fail-Fast.
        if raw.allow_credentials {
            return Err(EngineError::Config(format!(
                "app `{app_id}`: cors.allowed_origins [\"*\"] cannot be combined with \
                 allow_credentials = true — list explicit origins instead"
            )));
        }
        AllowedOrigins::Any
    } else {
        let mut origins = Vec::with_capacity(raw.allowed_origins.len());
        for origin in &raw.allowed_origins {
            validate_origin(origin).map_err(|reason| {
                EngineError::Config(format!(
                    "app `{app_id}`: cors.allowed_origins entry `{origin}`: {reason}"
                ))
            })?;
            origins.push(origin.to_ascii_lowercase());
        }
        origins.sort();
        origins.dedup();
        AllowedOrigins::List(origins.into())
    };

    let allowed_methods = match raw.allowed_methods {
        None => Arc::from(ALL_HTTP_METHODS),
        Some(methods) => {
            if methods.is_empty() {
                return Err(EngineError::Config(format!(
                    "app `{app_id}`: cors.allowed_methods must not be empty"
                )));
            }
            let mut parsed = methods
                .iter()
                .map(|raw_method| {
                    HttpMethod::parse(raw_method).ok_or_else(|| {
                        EngineError::Config(format!(
                            "app `{app_id}`: cors.allowed_methods entry `{raw_method}` is \
                             not supported (allowed: GET, POST, PUT, PATCH, DELETE — \
                             OPTIONS-Preflights beantwortet die Engine selbst)"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            parsed.sort();
            parsed.dedup();
            parsed.into()
        }
    };

    let allowed_headers = match raw.allowed_headers {
        None => Arc::from_iter(DEFAULT_CORS_HEADERS.iter().map(|name| name.to_string())),
        Some(headers) => {
            if headers.is_empty() {
                return Err(EngineError::Config(format!(
                    "app `{app_id}`: cors.allowed_headers must not be empty"
                )));
            }
            let mut normalized = Vec::with_capacity(headers.len());
            for name in &headers {
                validate_header_name(name).map_err(|reason| {
                    EngineError::Config(format!(
                        "app `{app_id}`: cors.allowed_headers entry `{name}`: {reason}"
                    ))
                })?;
                normalized.push(name.to_ascii_lowercase());
            }
            normalized.sort();
            normalized.dedup();
            normalized.into()
        }
    };

    let exposed_headers = match raw.exposed_headers {
        None => Arc::from_iter(
            DEFAULT_CORS_EXPOSED_HEADERS
                .iter()
                .map(|name| name.to_string()),
        ),
        Some(headers) => {
            if headers.is_empty() {
                return Err(EngineError::Config(format!(
                    "app `{app_id}`: cors.exposed_headers must not be empty \
                     (remove the key to keep the [\"location\"] default)"
                )));
            }
            let mut normalized = Vec::with_capacity(headers.len());
            for name in &headers {
                validate_header_name(name).map_err(|reason| {
                    EngineError::Config(format!(
                        "app `{app_id}`: cors.exposed_headers entry `{name}`: {reason}"
                    ))
                })?;
                normalized.push(name.to_ascii_lowercase());
            }
            normalized.sort();
            normalized.dedup();
            normalized.into()
        }
    };

    if let Some(age) = raw.max_age_secs {
        if age == 0 || age > MAX_CORS_MAX_AGE_SECS {
            return Err(EngineError::Config(format!(
                "app `{app_id}`: cors.max_age_secs must be between 1 and {MAX_CORS_MAX_AGE_SECS}"
            )));
        }
    }

    Ok(CorsConfig {
        allowed_origins,
        allowed_methods,
        allowed_headers,
        exposed_headers,
        allow_credentials: raw.allow_credentials,
        max_age_secs: raw.max_age_secs,
    })
}

/// Eine Origin ist genau `scheme://host[:port]` — kein Pfad, keine Query,
/// kein Fragment, keine Userinfo (`@`). IPv6-Hosts in Brackets sind erlaubt.
/// `*` wird vom Aufrufer gesondert behandelt und ist hier ein Fehler.
fn validate_origin(origin: &str) -> Result<(), String> {
    if origin == "*" {
        return Err("the wildcard must be the only entry: allowed_origins = [\"*\"]".into());
    }
    if origin.is_empty() || origin.len() > 256 {
        return Err("length must be 1..=256 characters".into());
    }
    let Some((scheme, authority)) = origin.split_once("://") else {
        return Err(
            "must have the form `scheme://host[:port]` (e.g. `https://app.example.com`)".into(),
        );
    };
    let scheme_ok = !scheme.is_empty()
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    if !scheme_ok {
        return Err(format!("invalid scheme `{scheme}:`"));
    }
    if authority.is_empty() {
        return Err("host must not be empty".into());
    }
    // Zeichen-Pruefung nur auf dem Host-Teil (das Scheme enthaelt `://`).
    if authority.contains(['/', '?', '#', '@', ' ']) {
        return Err(
            "must not contain path/query/fragment/userinfo or whitespace (host[:port] only)".into(),
        );
    }
    let host_ok = authority
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']'));
    if !host_ok {
        return Err("host must match [A-Za-z0-9._-] (optional `:port`, `[...]` for IPv6)".into());
    }
    Ok(())
}

/// HTTP-Headername (Token): `[A-Za-z0-9!#$%&'*+.^_`|~-]`, max. 128 Zeichen.
fn validate_header_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || is_header_token_special(b));
    if ok {
        Ok(())
    } else {
        Err("must be a valid HTTP header name (token, 1..=128 chars)".into())
    }
}

fn is_header_token_special(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}

/// App-IDs werden Teil der URL: streng auf `[a-z0-9_-]`, max. 64 Zeichen.
fn validate_app_id(app_id: &str) -> Result<(), EngineError> {
    let ok = !app_id.is_empty()
        && app_id.len() <= 64
        && app_id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        Err(EngineError::Config(format!(
            "invalid app id `{app_id}`: must match [a-z0-9_-] (1..=64 chars)"
        )))
    }
}

/// Konfigurierte Pfade sind Kollektions-Pfade mit genau einem Segment
/// (`/tasks`). Item-Operationen (`/tasks/<id>`) werden daraus abgeleitet.
fn normalize_collection_path(path: &str) -> Result<String, String> {
    let Some(segment) = path.strip_prefix('/') else {
        return Err(format!("path `{path}` must start with `/`"));
    };
    if segment.contains('/') {
        return Err(format!(
            "path `{path}` must be a single collection segment (e.g. `/tasks`)"
        ));
    }
    let ok = !segment.is_empty()
        && segment.len() <= 64
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !ok {
        return Err(format!(
            "path segment `{segment}` must match [A-Za-z0-9_-] (1..=64 chars)"
        ));
    }
    Ok(format!("/{segment}"))
}

/// Filter-/Feldnamen: `[A-Za-z0-9_]`, max. 64 Zeichen. Damit sind Pfad-
/// Traversale oder Sonderzeichen in Feldnamen von vornherein ausgeschlossen.
fn validate_field_name(field: &str) -> Result<(), String> {
    let ok = !field.is_empty()
        && field.len() <= 64
        && field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok {
        Ok(())
    } else {
        Err("must match [A-Za-z0-9_] (1..=64 chars)".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Das Blueprint-Beispiel aus dem Projektkonzept — unveraendert.
    const BLUEPRINT_TOML: &str = r#"
[apps.todo_app]
api_key_secret = "super_geheimes_todo_salt_123"

  [apps.todo_app.endpoints.tasks_get]
  path = "/tasks"
  method = "GET"
  auth_required = false
  paging_default = 20

  [apps.todo_app.endpoints.tasks_create]
  path = "/tasks"
  method = "POST"
  auth_required = true

  business_logic = """
  fn on_request(payload, user) {
      if user.role != "premium" && payload.is_priority == true {
          throw "Nur Premium-Nutzer koennen Prioritaets-Tasks erstellen!";
      }
      if payload.title.len() == 0 {
          throw "Titel darf nicht leer sein.";
      }
      payload.created_by = user.id;
      payload.status = "offen";
      return payload;
  }
  """
"#;

    #[test]
    fn blueprint_config_parses_and_precompiles() {
        let config = EngineConfig::from_toml(BLUEPRINT_TOML).expect("blueprint config must load");
        let app = config.apps.get("todo_app").expect("todo_app");
        assert_eq!(app.endpoints.len(), 2);

        let get = app.endpoints.get("tasks_get").unwrap();
        assert_eq!(get.path, "/tasks");
        assert_eq!(get.method, HttpMethod::Get);
        assert!(!get.auth_required);
        assert_eq!(get.paging_default, 20);
        assert!(get.script.is_none());

        let create = app.endpoints.get("tasks_create").unwrap();
        assert!(create.auth_required);
        assert!(
            create.script.is_some(),
            "business_logic must be precompiled"
        );
    }

    #[test]
    fn empty_config_is_rejected() {
        assert!(matches!(
            EngineConfig::from_toml(""),
            Err(EngineError::Config(_))
        ));
    }

    #[test]
    fn duplicate_route_is_rejected() {
        let src = r#"
[apps.a]
api_key_secret = "secret_secret_geheim"
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "GET"
  [apps.a.endpoints.two]
  path = "/tasks"
  method = "get"
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("same route"), "{err}");
    }

    #[test]
    fn auth_without_secret_is_rejected() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "POST"
  auth_required = true
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("api_key_secret"), "{err}");
    }

    #[test]
    fn unsupported_method_is_rejected() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "BREW"
"#;
        assert!(matches!(
            EngineConfig::from_toml(src),
            Err(EngineError::Config(_))
        ));
    }

    #[test]
    fn nested_path_is_rejected() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.one]
  path = "/tasks/deep"
  method = "GET"
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("single collection segment"), "{err}");
    }

    #[test]
    fn invalid_filter_field_is_rejected() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "GET"
  filter_fields = ["status", "bad field!"]
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("invalid filter field"), "{err}");
    }

    #[test]
    fn script_syntax_error_fails_at_startup() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "POST"
  business_logic = """
  fn on_request(payload, user) {
      return payload
  """ 
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(
            matches!(err, EngineError::ScriptCompile { .. }),
            "expected ScriptCompile, got: {err}"
        );
    }

    #[test]
    fn script_without_on_request_hook_is_rejected() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "POST"
  business_logic = """
  fn wrong_name(payload, user) {
      return payload;
  }
  """
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("on_request"), "{err}");
    }

    #[test]
    fn script_with_wrong_arity_is_rejected() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "POST"
  business_logic = """
  fn on_request(payload) {
      return payload;
  }
  """
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("2 parameters"), "{err}");
    }

    #[test]
    fn short_secret_is_rejected() {
        let src = r#"
[apps.a]
api_key_secret = "short"
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "GET"
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(
            err.message()
                .contains(&format!("at least {MIN_API_KEY_SECRET_LEN} characters")),
            "{err}"
        );
    }

    #[test]
    fn env_indirection_resolves_and_enforces_min_length() {
        let src = r#"
[apps.a]
api_key_secret = "${TEST_APP_SECRET}"
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "GET"
"#;
        let file: AppsFile = toml::from_str(src).unwrap();
        let lookup = |name: &str| {
            (name == "TEST_APP_SECRET").then(|| "ein-langes-test-geheimnis".to_string())
        };
        let config = EngineConfig::validate_with(file, lookup).expect("indirection must resolve");
        assert_eq!(
            config.apps["a"].api_key_secret.as_deref(),
            Some("ein-langes-test-geheimnis")
        );

        // Aufgeloester zu kurzer Wert faellt ebenfalls durch die Mindest-
        // laenge — die Pruefung gilt nach der Indirection, nicht davor.
        let file: AppsFile = toml::from_str(src).unwrap();
        let lookup = |name: &str| (name == "TEST_APP_SECRET").then(|| "kurz".to_string());
        let err = EngineConfig::validate_with(file, lookup).unwrap_err();
        assert!(
            err.message()
                .contains(&format!("at least {MIN_API_KEY_SECRET_LEN} characters")),
            "{err}"
        );
    }

    #[test]
    fn env_indirection_fails_fast_on_missing_variable() {
        let src = r#"
[apps.a]
api_key_secret = "${DEFINITELY_UNSET_VAR_XYZ}"
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "GET"
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(
            err.message().contains("DEFINITELY_UNSET_VAR_XYZ") && err.message().contains("not set"),
            "{err}"
        );
    }

    #[test]
    fn partial_env_form_stays_literal() {
        // Nicht exakt `${VAR}` (Praefix davor): bleibt literal, keine
        // Indirection — so bleiben Secrets mit `$`-Zeichen unangetastet.
        let src = r#"
[apps.a]
api_key_secret = "pa$$w0rd-${not_a_var}"
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "GET"
"#;
        let config = EngineConfig::from_toml(src).expect("literal secret must load");
        assert_eq!(
            config.apps["a"].api_key_secret.as_deref(),
            Some("pa$$w0rd-${not_a_var}")
        );
    }

    #[test]
    fn invalid_app_id_is_rejected() {
        let src = r#"
[apps.BadApp]
  [apps.BadApp.endpoints.one]
  path = "/tasks"
  method = "GET"
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("invalid app id"), "{err}");
    }

    #[test]
    fn filter_fields_are_sorted_and_deduped() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "GET"
  filter_fields = ["status", "album", "status"]
"#;
        let config = EngineConfig::from_toml(src).unwrap();
        let ep = config.apps["a"].endpoints["one"].clone();
        let fields = ep.filter_fields.clone().expect("filter fields");
        assert_eq!(fields.as_ref(), ["album", "status"]);
    }

    #[test]
    fn paging_default_bounds() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.zero]
  path = "/zero"
  method = "GET"
  paging_default = 0
"#;
        assert!(matches!(
            EngineConfig::from_toml(src),
            Err(EngineError::Config(_))
        ));

        let src = r#"
[apps.a]
  [apps.a.endpoints.huge]
  path = "/huge"
  method = "GET"
  paging_default = 1000
"#;
        assert!(matches!(
            EngineConfig::from_toml(src),
            Err(EngineError::Config(_))
        ));
    }

    // --- CORS ------------------------------------------------------------------

    #[test]
    fn cors_section_parses_with_defaults() {
        let src = r#"
[apps.a]
  [apps.a.cors]
  allowed_origins = ["https://app.example.com"]
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#;
        let config = EngineConfig::from_toml(src).expect("cors config must load");
        let cors = config.apps["a"]
            .cors
            .as_ref()
            .expect("cors section must be present");

        // Defaults: alle fuenf Methoden, Engine-Header, keine Credentials,
        // keine Preflight-Cachezeit.
        assert_eq!(
            cors.allowed_methods.as_ref(),
            [
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Put,
                HttpMethod::Patch,
                HttpMethod::Delete
            ]
        );
        assert_eq!(
            cors.allowed_headers.as_ref(),
            ["content-type", "x-api-key", "x-user-id", "x-user-role"]
        );
        assert!(!cors.allow_credentials);
        assert!(cors.max_age_secs.is_none());
        assert_eq!(
            cors.exposed_headers.as_ref(),
            ["location"],
            "Default: der 201er-Location-Header ist aus JS lesbar"
        );

        // Origin-Pruefung ist case-insensitive, aber exakt (kein Suffix-Match).
        assert!(cors.origin_allowed("https://app.example.com"));
        assert!(cors.origin_allowed("HTTPS://APP.EXAMPLE.COM"));
        assert!(!cors.origin_allowed("https://evil-app.example.com"));
        assert!(!cors.origin_allowed("https://app.example.com.evil.dev"));
        assert!(cors.method_allowed("get"));
        assert!(!cors.method_allowed("OPTIONS"));
        assert!(cors.header_allowed("Content-Type"));
        assert!(!cors.header_allowed("x-internal-auth"));

        assert_eq!(cors.allow_methods_header(), "GET, POST, PUT, PATCH, DELETE");
    }

    #[test]
    fn cors_explicit_options_and_origin_normalization() {
        let src = r#"
[apps.a]
  [apps.a.cors]
  allowed_origins = ["HTTPS://App.Example.COM", "http://localhost:3000"]
  allowed_methods = ["post", "GET"]
  allowed_headers = ["Content-Type", "X-Api-Key"]
  allow_credentials = true
  max_age_secs = 600
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#;
        let config = EngineConfig::from_toml(src).expect("cors config must load");
        let cors = config.apps["a"].cors.as_ref().unwrap();

        assert_eq!(
            cors.allowed_headers.as_ref(),
            ["content-type", "x-api-key"],
            "Header-Namen werden lowercase normalisiert und sortiert"
        );
        assert_eq!(
            cors.allowed_methods.as_ref(),
            [HttpMethod::Get, HttpMethod::Post]
        );
        assert!(cors.allow_credentials);
        assert_eq!(cors.max_age_secs, Some(600));
    }

    #[test]
    fn cors_exposed_headers_default_normalization_and_rejection() {
        // Explizite Liste: lowercase, sortiert, dedupliziert.
        let src = r#"
[apps.a]
  [apps.a.cors]
  allowed_origins = ["https://app.example.com"]
  exposed_headers = ["X-Request-Id", "Location", "LOCATION"]
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#;
        let config = EngineConfig::from_toml(src).expect("cors config must load");
        let cors = config.apps["a"].cors.as_ref().unwrap();
        assert_eq!(cors.exposed_headers.as_ref(), ["location", "x-request-id"]);
        assert_eq!(cors.expose_headers_header(), "location, x-request-id");

        // Leere Liste ist abgelehnt (Fail-Fast wie bei allowed_headers).
        let empty = src.replace(
            "exposed_headers = [\"X-Request-Id\", \"Location\", \"LOCATION\"]",
            "exposed_headers = []",
        );
        let err = EngineConfig::from_toml(&empty).unwrap_err();
        assert!(err.message().contains("cors.exposed_headers"), "{err}");

        // Ungueltiger Header-Name wird abgelehnt.
        let bad = src.replace(
            "exposed_headers = [\"X-Request-Id\", \"Location\", \"LOCATION\"]",
            "exposed_headers = [\"bad header!\"]",
        );
        let err = EngineConfig::from_toml(&bad).unwrap_err();
        assert!(err.message().contains("cors.exposed_headers"), "{err}");
    }

    #[test]
    fn cors_wildcard_without_credentials_is_allowed() {
        let src = r#"
[apps.a]
  [apps.a.cors]
  allowed_origins = ["*"]
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#;
        let config = EngineConfig::from_toml(src).expect("wildcard cors must load");
        let cors = config.apps["a"].cors.as_ref().unwrap();
        assert!(matches!(cors.allowed_origins, AllowedOrigins::Any));
        assert!(cors.origin_allowed("https://irgendwas.example"));
    }

    #[test]
    fn cors_wildcard_with_credentials_is_rejected() {
        let src = r#"
[apps.a]
  [apps.a.cors]
  allowed_origins = ["*"]
  allow_credentials = true
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("allow_credentials"), "{err}");
    }

    #[test]
    fn cors_mixed_wildcard_list_is_rejected() {
        let src = r#"
[apps.a]
  [apps.a.cors]
  allowed_origins = ["*", "https://app.example.com"]
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("cannot be combined"), "{err}");
    }

    #[test]
    fn cors_empty_origins_is_rejected() {
        let src = r#"
[apps.a]
  [apps.a.cors]
  allowed_origins = []
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("must not be empty"), "{err}");
    }

    #[test]
    fn cors_invalid_origins_are_rejected() {
        let cases = [
            ("app.example.com", "fehlendes scheme"),
            ("https://", "leerer Host"),
            ("https://app.example.com/", "Pfad-Slash"),
            ("https://app.example.com/api", "Pfad"),
            ("https://app.example.com?x=1", "Query"),
            ("https://app.example.com#f", "Fragment"),
            ("https://user@app.example.com", "Userinfo"),
            ("https://app example.com", "Leerzeichen"),
            ("1https://app.example.com", "Scheme ohne Leading-Letter"),
            ("", "leere Origin"),
        ];
        for (origin, reason) in cases {
            let src = format!(
                r#"
[apps.a]
  [apps.a.cors]
  allowed_origins = ["{origin}"]
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#
            );
            let err = EngineConfig::from_toml(&src).unwrap_err();
            assert!(
                err.message().contains("cors.allowed_origins"),
                "case `{origin}` ({reason}): {err}"
            );
        }
    }

    #[test]
    fn cors_unsupported_methods_are_rejected() {
        let src = r#"
[apps.a]
  [apps.a.cors]
  allowed_origins = ["https://app.example.com"]
  allowed_methods = ["GET", "OPTIONS"]
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(
            err.message().contains("OPTIONS") && err.message().contains("not supported"),
            "{err}"
        );
    }

    #[test]
    fn cors_invalid_header_names_are_rejected() {
        let src = r#"
[apps.a]
  [apps.a.cors]
  allowed_origins = ["https://app.example.com"]
  allowed_headers = ["content-type", "bad header!"]
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("cors.allowed_headers"), "{err}");
    }

    #[test]
    fn cors_max_age_bounds() {
        let src = r#"
[apps.a]
  [apps.a.cors]
  allowed_origins = ["https://app.example.com"]
  max_age_secs = 0
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("max_age_secs"), "{err}");

        let src = src.replace("max_age_secs = 0", "max_age_secs = 100000");
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("max_age_secs"), "{err}");
    }
}
