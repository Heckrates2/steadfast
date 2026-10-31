//! Parsen und Validieren der `apps.toml` inkl. Vorkompilieren der
//! Rhai-Skripte. Alles passiert einmalig beim Engine-Start (Fail-Fast);
//! zur Laufzeit wird nur noch in den fertigen Runtime-Strukturen gelesen.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;

use crate::error::EngineError;
use crate::schema::{EndpointSchema, FieldType};
use crate::script::{CompiledScript, ScriptRuntime};

/// Default-Seitengroesse, wenn ein Endpunkt kein `paging_default` setzt.
pub const DEFAULT_PAGE_SIZE: usize = 20;
/// Harte Obergrenze fuer `?limit=` und `paging_default`.
pub const MAX_PAGE_SIZE: usize = 100;
/// Mindestlaenge fuer `api_key_secret` (nach `${ENV_VAR}`-Aufloesung) —
/// grob genug, um Brute-Force auf kurze Keys unattraktiv zu machen.
pub const MIN_API_KEY_SECRET_LEN: usize = 16;
/// Mindestlaenge fuer `auth.jwt_secret` (nach `${ENV_VAR}`-Aufloesung).
/// HS256-Sicherheit haengt an der Entropie des Secrets; 32 Zeichen sind das
/// Minimum fuer einen vollstaendig besetzten SHA-256/HMAC-Zustand.
pub const MIN_JWT_SECRET_LEN: usize = 32;
/// Harte Obergrenze fuer `auth.password_policy.max_length`: Argon2 hasht
/// beliebige Eingabelaengen — ohne Deckel koennte ein Angreifer mit riesigen
/// Passwort-Strings CPU/RAM auf dem Login-Endpunkt verbrennen (DoS).
pub const HARD_MAX_PASSWORD_LEN: usize = 1024;
/// Maximale Anzahl Eintraege in `roles` eines Endpunkts.
pub const MAX_ENDPOINT_ROLES: usize = 8;
/// Default/Range-Grenzen der Token-Lebenszeiten (Sekunden).
pub const DEFAULT_ACCESS_TOKEN_SECS: u64 = 900;
pub const MIN_ACCESS_TOKEN_SECS: u64 = 60;
pub const MAX_ACCESS_TOKEN_SECS: u64 = 86_400;
pub const DEFAULT_REFRESH_TOKEN_SECS: u64 = 2_592_000;
pub const MIN_REFRESH_TOKEN_SECS: u64 = 3_600;
pub const MAX_REFRESH_TOKEN_SECS: u64 = 31_536_000;

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
/// Preflights. `authorization` gehoert dazu, seit Endpunkte per
/// `auth_mode = "jwt"` Bearer-Tokens lesen.)
const DEFAULT_CORS_HEADERS: [&str; 5] = [
    "authorization",
    "content-type",
    "x-api-key",
    "x-user-id",
    "x-user-role",
];

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
    auth: Option<AuthConfigRaw>,
    #[serde(default)]
    endpoints: HashMap<String, EndpointRaw>,
}

/// Rohe `[apps.<id>.auth]`-Sektion: per-App Benutzer-Authentifizierung
/// (JWT + Refresh-Rotation). `deny_unknown_fields` macht Tippfehler zu
/// Startfehlern, statt Auth-Einstellungen still zu ignorieren.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthConfigRaw {
    #[serde(default)]
    enabled: bool,
    jwt_secret: Option<String>,
    access_token_secs: Option<u64>,
    refresh_token_secs: Option<u64>,
    #[serde(default)]
    registration_open: bool,
    allowed_origins: Option<Vec<String>>,
    admin_email: Option<String>,
    admin_password: Option<String>,
    #[serde(default)]
    password_policy: PasswordPolicyRaw,
    #[serde(default)]
    rate_limit: AuthRateLimitRaw,
}

/// Rohe `[apps.<id>.auth.password_policy]`-Sektion — jede Regel einzeln
/// konfigurierbar; fehlende Felder bekommen die Defaults.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordPolicyRaw {
    min_length: Option<usize>,
    max_length: Option<usize>,
    require_lowercase: Option<bool>,
    require_uppercase: Option<bool>,
    require_digits: Option<bool>,
    require_special: Option<bool>,
}

/// Rohe `[apps.<id>.auth.rate_limit]`-Sektion (Anfragen pro Minute je
/// Client-IP, Token-Bucket).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthRateLimitRaw {
    login_per_min: Option<u64>,
    register_per_min: Option<u64>,
    refresh_per_min: Option<u64>,
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
    /// Neu: `"api_key"` oder `"jwt"` (schliesst `auth_required = true` aus).
    /// Ohne Angabe gilt weiterhin `auth_required`.
    auth_mode: Option<String>,
    /// Rollen-Allowlist, nur mit `auth_mode = "jwt"`.
    roles: Option<Vec<String>>,
    paging_default: Option<usize>,
    filter_fields: Option<Vec<String>>,
    /// `bulk = true` macht `PATCH /{app}/{collection}` (ohne Item-ID) zum
    /// atomaren Sammel-Patch; `PATCH /{app}/{collection}/{id}` bleibt
    /// unveraendert der Single-Doc-Patch desselben Endpunkts.
    #[serde(default)]
    bulk: bool,
    business_logic: Option<String>,
    #[serde(default)]
    schema: Option<SchemaRaw>,
}

/// Rohe `[endpoint.schema]`-Sektion. `deny_unknown_fields` macht Tippfehler
/// (`requred = [...]`) zu Startfehlern, statt Validierung stillschweigend
/// zu überspringen — die Sektion verspricht Pruefungen, die dann kommen.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaRaw {
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    allow_unknown_fields: bool,
    #[serde(default)]
    types: HashMap<String, String>,
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
    /// Authentifizierungsmodus (loest `auth_required` ab; `auth_required`
    /// bleibt als Kurzform fuer `auth_mode = "api_key"` in der TOML).
    pub auth_mode: AuthMode,
    /// Rollen-Allowlist (nur `AuthMode::Jwt`): Rolle des Benutzers (frisch
    /// aus dem User-Dokument) muss in dieser Liste stehen, sonst 403.
    /// `None` = jeder authentifizierte Benutzer der App.
    pub roles: Option<Arc<[String]>>,
    /// Seitengroesse fuer GET-Listen ohne explizites `?limit=`.
    pub paging_default: usize,
    /// Optionale Allowlist filterbarer Felder.
    pub filter_fields: Option<Arc<[String]>>,
    /// Sammel-Patch aktiviert: `PATCH /{app}/{collection}` (ohne Item-ID)
    /// wendet `{"filter": ..., "set": ...}` atomar auf alle Treffer an.
    /// Nur auf PATCH-Endpunkten zulaessig (Startfehler sonst).
    pub bulk: bool,
    /// Vorkompiliertes Schema fuer Mutationen (POST/PUT/PATCH). `None` = keine
    /// Validierung konfiguriert — der Hot Path bleibt dann unangetastet.
    pub schema: Option<Arc<EndpointSchema>>,
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

/// Authentifizierungsmodus eines Endpunkts. `None` = oeffentlich (bisher
/// `auth_required = false`), `ApiKey` = bisheriges `auth_required = true`
/// (`X-API-Key`), `Jwt` = Bearer-Access-Token der App-Auth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Oeffentlicher Endpunkt.
    None,
    /// `X-API-Key` gegen das App-Secret (bisheriges Verhalten).
    ApiKey,
    /// `Authorization: Bearer <JWT>` gegen den JWT-Secret der App.
    Jwt,
}

impl AuthMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMode::None => "none",
            AuthMode::ApiKey => "api_key",
            AuthMode::Jwt => "jwt",
        }
    }
}

/// Passwort-Regeln einer App-Auth — jede Regel einzeln per TOML schaltbar.
/// `check` liefert die verletzten Regeln als statische Meldungen fuer den
/// 400-Body (nur bei Registrierung/Admin-Anlage; der Login antwortet
/// grundsätzlich generisch, um kein Policy-Orakel zu sein).
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub max_length: usize,
    pub require_lowercase: bool,
    pub require_uppercase: bool,
    pub require_digits: bool,
    /// Mind. ein Zeichen, das weder Buchstabe noch Ziffer ist (Unicode-
    /// bewusst: jedes nicht-alphanumerische Zeichen zaehlt als Sonderzeichen).
    pub require_special: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 10,
            max_length: 128,
            require_lowercase: true,
            require_uppercase: true,
            require_digits: true,
            require_special: true,
        }
    }
}

impl PasswordPolicy {
    /// Prueft ein Passwort gegen alle Regeln. Ok bei leerer Verstoßliste.
    pub fn check(&self, password: &str) -> Result<(), Vec<&'static str>> {
        let mut violations = Vec::new();
        let chars = password.chars().count();
        if chars < self.min_length {
            violations.push("password must be at least {min_length} characters long");
        }
        if chars > self.max_length {
            violations.push("password must be at most {max_length} characters long");
        }
        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            violations.push("password must contain a lowercase letter");
        }
        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            violations.push("password must contain an uppercase letter");
        }
        if self.require_digits && !password.chars().any(|c| c.is_ascii_digit()) {
            violations.push("password must contain a digit");
        }
        if self.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            violations.push("password must contain a special character (not a letter or digit)");
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// Rate-Limit-Deckel der Auth-Endpunkte (Token-Bucket je Client-IP und App):
/// Capacity = angegebener Wert, Auffuellung = Wert/60 pro Sekunde.
#[derive(Debug, Clone)]
pub struct AuthRateLimit {
    pub login_per_min: u64,
    pub register_per_min: u64,
    pub refresh_per_min: u64,
}

impl Default for AuthRateLimit {
    fn default() -> Self {
        Self {
            login_per_min: 10,
            register_per_min: 5,
            refresh_per_min: 30,
        }
    }
}

/// Bootstrap-Admin einer App-Auth: wird beim Start angelegt, falls die
/// E-Mail noch nicht existiert (Passwort unterliegt der Passwort-Policy).
#[derive(Debug, Clone)]
pub struct AdminBootstrap {
    pub email: String,
    pub password: String,
}

/// Fertig validierte `[apps.<id>.auth]`-Einstellungen. Nur aktiv
/// (`AppConfigRuntime::auth = Some`) wenn `enabled = true` — ansonsten
/// bleibt die App beim bisherigen Verhalten (API-Key/Gateway-Modell).
#[derive(Debug, Clone)]
pub struct AuthSettings {
    /// Aufgeloester JWT-Signatur-Schluessel (HS256), nie im Klartext loggen.
    pub jwt_secret: Arc<str>,
    pub access_token_secs: u64,
    pub refresh_token_secs: u64,
    pub registration_open: bool,
    /// Origins fuer den Cookie-Modus (CSRF-Origin-Check), lowercase sortiert.
    /// `None` = keine Cookie-Herkunft freigegeben (nur Bearer-Modus).
    pub allowed_origins: Option<Arc<[String]>>,
    pub admin: Option<AdminBootstrap>,
    pub password_policy: PasswordPolicy,
    pub rate_limit: AuthRateLimit,
}

/// Eine Anwendung: Secret plus alle Endpunkte (Schluessel = Endpunktname).
#[derive(Debug, Clone)]
pub struct AppConfigRuntime {
    pub api_key_secret: Option<Arc<str>>,
    pub cors: Option<Arc<CorsConfig>>,
    /// Aktive App-Auth (`[auth]` mit `enabled = true`), sonst `None`.
    pub auth: Option<Arc<AuthSettings>>,
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
                let resolved = resolve_secret(&app_id, "api_key_secret", raw, &env_lookup)?;
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

        // App-Auth vor den Endpunkten aufloesen: Der `auth_mode = "jwt"`
        // Check jedes Endpunkts braucht das Ergebnis.
        let auth = match raw_app.auth {
            None => None,
            Some(raw_auth) => validate_auth_settings(&app_id, raw_auth, &env_lookup)?.map(Arc::new),
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

            // `bulk = true` ist nur auf PATCH sinnvoll — der Sammel-Patch
            // lebt im selben Endpunkt wie der Single-Doc-Patch (die Config
            // kennt nur Kollektionspfade; (Pfad, Methode) ist eindeutig).
            // Auf anderen Methoden waere das Flag toter Config-Code.
            if raw_ep.bulk && method != HttpMethod::Patch {
                return Err(EngineError::Config(format!(
                    "app `{app_id}`, endpoint `{endpoint_name}`: bulk is only \
                     supported on PATCH ({} dispatches by item id, not by collection)",
                    method.as_str()
                )));
            }

            // Schema-Validierung ist nur fuer Body-tragende Mutationen
            // sinnvoll; auf GET/DELETE waere sie toter Config-Code —
            // lieber laut abweisen, als ein falsches Sicherheitsgefuehl
            // zu erzeugen.
            let schema = match &raw_ep.schema {
                None => None,
                Some(raw_schema) => {
                    if !matches!(
                        method,
                        HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
                    ) {
                        return Err(EngineError::Config(format!(
                            "app `{app_id}`, endpoint `{endpoint_name}`: schema is only \
                             supported on POST, PUT and PATCH ({} has no request body)",
                            method.as_str()
                        )));
                    }
                    Some(Arc::new(compile_schema(
                        &app_id,
                        &endpoint_name,
                        raw_schema,
                    )?))
                }
            };

            // Auth-Modus: `auth_mode` (neu) oder `auth_required` (Kurzform
            // fuer "api_key"). Beide zusammen sind mehrdeutig -> Fail-Fast.
            let auth_mode = match raw_ep.auth_mode.as_deref() {
                None => {
                    if raw_ep.auth_required {
                        AuthMode::ApiKey
                    } else {
                        AuthMode::None
                    }
                }
                Some("api_key") => {
                    if raw_ep.auth_required {
                        return Err(EngineError::Config(format!(
                            "app `{app_id}`, endpoint `{endpoint_name}`: \
                             auth_mode and auth_required = true say the same thing twice — \
                             pick auth_mode = \"api_key\" or auth_required (not both)"
                        )));
                    }
                    AuthMode::ApiKey
                }
                Some("jwt") => {
                    if raw_ep.auth_required {
                        return Err(EngineError::Config(format!(
                            "app `{app_id}`, endpoint `{endpoint_name}`: \
                             auth_mode = \"jwt\" cannot be combined with auth_required = true \
                             (that would demand API key AND JWT)"
                        )));
                    }
                    if auth.is_none() {
                        return Err(EngineError::Config(format!(
                            "app `{app_id}`, endpoint `{endpoint_name}`: \
                             auth_mode = \"jwt\" requires an enabled [auth] section on the app"
                        )));
                    }
                    AuthMode::Jwt
                }
                Some(other) => {
                    return Err(EngineError::Config(format!(
                        "app `{app_id}`, endpoint `{endpoint_name}`: unknown auth_mode \
                         `{other}` (allowed: \"api_key\", \"jwt\")"
                    )));
                }
            };
            if auth_mode == AuthMode::ApiKey && secret.is_none() {
                return Err(EngineError::Config(format!(
                    "app `{app_id}`, endpoint `{endpoint_name}`: auth (api_key) \
                     requires api_key_secret on the app"
                )));
            }
            // Aktivierte App-Auth betreibt den `/_auth`-Subrouter — der
            // Kollektionspfad dorthin ist dann reserviert.
            if auth.is_some() && path == "/_auth" {
                return Err(EngineError::Config(format!(
                    "app `{app_id}`, endpoint `{endpoint_name}`: path `/_auth` is reserved \
                     for the app auth endpoints while [auth] is enabled"
                )));
            }

            let roles = match raw_ep.roles {
                None => None,
                Some(roles) => {
                    if auth_mode != AuthMode::Jwt {
                        return Err(EngineError::Config(format!(
                            "app `{app_id}`, endpoint `{endpoint_name}`: roles require \
                             auth_mode = \"jwt\" (API-key requests carry no role)"
                        )));
                    }
                    if roles.is_empty() {
                        return Err(EngineError::Config(format!(
                            "app `{app_id}`, endpoint `{endpoint_name}`: roles must not be \
                             empty (an empty allowlist could never match — remove the key to \
                             allow every authenticated user)"
                        )));
                    }
                    if roles.len() > MAX_ENDPOINT_ROLES {
                        return Err(EngineError::Config(format!(
                            "app `{app_id}`, endpoint `{endpoint_name}`: at most \
                             {MAX_ENDPOINT_ROLES} roles per endpoint"
                        )));
                    }
                    for role in &roles {
                        validate_role_name(role).map_err(|reason| {
                            EngineError::Config(format!(
                                "app `{app_id}`, endpoint `{endpoint_name}`: invalid role \
                                 `{role}`: {reason}"
                            ))
                        })?;
                    }
                    let mut unique = roles;
                    unique.sort();
                    unique.dedup();
                    Some(unique.into())
                }
            };

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
                    auth_mode,
                    roles,
                    paging_default,
                    filter_fields,
                    bulk: raw_ep.bulk,
                    schema,
                    script,
                }),
            );
        }

        apps.insert(
            app_id,
            AppConfigRuntime {
                api_key_secret: secret.map(Into::into),
                cors,
                auth,
                endpoints,
            },
        );
    }

    Ok(EngineConfig { apps })
}

/// Validiert die `[auth]`-Sektion einer App. `Ok(None)` = deaktiviert
/// (`enabled = false` oder gar nicht gesetzt) — die App bleibt dann beim
/// API-Key/Gateway-Modell. `Ok(Some)` = aktive Auth-Settings.
fn validate_auth_settings(
    app_id: &str,
    raw: AuthConfigRaw,
    env_lookup: &impl Fn(&str) -> Option<String>,
) -> Result<Option<AuthSettings>, EngineError> {
    if !raw.enabled {
        return Ok(None);
    }

    // JWT-Secret: Pflicht, ${ENV}-Indirektion wie beim API-Key, min 32 Zeichen.
    let jwt_secret = raw.jwt_secret.ok_or_else(|| {
        EngineError::Config(format!(
            "app `{app_id}`: auth.enabled = true requires auth.jwt_secret \
             (min {MIN_JWT_SECRET_LEN} chars; `${{ENV_VAR}}` indirection recommended)"
        ))
    })?;
    let jwt_secret = resolve_secret(app_id, "auth.jwt_secret", &jwt_secret, env_lookup)?;
    if jwt_secret.chars().count() < MIN_JWT_SECRET_LEN {
        return Err(EngineError::Config(format!(
            "app `{app_id}`: auth.jwt_secret must be at least {MIN_JWT_SECRET_LEN} characters"
        )));
    }

    let access_token_secs = match raw.access_token_secs {
        None => DEFAULT_ACCESS_TOKEN_SECS,
        Some(secs) if (MIN_ACCESS_TOKEN_SECS..=MAX_ACCESS_TOKEN_SECS).contains(&secs) => secs,
        Some(secs) => {
            return Err(EngineError::Config(format!(
                "app `{app_id}`: auth.access_token_secs = {secs} is outside \
                 {MIN_ACCESS_TOKEN_SECS}..={MAX_ACCESS_TOKEN_SECS}"
            )));
        }
    };
    let refresh_token_secs = match raw.refresh_token_secs {
        None => DEFAULT_REFRESH_TOKEN_SECS,
        Some(secs) if (MIN_REFRESH_TOKEN_SECS..=MAX_REFRESH_TOKEN_SECS).contains(&secs) => secs,
        Some(secs) => {
            return Err(EngineError::Config(format!(
                "app `{app_id}`: auth.refresh_token_secs = {secs} is outside \
                 {MIN_REFRESH_TOKEN_SECS}..={MAX_REFRESH_TOKEN_SECS}"
            )));
        }
    };

    // Origins fuer den Cookie-Modus: exakte Origins, kein `*` (Credentials +
    // Wildcard schliessen sich aus; der Origin-Check ist der CSRF-Schutz).
    let allowed_origins = match raw.allowed_origins {
        None => None,
        Some(origins) => {
            if origins.is_empty() {
                return Err(EngineError::Config(format!(
                    "app `{app_id}`: auth.allowed_origins must not be empty \
                     (remove the key to disable the cookie mode)"
                )));
            }
            let mut normalized = Vec::with_capacity(origins.len());
            for origin in &origins {
                if origin == "*" {
                    return Err(EngineError::Config(format!(
                        "app `{app_id}`: auth.allowed_origins cannot use `*` — the cookie \
                         mode checks an exact Origin (CSRF protection)"
                    )));
                }
                validate_origin(origin).map_err(|reason| {
                    EngineError::Config(format!(
                        "app `{app_id}`: auth.allowed_origins entry `{origin}`: {reason}"
                    ))
                })?;
                normalized.push(origin.to_ascii_lowercase());
            }
            normalized.sort();
            normalized.dedup();
            Some(normalized.into())
        }
    };

    // Bootstrap-Admin: nur paarweise (E-Mail + Passwort) sinnvoll.
    let admin = match (raw.admin_email, raw.admin_password) {
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => {
            return Err(EngineError::Config(format!(
                "app `{app_id}`: auth.admin_email and auth.admin_password must be set together"
            )));
        }
        (Some(email), Some(password)) => Some(AdminBootstrap {
            email: validate_email(app_id, &email)?,
            password: resolve_secret(app_id, "auth.admin_password", &password, env_lookup)?,
        }),
    };

    // Passwort-Policy; das Bootstrap-Passwort unterliegt derselben Policy
    // (Fail-Fast beim Start statt eines nie funktionierenden Admin-Logins).
    let password_policy = validate_password_policy(app_id, raw.password_policy)?;
    if let Some(admin) = &admin {
        if let Err(violations) = password_policy.check(&admin.password) {
            return Err(EngineError::Config(format!(
                "app `{app_id}`: auth.admin_password violates the password policy: {}",
                violations.join("; ")
            )));
        }
    }

    let rate_limit = validate_rate_limit(app_id, raw.rate_limit)?;

    Ok(Some(AuthSettings {
        jwt_secret: jwt_secret.into(),
        access_token_secs,
        refresh_token_secs,
        registration_open: raw.registration_open,
        allowed_origins,
        admin,
        password_policy,
        rate_limit,
    }))
}

/// Passwort-Policy: Laengen gedeckelt (`max <= HARD_MAX_PASSWORD_LEN`,
/// `min <= max`), Klassenregeln sind freie Schalter.
fn validate_password_policy(
    app_id: &str,
    raw: PasswordPolicyRaw,
) -> Result<PasswordPolicy, EngineError> {
    let defaults = PasswordPolicy::default();
    let min_length = raw.min_length.unwrap_or(defaults.min_length);
    let max_length = raw.max_length.unwrap_or(defaults.max_length);
    if min_length < 1 {
        return Err(EngineError::Config(format!(
            "app `{app_id}`: auth.password_policy.min_length must be >= 1"
        )));
    }
    if max_length > HARD_MAX_PASSWORD_LEN {
        return Err(EngineError::Config(format!(
            "app `{app_id}`: auth.password_policy.max_length must be <= {HARD_MAX_PASSWORD_LEN} \
             (hard cap against Argon2 DoS)"
        )));
    }
    if min_length > max_length {
        return Err(EngineError::Config(format!(
            "app `{app_id}`: auth.password_policy.min_length ({min_length}) must not exceed \
             max_length ({max_length})"
        )));
    }
    Ok(PasswordPolicy {
        min_length,
        max_length,
        require_lowercase: raw.require_lowercase.unwrap_or(defaults.require_lowercase),
        require_uppercase: raw.require_uppercase.unwrap_or(defaults.require_uppercase),
        require_digits: raw.require_digits.unwrap_or(defaults.require_digits),
        require_special: raw.require_special.unwrap_or(defaults.require_special),
    })
}

fn validate_rate_limit(app_id: &str, raw: AuthRateLimitRaw) -> Result<AuthRateLimit, EngineError> {
    let defaults = AuthRateLimit::default();
    let check = |name: &str, value: Option<u64>, default: u64| -> Result<u64, EngineError> {
        match value {
            None => Ok(default),
            Some(v) if (1..=10_000).contains(&v) => Ok(v),
            Some(v) => Err(EngineError::Config(format!(
                "app `{app_id}`: auth.rate_limit.{name} = {v} is outside 1..=10000"
            ))),
        }
    };
    Ok(AuthRateLimit {
        login_per_min: check("login_per_min", raw.login_per_min, defaults.login_per_min)?,
        register_per_min: check(
            "register_per_min",
            raw.register_per_min,
            defaults.register_per_min,
        )?,
        refresh_per_min: check(
            "refresh_per_min",
            raw.refresh_per_min,
            defaults.refresh_per_min,
        )?,
    })
}

/// Einfache E-Mail-Pruefung fuer Identifikatoren (keine SMTP-Validierung):
/// ASCII, druckbar, genau ein `@`, beide Seiten nichtleer, max. 254 Zeichen.
fn validate_email(app_id: &str, email: &str) -> Result<String, EngineError> {
    let ok = (3..=254).contains(&email.len())
        && email.is_ascii()
        && !email.contains(char::is_whitespace)
        && email.matches('@').count() == 1
        && {
            let (local, domain) = email.split_once('@').expect("genau ein @");
            !local.is_empty() && !domain.is_empty()
        };
    if ok {
        Ok(email.to_ascii_lowercase())
    } else {
        Err(EngineError::Config(format!(
            "app `{app_id}`: invalid email `{email}` (ASCII, exactly one `@`, non-empty \
             local part and domain, 3..=254 chars)"
        )))
    }
}

/// Rollennamen: `[A-Za-z0-9_-]`, max. 32 Zeichen — Rollen landen in JWTs,
/// Store-Dokumenten und Konfigurationen und sollten dort unauffaellig bleiben.
fn validate_role_name(role: &str) -> Result<(), String> {
    let ok = !role.is_empty()
        && role.len() <= 32
        && role
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        Err("must match [A-Za-z0-9_-] (1..=32 chars)".into())
    }
}

/// Löst die `${ENV_VAR}`-Indirection fuer Secrets auf: Exakt die Form
/// `${NAME}` wird beim Start aus der Umgebung gelesen (Fail-Fast bei
/// fehlender oder leerer Variable). Alles andere bleibt literal — Klartext
/// in der apps.toml ist weiterhin erlaubt (Demo/Dev), die Indirection ist
/// der empfohlene Weg fuer den Betrieb.
fn resolve_secret(
    app_id: &str,
    field: &str,
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
            "app `{app_id}`: {field} `${{...}}` names an empty environment variable"
        )));
    }
    match env_lookup(name) {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_) => Err(EngineError::Config(format!(
            "app `{app_id}`: environment variable `{name}` ({field}) is set but empty"
        ))),
        None => Err(EngineError::Config(format!(
            "app `{app_id}`: environment variable `{name}` ({field}) is not set — \
             export it before starting the engine"
        ))),
    }
}

// --- Schema-Validierung --------------------------------------------------------

/// Uebersetzt die rohe `[schema]`-Sektion in das vorkompilierte
/// [`EndpointSchema`]. Alle Fehler sind Config-Fehler (Fail-Fast beim
/// Start): unbekannte Typ-Strings, ungueltige Feldnamen.
fn compile_schema(
    app_id: &str,
    endpoint_name: &str,
    raw: &SchemaRaw,
) -> Result<EndpointSchema, EngineError> {
    let context = format!("app `{app_id}`, endpoint `{endpoint_name}`: schema");

    let mut types = HashMap::with_capacity(raw.types.len());
    for (field, type_str) in &raw.types {
        validate_field_name(field).map_err(|reason| {
            EngineError::Config(format!(
                "{context}: invalid field `{field}` in `schema.types`: {reason}"
            ))
        })?;
        let field_type = FieldType::parse(type_str).ok_or_else(|| {
            EngineError::Config(format!(
                "{context}: unknown type `{type_str}` for field `{field}` \
                 (allowed: \"string\", \"number\", \"boolean\", \"object\", \"array\", \"null\", \
                 \"date\" (YYYY-MM-DD), \"datetime\" (RFC 3339 mit Offset))"
            ))
        })?;
        types.insert(field.clone(), field_type);
    }

    for field in &raw.required {
        validate_field_name(field).map_err(|reason| {
            EngineError::Config(format!(
                "{context}: invalid field `{field}` in `schema.required`: {reason}"
            ))
        })?;
    }

    Ok(EndpointSchema::new(
        raw.required.clone(),
        types,
        raw.allow_unknown_fields,
    ))
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
        assert_eq!(get.auth_mode, AuthMode::None);
        assert_eq!(get.paging_default, 20);
        assert!(get.script.is_none());

        let create = app.endpoints.get("tasks_create").unwrap();
        assert_eq!(create.auth_mode, AuthMode::ApiKey);
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
    fn bulk_flag_is_only_valid_on_patch() {
        // Der Sammel-Patch lebt im selben Endpunkt wie der Single-Doc-Patch
        // und dispatcht intern nach Item-ID — auf GET/POST/PUT/DELETE waere
        // das Flag toter Config-Code, also Startfehler statt Stillschweigen.
        let src = r#"
[apps.a]
  [apps.a.endpoints.bulk_get]
  path = "/ledger"
  method = "GET"
  bulk = true
  filter_fields = ["paid"]
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("bulk"), "{err}");
    }

    #[test]
    fn bulk_patch_endpoint_compiles_and_defaults_to_false() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.ledger_get]
  path = "/ledger"
  method = "GET"

  [apps.a.endpoints.ledger_patch]
  path = "/ledger"
  method = "PATCH"
  bulk = true
  filter_fields = ["person", "paid"]
"#;
        let config = EngineConfig::from_toml(src).expect("bulk patch config must load");
        let app = config.apps.get("a").unwrap();
        assert!(app.endpoints.get("ledger_patch").unwrap().bulk);

        // Ohne Flag bleibt alles beim Alten — Bestands-Configs (insb. der
        // Single-Doc-Patch) laufen unveraendert weiter.
        assert!(!app.endpoints.get("ledger_get").unwrap().bulk);
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

    // --- Schema ----------------------------------------------------------------

    #[test]
    fn schema_section_precompiles_into_runtime() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.create]
  path = "/tasks"
  method = "POST"

    [apps.a.endpoints.create.schema]
    required = ["title", "grp"]
    allow_unknown_fields = true

      [apps.a.endpoints.create.schema.types]
      title = "string"
      grp = "string"
      summe = "number"
      is_priority = "boolean"
"#;
        let config = EngineConfig::from_toml(src).expect("schema config must load");
        let ep = config.apps["a"].endpoints["create"].clone();
        let schema = ep.schema.as_ref().expect("schema must be precompiled");
        assert_eq!(schema.required().len(), 2);
        assert!(schema.required().contains("title"));
        assert_eq!(schema.types().len(), 4);
        assert_eq!(schema.types()["summe"], FieldType::Number);
        assert!(schema.allow_unknown_fields());

        // Vorlauf-Verhalten: gültiges Dokument passiert, Verstoß sammelt
        // alle Details (Detailqualitaet testet EndpointSchema selbst — hier
        // nur der Durchlauf durch die Config).
        assert_eq!(
            schema.validate(&serde_json::json!({"title": "x", "grp": "g"}), false),
            Ok(())
        );
    }

    #[test]
    fn schema_defaults_to_strict_and_no_required() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.create]
  path = "/tasks"
  method = "POST"

    [apps.a.endpoints.create.schema]
    types = { summe = "number" }
"#;
        let config = EngineConfig::from_toml(src).unwrap();
        let schema = config.apps["a"].endpoints["create"]
            .schema
            .as_ref()
            .expect("schema");
        assert!(!schema.allow_unknown_fields(), "Default ist strikt");
        assert!(schema.required().is_empty());
    }

    #[test]
    fn date_and_datetime_types_compile_at_startup() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.create]
  path = "/events"
  method = "POST"

    [apps.a.endpoints.create.schema]
    required = ["title", "starts_at"]
    allow_unknown_fields = true

      [apps.a.endpoints.create.schema.types]
      title = "string"
      starts_at = "datetime"
      birthday = "date"
"#;
        let config = EngineConfig::from_toml(src).unwrap();
        let schema = config.apps["a"].endpoints["create"]
            .schema
            .as_ref()
            .expect("schema");
        assert_eq!(
            schema.types().get("starts_at").map(FieldType::as_str),
            Some("datetime")
        );
        assert_eq!(
            schema.types().get("birthday").map(FieldType::as_str),
            Some("date")
        );
        // Und die Formatpruefung greift aus dem kompilierten Schema heraus.
        assert_eq!(
            schema.validate(
                &serde_json::json!({
                    "title": "Release",
                    "starts_at": "2026-11-05T09:00:00Z",
                    "birthday": "1990-07-14"
                }),
                false
            ),
            Ok(())
        );
        assert!(
            schema
                .validate(
                    &serde_json::json!({
                        "title": "Release",
                        "starts_at": "05.11.2026 09:00",
                        "birthday": "1990-07-14"
                    }),
                    false
                )
                .is_err()
        );
    }

    #[test]
    fn unknown_schema_type_fails_at_startup() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.create]
  path = "/tasks"
  method = "POST"

    [apps.a.endpoints.create.schema]
    types = { summe = "integer" }
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(
            err.message().contains("unknown type `integer`") && err.message().contains("allowed"),
            "{err}"
        );
    }

    #[test]
    fn schema_with_invalid_field_name_fails_at_startup() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.create]
  path = "/tasks"
  method = "POST"

    [apps.a.endpoints.create.schema]
    required = ["title", "bad field!"]
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(
            err.message().contains("schema.required") && err.message().contains("bad field!"),
            "{err}"
        );

        let src = src.replace(
            "required = [\"title\", \"bad field!\"]",
            "types = { \"bad key!\" = \"string\" }",
        );
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("schema.types"), "{err}");
    }

    #[test]
    fn schema_on_get_endpoint_is_rejected() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.list]
  path = "/tasks"
  method = "GET"

    [apps.a.endpoints.list.schema]
    required = ["title"]
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(
            err.message()
                .contains("only supported on POST, PUT and PATCH"),
            "{err}"
        );
    }

    #[test]
    fn schema_typo_is_not_silently_ignored() {
        // deny_unknown_fields: `requred` statt `required` muss den Start
        // abbrechen, nicht eine Schema-lose Strecke freischalten.
        let src = r#"
[apps.a]
  [apps.a.endpoints.create]
  path = "/tasks"
  method = "POST"

    [apps.a.endpoints.create.schema]
    requred = ["title"]
"#;
        assert!(matches!(
            EngineConfig::from_toml(src),
            Err(EngineError::Config(_))
        ));
    }

    #[test]
    fn schema_on_all_mutation_methods_is_accepted() {
        let src = r#"
[apps.a]
  [apps.a.endpoints.post_ep]
  path = "/tasks"
  method = "POST"
  [apps.a.endpoints.post_ep.schema]
  required = ["title"]
  [apps.a.endpoints.put_ep]
  path = "/tasks"
  method = "PUT"
  [apps.a.endpoints.put_ep.schema]
  required = ["title"]
  [apps.a.endpoints.patch_ep]
  path = "/tasks"
  method = "PATCH"
  [apps.a.endpoints.patch_ep.schema]
  types = { status = "string" }
"#;
        let config = EngineConfig::from_toml(src).expect("mutations accept schema");
        assert!(config.apps["a"].endpoints["post_ep"].schema.is_some());
        assert!(config.apps["a"].endpoints["put_ep"].schema.is_some());
        assert!(config.apps["a"].endpoints["patch_ep"].schema.is_some());
    }

    #[test]
    fn endpoints_without_schema_stay_schema_free() {
        let config = EngineConfig::from_toml(BLUEPRINT_TOML).expect("blueprint");
        for ep in config.apps["todo_app"].endpoints.values() {
            assert!(ep.schema.is_none(), "{}", ep.name);
        }
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
            [
                "authorization",
                "content-type",
                "x-api-key",
                "x-user-id",
                "x-user-role"
            ]
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

    // --- App-Auth ([apps.x.auth], auth_mode, roles) -----------------------------

    /// Minimal-Config mit aktiver Auth und einem jwt-Endpunkt (Literal-Secrets
    /// nur im Test; produktiv ${ENV}-Indirection).
    const AUTH_MINIMAL: &str = r#"
[apps.a]
  [apps.a.auth]
  enabled = true
  jwt_secret = "0123456789abcdef0123456789abcdef"

    [apps.a.endpoints.tasks_get]
    path = "/tasks"
    method = "GET"

    [apps.a.endpoints.tasks_post]
    path = "/tasks"
    method = "POST"
    auth_mode = "jwt"
"#;

    #[test]
    fn auth_section_parses_with_defaults() {
        let config = EngineConfig::from_toml(AUTH_MINIMAL).expect("auth config must load");
        let app = &config.apps["a"];
        let auth = app.auth.as_ref().expect("auth settings");
        assert_eq!(auth.access_token_secs, DEFAULT_ACCESS_TOKEN_SECS);
        assert_eq!(auth.refresh_token_secs, DEFAULT_REFRESH_TOKEN_SECS);
        assert!(!auth.registration_open);
        assert!(auth.allowed_origins.is_none());
        assert!(auth.admin.is_none());
        assert_eq!(auth.rate_limit.login_per_min, 10);
        assert_eq!(auth.rate_limit.register_per_min, 5);
        assert_eq!(auth.rate_limit.refresh_per_min, 30);

        let post = app.endpoints["tasks_post"].clone();
        assert_eq!(post.auth_mode, AuthMode::Jwt);
        assert!(post.roles.is_none());
        let get = app.endpoints["tasks_get"].clone();
        assert_eq!(get.auth_mode, AuthMode::None);
    }

    #[test]
    fn auth_disabled_leaves_apps_untouched() {
        // enabled = false (oder keine Sektion): Auth bleibt aus, selbst wenn
        // Restwerte herumstehen — die App verhaelt sich wie vorher.
        let src = r#"
[apps.a]
  [apps.a.auth]
  enabled = false
  jwt_secret = "0123456789abcdef0123456789abcdef"
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#;
        let config = EngineConfig::from_toml(src).expect("disabled auth must load");
        assert!(config.apps["a"].auth.is_none());
        assert_eq!(config.apps["a"].endpoints["one"].auth_mode, AuthMode::None);
    }

    #[test]
    fn auth_enabled_without_jwt_secret_is_rejected() {
        let src = r#"
[apps.a]
  [apps.a.auth]
  enabled = true
    [apps.a.endpoints.one]
    path = "/tasks"
    method = "GET"
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("jwt_secret"), "{err}");
    }

    #[test]
    fn auth_short_jwt_secret_is_rejected() {
        let src = AUTH_MINIMAL.replace("0123456789abcdef0123456789abcdef", "zu_kurz_1234567890");
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(
            err.message()
                .contains(&format!("at least {MIN_JWT_SECRET_LEN} characters")),
            "{err}"
        );
    }

    #[test]
    fn auth_jwt_secret_env_indirection() {
        let src = AUTH_MINIMAL.replace(
            "jwt_secret = \"0123456789abcdef0123456789abcdef\"",
            "jwt_secret = \"${TEST_JWT_SECRET}\"",
        );
        let file: AppsFile = toml::from_str(&src).unwrap();
        let lookup = |name: &str| (name == "TEST_JWT_SECRET").then(|| "x".repeat(48).to_string());
        let config = EngineConfig::validate_with(file, lookup).expect("env must resolve");
        assert_eq!(
            config.apps["a"].auth.as_ref().unwrap().jwt_secret.as_ref(),
            "x".repeat(48)
        );

        // Fehlende Variable: Fail-Fast mit Variablenname.
        let file: AppsFile = toml::from_str(&src).unwrap();
        let lookup = |name: &str| (name == "OTHER").then(|| "y".to_string());
        let err = EngineConfig::validate_with(file, lookup).unwrap_err();
        assert!(err.message().contains("TEST_JWT_SECRET"), "{err}");
    }

    #[test]
    fn auth_token_lifetimes_are_bounded() {
        for (field, value) in [
            ("access_token_secs", "59"),
            ("access_token_secs", "100000"),
            ("refresh_token_secs", "3599"),
            ("refresh_token_secs", "40000000"),
        ] {
            let src = AUTH_MINIMAL.replace(
                "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n",
                &format!(
                    "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n  {field} = {value}\n"
                ),
            );
            let err = EngineConfig::from_toml(&src).unwrap_err();
            assert!(err.message().contains(field), "{field}={value}: {err}");
        }
    }

    #[test]
    fn auth_allowed_origins_reject_wildcard_and_validate() {
        let src = AUTH_MINIMAL.replace(
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n",
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n  allowed_origins = [\"*\"]\n",
        );
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("cannot use `*`"), "{err}");

        let src = AUTH_MINIMAL.replace(
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n",
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n  \
             allowed_origins = [\"https://APP.example.com\", \"https://app.example.com\"]\n",
        );
        let config = EngineConfig::from_toml(&src).expect("origins must normalize");
        assert_eq!(
            config.apps["a"]
                .auth
                .as_ref()
                .unwrap()
                .allowed_origins
                .as_deref(),
            Some(&["https://app.example.com".to_string()][..]),
            "Case-Duplikat wird nach Lowercase-Normalisierung dedupliziert"
        );
    }

    #[test]
    fn auth_admin_bootstrap_pairing_and_policy() {
        // Nur E-Mail ohne Passwort: Fail-Fast.
        let src = AUTH_MINIMAL.replace(
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n",
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n  \
             admin_email = \"admin@example.com\"\n",
        );
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("together"), "{err}");

        // Bootstrap-Passwort, das die eigene Policy verletzt: Fail-Fast.
        let src = AUTH_MINIMAL.replace(
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n",
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n  \
             admin_email = \"admin@example.com\"\n  admin_password = \"kurz\"\n",
        );
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("password policy"), "{err}");

        // Gueltiges Paar (Policy-konform) mit ENV-Indirection.
        let src = AUTH_MINIMAL.replace(
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n",
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n  \
             admin_email = \"Admin@Example.com\"\n  admin_password = \"${ADMIN_PW}\"\n",
        );
        let file: AppsFile = toml::from_str(&src).unwrap();
        let lookup =
            |name: &str| (name == "ADMIN_PW").then(|| "V3ry-Secret_Passphrase!".to_string());
        let config = EngineConfig::validate_with(file, lookup).expect("admin bootstrap");
        let admin = config.apps["a"]
            .auth
            .as_ref()
            .unwrap()
            .admin
            .clone()
            .unwrap();
        assert_eq!(admin.email, "admin@example.com", "E-Mail wird normalisiert");
        assert_eq!(admin.password, "V3ry-Secret_Passphrase!");
    }

    #[test]
    fn password_policy_defaults_and_switches() {
        let defaults = PasswordPolicy::default();
        assert!(defaults.check("Abcdef1!xyz").is_ok());
        // Default-Policy: jede Klasse einzeln entfernen -> genau eine Regel
        // wird als verletzt gemeldet (Laenge jeweils konform halten).
        let cases = [
            ("abcdefg1!x", "uppercase letter"),
            ("ABCDEFG1!Q", "lowercase letter"),
            ("Abcdefgh!x", "digit"),
            ("Abcdefg1Ax", "special character"),
            ("Ab1!", "characters long"),
        ];
        for (password, expected) in cases {
            let violations = match defaults.check(password) {
                Err(violations) => violations,
                Ok(()) => panic!("expected a violation for `{password}`"),
            };
            assert_eq!(violations.len(), 1, "{password}: {violations:?}");
            assert!(
                violations[0].contains(expected),
                "{password}: {violations:?}"
            );
        }

        // Alles ausgeschaltet: kurzes Passwort ohne Klassen ist ok.
        let lenient = PasswordPolicy {
            min_length: 1,
            max_length: HARD_MAX_PASSWORD_LEN,
            require_lowercase: false,
            require_uppercase: false,
            require_digits: false,
            require_special: false,
        };
        assert!(lenient.check("a").is_ok());
        assert!(
            lenient
                .check(&"x".repeat(HARD_MAX_PASSWORD_LEN + 1))
                .is_err()
        );

        // Laengen-Grenzen (chars, nicht Bytes) plus several violations at once.
        let strict = PasswordPolicy {
            min_length: 4,
            ..PasswordPolicy::default()
        };
        assert!(
            strict.check("Aa1!äöü").is_ok(),
            "Unicode zaehlt als Sonderzeichen"
        );
        assert_eq!(
            strict.check("ab").unwrap_err().len(),
            4,
            "Laenge + Gross + Ziffer + Sonderzeichen"
        );
    }

    #[test]
    fn password_policy_config_bounds() {
        // min > max und max ueber Hard-Cap sind Startfehler.
        let base = "  password_policy = { min_length = 20, max_length = 10 }\n";
        let src = AUTH_MINIMAL.replace(
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n",
            &format!("  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n{base}"),
        );
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("min_length"), "{err}");

        let base = "  password_policy = { max_length = 5000 }\n";
        let src = AUTH_MINIMAL.replace(
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n",
            &format!("  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n{base}"),
        );
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("hard cap"), "{err}");
    }

    #[test]
    fn auth_rate_limit_bounds() {
        let src = AUTH_MINIMAL.replace(
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n",
            "  jwt_secret = \"0123456789abcdef0123456789abcdef\"\n  \
             rate_limit = { login_per_min = 0 }\n",
        );
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("login_per_min"), "{err}");
    }

    #[test]
    fn jwt_mode_without_enabled_auth_is_rejected() {
        let src = AUTH_MINIMAL.replace("  enabled = true\n", "");
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(
            err.message().contains("auth_mode") && err.message().contains("[auth]"),
            "{err}"
        );
    }

    #[test]
    fn auth_mode_and_auth_required_conflict() {
        let src = AUTH_MINIMAL.replace(
            "    auth_mode = \"jwt\"",
            "    auth_mode = \"jwt\"\n    auth_required = true",
        );
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("cannot be combined"), "{err}");

        // auth_mode = "api_key" + auth_required: doppelt gemoppelt -> Fehler.
        let src = AUTH_MINIMAL.replace(
            "    auth_mode = \"jwt\"",
            "    auth_mode = \"api_key\"\n    auth_required = true",
        );
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("say the same thing twice"), "{err}");
    }

    #[test]
    fn auth_mode_api_key_still_requires_secret() {
        let src = AUTH_MINIMAL.replace("auth_mode = \"jwt\"", "auth_mode = \"api_key\"");
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("api_key_secret"), "{err}");
    }

    #[test]
    fn auth_mode_api_key_parses_like_auth_required() {
        let src = r#"
[apps.a]
api_key_secret = "secret_secret_geheim"
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "POST"
  auth_mode = "api_key"
  [apps.a.endpoints.two]
  path = "/tasks"
  method = "GET"
"#;
        let config = EngineConfig::from_toml(src).unwrap();
        assert_eq!(
            config.apps["a"].endpoints["one"].auth_mode,
            AuthMode::ApiKey
        );
        assert_eq!(config.apps["a"].endpoints["two"].auth_mode, AuthMode::None);
    }

    #[test]
    fn unknown_auth_mode_is_rejected() {
        let src = AUTH_MINIMAL.replace("auth_mode = \"jwt\"", "auth_mode = \"oauth\"");
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("unknown auth_mode `oauth`"), "{err}");
    }

    #[test]
    fn roles_are_validated_and_normalized() {
        let src = AUTH_MINIMAL.replace(
            "    auth_mode = \"jwt\"",
            "    auth_mode = \"jwt\"\n    roles = [\"admin\", \"User-1\", \"admin\"]",
        );
        let config = EngineConfig::from_toml(&src).expect("roles must load");
        let roles = config.apps["a"].endpoints["tasks_post"]
            .roles
            .clone()
            .unwrap();
        assert_eq!(roles.as_ref(), ["User-1", "admin"]);

        let bad = AUTH_MINIMAL.replace(
            "    auth_mode = \"jwt\"",
            "    auth_mode = \"jwt\"\n    roles = [\"bad role!\"]",
        );
        let err = EngineConfig::from_toml(&bad).unwrap_err();
        assert!(err.message().contains("invalid role"), "{err}");

        let empty = AUTH_MINIMAL.replace(
            "    auth_mode = \"jwt\"",
            "    auth_mode = \"jwt\"\n    roles = []",
        );
        let err = EngineConfig::from_toml(&empty).unwrap_err();
        assert!(err.message().contains("must not be empty"), "{err}");
    }

    #[test]
    fn roles_without_jwt_mode_are_rejected() {
        let src = r#"
[apps.a]
api_key_secret = "secret_secret_geheim"
  [apps.a.endpoints.one]
  path = "/tasks"
  method = "POST"
  auth_required = true
  roles = ["admin"]
"#;
        let err = EngineConfig::from_toml(src).unwrap_err();
        assert!(err.message().contains("roles require"), "{err}");
    }

    #[test]
    fn auth_path_is_reserved_when_auth_enabled() {
        let src = AUTH_MINIMAL.replace("path = \"/tasks\"", "path = \"/_auth\"");
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(err.message().contains("reserved"), "{err}");

        // Ohne aktivierte Auth bleibt /_auth eine ganz normale Kollektion.
        let src = r#"
[apps.a]
  [apps.a.auth]
  enabled = false
  jwt_secret = "0123456789abcdef0123456789abcdef"
    [apps.a.endpoints.one]
    path = "/_auth"
    method = "GET"
"#;
        let config = EngineConfig::from_toml(src).expect("/_auth ohne Auth ist erlaubt");
        assert_eq!(config.apps["a"].endpoints["one"].path, "/_auth");
    }

    #[test]
    fn auth_section_typos_fail_fast() {
        let src =
            AUTH_MINIMAL.replace("  enabled = true\n", "  enabled = true\n  sekret = \"x\"\n");
        let err = EngineConfig::from_toml(&src).unwrap_err();
        assert!(matches!(err, EngineError::Config(_)));
    }
}
