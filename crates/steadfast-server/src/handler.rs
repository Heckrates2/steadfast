//! Der Hot Path: Config-Lookup -> Auth -> Rhai-Sandbox -> CRUD -> Response.

use std::collections::HashMap;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use steadfast_core::{
    AuthMode, EndpointRuntime, EngineError, HttpMethod, MAX_PAGE_SIZE, ScriptRuntime,
};
use steadfast_storage::{
    BulkPatchOutcome, BulkPatchReport, ListParams, ListResult, PatchOutcome, RangeOp, SortSpec,
};
use uuid::Uuid;

use crate::auth::{
    API_KEY_HEADER, INTERNAL_AUTH_HEADER, duplicate_identity_header, extract_user, verify_api_key,
    verify_gateway_secret,
};
use crate::state::{AppState, PathRoutes};

/// DoS-Grenzen fuer den Query-String bei Listen-Endpunkten.
const MAX_FILTERS: usize = 16;
const MAX_FILTER_VALUE_LEN: usize = 256;
const MAX_ITEM_ID_LEN: usize = 256;
const MAX_CLIENT_ID_LEN: usize = 256;

/// N2: Hartes Body-Limit fuer alle Endpunkte (DefaultBodyLimit im Router).
/// JSON-Dokumente dieser Groesse sind grosszuegig bemessen; ohne Limit
/// wuerden unautorisierte Requests Bodies beliebiger Groesse puffern.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Reservierte Query-Parameter der Sortierung.
const SORT_PARAM: &str = "sort";
const ORDER_PARAM: &str = "order";

/// Bereichs-Suffixe: `feld_min`/`feld_max` inklusive, `feld_gt`/`feld_lt`
/// exklusiv. Die Suffixe sind untereinander disjunkt; gefunden wird das
/// erste passende.
const RANGE_SUFFIXES: [(&str, RangeOp); 4] = [
    ("_min", RangeOp::Gte),
    ("_max", RangeOp::Lte),
    ("_gt", RangeOp::Gt),
    ("_lt", RangeOp::Lt),
];

/// Infallibler Extractor fuer die Client-IP (Rate-Limiting der App-Auth):
/// liest nur die `ConnectInfo`-Extension, die `main` via
/// `into_make_service_with_connect_info` beifuegt — fehlt sie (Tests ohne
/// Socket, eingebettete Routers), ist die Adresse schlicht `None` und der
/// Rate-Limiter teilt sich den Ersatzschluessel "unknown". Ein natives
/// `Option<ConnectInfo>` scheitert: axum 0.8 verlangt dafuer
/// `OptionalFromRequestParts`, das ConnectInfo nicht implementiert.
pub(crate) struct ClientIp(Option<std::net::IpAddr>);

impl<S> axum::extract::FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(
            parts
                .extensions
                .get::<ConnectInfo<std::net::SocketAddr>>()
                .map(|info| info.0.ip()),
        ))
    }
}

pub async fn handle(
    State(state): State<AppState>,
    client_ip: ClientIp,
    method: Method,
    Path((app_id, rest)): Path<(String, String)>,
    headers: HeaderMap,
    Query(raw_query): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    // --- H1': Identitaets-Header nur einmal pro Request ---------------------
    // `HeaderMap::get` liefert bei Duplikaten den ersten Wert — ein Gateway
    // mit Append-Semantik wuerde gefaelschte Client-Werte gewinnen. Mehrfach
    // gesendete Identitaets-Header sind mehrdeutig und werden pauschal mit
    // 400 abgelehnt, bevor irgendeine darauf gestuetze Entscheidung laeuft.
    if let Some(name) = duplicate_identity_header(&headers) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "duplicate_header",
            &format!("header `{name}` must be sent at most once"),
        );
    }

    let rest = rest.trim_end_matches('/');
    // N5: HEAD laeuft durch den GET-Pfad; der Body wird am Ende entfernt.
    let is_head = method.as_str() == "HEAD";

    let Some(app_routes) = state.app(&app_id) else {
        return not_found();
    };

    // --- App-Auth: /{app_id}/_auth/* Subrouter ------------------------------
    // Vor dem Config-Lookup: aktivierte App-Auths betreiben ihre Endpunkte
    // unterhalb des reservierten `/_auth`-Segments (Login/Refresh/...).
    // Die Pfadaufteilung dorthin ist tiefer (users/{id}) als die
    // Kollektions-/Item-Logik unten — deshalb hier gesondert.
    if let Some(app_auth) = state.app_auth(&app_id) {
        if let Some(sub_path) = auth_sub_path(rest) {
            let response = steadfast_auth::route(
                app_auth,
                sub_path,
                &method,
                &headers,
                &raw_query,
                body,
                client_ip.0,
            );
            return if is_head {
                strip_body(response).await
            } else {
                response
            };
        }
    }

    // --- Pfad auftrennen: /{app_id}/{collection}[/{item_id}] -------------
    let (config_path, item_id) = match rest.split_once('/') {
        Some((collection, id)) => {
            if collection.is_empty()
                || id.is_empty()
                || id.len() > MAX_ITEM_ID_LEN
                || id.contains('/')
            {
                return not_found();
            }
            (format!("/{collection}"), Some(id.to_string()))
        }
        None => (format!("/{rest}"), None),
    };

    // --- Config-Lookup im RAM (O(1)) --------------------------------------
    let Some(path_routes) = app_routes.path(&config_path) else {
        // N1: Fuer Apps mit Secret wird unbekannten Pfaden keine Struktur
        // verraten — ohne gueltigen Key gibt es 401 statt 404, erst
        // authentifizierte Clients unterscheiden 404/405 von 401.
        return hidden_behind_auth(app_routes, state.app_auth(&app_id), &headers, not_found);
    };
    let core_method = match method.as_str() {
        "GET" | "HEAD" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        // Andere Methoden sind im MVP nicht konfigurierbar (N1: auch hier
        // kein Struktur-Oracle fuer unauthentifizierte Requests).
        _ => {
            return hidden_behind_auth(app_routes, state.app_auth(&app_id), &headers, || {
                method_not_allowed(path_routes)
            });
        }
    };
    let Some(endpoint) = path_routes.method(core_method) else {
        return hidden_behind_auth(app_routes, state.app_auth(&app_id), &headers, || {
            method_not_allowed(path_routes)
        });
    };

    // --- Auth (sofortiger Abbruch bei Fehlschlag) -------------------------
    // `jwt_user`: frisch verifizierter Benutzer (Rolle aus dem Store) —
    // seine Claims gewinnen spaeter ueber den X-User-*-Headern, damit kein
    // Client per Header eine Rolle schmieden kann.
    let mut jwt_user: Option<(String, String)> = None;
    match endpoint.auth_mode {
        AuthMode::None => {}
        AuthMode::ApiKey => {
            let Some(secret) = app_routes.secret() else {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "config_error",
                    "endpoint requires auth but the app has no api_key_secret",
                );
            };
            let provided = headers.get(API_KEY_HEADER).and_then(|v| v.to_str().ok());
            if !verify_api_key(provided, secret) {
                return error_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "missing or invalid API key",
                );
            }
        }
        AuthMode::Jwt => {
            let Some(app_auth) = state.app_auth(&app_id) else {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "config_error",
                    "endpoint requires jwt auth but the app auth is not active",
                );
            };
            let Some(authenticated) = app_auth.verify_bearer_user(&headers) else {
                return error_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "missing or invalid access token",
                );
            };
            if let Some(roles) = &endpoint.roles {
                if !roles.contains(&authenticated.role) {
                    return error_response(
                        StatusCode::FORBIDDEN,
                        "forbidden",
                        "the authenticated user's role is not allowed on this endpoint",
                    );
                }
            }
            jwt_user = Some((authenticated.user_id, authenticated.role));
        }
    }
    // H1': Ist ein Gateway-Secret konfiguriert, muessen X-User-*-Header per
    // X-Internal-Auth ihre Herkunft vom Gateway belegen — sonst fallen sie
    // auf die Defaults (anonymous/user) zurueck. Ohne konfiguriertes
    // Gateway-Secret bleibt das bisherige Vertrauensmodell (dokumentiert).
    // Praezedenz: verifiziertes JWT > Gateway-geprovene Header > Defaults.
    let user = match jwt_user {
        Some((id, role)) => json!({ "id": id, "role": role }),
        None => {
            let identity_trusted = match state.gateway_secret() {
                Some(secret) => {
                    let provided = headers
                        .get(INTERNAL_AUTH_HEADER)
                        .and_then(|v| v.to_str().ok());
                    verify_gateway_secret(provided, secret)
                }
                None => true,
            };
            extract_user(&headers, identity_trusted)
        }
    };

    // --- CRUD-Dispatch ------------------------------------------------------
    let collection = endpoint.path.trim_start_matches('/');
    let response = match (core_method, item_id.as_deref()) {
        (HttpMethod::Get, Some(id)) => get_item(&state, &app_id, collection, id),
        (HttpMethod::Get, None) => get_list(&state, endpoint, &app_id, collection, &raw_query),
        (HttpMethod::Post, None) => post_create(&state, endpoint, &app_id, collection, body, user),
        (HttpMethod::Post, Some(_)) => not_found(),
        (HttpMethod::Put, Some(id)) => {
            put_replace(&state, endpoint, &app_id, collection, id, body, user)
        }
        (HttpMethod::Put, None) => bad_request("PUT requires an item id: /{app}/{collection}/{id}"),
        (HttpMethod::Patch, Some(id)) => {
            patch_merge(&state, endpoint, &app_id, collection, id, body, user)
        }
        // `bulk = true`: PATCH auf der Kollektion (ohne Item-ID) ist der
        // atomare Sammel-Patch. Der Single-Doc-Patch desselben Endpunkts
        // (mit Item-ID) bleibt unveraendert.
        (HttpMethod::Patch, None) if endpoint.bulk => {
            patch_bulk(&state, endpoint, &app_id, collection, body, user)
        }
        (HttpMethod::Patch, None) => {
            bad_request("PATCH requires an item id: /{app}/{collection}/{id}")
        }
        (HttpMethod::Delete, Some(id)) => delete_item(&state, &app_id, collection, id),
        (HttpMethod::Delete, None) => {
            bad_request("DELETE requires an item id: /{app}/{collection}/{id}")
        }
    };
    // N5: HEAD verhaelt sich wie GET (gleiche Header inkl. Content-Length),
    // liefert aber keinen Body.
    if is_head {
        return strip_body(response).await;
    }
    response
}

/// N1: Fuehrt `respond` nur aus, wenn der Request die Struktur der App
/// sehen darf. Apps mit Secret verlangen einen gueltigen API-Key; Apps mit
/// aktiver App-Auth einen gueltigen Bearer (beide vorhanden: jedes der
/// beiden Credentials genuegt). Die Pruefung laeuft ausschliesslich auf
/// Fehlerpfaden — der Hot Path (gueltige Route) zahlt nichts dafuer.
fn hidden_behind_auth(
    app_routes: &crate::state::AppRoutes,
    app_auth: Option<&std::sync::Arc<steadfast_auth::AppAuth>>,
    headers: &HeaderMap,
    respond: impl FnOnce() -> Response,
) -> Response {
    let key_ok = app_routes.secret().is_some_and(|secret| {
        let provided = headers.get(API_KEY_HEADER).and_then(|v| v.to_str().ok());
        verify_api_key(provided, secret)
    });
    let bearer_ok = app_auth.is_some_and(|auth| auth.verify_bearer(headers).is_some());
    let needs_auth = app_routes.secret().is_some() || app_auth.is_some();
    if needs_auth && !key_ok && !bearer_ok {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid credentials",
        );
    }
    respond()
}

/// Liefert den Pfad unterhalb des reservierten `/_auth`-Segments, falls
/// `rest` dorthin zeigt (`"_auth"` -> `""`, `"_auth/login"` -> `"login"`).
fn auth_sub_path(rest: &str) -> Option<&str> {
    if rest == steadfast_auth::AUTH_PATH_SEGMENT {
        Some("")
    } else {
        rest.strip_prefix(&format!("{}/", steadfast_auth::AUTH_PATH_SEGMENT))
    }
}

/// N5: Entfernt den Body einer vollstaendig gepufferten Response und setzt
/// Content-Length auf die urspruengliche Body-Groesse — HEAD liefert so
/// dieselben Header wie GET, nur ohne Bytes auf der Leitung.
async fn strip_body(response: Response) -> Response {
    let (mut parts, body) = response.into_parts();
    let len = body
        .collect()
        .await
        .map(|data| data.to_bytes().len())
        .unwrap_or(0);
    if let Ok(value) = len.to_string().parse() {
        parts
            .headers
            .insert(axum::http::header::CONTENT_LENGTH, value);
    }
    Response::from_parts(parts, Body::empty())
}

// --- GET ---------------------------------------------------------------------

fn get_list(
    state: &AppState,
    endpoint: &EndpointRuntime,
    app_id: &str,
    collection: &str,
    raw_query: &HashMap<String, String>,
) -> Response {
    let params = match parse_list_query(raw_query, endpoint) {
        Ok(params) => params,
        Err(err) => return engine_error_response(&err),
    };
    let result = state.store().list(app_id, collection, params);
    list_response(&result)
}

/// Baut die Listen-Antwort direkt in den Ausgabepuffer: die Seite (maximal
/// `MAX_PAGE_SIZE` Dokumente) wird per Referenz serialisiert. Die geteilten
/// `Arc`-Dokumente aus dem Store werden nie kopiert — der einzige Puffer ist
/// der Response-Body selbst.
fn list_response(result: &ListResult) -> Response {
    let mut buf = Vec::with_capacity(96 + result.items.len() * 192);
    let serialized = (|| -> Result<(), serde_json::Error> {
        buf.extend_from_slice(b"{\"items\":[");
        let mut first = true;
        for doc in &result.items {
            if !first {
                buf.push(b',');
            }
            first = false;
            serde_json::to_writer(&mut buf, doc.as_ref())?;
        }
        buf.extend_from_slice(b"],\"total\":");
        serde_json::to_writer(&mut buf, &result.total)?;
        buf.extend_from_slice(b",\"page\":");
        serde_json::to_writer(&mut buf, &result.page)?;
        buf.extend_from_slice(b",\"limit\":");
        serde_json::to_writer(&mut buf, &result.limit)?;
        buf.push(b'}');
        Ok(())
    })();

    match serialized {
        Ok(()) => Response::builder()
            .status(StatusCode::OK)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(buf))
            .expect("statische Response-Teile sind immer gueltig"),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialization_failed",
            "failed to serialize list response",
        ),
    }
}

fn get_item(state: &AppState, app_id: &str, collection: &str, id: &str) -> Response {
    match state.store().get(app_id, collection, id) {
        Some(doc) => json_response(StatusCode::OK, &doc),
        None => not_found(),
    }
}

/// Ein Query-Feldname ist genau dann gueltig, wenn er 1..=64 Bytes lang ist
/// und nur `[A-Za-z0-9_]` enthaelt — identisch zur Feldvalidierung der
/// Config (steadfast-core). Alles andere (Leerzeichen, Klammern, Anfuehrungs-
/// zeichen, Operator-Artefakte wie `album[$gt]`) ist kein Feldname und wird
/// mit 400 abgelehnt, statt stillschweigend nichts zu matchen.
fn is_valid_query_field(field: &str) -> bool {
    (1..=64).contains(&field.len())
        && field
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Query-String -> Paging + Gleichheits-/Bereichs-Filter + Sortierung,
/// inkl. DoS-Grenzen (Anzahl/Groesse der Parameter) und optionaler
/// Feld-Allowlist. Es gibt hier bewusst keine Abfragesprache:
///
/// - Reservierte Schluessel sind `page`, `limit`, `sort`, `order`.
/// - `feld=wert` ist ein Gleichheitsfilter; `feld_min`/`feld_max`
///   (inklusive) und `feld_gt`/`feld_lt` (exklusiv) sind Bereichsfilter.
///   Ein Suffix wird nur abgeschnitten, wenn der Basisname ein gueltiger
///   Feldname ist — das Feld `x_min` bleibt damit per `x_min=…` als
///   Gleichheitsfilter addressierbar.
/// - `sort=<feld>` sortiert, `order=asc|desc` (Default asc) dreht;
///   `order` ohne `sort` ist ein Fehler.
/// - Feldnamen muessen `is_valid_query_field` bestehen (400 sonst).
///   WERTE sind und bleiben reine Daten: Sie werden ausschliesslich
///   verglichen (`steadfast_storage::value_matches`/`value_in_range`), nie
///   als Ausdruck interpretiert — Injection per URL ist strukturell
///   ausgeschlossen.
fn parse_list_query(
    raw_query: &HashMap<String, String>,
    endpoint: &EndpointRuntime,
) -> Result<ListParams, EngineError> {
    let mut page: Option<usize> = None;
    let mut limit: Option<usize> = None;
    let mut filters: Vec<(String, String)> = Vec::new();
    let mut ranges: Vec<(String, RangeOp, String)> = Vec::new();
    let mut sort_field: Option<String> = None;
    let mut descending = false;
    let mut order_seen = false;

    for (key, value) in raw_query {
        match key.as_str() {
            "page" => {
                let parsed: usize = value.parse().map_err(|_| {
                    EngineError::BadRequest(format!("invalid `page` value `{value}`"))
                })?;
                if parsed < 1 {
                    return Err(EngineError::BadRequest("`page` must be >= 1".into()));
                }
                page = Some(parsed);
            }
            "limit" => {
                let parsed: usize = value.parse().map_err(|_| {
                    EngineError::BadRequest(format!("invalid `limit` value `{value}`"))
                })?;
                if !(1..=MAX_PAGE_SIZE).contains(&parsed) {
                    return Err(EngineError::BadRequest(format!(
                        "`limit` must be between 1 and {MAX_PAGE_SIZE}"
                    )));
                }
                limit = Some(parsed);
            }
            SORT_PARAM => {
                if !is_valid_query_field(value) {
                    return Err(EngineError::BadRequest(format!(
                        "invalid `sort` field `{value}`"
                    )));
                }
                sort_field = Some(value.clone());
            }
            ORDER_PARAM => {
                order_seen = true;
                match value.as_str() {
                    "asc" => descending = false,
                    "desc" => descending = true,
                    other => {
                        return Err(EngineError::BadRequest(format!(
                            "invalid `order` value `{other}` (must be `asc` or `desc`)"
                        )));
                    }
                }
            }
            _ => {
                let range = RANGE_SUFFIXES.iter().find_map(|(suffix, op)| {
                    key.strip_suffix(suffix)
                        .filter(|base| is_valid_query_field(base))
                        .map(|base| (*op, base.to_string()))
                });
                match range {
                    Some((op, base)) => ranges.push((base, op, value.clone())),
                    None => filters.push((key.clone(), value.clone())),
                }
            }
        }
    }

    if order_seen && sort_field.is_none() {
        return Err(EngineError::BadRequest(
            "`order` requires `sort=<field>`".into(),
        ));
    }

    if filters.len() + ranges.len() > MAX_FILTERS {
        return Err(EngineError::BadRequest(format!(
            "too many filter parameters (max {MAX_FILTERS})"
        )));
    }
    for (key, value) in &filters {
        if !is_valid_query_field(key) {
            return Err(EngineError::BadRequest(format!(
                "invalid filter field `{key}`"
            )));
        }
        if value.len() > MAX_FILTER_VALUE_LEN {
            return Err(EngineError::BadRequest(
                "filter value too long (max 256 bytes)".into(),
            ));
        }
    }
    for (_, _, value) in &ranges {
        if value.len() > MAX_FILTER_VALUE_LEN {
            return Err(EngineError::BadRequest(
                "range bound too long (max 256 bytes)".into(),
            ));
        }
    }

    if let Some(allowed) = &endpoint.filter_fields {
        for (key, _) in &filters {
            if !allowed.iter().any(|field| field == key) {
                return Err(EngineError::BadRequest(format!(
                    "filtering on `{key}` is not allowed for this endpoint"
                )));
            }
        }
        for (base, _, _) in &ranges {
            if !allowed.iter().any(|field| field == base) {
                return Err(EngineError::BadRequest(format!(
                    "filtering on `{base}` is not allowed for this endpoint"
                )));
            }
        }
        if let Some(field) = &sort_field {
            if !allowed.iter().any(|allowed_field| allowed_field == field) {
                return Err(EngineError::BadRequest(format!(
                    "sorting on `{field}` is not allowed for this endpoint"
                )));
            }
        }
    }

    Ok(ListParams {
        page: page.unwrap_or(1),
        limit: limit.unwrap_or(endpoint.paging_default),
        filters,
        ranges,
        sort: sort_field.map(|field| SortSpec { field, descending }),
    })
}

// --- POST --------------------------------------------------------------------

fn post_create(
    state: &AppState,
    endpoint: &EndpointRuntime,
    app_id: &str,
    collection: &str,
    body: Bytes,
    user: Value,
) -> Response {
    let doc = match parse_json_object(&body) {
        Ok(doc) => doc,
        Err(response) => return *response,
    };
    // Schema-Validierung vor Skript und Store (Fail-Fast): ungueltige
    // Payloads kosten nur den Parse, nicht die Sandbox und nicht den
    // Schreib-Mutex der Kollektion. Vollmodus: required wird geprueft.
    if let Some(schema) = &endpoint.schema {
        if let Err(details) = schema.validate(&doc, false) {
            return validation_failed_response(&details);
        }
    }
    let mut doc = match run_script(endpoint, doc, user) {
        Ok(doc) => doc,
        Err(response) => return *response,
    };

    // ID: vom Skript gesetzt (falls sinnvoll) oder Engine-seitige UUID v4.
    let script_id = doc
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty());
    let id = match script_id {
        Some(id) => id.to_string(),
        None => {
            doc["id"] = Value::String(Uuid::new_v4().to_string());
            doc["id"].as_str().expect("just set").to_string()
        }
    };
    if id.len() > MAX_CLIENT_ID_LEN {
        return bad_request("`id` too long (max 256 bytes)");
    }

    // M1: POST ist create-if-absent — eine bereits vorhandene ID liefert 409
    // (Bestand bleibt unangetastet), statt sie stillschweigend zu
    // ueberschreiben. Das vorhandene Dokument wird nicht zurueckgegeben; wer
    // es lesen will, ruft GET auf.
    let stored = match state.store().create(app_id, collection, &id, doc) {
        Ok(stored) => stored,
        Err(_) => {
            return error_response(
                StatusCode::CONFLICT,
                "already_exists",
                &format!("a document with id `{id}` already exists"),
            );
        }
    };
    let mut response = json_response(StatusCode::CREATED, &stored);
    if let Ok(location) = format!("/{app_id}/{collection}/{id}").parse() {
        response
            .headers_mut()
            .insert(axum::http::header::LOCATION, location);
    }
    response
}

// --- PUT / PATCH --------------------------------------------------------------

fn put_replace(
    state: &AppState,
    endpoint: &EndpointRuntime,
    app_id: &str,
    collection: &str,
    id: &str,
    body: Bytes,
    user: Value,
) -> Response {
    let doc = match parse_json_object(&body) {
        Ok(doc) => doc,
        Err(response) => return *response,
    };
    // PUT ersetzt vollstaendig — required wird wie bei POST geprueft, bevor
    // Skript laeuft oder der Store gesperrt wird.
    if let Some(schema) = &endpoint.schema {
        if let Err(details) = schema.validate(&doc, false) {
            return validation_failed_response(&details);
        }
    }
    let doc = match run_script(endpoint, doc, user) {
        Ok(doc) => doc,
        Err(response) => return *response,
    };
    match state.store().replace(app_id, collection, id, doc) {
        Some(stored) => json_response(StatusCode::OK, &stored),
        None => not_found(),
    }
}

fn patch_merge(
    state: &AppState,
    endpoint: &EndpointRuntime,
    app_id: &str,
    collection: &str,
    id: &str,
    body: Bytes,
    user: Value,
) -> Response {
    let patch = match parse_json_object(&body) {
        Ok(doc) => doc,
        Err(response) => return *response,
    };
    // Patch-Semantik (partial = true): fehlende required-Felder sind kein
    // Fehler — der Rest kommt aus dem Bestand. Typ- und Unknown-Field-
    // Regeln gelten weiterhin fuer jeden uebergebenen Wert. Die Pruefung
    // laeuft vor `patch_merge` und damit VOR dem Schreib-Mutex: Ein
    // typfremder Patch kostet keine Sperre und aendert nichts am Bestand.
    if let Some(schema) = &endpoint.schema {
        if let Err(details) = schema.validate(&patch, true) {
            return validation_failed_response(&details);
        }
    }
    // N4: Merge + Skript laufen IM Store unter dem per-Kollektion-Schreib-
    // Mutex — zwei gleichzeitige PATCHes auf dasselbe Dokument koennen sich
    // nicht mehr gegenseitig ueberschreiben (kein lost update zwischen get
    // und replace). Der Store loest evicierte Dokumente VOR dem Sperren auf.
    // Ein Skript-`throw` (422) bricht ab, ohne etwas zu committen; der neue
    // seq-Eintrag ordnet das Dokument wie bei PUT hinten ein.
    let outcome = state
        .store()
        .patch_merge(app_id, collection, id, |current| {
            let merged = merge_shallow(current, patch);
            run_script(endpoint, merged, user)
        });
    match outcome {
        PatchOutcome::Updated(stored) => json_response(StatusCode::OK, &stored),
        PatchOutcome::NotFound => not_found(),
        PatchOutcome::Rejected(response) => *response,
    }
}

fn merge_shallow(mut base: Value, patch: Value) -> Value {
    if let (Value::Object(base_map), Value::Object(patch_map)) = (&mut base, &patch) {
        for (key, value) in patch_map {
            base_map.insert(key.clone(), value.clone());
        }
    }
    base
}

// --- PATCH (Sammel-Patch, bulk = true) ----------------------------------------

/// Atomarer Sammel-Patch auf der Kollektion: `{"filter": {...}, "set": {...}}`
/// wendet `set` auf alle Dokumente an, die `filter` erfuellen — in EINEM
/// Request, unter EINEM Schreib-Mutex, all-or-nothing. Der Filter folgt
/// exakt der GET-Semantik (Gleichheit + `_min/_max/_gt/_lt`-Bereiche,
/// Allowlist, DoS-Grenzen); `set` wird wie beim Single-PATCH nur
/// typmaessig validiert (partial, keine required-Pflicht). Die Antwort
/// zaehlt `matched` (Treffer zum Commit-Zeitpunkt) und `patched`
/// (tatsaechlich neu geschrieben; No-ops werden uebersprungen).
fn patch_bulk(
    state: &AppState,
    endpoint: &EndpointRuntime,
    app_id: &str,
    collection: &str,
    body: Bytes,
    user: Value,
) -> Response {
    let body = match parse_json_object(&body) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    // Genau zwei Schluessel: `filter` und `set` — alles andere (Tippfehler
    // wie `filters`, verschachtelte Payloads) ist eine 400, bevor irgendwas
    // gelesen wird.
    let mut filter: Option<Value> = None;
    let mut set: Option<Value> = None;
    let shape_hint = "bulk patch body must be a JSON object with exactly \
                      {\"filter\": {...}, \"set\": {...}}";
    let Value::Object(body_map) = body else {
        return bad_request("request body must be a JSON object");
    };
    for (key, value) in body_map {
        match key.as_str() {
            "filter" => filter = Some(value),
            "set" => set = Some(value),
            _ => return bad_request(shape_hint),
        }
    }
    let (Some(Value::Object(filter)), Some(Value::Object(set))) = (filter, set) else {
        return bad_request(shape_hint);
    };
    if filter.is_empty() {
        // Verwechslungsschutz: "alle Dokumente" gibt es nur mit explizitem
        // Filter, niemals als implizites Default.
        return bad_request(
            "bulk patch requires a non-empty `filter` object — \
             an empty filter would match every document",
        );
    }
    if set.is_empty() {
        return bad_request("bulk patch requires a non-empty `set` object");
    }

    // Filter-Objekt -> Gleichheits-/Bereichsfilter mit denselben Regeln wie
    // der Query-String von GET (Feldnamen, Allowlist, Grenzen, Rohwerte).
    let (filters, ranges) = match parse_bulk_filter(&filter, endpoint.filter_fields.as_deref()) {
        Ok(parsed) => parsed,
        Err(message) => return bad_request(&message),
    };

    // `set` wird doc-unabhaengig geprueft (partial = true, wie beim Single-
    // PATCH: fehlende required-Felder kommen aus dem Bestand, Typ- und
    // Unknown-Field-Regeln gelten). Das laeuft VOR dem Schreib-Mutex und
    // VOR der ersten Transformation — ein typfremdes `set` veraendert nie
    // ein einziges Dokument.
    let set = Value::Object(set);
    if let Some(schema) = &endpoint.schema {
        if let Err(details) = schema.validate(&set, true) {
            return validation_failed_response(&details);
        }
    }

    // Merge + Skript laufen pro Treffer IM Store unter dem per-Kollektion-
    // Schreib-Mutex (dieselbe Invariante wie beim Single-PATCH). Ein
    // Skript-`throw` fuer IRGENDEIN Treffer bricht ab, bevor der erste
    // Commit passiert — der Bestand bleibt vollstaendig unveraendert.
    let outcome =
        state
            .store()
            .patch_merge_bulk(app_id, collection, &filters, &ranges, |current| {
                let merged = merge_shallow(current, set.clone());
                run_script(endpoint, merged, user.clone())
            });
    match outcome {
        BulkPatchOutcome::Completed(BulkPatchReport { matched, patched }) => json_response(
            StatusCode::OK,
            &json!({ "matched": matched, "patched": patched }),
        ),
        BulkPatchOutcome::Rejected(response) => *response,
    }
}

/// Filterergebnis des Sammel-Patch-Koerpers: Gleichheits- und Bereichsfilter
/// in genau der Form, die `MemoryStore::patch_merge_bulk` erwartet
/// (identisch zum Filteranteil von `ListParams`).
type ParsedBulkFilter = (Vec<(String, String)>, Vec<(String, RangeOp, String)>);

/// JSON-`filter`-Objekt -> `(filters, ranges)` mit GET-Semantik: Feldnamen
/// muessen `is_valid_query_field` bestehen, Suffixe `_min/_max/_gt/_lt`
/// machen den Key zum Bereichsfilter (Basisname bleibt Allowlist-Massstab),
/// Werte werden als reine Vergleichs-Rohwerte uebersetzt (String bleibt,
/// Bool -> "true"/"false", Zahl -> kanonischer Text; Objekte/Arrays/null
/// matchen nie und werden mit 400 abgelehnt, statt still leer zu laufen).
/// DoS-Grenzen (`MAX_FILTERS`, `MAX_FILTER_VALUE_LEN`) und die optionale
/// Allowlist entsprechen `parse_list_query`.
fn parse_bulk_filter(
    filter: &serde_json::Map<String, Value>,
    allowed: Option<&[String]>,
) -> Result<ParsedBulkFilter, String> {
    if filter.len() > MAX_FILTERS {
        return Err(format!("too many filter fields (max {MAX_FILTERS})"));
    }
    let mut filters: Vec<(String, String)> = Vec::new();
    let mut ranges: Vec<(String, RangeOp, String)> = Vec::new();
    for (key, value) in filter {
        let raw = match value {
            Value::String(s) => s.clone(),
            Value::Bool(true) => "true".to_string(),
            Value::Bool(false) => "false".to_string(),
            // Zahl: serde_json liefert den kanonischen Text (i64/u64/f64),
            // den auch `value_matches`/`value_in_range` zurueckparsen.
            Value::Number(number) => number.to_string(),
            Value::Object(_) | Value::Array(_) | Value::Null => {
                return Err(format!(
                    "filter value for `{key}` must be a string, number, or boolean"
                ));
            }
        };
        let range = RANGE_SUFFIXES.iter().find_map(|(suffix, op)| {
            key.strip_suffix(suffix)
                .filter(|base| is_valid_query_field(base))
                .map(|base| (*op, base.to_string()))
        });
        if let Some((op, base)) = range {
            if raw.len() > MAX_FILTER_VALUE_LEN {
                return Err("range bound too long (max 256 bytes)".to_string());
            }
            ranges.push((base, op, raw));
        } else {
            if !is_valid_query_field(key) {
                return Err(format!("invalid filter field `{key}`"));
            }
            if raw.len() > MAX_FILTER_VALUE_LEN {
                return Err("filter value too long (max 256 bytes)".to_string());
            }
            filters.push((key.clone(), raw));
        }
    }
    if let Some(allowed) = allowed {
        for (key, _) in &filters {
            if !allowed.iter().any(|field| field == key) {
                return Err(format!(
                    "filtering on `{key}` is not allowed for this endpoint"
                ));
            }
        }
        for (base, _, _) in &ranges {
            if !allowed.iter().any(|field| field == base) {
                return Err(format!(
                    "filtering on `{base}` is not allowed for this endpoint"
                ));
            }
        }
    }
    Ok((filters, ranges))
}

// --- DELETE -------------------------------------------------------------------

fn delete_item(state: &AppState, app_id: &str, collection: &str, id: &str) -> Response {
    match state.store().delete(app_id, collection, id) {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => not_found(),
    }
}

// --- Hilfsbausteine -------------------------------------------------------------

/// Fuehrt den vorkompilierten Hook aus (falls konfiguriert) und mappt
/// Sandbox-Fehler auf HTTP-Antworten. Payload/User bleiben strukturierte
/// Werte — Nutzereingaben werden nie als Code interpretiert. Der Err-Typ
/// ist geboxt, weil `Response` groesser als die Clippy-Schwelle ist und
/// Fehlerpfade billig bleiben sollen.
fn run_script(
    endpoint: &EndpointRuntime,
    payload: Value,
    user: Value,
) -> Result<Value, Box<Response>> {
    let Some(script) = &endpoint.script else {
        return Ok(payload);
    };
    match ScriptRuntime::exec(script, payload, user) {
        Ok(result) => Ok(result),
        Err(err) => Err(Box::new(engine_error_response(&err))),
    }
}

fn parse_json_object(body: &Bytes) -> Result<Value, Box<Response>> {
    if body.is_empty() {
        return Err(Box::new(bad_request(
            "request body must be a non-empty JSON object",
        )));
    }
    let value: Value = serde_json::from_slice(body)
        .map_err(|err| EngineError::InvalidJson(err.to_string()))
        .map_err(|err| Box::new(engine_error_response(&err)))?;
    if !value.is_object() {
        return Err(Box::new(bad_request("request body must be a JSON object")));
    }
    Ok(value)
}

fn json_response(status: StatusCode, value: &Value) -> Response {
    // Serialisierung per Referenz — kein Deep-Clone des Dokuments.
    (status, Json(value)).into_response()
}

pub fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(
        status,
        &json!({ "error": { "code": code, "message": message } }),
    )
}

/// 400 mit den sortierten Schema-Verletzungen. Die Details sind reine
/// Diagnosen der Client-Payload (Feldname + Regel) und duerfen an den
/// Client durchgereicht werden — es leakt keine Engine-Interna. Das
/// geschachtelte `error.code`-Format entspricht allen anderen
/// Engine-Fehlern; `details` traegt die pro-Feld-Meldungen.
fn validation_failed_response(details: &[String]) -> Response {
    json_response(
        StatusCode::BAD_REQUEST,
        &json!({
            "error": {
                "code": "validation_failed",
                "message": "payload failed schema validation",
                "details": details,
            }
        }),
    )
}

fn engine_error_response(err: &EngineError) -> Response {
    let status = StatusCode::from_u16(err.status()).expect("engine errors carry valid statuses");
    // N3: Der Client bekommt die generische, client-sichere Meldung; das
    // interne Detail (serde-Text, Sandbox-Interna) geht ins Log.
    if status >= StatusCode::INTERNAL_SERVER_ERROR {
        tracing::warn!(status = status.as_u16(), error = %err, "engine error");
    } else {
        tracing::debug!(status = status.as_u16(), error = %err, "engine error");
    }
    error_response(status, err.code(), &err.client_message())
}

fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not_found", "resource not found")
}

fn bad_request(message: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, "bad_request", message)
}

fn method_not_allowed(path_routes: &PathRoutes) -> Response {
    let allow = path_routes
        .allowed_methods()
        .map(|m| m.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let mut response = error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        &format!("allowed methods: {allow}"),
    );
    if let Ok(header_value) = allow.parse() {
        response
            .headers_mut()
            .insert(axum::http::header::ALLOW, header_value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::build_router;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use steadfast_core::EngineConfig;
    use steadfast_storage::MemoryStore;
    use tower::ServiceExt;

    const TODO_SECRET: &str = "super_geheimes_todo_salt_123";
    const GALLERY_SECRET: &str = "gallery_secret_456";
    const LEDGER_SECRET: &str = "ledger_secret_789";

    const TEST_TOML: &str = r#"
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

  [apps.todo_app.endpoints.tasks_replace]
  path = "/tasks"
  method = "PUT"
  auth_required = true

  [apps.todo_app.endpoints.tasks_patch]
  path = "/tasks"
  method = "PATCH"
  auth_required = true

  business_logic = """
  fn on_request(payload, user) {
      if payload.title.len() == 0 {
          throw "Titel darf nicht leer sein.";
      }
      payload.patched_by = user.id;
      return payload;
  }
  """

  [apps.todo_app.endpoints.tasks_delete]
  path = "/tasks"
  method = "DELETE"
  auth_required = true

[apps.gallery_app]
api_key_secret = "gallery_secret_456"

  [apps.gallery_app.endpoints.photos_get]
  path = "/photos"
  method = "GET"
  auth_required = true
  paging_default = 5
  filter_fields = ["album", "title", "taken"]

  [apps.gallery_app.endpoints.photos_create]
  path = "/photos"
  method = "POST"
  auth_required = true

  [apps.gallery_app.endpoints.photos_loop]
  path = "/boom"
  method = "POST"
  auth_required = false
  business_logic = """
  fn on_request(payload, user) {
      while payload.len() >= 0 {
          let x = 1;
      }
      return payload;
  }
  """

[apps.form_app]

  [apps.form_app.endpoints.contacts_get]
  path = "/contacts"
  method = "GET"

  [apps.form_app.endpoints.contacts_create]
  path = "/contacts"
  method = "POST"

    [apps.form_app.endpoints.contacts_create.schema]
    required = ["name", "grp"]
    allow_unknown_fields = true

      [apps.form_app.endpoints.contacts_create.schema.types]
      name = "string"
      grp = "string"
      summe = "number"
      is_priority = "boolean"

  [apps.form_app.endpoints.contacts_replace]
  path = "/contacts"
  method = "PUT"

    [apps.form_app.endpoints.contacts_replace.schema]
    required = ["name", "grp"]
    allow_unknown_fields = true

      [apps.form_app.endpoints.contacts_replace.schema.types]
      name = "string"
      grp = "string"

  [apps.form_app.endpoints.contacts_patch]
  path = "/contacts"
  method = "PATCH"

    [apps.form_app.endpoints.contacts_patch.schema]
    allow_unknown_fields = true

      [apps.form_app.endpoints.contacts_patch.schema.types]
      summe = "number"
      name = "string"

  [apps.form_app.endpoints.strict_create]
  path = "/strict"
  method = "POST"

    [apps.form_app.endpoints.strict_create.schema]
    required = ["name"]
    allow_unknown_fields = false

      [apps.form_app.endpoints.strict_create.schema.types]
      name = "string"

[apps.events_app]

  [apps.events_app.endpoints.events_create]
  path = "/events"
  method = "POST"

    [apps.events_app.endpoints.events_create.schema]
    required = ["title", "starts_at"]
    allow_unknown_fields = true

      [apps.events_app.endpoints.events_create.schema.types]
      title = "string"
      starts_at = "datetime"
      birthday = "date"

[apps.minimal_app]

  [apps.minimal_app.endpoints.only_get]
  path = "/only"
  method = "GET"

[apps.ledger_app]
api_key_secret = "ledger_secret_789"

  [apps.ledger_app.endpoints.ledger_get]
  path = "/ledger"
  method = "GET"
  auth_required = true
  filter_fields = ["person", "paid"]

  [apps.ledger_app.endpoints.ledger_create]
  path = "/ledger"
  method = "POST"
  auth_required = true

    [apps.ledger_app.endpoints.ledger_create.schema]
    required = ["person"]
    allow_unknown_fields = false

      [apps.ledger_app.endpoints.ledger_create.schema.types]
      person = "string"
      amount = "number"
      paid = "boolean"

  [apps.ledger_app.endpoints.ledger_patch]
  path = "/ledger"
  method = "PATCH"
  auth_required = true
  bulk = true
  filter_fields = ["person", "paid"]

    [apps.ledger_app.endpoints.ledger_patch.schema]
    allow_unknown_fields = false

      [apps.ledger_app.endpoints.ledger_patch.schema.types]
      person = "string"
      amount = "number"
      paid = "boolean"

[apps.script_app]

  [apps.script_app.endpoints.items_get]
  path = "/items"
  method = "GET"

  [apps.script_app.endpoints.items_create]
  path = "/items"
  method = "POST"

  [apps.script_app.endpoints.items_bulk_patch]
  path = "/items"
  method = "PATCH"
  bulk = true
  filter_fields = ["kind"]

  business_logic = """
  fn on_request(payload, user) {
      if payload.name == "boom" {
          throw "Sammel-Patch abgebrochen";
      }
      payload.touched = true;
      return payload;
  }
  """
"#;

    fn app() -> axum::Router {
        let config = EngineConfig::from_toml(TEST_TOML).expect("test config");
        build_router(
            AppState::build_with_store(config, Arc::new(MemoryStore::new()), None).expect("state"),
        )
    }

    /// Router mit aktivierter Gateway-Provenienzpruefung (H1').
    fn app_with_gateway_secret(secret: &str) -> axum::Router {
        let config = EngineConfig::from_toml(TEST_TOML).expect("test config");
        build_router(
            AppState::build_with_store(
                config,
                Arc::new(MemoryStore::new()),
                Some(secret.to_string()),
            )
            .expect("state"),
        )
    }

    fn req(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    fn req_auth(method: &str, uri: &str, headers: &[(&str, String)]) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, value.as_str());
        }
        builder.body(Body::empty()).unwrap()
    }

    fn req_json(
        method: &str,
        uri: &str,
        headers: &[(&str, String)],
        body: &Value,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, value.as_str());
        }
        builder
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    async fn send(router: axum::Router, request: Request<Body>) -> Response {
        router.oneshot(request).await.unwrap()
    }

    async fn body_json(response: Response) -> Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).expect("response body must be JSON")
    }

    fn auth_headers(role: &str) -> Vec<(&'static str, String)> {
        vec![
            ("x-api-key", TODO_SECRET.to_string()),
            ("x-user-id", "user_1".to_string()),
            ("x-user-role", role.to_string()),
        ]
    }

    #[tokio::test]
    async fn health_endpoint_works() {
        let response = send(app(), req("GET", "/health")).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_app_and_path_are_hidden_behind_auth() {
        // Unbekannte App: 404 (die Engine kann ohne App-Config nichts pruefen).
        let response = send(app(), req("GET", "/no_such_app/tasks")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // N1: Bekannte App MIT Secret, unbekannter Pfad — ohne gueltigen Key
        // gibt es 401 statt 404, sonst waere die Pfadstruktur ein
        // Enumeration-Oracle fuer Unauthentifizierte.
        let response = send(app(), req("GET", "/todo_app/no_such_path")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Mit gueltigem Key sieht der authentifizierte Client die echte 404.
        let headers = [("x-api-key", TODO_SECRET.to_string())];
        let response = send(app(), req_auth("GET", "/todo_app/no_such_path", &headers)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Apps OHNE Secret (alles offen) behalten das alte Verhalten.
        let response = send(app(), req("GET", "/minimal_app/no_such_path")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unconfigured_method_is_hidden_behind_auth() {
        // N1: unkonfigurierte Methode auf bekanntem Pfad — 401 ohne Key.
        let response = send(app(), req("POST", "/minimal_app/only")).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

        let response = send(app(), req("OPTIONS", "/todo_app/tasks")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let headers = [("x-api-key", TODO_SECRET.to_string())];
        let response = send(app(), req_auth("OPTIONS", "/todo_app/tasks", &headers)).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn duplicate_identity_headers_are_rejected() {
        // H1': Ein Gateway mit Append-Semantik wuerde duplizierte Header
        // durchreichen — der erste (gefaelschte) Wert wuerde gewinnen.
        // Mehrfach gesendete Identitaets-Header sind pauschal 400.
        let builder = |name: &'static str| {
            let body = json!({"title": "x"});
            Request::builder()
                .method("POST")
                .uri("/todo_app/tasks")
                .header("content-type", "application/json")
                .header(name, TODO_SECRET)
                .header(name, TODO_SECRET) // Duplikat
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        };
        for name in ["x-api-key", "x-user-id", "x-user-role", "x-internal-auth"] {
            let response = send(app(), builder(name)).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
            let json = body_json(response).await;
            assert_eq!(json["error"]["code"], "duplicate_header", "{name}");
            assert!(
                json["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("at most once"),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn gateway_secret_gates_identity_headers() {
        // H1': Mit konfiguriertem Gateway-Secret zaehlen X-User-*-Header nur
        // mit gueltigem X-Internal-Auth. Das POST-Skript spiegelt user.id in
        // created_by — damit ist sichtbar, welche Identitaet wirklich galt.
        const GW_SECRET: &str = "gateway_shared_secret_1";
        let router = app_with_gateway_secret(GW_SECRET);
        let body = json!({"title": "gw-test"});

        // Ohne X-Internal-Auth: gespoofte Identitaet faellt auf anonymous.
        let response = send(
            router.clone(),
            req_json("POST", "/todo_app/tasks", &auth_headers("free"), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let doc = body_json(response).await;
        assert_eq!(
            doc["created_by"], "anonymous",
            "unproven header must be ignored"
        );

        // Falsches X-Internal-Auth: dito.
        let mut headers = auth_headers("free");
        headers.push(("x-internal-auth", "falsches-gateway-secret".to_string()));
        let response = send(
            router.clone(),
            req_json("POST", "/todo_app/tasks", &headers, &body),
        )
        .await;
        let doc = body_json(response).await;
        assert_eq!(doc["created_by"], "anonymous");

        // Gueltiges X-Internal-Auth: Identitaet gilt.
        let mut headers = auth_headers("premium");
        headers.push(("x-internal-auth", GW_SECRET.to_string()));
        let response = send(
            router.clone(),
            req_json(
                "POST",
                "/todo_app/tasks",
                &headers,
                &json!({"title": "prio", "is_priority": true}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let doc = body_json(response).await;
        assert_eq!(doc["created_by"], "user_1");

        // Rollen-Spoofing ohne Provenienz: premium wird nicht honoring —
        // das Prioritaets-Skript lehnt die free-Default-Rolle mit 422 ab.
        let response = send(
            router.clone(),
            req_json(
                "POST",
                "/todo_app/tasks",
                &auth_headers("premium"),
                &json!({"title": "spoof", "is_priority": true}),
            ),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "spoofed premium role must not pass without provenance"
        );
    }

    #[tokio::test]
    async fn method_not_allowed_carries_allow_header() {
        let response = send(app(), req("POST", "/minimal_app/only")).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(axum::http::header::ALLOW).unwrap(),
            "GET"
        );
    }

    #[tokio::test]
    async fn create_requires_api_key() {
        let body = json!({"title": "ohne key"});
        let response = send(app(), req_json("POST", "/todo_app/tasks", &[], &body)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let wrong = vec![("x-api-key", "wrong_key".to_string())];
        let response = send(app(), req_json("POST", "/todo_app/tasks", &wrong, &body)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_rejects_non_premium_priority_with_422() {
        let body = json!({"title": "Prio", "is_priority": true});
        let response = send(
            app(),
            req_json("POST", "/todo_app/tasks", &auth_headers("free"), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "script_rejected");
        assert!(
            json["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Premium")
        );
    }

    #[tokio::test]
    async fn create_rejects_empty_title_with_422() {
        let body = json!({"title": ""});
        let response = send(
            app(),
            req_json("POST", "/todo_app/tasks", &auth_headers("premium"), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn create_happy_path_sets_script_fields_and_location() {
        let body = json!({"title": "Erste Aufgabe", "is_priority": true});
        let response = send(
            app(),
            req_json("POST", "/todo_app/tasks", &auth_headers("premium"), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(location.starts_with("/todo_app/tasks/"), "{location}");

        let json = body_json(response).await;
        assert_eq!(json["created_by"], "user_1");
        assert_eq!(json["status"], "offen");
        assert_eq!(json["title"], "Erste Aufgabe");
        assert!(!json["id"].as_str().unwrap().is_empty());
        assert_eq!(
            location,
            format!("/todo_app/tasks/{}", json["id"].as_str().unwrap())
        );
    }

    #[tokio::test]
    async fn create_with_existing_id_conflicts_409_and_keeps_original() {
        let router = app();
        let body = json!({"title": "original", "id": "feste-id"});
        let response = send(
            router.clone(),
            req_json("POST", "/todo_app/tasks", &auth_headers("free"), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = body_json(response).await;
        assert_eq!(created["id"], "feste-id");

        // Zweiter POST mit derselben (vom Client gesetzten) ID -> 409.
        let body = json!({"title": "UEBERSCHREIBEN", "id": "feste-id"});
        let response = send(
            router.clone(),
            req_json("POST", "/todo_app/tasks", &auth_headers("premium"), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let err = body_json(response).await;
        assert_eq!(err["error"]["code"], "already_exists");

        // Der Bestand ist unangetastet: weder inhaltlich noch in der Menge.
        let response = send(router.clone(), req("GET", "/todo_app/tasks/feste-id")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let doc = body_json(response).await;
        assert_eq!(
            doc["title"], "original",
            "409 darf den Bestand nicht anfassen"
        );

        let response = send(router, req("GET", "/todo_app/tasks")).await;
        let list = body_json(response).await;
        assert_eq!(list["total"], 1, "409 darf weder duplizieren noch umordnen");
    }

    #[tokio::test]
    async fn create_with_invalid_json_is_400() {
        let request = Request::builder()
            .method("POST")
            .uri("/todo_app/tasks")
            .header("x-api-key", TODO_SECRET)
            .header("content-type", "application/json")
            .body(Body::from("{not json"))
            .unwrap();
        let response = send(app(), request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // N3: Der serde-Fehlertext ist ein Internum — der Client bekommt die
        // generische Meldung, das Detail geht ins Log.
        let json = body_json(response).await;
        assert_eq!(json["error"]["message"], "request body must be valid JSON");
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_413() {
        // N2: DefaultBodyLimit deckelt den Body-Puffer unabhaengig von der
        // Auth — groessere Bodies sterben als 413, bevor Logik laeuft.
        let mut doc = json!({"title": "x", "filler": "a".repeat(512)});
        let big = serde_json::to_vec(&doc).unwrap();
        doc["filler"] = json!("a".repeat(MAX_BODY_BYTES - big.len() + 1024));
        let body = serde_json::to_vec(&doc).unwrap();
        assert!(body.len() > MAX_BODY_BYTES);

        let request = Request::builder()
            .method("POST")
            .uri("/todo_app/tasks")
            .header("x-api-key", TODO_SECRET)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = send(app(), request).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn create_with_non_object_json_is_400() {
        let request = Request::builder()
            .method("POST")
            .uri("/todo_app/tasks")
            .header("x-api-key", TODO_SECRET)
            .header("content-type", "application/json")
            .body(Body::from("[1,2,3]"))
            .unwrap();
        let response = send(app(), request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_returns_documents_with_paging_and_filter() {
        let router = app();
        let roles = [
            ("premium", true),
            ("free", false),
            ("free", false),
            ("free", false),
        ];
        let mut ids = Vec::new();
        for (i, (role, priority)) in roles.iter().enumerate() {
            let body = json!({"title": format!("task {i}"), "is_priority": priority});
            let response = send(
                router.clone(),
                req_json("POST", "/todo_app/tasks", &auth_headers(role), &body),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
            ids.push(
                body_json(response).await["id"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
        }

        // Paging: limit=2, page=1/2.
        let response = send(router.clone(), req("GET", "/todo_app/tasks?limit=2&page=1")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_json(response).await;
        assert_eq!(list["total"], 4);
        assert_eq!(list["page"], 1);
        assert_eq!(list["limit"], 2);
        assert_eq!(list["items"].as_array().unwrap().len(), 2);

        let response = send(router.clone(), req("GET", "/todo_app/tasks?limit=2&page=2")).await;
        let list = body_json(response).await;
        assert_eq!(list["items"].as_array().unwrap().len(), 2);

        // Filter auf Skript-Feld status (alle durch das Skript auf "offen").
        let response = send(router.clone(), req("GET", "/todo_app/tasks?status=offen")).await;
        let list = body_json(response).await;
        assert_eq!(list["total"], 4);

        let response = send(
            router.clone(),
            req("GET", "/todo_app/tasks?status=offen%27%20OR%201%3D1%20--"),
        )
        .await;
        let list = body_json(response).await;
        assert_eq!(list["total"], 0, "injection-like filter matches nothing");

        // Filter per id.
        let response = send(
            router.clone(),
            req("GET", &format!("/todo_app/tasks?id={}", ids[0])),
        )
        .await;
        let list = body_json(response).await;
        assert_eq!(list["total"], 1);

        // Ungueltige Paging-Parameter -> 400.
        let response = send(router.clone(), req("GET", "/todo_app/tasks?page=abc")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = send(router.clone(), req("GET", "/todo_app/tasks?limit=500")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_item_404_and_found() {
        let router = app();
        let body = json!({"title": "x"});
        let response = send(
            router.clone(),
            req_json("POST", "/todo_app/tasks", &auth_headers("free"), &body),
        )
        .await;
        let id = body_json(response).await["id"]
            .as_str()
            .unwrap()
            .to_string();

        let response = send(router.clone(), req("GET", &format!("/todo_app/tasks/{id}"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let doc = body_json(response).await;
        assert_eq!(doc["id"], id.as_str());

        let response = send(router, req("GET", "/todo_app/tasks/does-not-exist")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_replaces_completely_and_forces_id() {
        let router = app();
        let body = json!({"title": "alt", "keep": true});
        let response = send(
            router.clone(),
            req_json("POST", "/todo_app/tasks", &auth_headers("free"), &body),
        )
        .await;
        let id = body_json(response).await["id"]
            .as_str()
            .unwrap()
            .to_string();

        let replacement = json!({"title": "neu", "id": "HACKED"});
        let response = send(
            router.clone(),
            req_json(
                "PUT",
                &format!("/todo_app/tasks/{id}"),
                &auth_headers("free"),
                &replacement,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let doc = body_json(response).await;
        assert_eq!(doc["id"], id.as_str(), "id must be forced to the path id");
        assert_eq!(doc["title"], "neu");
        assert!(doc.get("keep").is_none(), "PUT must not merge");

        let response = send(
            router.clone(),
            req_json(
                "PUT",
                "/todo_app/tasks/missing-id",
                &auth_headers("free"),
                &replacement,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // PUT ohne API-Key -> 401.
        let response = send(
            router,
            req_json("PUT", &format!("/todo_app/tasks/{id}"), &[], &replacement),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn patch_merges_and_runs_script_on_result() {
        let router = app();
        let body = json!({"title": "original", "note": "bleibt"});
        let response = send(
            router.clone(),
            req_json("POST", "/todo_app/tasks", &auth_headers("free"), &body),
        )
        .await;
        let id = body_json(response).await["id"]
            .as_str()
            .unwrap()
            .to_string();

        let patch = json!({"status": "erledigt"});
        let response = send(
            router.clone(),
            req_json(
                "PATCH",
                &format!("/todo_app/tasks/{id}"),
                &auth_headers("premium"),
                &patch,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let doc = body_json(response).await;
        assert_eq!(
            doc["status"], "erledigt",
            "merge must preserve patched field"
        );
        assert_eq!(doc["title"], "original", "PATCH must merge, not replace");
        assert_eq!(doc["note"], "bleibt");
        assert_eq!(
            doc["patched_by"], "user_1",
            "script must run on the merged result"
        );

        let response = send(
            router.clone(),
            req_json(
                "PATCH",
                "/todo_app/tasks/missing-id",
                &auth_headers("premium"),
                &patch,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Das PATCH-Skript validiert das Merge-Ergebnis: leerer Titel -> 422.
        let response = send(
            router,
            req_json(
                "PATCH",
                &format!("/todo_app/tasks/{id}"),
                &auth_headers("premium"),
                &json!({"title": ""}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn delete_returns_204_then_404() {
        let router = app();
        let body = json!({"title": "weg damit"});
        let response = send(
            router.clone(),
            req_json("POST", "/todo_app/tasks", &auth_headers("free"), &body),
        )
        .await;
        let id = body_json(response).await["id"]
            .as_str()
            .unwrap()
            .to_string();

        let response = send(
            router.clone(),
            req_auth(
                "DELETE",
                &format!("/todo_app/tasks/{id}"),
                &auth_headers("free"),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = send(
            router.clone(),
            req_auth(
                "DELETE",
                &format!("/todo_app/tasks/{id}"),
                &auth_headers("free"),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = send(router, req("GET", &format!("/todo_app/tasks/{id}"))).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_with_auth_required_needs_api_key() {
        let response = send(app(), req("GET", "/gallery_app/photos")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn filter_field_allowlist_is_enforced() {
        let router = app();
        let headers = [("x-api-key", GALLERY_SECRET.to_string())];

        // Erlaubtes Feld (Allowlist) funktioniert.
        let response = send(
            router.clone(),
            req_auth("GET", "/gallery_app/photos?album=1", &headers),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // Nicht erlaubtes Feld -> 400.
        let response = send(
            router.clone(),
            req_auth("GET", "/gallery_app/photos?status=x", &headers),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // paging_default = 5 gilt, limit bleibt auf 100 gecappt.
        let response = send(
            router,
            req_auth("GET", "/gallery_app/photos?limit=50", &headers),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_json(response).await;
        assert_eq!(list["limit"], 50);
    }

    /// Legt fuenf Fotos mit album (1..5), title und taken (ISO-Datum) an.
    async fn seed_gallery_photos(router: &axum::Router) {
        let photos = [
            ("p1", 1, "apfel", "2024-01-05"),
            ("p2", 2, "birne", "2024-03-10"),
            ("p3", 3, "cashew", "2024-05-15"),
            ("p4", 4, "dattel", "2024-07-20"),
            ("p5", 5, "eschalotte", "2024-02-01"),
        ];
        for (id, album, title, taken) in photos {
            let body = json!({"id": id, "album": album, "title": title, "taken": taken});
            let response = send(
                router.clone(),
                req_json(
                    "POST",
                    "/gallery_app/photos",
                    &[("x-api-key", GALLERY_SECRET.to_string())],
                    &body,
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
        }
    }

    #[tokio::test]
    async fn range_and_sort_queries_work_over_http() {
        let router = app();
        seed_gallery_photos(&router).await;
        let headers = [("x-api-key", GALLERY_SECRET.to_string())];

        // Von-bis inklusive (album_min/album_max).
        let response = send(
            router.clone(),
            req_auth(
                "GET",
                "/gallery_app/photos?album_min=2&album_max=3",
                &headers,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_json(response).await;
        assert_eq!(list["total"], 2);
        let albums: Vec<i64> = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["album"].as_i64().unwrap())
            .collect();
        assert_eq!(albums, vec![2, 3]);

        // Exklusive Grenze (album_gt).
        let response = send(
            router.clone(),
            req_auth("GET", "/gallery_app/photos?album_gt=4", &headers),
        )
        .await;
        let list = body_json(response).await;
        assert_eq!(list["total"], 1);
        assert_eq!(list["items"][0]["id"], "p5");

        // String-Bereich ueber ISO-Daten (byte-lexikographisch korrekt).
        let response = send(
            router.clone(),
            req_auth(
                "GET",
                "/gallery_app/photos?taken_min=2024-03-01&taken_max=2024-06-30",
                &headers,
            ),
        )
        .await;
        let list = body_json(response).await;
        assert_eq!(list["total"], 2, "nur p2 und p3 liegen im Zeitfenster");

        // Sortierung absteigend ueber die volle Liste.
        let response = send(
            router.clone(),
            req_auth("GET", "/gallery_app/photos?sort=album&order=desc", &headers),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_json(response).await;
        assert_eq!(list["total"], 5);
        let albums: Vec<i64> = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["album"].as_i64().unwrap())
            .collect();
        assert_eq!(albums, vec![5, 4, 3, 2, 1]);

        // Sortierung aufsteigend ist Default (order weglassen).
        let response = send(
            router.clone(),
            req_auth("GET", "/gallery_app/photos?sort=taken", &headers),
        )
        .await;
        let list = body_json(response).await;
        let ids: Vec<&str> = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["p1", "p5", "p2", "p3", "p4"]);

        // Kombiniert: Bereich + Sortierung + sortiertes Paging — Seite 2
        // der absteigend sortierten Restmenge (Alben 2..5 → [p5,p4,p3,p2]).
        let response = send(
            router,
            req_auth(
                "GET",
                "/gallery_app/photos?album_min=2&sort=album&order=desc&page=2&limit=2",
                &headers,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_json(response).await;
        assert_eq!(list["total"], 4);
        let ids: Vec<&str> = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["p3", "p2"]);
    }

    #[tokio::test]
    async fn range_and_sort_parameters_are_strictly_validated() {
        let router = app();
        seed_gallery_photos(&router).await;
        let headers = [("x-api-key", GALLERY_SECRET.to_string())];

        let expect_400 = |uri: &'static str| {
            let router = router.clone();
            let headers = headers.clone();
            async move {
                let response = send(router, req_auth("GET", uri, &headers)).await;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
            }
        };

        // `order` ohne `sort` ist sinnlos und wird abgelehnt.
        expect_400("/gallery_app/photos?order=asc").await;
        // Unbekannter order-Wert.
        expect_400("/gallery_app/photos?sort=album&order=sideways").await;
        // Sortierfeld mit ungueltigem Namen (Leerzeichen).
        expect_400("/gallery_app/photos?sort=al%20bum").await;
        // Sortierfeld nicht in der Allowlist.
        expect_400("/gallery_app/photos?sort=nope").await;
        // Bereich ueber nicht erlaubtes Feld (Basisname zaehlt).
        expect_400("/gallery_app/photos?nope_min=1").await;
        // Ungueltige Feldnamen: Klammern/Operator-Artefakte werden an der
        // Tuer abgewiesen (400), statt stillschweigend nichts zu matchen —
        // klassische NoSQL-Operator-Injection-Versuche laufen leer.
        expect_400("/gallery_app/photos?album%5B%5D=x").await;
        expect_400("/gallery_app/photos?album%5B%24gt%5D=1").await;
        expect_400("/gallery_app/photos?al%27bum=1").await;
        expect_400("/gallery_app/photos?al%28bum_min=1").await;

        // Injection-artige WERTE bleiben demgegenueber einfache Daten: Sie
        // verletzen keine Feldnamen-Regel und werden nur verglichen —
        // numerischer Bereich + nicht numerierbare Grenze = leer.
        let response = send(
            router.clone(),
            req_auth(
                "GET",
                "/gallery_app/photos?album_min=1%29%20OR%20%281%3D1",
                &headers,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_json(response).await;
        assert_eq!(list["total"], 0, "Werte sind Daten und matchen hier nichts");

        // Nicht-endliche numerische Grenze ("NaN") matcht ebenfalls nichts.
        let response = send(
            router,
            req_auth("GET", "/gallery_app/photos?album_min=NaN", &headers),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_json(response).await;
        assert_eq!(list["total"], 0);
    }

    #[tokio::test]
    async fn infinite_loop_script_hits_sandbox_limit() {
        let response = send(
            app(),
            req_json("POST", "/gallery_app/boom", &[], &json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "script_limit_exceeded");
    }

    #[tokio::test]
    async fn schema_valid_document_with_unknown_fields_passes() {
        // allow_unknown_fields = true: alle required-Felder gesetzt, Typen
        // korrekt, zusaetzliche undeklarierte Felder sind erlaubt.
        let body = json!({
            "name": "Ada Lovelace",
            "grp": "kunden",
            "summe": 42.5,
            "is_priority": false,
            "notiz": "freies Feld",
            "tags": ["a", "b"]
        });
        let response = send(app(), req_json("POST", "/form_app/contacts", &[], &body)).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let doc = body_json(response).await;
        assert_eq!(doc["name"], "Ada Lovelace");
        assert_eq!(doc["summe"], 42.5);

        // Optionale getypte Felder duerfen fehlen.
        let response = send(
            app(),
            req_json(
                "POST",
                "/form_app/contacts",
                &[],
                &json!({"name": "nur pflicht", "grp": "g"}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn schema_rejects_missing_required_and_wrong_types_with_400() {
        // Fehlendes required-Feld UND typfremde Felder: 400 mit allen
        // Details (gesammelt, nicht nur der erste Fund).
        let body = json!({
            "name": 7,
            "summe": "keine zahl",
            "is_priority": "ja"
        });
        let response = send(app(), req_json("POST", "/form_app/contacts", &[], &body)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let err = body_json(response).await;
        assert_eq!(err["error"]["code"], "validation_failed");
        let details = err["error"]["details"].as_array().expect("details");
        let details: Vec<&str> = details
            .iter()
            .map(|d| d.as_str().expect("string detail"))
            .collect();
        assert!(details.contains(&"Field 'grp' is required"), "{details:?}");
        assert!(
            details.contains(&"Field 'name' must be a string"),
            "{details:?}"
        );
        assert!(
            details.contains(&"Field 'summe' must be a number"),
            "{details:?}"
        );
        assert!(
            details.contains(&"Field 'is_priority' must be a boolean"),
            "{details:?}"
        );

        // Abgewiesene Dokumente erreichen die Kollektion nicht.
        let response = send(app(), req("GET", "/form_app/contacts")).await;
        let list = body_json(response).await;
        assert_eq!(list["total"], 0);
    }

    #[tokio::test]
    async fn schema_patch_partial_passes_without_required_fields() {
        let router = app();
        let body = json!({"name": "original", "grp": "g1", "notiz": "bleibt"});
        let response = send(
            router.clone(),
            req_json("POST", "/form_app/contacts", &[], &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let id = body_json(response).await["id"]
            .as_str()
            .unwrap()
            .to_string();

        // Partieller Patch ohne die required-Felder name/grp: valide —
        // nur der uebergebene Ausschnitt wird typgeprueft.
        let patch = json!({"summe": 5});
        let response = send(
            router.clone(),
            req_json("PATCH", &format!("/form_app/contacts/{id}"), &[], &patch),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let doc = body_json(response).await;
        assert_eq!(doc["summe"], 5);
        assert_eq!(doc["name"], "original", "PATCH must merge, not replace");

        // Typ-Regel greift im Patch weiterhin: typfremder Wert -> 400 und
        // der Bestand bleibt unangetastet.
        let response = send(
            router.clone(),
            req_json(
                "PATCH",
                &format!("/form_app/contacts/{id}"),
                &[],
                &json!({"summe": "text"}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let err = body_json(response).await;
        assert_eq!(err["error"]["code"], "validation_failed");

        let response = send(
            router.clone(),
            req("GET", &format!("/form_app/contacts/{id}")),
        )
        .await;
        let doc = body_json(response).await;
        assert_eq!(
            doc["summe"], 5,
            "abgewiesener Patch darf den Bestand nicht anfassen"
        );
    }

    #[tokio::test]
    async fn strict_endpoint_rejects_unknown_fields() {
        let body = json!({"name": "ok", "surprise": true});
        let response = send(app(), req_json("POST", "/form_app/strict", &[], &body)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let err = body_json(response).await;
        assert_eq!(err["error"]["code"], "validation_failed");
        let details = err["error"]["details"].as_array().unwrap();
        assert!(
            details[0]
                .as_str()
                .unwrap()
                .contains("Field 'surprise' is not allowed"),
            "{details:?}"
        );

        // Ohne zusaetzliche Felder geht derselbe Payload durch.
        let response = send(
            app(),
            req_json("POST", "/form_app/strict", &[], &json!({"name": "ok"})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn schema_date_and_datetime_formats_are_enforced() {
        // RFC 3339 mit Offset plus ISO-Datum: 201.
        let body = json!({
            "title": "Release",
            "starts_at": "2026-11-05T09:00:00+01:00",
            "birthday": "1990-07-14"
        });
        let response = send(app(), req_json("POST", "/events_app/events", &[], &body)).await;
        assert_eq!(response.status(), StatusCode::CREATED);

        // Deutsche Schreibweise bzw. Nicht-Schaltjahr: 400 mit beiden
        // Verstoessen, deterministisch sortiert in den Details.
        let body = json!({
            "title": "Release",
            "starts_at": "23.10.2026 14:30",
            "birthday": "2023-02-29"
        });
        let response = send(app(), req_json("POST", "/events_app/events", &[], &body)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let err = body_json(response).await;
        assert_eq!(err["error"]["code"], "validation_failed");
        let details = err["error"]["details"].as_array().unwrap();
        assert_eq!(
            details
                .iter()
                .map(|d| d.as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "Field 'birthday' must be a date",
                "Field 'starts_at' must be a datetime",
            ],
            "{details:?}"
        );
    }

    #[tokio::test]
    async fn schema_put_enforces_required_like_post() {
        let router = app();
        let body = json!({"name": "alt", "grp": "g1"});
        let response = send(
            router.clone(),
            req_json("POST", "/form_app/contacts", &[], &body),
        )
        .await;
        let id = body_json(response).await["id"]
            .as_str()
            .unwrap()
            .to_string();

        // PUT ohne required-Feld -> 400 (Replace-Semantik, kein Partial).
        let response = send(
            router.clone(),
            req_json(
                "PUT",
                &format!("/form_app/contacts/{id}"),
                &[],
                &json!({"name": "unvollstaendig"}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let err = body_json(response).await;
        let details = err["error"]["details"].as_array().unwrap();
        assert!(
            details
                .iter()
                .any(|d| d.as_str().unwrap() == "Field 'grp' is required"),
            "{details:?}"
        );

        // Vollstaendiges PUT geht durch.
        let response = send(
            router,
            req_json(
                "PUT",
                &format!("/form_app/contacts/{id}"),
                &[],
                &json!({"name": "neu", "grp": "g2"}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn head_returns_headers_without_body() {
        // N5: HEAD verhaelt sich wie GET — gleicher Status, Content-Length
        // der GET-Antwort, aber kein Body.
        let router = app();
        let body = json!({"title": "fuer-head"});
        send(
            router.clone(),
            req_json("POST", "/todo_app/tasks", &auth_headers("free"), &body),
        )
        .await;

        let response = send(router.clone(), req("HEAD", "/todo_app/tasks")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let content_length: usize = response
            .headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .expect("HEAD must carry the GET content-length");
        assert!(content_length > 0);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.is_empty(), "HEAD must not send a body");
    }

    // --- Sammel-Patch (bulk = true) -------------------------------------------------

    fn ledger_headers() -> Vec<(&'static str, String)> {
        vec![("x-api-key", LEDGER_SECRET.to_string())]
    }

    async fn seed_ledger(router: &axum::Router, docs: &[Value]) {
        for doc in docs {
            let response = send(
                router.clone(),
                req_json("POST", "/ledger_app/ledger", &ledger_headers(), doc),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
        }
    }

    async fn ledger_ids(router: &axum::Router, query: &str) -> Vec<String> {
        let response = send(
            router.clone(),
            req_auth(
                "GET",
                &format!("/ledger_app/ledger{query}"),
                &ledger_headers(),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_json(response).await;
        list["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|doc| doc["id"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn bulk_patch_updates_all_matching_documents_over_http() {
        let router = app();
        seed_ledger(
            &router,
            &[
                json!({"person": "ann", "paid": true}),
                json!({"person": "ann", "paid": true}),
                json!({"person": "bob", "paid": true}),
                json!({"person": "bob", "paid": false}),
            ],
        )
        .await;

        // Ein Request statt mehrerer einzelner PATCHes: alle bezahlten
        // Dokumente in einem Zug auf `paid = false`.
        let body = json!({"filter": {"paid": true}, "set": {"paid": false}});
        let response = send(
            router.clone(),
            req_json("PATCH", "/ledger_app/ledger", &ledger_headers(), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let report = body_json(response).await;
        assert_eq!(report["matched"], 3);
        assert_eq!(report["patched"], 3);

        // Der Sekundaerindex stimmt hinterher exakt (der GET-Fastpath liest
        // ihn ohne Nachpruefung — Geistereintraege waeren hier sichtbar).
        assert!(ledger_ids(&router, "?paid=true").await.is_empty());
        assert_eq!(ledger_ids(&router, "?paid=false").await.len(), 4);
    }

    #[tokio::test]
    async fn bulk_patch_filter_selects_subset_and_counts_noops() {
        let router = app();
        seed_ledger(
            &router,
            &[
                json!({"person": "ann", "paid": true}),
                json!({"person": "bob", "paid": true}),
                json!({"person": "ann", "paid": false}),
            ],
        )
        .await;

        let body = json!({"filter": {"person": "ann"}, "set": {"paid": false}});
        let response = send(
            router.clone(),
            req_json("PATCH", "/ledger_app/ledger", &ledger_headers(), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let report = body_json(response).await;
        // Nur die ann-Dokumente sind Treffer; das dritte erfuellt den Filter,
        // ist durch das `set` aber bereits im Zielzustand — `matched` zaehlt
        // es, `patched` nicht (kein Commit, kein WAL-Op).
        assert_eq!(report["matched"], 2);
        assert_eq!(report["patched"], 1);
        assert_eq!(ledger_ids(&router, "?paid=true").await.len(), 1);
    }

    #[tokio::test]
    async fn bulk_patch_schema_violation_changes_nothing() {
        let router = app();
        seed_ledger(
            &router,
            &[
                json!({"person": "ann", "paid": true}),
                json!({"person": "bob", "paid": true}),
            ],
        )
        .await;

        // Typverletzung im `set`: 400, und kein einziges Dokument aendert
        // sich — die Pruefung laeuft vor dem Schreib-Mutex.
        let body = json!({"filter": {"paid": true}, "set": {"paid": "yes"}});
        let response = send(
            router.clone(),
            req_json("PATCH", "/ledger_app/ledger", &ledger_headers(), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let err = body_json(response).await;
        assert_eq!(err["error"]["code"], "validation_failed");
        assert_eq!(ledger_ids(&router, "?paid=true").await.len(), 2);

        // Unbekanntes Feld im `set` (allow_unknown_fields = false): dieselbe
        // Garantie.
        let body = json!({"filter": {"paid": true}, "set": {"memo": "x"}});
        let response = send(
            router.clone(),
            req_json("PATCH", "/ledger_app/ledger", &ledger_headers(), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(ledger_ids(&router, "?paid=true").await.len(), 2);
    }

    #[tokio::test]
    async fn bulk_patch_rejects_filter_fields_outside_the_allowlist() {
        let router = app();
        seed_ledger(&router, &[json!({"person": "ann", "paid": true})]).await;

        // `amount` steht nicht in filter_fields — der Sammel-Patch teilt die
        // Allowlist mit GET.
        let body = json!({"filter": {"amount": 10}, "set": {"paid": false}});
        let response = send(
            router.clone(),
            req_json("PATCH", "/ledger_app/ledger", &ledger_headers(), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let err = body_json(response).await;
        assert!(
            err["error"]["message"]
                .as_str()
                .unwrap()
                .contains("filtering on `amount` is not allowed")
        );
    }

    #[tokio::test]
    async fn bulk_patch_rejects_invalid_body_shapes() {
        let router = app();
        let cases: Vec<(Value, &str)> = vec![
            (json!({"set": {"paid": false}}), "filter fehlt"),
            (json!({"filter": {}, "set": {"paid": false}}), "filter leer"),
            (json!({"filter": {"paid": true}}), "set fehlt"),
            (json!({"filter": {"paid": true}, "set": {}}), "set leer"),
            (
                json!({"filter": {"paid": true}, "set": {"paid": false}, "where": {}}),
                "zusaetzlicher Schluessel",
            ),
            (
                json!({"filter": {"paid": {}}, "set": {"paid": false}}),
                "Filter-Wert ist ein Objekt",
            ),
            (json!([1, 2, 3]), "Koerper ist kein Objekt"),
        ];
        for (body, what) in cases {
            let response = send(
                router.clone(),
                req_json("PATCH", "/ledger_app/ledger", &ledger_headers(), &body),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{what}");
        }
    }

    #[tokio::test]
    async fn bulk_patch_requires_the_same_authentication_as_crud() {
        let router = app();
        let body = json!({"filter": {"paid": true}, "set": {"paid": false}});

        let response = send(
            router.clone(),
            req_json("PATCH", "/ledger_app/ledger", &[], &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let wrong = vec![("x-api-key", "wrong_key".to_string())];
        let response = send(
            router.clone(),
            req_json("PATCH", "/ledger_app/ledger", &wrong, &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn single_doc_patch_still_works_on_a_bulk_endpoint() {
        let router = app();
        seed_ledger(
            &router,
            &[
                json!({"person": "ann", "paid": true}),
                json!({"person": "bob", "paid": true}),
            ],
        )
        .await;
        let ids = ledger_ids(&router, "?person=ann").await;
        let id = ids[0].clone();

        // Mit Item-ID greift der gewohnte Single-PATCH desselben Endpunkts —
        // `bulk = true` aendert nur die id-lose Kollektionsform.
        let response = send(
            router.clone(),
            req_json(
                "PATCH",
                &format!("/ledger_app/ledger/{id}"),
                &ledger_headers(),
                &json!({"amount": 99}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let doc = body_json(response).await;
        assert_eq!(doc["amount"], 99);
        assert_eq!(doc["paid"], true);

        // Und der Sammel-Patch sieht die geaenderten Daten: 1 Treffer,
        // 1 Commit (die 99 bleibt beim Merge erhalten).
        let body = json!({"filter": {"person": "ann"}, "set": {"paid": false}});
        let response = send(
            router.clone(),
            req_json("PATCH", "/ledger_app/ledger", &ledger_headers(), &body),
        )
        .await;
        let report = body_json(response).await;
        assert_eq!(report["matched"], 1);
        assert_eq!(report["patched"], 1);
        assert_eq!(ledger_ids(&router, "?paid=true").await.len(), 1);
    }

    #[tokio::test]
    async fn collection_patch_without_bulk_flag_stays_rejected() {
        // tasks_patch hat kein bulk = true: der Kollektions-PATCH bleibt die
        // gewohnte 400 ("Item-ID erforderlich") — kein Breaking Change fuer
        // bestehende Konfigurationen.
        let response = send(
            app(),
            req_json(
                "PATCH",
                "/todo_app/tasks",
                &auth_headers("premium"),
                &json!({"title": "x"}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let err = body_json(response).await;
        assert!(
            err["error"]["message"]
                .as_str()
                .unwrap()
                .contains("item id")
        );
    }

    #[tokio::test]
    async fn bulk_patch_runs_the_script_per_document() {
        let router = app();
        for name in ["ok_1", "ok_2"] {
            let response = send(
                router.clone(),
                req_json(
                    "POST",
                    "/script_app/items",
                    &[],
                    &json!({"kind": "item", "name": name}),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        let body = json!({"filter": {"kind": "item"}, "set": {"note": "x"}});
        let response = send(
            router.clone(),
            req_json("PATCH", "/script_app/items", &[], &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let report = body_json(response).await;
        assert_eq!(report["matched"], 2);
        assert_eq!(report["patched"], 2);

        // Das Skript hat je Dokument `touched` gesetzt, der Merge `note`.
        let response = send(router.clone(), req("GET", "/script_app/items")).await;
        let list = body_json(response).await;
        for doc in list["items"].as_array().unwrap() {
            assert_eq!(doc["touched"], true);
            assert_eq!(doc["note"], "x");
        }
    }

    #[tokio::test]
    async fn bulk_patch_script_rejection_commits_nothing() {
        let router = app();
        for name in ["ok_1", "ok_2", "boom"] {
            let response = send(
                router.clone(),
                req_json(
                    "POST",
                    "/script_app/items",
                    &[],
                    &json!({"kind": "item", "name": name}),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        // Der Skript-`throw` fuer IRGENDEIN Treffer bricht den ganzen
        // Sammel-Patch ab — auch die beiden an sich passierenden Dokumente
        // bleiben unveraendert (weder `note` noch `touched`).
        let body = json!({"filter": {"kind": "item"}, "set": {"note": "x"}});
        let response = send(
            router.clone(),
            req_json("PATCH", "/script_app/items", &[], &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let err = body_json(response).await;
        assert_eq!(err["error"]["code"], "script_rejected");
        assert!(
            err["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Sammel-Patch abgebrochen")
        );

        let response = send(router.clone(), req("GET", "/script_app/items")).await;
        let list = body_json(response).await;
        assert_eq!(list["total"], 3);
        for doc in list["items"].as_array().unwrap() {
            assert!(doc.get("note").is_none());
            assert!(doc.get("touched").is_none());
        }
    }

    // --- App-Auth: /_auth-Dispatch und auth_mode = "jwt" ------------------------

    const AUTH_TEST_TOML: &str = r#"
[apps.auth_app]
api_key_secret = "auth_app_secret_123_geheim"

  [apps.auth_app.auth]
  enabled = true
  jwt_secret = "auth_app_jwt_secret_0123456789abcdef"
  registration_open = true
  admin_email = "admin@auth.app"
  admin_password = "Admin-Passw0rt!"

    [apps.auth_app.auth.rate_limit]
    login_per_min = 1000
    refresh_per_min = 1000

  [apps.auth_app.endpoints.notes_get]
  path = "/notes"
  method = "GET"

  [apps.auth_app.endpoints.notes_post]
  path = "/notes"
  method = "POST"
  auth_mode = "jwt"

  business_logic = """
  fn on_request(payload, user) {
      payload.created_by = user.id;
      return payload;
  }
  """

  [apps.auth_app.endpoints.notes_patch_bulk]
  path = "/notes"
  method = "PATCH"
  auth_mode = "jwt"
  bulk = true
  filter_fields = ["done"]

  [apps.auth_app.endpoints.audit_get]
  path = "/audit"
  method = "GET"
  auth_mode = "jwt"
  roles = ["admin"]

  [apps.auth_app.endpoints.machine_import]
  path = "/imports"
  method = "POST"
  auth_mode = "api_key"

[apps.other_app]

  [apps.other_app.auth]
  enabled = true
  jwt_secret = "other_app_jwt_secret_9876543210fedcba"

    [apps.other_app.auth.rate_limit]
    login_per_min = 1000

  [apps.other_app.endpoints.stuff_post]
  path = "/stuff"
  method = "POST"
  auth_mode = "jwt"
"#;

    fn auth_router() -> axum::Router {
        let config = EngineConfig::from_toml(AUTH_TEST_TOML).expect("auth test config");
        build_router(
            AppState::build_with_store(config, Arc::new(MemoryStore::new()), None).expect("state"),
        )
    }

    /// Login ueber den VOLLSTAENDIGEN Router (Catch-All-Dispatch nach
    /// steadfast_auth) und liefert das Access-Token.
    async fn login_token(router: &axum::Router, app: &str, email: &str, password: &str) -> String {
        let response = send(
            router.clone(),
            req_json(
                "POST",
                &format!("/{app}/_auth/login"),
                &[],
                &json!({"email": email, "password": password}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "login muss klappen");
        let body = body_json(response).await;
        body["access_token"].as_str().expect("token").to_string()
    }

    fn bearer(token: &str) -> Vec<(&'static str, String)> {
        vec![("authorization", format!("Bearer {token}"))]
    }

    #[tokio::test]
    async fn auth_dispatch_login_me_and_refresh_through_router() {
        let router = auth_router();

        // Login (Bootstrap-Admin) laeuft durch den Catch-All in den
        // Auth-Subrouter — inklusive Security-Headern auf der Antwort.
        let token = login_token(&router, "auth_app", "admin@auth.app", "Admin-Passw0rt!").await;

        let response = send(
            router.clone(),
            req_auth("GET", "/auth_app/_auth/me", &bearer(&token)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let me = body_json(response).await;
        assert_eq!(me["email"], "admin@auth.app");
        assert_eq!(me["role"], "admin");

        // Falsches Passwort: uniforme 401 invalid_credentials.
        let response = send(
            router.clone(),
            req_json(
                "POST",
                "/auth_app/_auth/login",
                &[],
                &json!({"email": "admin@auth.app", "password": "falsch"}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let err = body_json(response).await;
        assert_eq!(err["error"]["code"], "invalid_credentials");
    }

    #[tokio::test]
    async fn jwt_endpoints_gate_write_and_feed_rhai_user_context() {
        let router = auth_router();
        let token = login_token(&router, "auth_app", "admin@auth.app", "Admin-Passw0rt!").await;

        // Ohne Token: 401; mit Token: 201 — und das Rhai-Skript sieht die
        // Benutzer-ID aus den JWT-Claims als user.id (created_by).
        let body = json!({"title": "erste Notiz"});
        let response = send(
            router.clone(),
            req_json("POST", "/auth_app/notes", &[], &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = send(
            router.clone(),
            req_json("POST", "/auth_app/notes", &bearer(&token), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let doc = body_json(response).await;
        assert!(
            doc["created_by"].as_str().unwrap().starts_with("u_"),
            "user.id aus den Claims: {}",
            doc["created_by"]
        );

        // Oeffentlicher GET bleibt offen; Bearer-Header stoeren nicht.
        let response = send(router.clone(), req("GET", "/auth_app/notes")).await;
        assert_eq!(response.status(), StatusCode::OK);

        // X-User-* kann die JWT-Identitaet NICHT ueberschreiben: Der
        // gespoofte Header darf created_by nicht anfaerben.
        let mut headers = bearer(&token);
        headers.push(("x-user-id", "spoofed-id".to_string()));
        let response = send(
            router.clone(),
            req_json("POST", "/auth_app/notes", &headers, &json!({"title": "x"})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let doc = body_json(response).await;
        assert_ne!(doc["created_by"], "spoofed-id");
    }

    #[tokio::test]
    async fn jwt_roles_are_enforced_fresh() {
        let router = auth_router();
        let admin = login_token(&router, "auth_app", "admin@auth.app", "Admin-Passw0rt!").await;

        // Admin darf den rollenbeschraenkten Endpunkt lesen.
        let response = send(
            router.clone(),
            req_auth("GET", "/auth_app/audit", &bearer(&admin)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // "user"-Rolle (Selbstregistrierung) bekommt 403, nicht 401.
        let response = send(
            router.clone(),
            req_json(
                "POST",
                "/auth_app/_auth/register",
                &[],
                &json!({"email": "leser@auth.app", "password": "Leser-Passw0rt!"}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let user = login_token(&router, "auth_app", "leser@auth.app", "Leser-Passw0rt!").await;
        let response = send(
            router.clone(),
            req_auth("GET", "/auth_app/audit", &bearer(&user)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Rollen-Aenderung greift sofort: Hochstufung zum admin via
        // Admin-PATCH oeffnet den Endpunkt ohne neues Token.
        let users = send(
            router.clone(),
            req_auth("GET", "/auth_app/_auth/users", &bearer(&admin)),
        )
        .await;
        let users = body_json(users).await;
        let leser_id = users["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["email"] == "leser@auth.app")
            .expect("leser")["id"]
            .as_str()
            .unwrap()
            .to_string();
        let response = send(
            router.clone(),
            req_json(
                "PATCH",
                &format!("/auth_app/_auth/users/{leser_id}"),
                &bearer(&admin),
                &json!({"role": "admin"}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = send(
            router.clone(),
            req_auth("GET", "/auth_app/audit", &bearer(&user)),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "neue Rolle greift sofort"
        );
    }

    #[tokio::test]
    async fn jwt_tenant_isolation_between_apps() {
        let router = auth_router();
        let token_a = login_token(&router, "auth_app", "admin@auth.app", "Admin-Passw0rt!").await;

        // Token von auth_app hat bei other_app nichts verloren (anderer
        // Secret + Issuer) — gleich ob der Endpunkt existiert oder nicht.
        let response = send(
            router.clone(),
            req_json("POST", "/other_app/stuff", &bearer(&token_a), &json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Und der Login mit den Credentials von App A schlaegt bei App B fehl.
        let response = send(
            router.clone(),
            req_json(
                "POST",
                "/other_app/_auth/login",
                &[],
                &json!({"email": "admin@auth.app", "password": "Admin-Passw0rt!"}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_key_and_jwt_operate_in_parallel() {
        let router = auth_router();

        // Der api_key-Endpunkt bleibt beim gewohnten X-API-Key-Modell —
        // ein Bearer-Token ersetzt ihn nicht.
        let response = send(
            router.clone(),
            req_json("POST", "/auth_app/imports", &[], &json!({"row": 1})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = send(
            router.clone(),
            req_json(
                "POST",
                "/auth_app/imports",
                &[("x-api-key", "auth_app_secret_123_geheim".to_string())],
                &json!({"row": 1}),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn unknown_paths_of_auth_apps_are_hidden() {
        let router = auth_router();
        // other_app hat nur jwt-Endpunkte: unbekannte Pfade geben 401 statt
        // 404 (N1 konsistent fuer JWT-Apps), mit Token die echte 404.
        let response = send(router.clone(), req("GET", "/other_app/gibtsnicht")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // other_app hat keinen Bootstrap-Admin -> Login-Loch bleibt 401
        // (registration_open default false). Stattdessen ueber auth_app:
        // unbekannter Pfad mit gueltigem Bearer -> echte 404.
        let token = login_token(&router, "auth_app", "admin@auth.app", "Admin-Passw0rt!").await;
        let response = send(
            router.clone(),
            req_auth("GET", "/auth_app/gibtsnicht", &bearer(&token)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // _auth-Subpfade: unbekannt -> 404 (Auth-Endpunkte sind kein
        // Struktur-Orakel: Login/Register sind ohnehin oeffentlich bekannt).
        let response = send(router.clone(), req("POST", "/auth_app/_auth/gibtsnicht")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // App OHNE aktive Auth: /_auth/... ist eine ganz normale (hier
        // unkonfigurierte) Kollektion -> 404, kein Auth-Dispatch.
        let response = send(app(), req("POST", "/minimal_app/_auth/login")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn bulk_patch_inherits_jwt_auth_exactly_like_crud() {
        let router = auth_router();
        let token = login_token(&router, "auth_app", "admin@auth.app", "Admin-Passw0rt!").await;

        for title in ["notiz a", "notiz b"] {
            let response = send(
                router.clone(),
                req_json(
                    "POST",
                    "/auth_app/notes",
                    &bearer(&token),
                    &json!({"title": title, "done": true}),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        // Ohne Token: 401, ganz wie beim Single-CRUD.
        let body = json!({"filter": {"done": true}, "set": {"done": false}});
        let response = send(
            router.clone(),
            req_json("PATCH", "/auth_app/notes", &[], &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Mit Token: derselbe Request laeuft durch.
        let response = send(
            router.clone(),
            req_json("PATCH", "/auth_app/notes", &bearer(&token), &body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let report = body_json(response).await;
        assert_eq!(report["matched"], 2);
        assert_eq!(report["patched"], 2);

        let response = send(router.clone(), req("GET", "/auth_app/notes")).await;
        let list = body_json(response).await;
        assert_eq!(list["total"], 2);
        for doc in list["items"].as_array().unwrap() {
            assert_eq!(doc["done"], false);
        }
    }
}
