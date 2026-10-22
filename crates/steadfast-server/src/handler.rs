//! Der Hot Path: Config-Lookup -> Auth -> Rhai-Sandbox -> CRUD -> Response.

use std::collections::HashMap;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use steadfast_core::{EndpointRuntime, EngineError, HttpMethod, ScriptRuntime, MAX_PAGE_SIZE};
use steadfast_storage::{ListParams, ListResult, PatchOutcome, RangeOp, SortSpec};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::{
    duplicate_identity_header, extract_user, verify_api_key, verify_gateway_secret,
    API_KEY_HEADER, INTERNAL_AUTH_HEADER,
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

pub async fn handle(
    State(state): State<AppState>,
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

    // --- Pfad auftrennen: /{app_id}/{collection}[/{item_id}] -------------
    let rest = rest.trim_end_matches('/');
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
    let Some(app_routes) = state.app(&app_id) else {
        return not_found();
    };
    let Some(path_routes) = app_routes.path(&config_path) else {
        // N1: Fuer Apps mit Secret wird unbekannten Pfaden keine Struktur
        // verraten — ohne gueltigen Key gibt es 401 statt 404, erst
        // authentifizierte Clients unterscheiden 404/405 von 401.
        return hidden_behind_auth(app_routes, &headers, not_found);
    };
    // HEAD laeuft durch den GET-Pfad; der Body wird am Ende entfernt.
    let is_head = method.as_str() == "HEAD";
    let core_method = match method.as_str() {
        "GET" | "HEAD" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        // Andere Methoden sind im MVP nicht konfigurierbar (N1: auch hier
        // kein Struktur-Oracle fuer unauthentifizierte Requests).
        _ => return hidden_behind_auth(app_routes, &headers, || {
            method_not_allowed(path_routes)
        }),
    };
    let Some(endpoint) = path_routes.method(core_method) else {
        return hidden_behind_auth(app_routes, &headers, || {
            method_not_allowed(path_routes)
        });
    };

    // --- Auth (sofortiger Abbruch bei Fehlschlag) -------------------------
    if endpoint.auth_required {
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
    // H1': Ist ein Gateway-Secret konfiguriert, muessen X-User-*-Header per
    // X-Internal-Auth ihre Herkunft vom Gateway belegen — sonst fallen sie
    // auf die Defaults (anonymous/user) zurueck. Ohne konfiguriertes
    // Gateway-Secret bleibt das bisherige Vertrauensmodell (dokumentiert).
    let identity_trusted = match state.gateway_secret() {
        Some(secret) => {
            let provided = headers.get(INTERNAL_AUTH_HEADER).and_then(|v| v.to_str().ok());
            verify_gateway_secret(provided, secret)
        }
        None => true,
    };
    let user = extract_user(&headers, identity_trusted);

    // --- CRUD-Dispatch ------------------------------------------------------
    let collection = endpoint.path.trim_start_matches('/');
    let response = match (core_method, item_id.as_deref()) {
        (HttpMethod::Get, Some(id)) => get_item(&state, &app_id, collection, id),
        (HttpMethod::Get, None) => get_list(&state, endpoint, &app_id, collection, &raw_query),
        (HttpMethod::Post, None) => post_create(&state, endpoint, &app_id, collection, body, user),
        (HttpMethod::Post, Some(_)) => not_found(),
        (HttpMethod::Put, Some(id)) => put_replace(&state, endpoint, &app_id, collection, id, body, user),
        (HttpMethod::Put, None) => bad_request("PUT requires an item id: /{app}/{collection}/{id}"),
        (HttpMethod::Patch, Some(id)) => patch_merge(&state, endpoint, &app_id, collection, id, body, user),
        (HttpMethod::Patch, None) => bad_request("PATCH requires an item id: /{app}/{collection}/{id}"),
        (HttpMethod::Delete, Some(id)) => delete_item(&state, &app_id, collection, id),
        (HttpMethod::Delete, None) => bad_request("DELETE requires an item id: /{app}/{collection}/{id}"),
    };
    // N5: HEAD verhaelt sich wie GET (gleiche Header inkl. Content-Length),
    // liefert aber keinen Body.
    if is_head {
        return strip_body(response).await;
    }
    response
}

/// N1: Fuehrt `respond` nur aus, wenn der Request den App-Key besteht;
/// Apps ohne Secret oder mit gueltigem Key sehen die echte 404/405-Antwort.
/// Die Pruefung laeuft ausschliesslich auf Fehlerpfaden — der Hot Path
/// (gueltige Route) zahlt nichts dafuer.
fn hidden_behind_auth(
    app_routes: &crate::state::AppRoutes,
    headers: &HeaderMap,
    respond: impl FnOnce() -> Response,
) -> Response {
    if let Some(secret) = app_routes.secret() {
        let provided = headers.get(API_KEY_HEADER).and_then(|v| v.to_str().ok());
        if !verify_api_key(provided, secret) {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing or invalid API key",
            );
        }
    }
    respond()
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
                let parsed: usize = value
                    .parse()
                    .map_err(|_| EngineError::BadRequest(format!("invalid `page` value `{value}`")))?;
                if parsed < 1 {
                    return Err(EngineError::BadRequest("`page` must be >= 1".into()));
                }
                page = Some(parsed);
            }
            "limit" => {
                let parsed: usize = value
                    .parse()
                    .map_err(|_| EngineError::BadRequest(format!("invalid `limit` value `{value}`")))?;
                if parsed < 1 || parsed > MAX_PAGE_SIZE {
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
            return Err(EngineError::BadRequest(format!("invalid filter field `{key}`")));
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
        Err(response) => return response,
    };
    let mut doc = match run_script(endpoint, doc, user) {
        Ok(doc) => doc,
        Err(response) => return response,
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
        response.headers_mut().insert(
            axum::http::header::LOCATION,
            location,
        );
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
        Err(response) => return response,
    };
    let doc = match run_script(endpoint, doc, user) {
        Ok(doc) => doc,
        Err(response) => return response,
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
        Err(response) => return response,
    };
    // N4: Merge + Skript laufen IM Store unter dem per-Kollektion-Schreib-
    // Mutex — zwei gleichzeitige PATCHes auf dasselbe Dokument koennen sich
    // nicht mehr gegenseitig ueberschreiben (kein lost update zwischen get
    // und replace). Der Store loest evicierte Dokumente VOR dem Sperren auf.
    // Ein Skript-`throw` (422) bricht ab, ohne etwas zu committen; der neue
    // seq-Eintrag ordnet das Dokument wie bei PUT hinten ein.
    let outcome = state.store().patch_merge(app_id, collection, id, |current| {
        let merged = merge_shallow(current, patch);
        run_script(endpoint, merged, user)
    });
    match outcome {
        PatchOutcome::Updated(stored) => json_response(StatusCode::OK, &stored),
        PatchOutcome::NotFound => not_found(),
        PatchOutcome::Rejected(response) => response,
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
/// Werte — Nutzereingaben werden nie als Code interpretiert.
fn run_script(endpoint: &EndpointRuntime, payload: Value, user: Value) -> Result<Value, Response> {
    let Some(script) = &endpoint.script else {
        return Ok(payload);
    };
    match ScriptRuntime::exec(script, payload, user) {
        Ok(result) => Ok(result),
        Err(err) => Err(engine_error_response(&err)),
    }
}

fn parse_json_object(body: &Bytes) -> Result<Value, Response> {
    if body.is_empty() {
        return Err(bad_request("request body must be a non-empty JSON object"));
    }
    let value: Value = serde_json::from_slice(body)
        .map_err(|err| EngineError::InvalidJson(err.to_string()))
        .map_err(|err| engine_error_response(&err))?;
    if !value.is_object() {
        return Err(bad_request("request body must be a JSON object"));
    }
    Ok(value)
}

fn json_response(status: StatusCode, value: &Value) -> Response {
    // Serialisierung per Referenz — kein Deep-Clone des Dokuments.
    (status, Json(value)).into_response()
}

pub fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(status, &json!({ "error": { "code": code, "message": message } }))
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
    use steadfast_core::EngineConfig;
    use steadfast_storage::MemoryStore;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    const TODO_SECRET: &str = "super_geheimes_todo_salt_123";
    const GALLERY_SECRET: &str = "gallery_secret_456";

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

[apps.minimal_app]

  [apps.minimal_app.endpoints.only_get]
  path = "/only"
  method = "GET"
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

    fn req_json(method: &str, uri: &str, headers: &[(&str, String)], body: &Value) -> Request<Body> {
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
        assert_eq!(doc["created_by"], "anonymous", "unproven header must be ignored");

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
            req_json("POST", "/todo_app/tasks", &headers, &json!({"title": "prio", "is_priority": true})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let doc = body_json(response).await;
        assert_eq!(doc["created_by"], "user_1");

        // Rollen-Spoofing ohne Provenienz: premium wird nicht honoring —
        // das Prioritaets-Skript lehnt die free-Default-Rolle mit 422 ab.
        let response = send(
            router.clone(),
            req_json("POST", "/todo_app/tasks", &auth_headers("premium"), &json!({"title": "spoof", "is_priority": true})),
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
        let response = send(
            app(),
            req_json("POST", "/todo_app/tasks", &wrong, &body),
        )
        .await;
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
        assert!(json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Premium"));
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
        assert_eq!(location, format!("/todo_app/tasks/{}", json["id"].as_str().unwrap()));
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
        assert_eq!(doc["title"], "original", "409 darf den Bestand nicht anfassen");

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
        let roles = [("premium", true), ("free", false), ("free", false), ("free", false)];
        let mut ids = Vec::new();
        for (i, (role, priority)) in roles.iter().enumerate() {
            let body = json!({"title": format!("task {i}"), "is_priority": priority});
            let response = send(
                router.clone(),
                req_json("POST", "/todo_app/tasks", &auth_headers(role), &body),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
            ids.push(body_json(response).await["id"].as_str().unwrap().to_string());
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
        let id = body_json(response).await["id"].as_str().unwrap().to_string();

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
        let id = body_json(response).await["id"].as_str().unwrap().to_string();

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
        let id = body_json(response).await["id"].as_str().unwrap().to_string();

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
        assert_eq!(doc["status"], "erledigt", "merge must preserve patched field");
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
        let id = body_json(response).await["id"].as_str().unwrap().to_string();

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
                req_json("POST", "/gallery_app/photos", &[("x-api-key", GALLERY_SECRET.to_string())], &body),
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
            req_auth("GET", "/gallery_app/photos?album_min=2&album_max=3", &headers),
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
    async fn head_returns_headers_without_body() {
        // N5: HEAD verhaelt sich wie GET — gleicher Status, Content-Length
        // der GET-Antwort, aber kein Body.
        let router = app();
        let body = json!({"title": "fuer-head"});
        send(router.clone(), req_json("POST", "/todo_app/tasks", &auth_headers("free"), &body)).await;

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
}
