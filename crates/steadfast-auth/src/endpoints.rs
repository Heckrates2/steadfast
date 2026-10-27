//! Der `/{app_id}/_auth/*`-Subrouter.
//!
//! | Methode & Pfad | Funktion | Auth |
//! |---|---|---|
//! | `POST /_auth/register` | Konto anlegen (nur bei `registration_open`) | — |
//! | `POST /_auth/login` | Access- + Refresh-Token | — |
//! | `POST /_auth/refresh` | Refresh-Rotation | Refresh-Token (Body/Cookie) |
//! | `POST /_auth/logout` | Refresh-Token widerrufen | Refresh-Token (Body/Cookie) |
//! | `GET /_auth/me` | Eigenes Profil | Access-Token |
//! | `GET /_auth/users` | Benutzer auflisten | Admin |
//! | `POST /_auth/users` | Benutzer anlegen | Admin |
//! | `PATCH /_auth/users/{id}` | Rolle/`disabled` aendern | Admin |
//!
//! Sicherheits-Grundsaetze: Login-Fehler sind immer die identische 401
//! `invalid_credentials` (unbekannte E-Mail, falsches Passwort, gesperrtes
//! oder deaktiviertes Konto) — inklusive Argon2-Dummy-Lauf fuer gleiche
//! Antwortzeiten. Fehlerbodies folgen dem Engine-Envelope
//! `{"error": {"code", "message"}}`. Jede Antwort traegt
//! `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` und
//! `Referrer-Policy: no-refender`-Aequivalent (no-referrer).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::rate_limit::Kind;
use crate::tokens::IssuedTokens;
use crate::users::{self, UserCreateError, public_profile};
use crate::{AppAuth, cookies, now_unix};

/// Obere Grenze fuer Admin-Listen (aligniert mit dem Store-Paging).
const MAX_LIST_LIMIT: usize = 100;

/// Der Subrouter. `sub_path` ist der Pfad unterhalb von `/{app_id}/_auth`
/// (z. B. `"login"`, `"users"`, `"users/u_123"`, `""`); `client_ip` speist
/// das Rate-Limiting (None teilt sich den Ersatzschluessel "unknown").
pub fn route(
    auth: &AppAuth,
    sub_path: &str,
    method: &Method,
    headers: &HeaderMap,
    query: &HashMap<String, String>,
    body: Bytes,
    client_ip: Option<IpAddr>,
) -> Response {
    let segments: Vec<&str> = sub_path.split('/').filter(|s| !s.is_empty()).collect();
    let method = method.as_str();
    let is_get = method == "GET" || method == "HEAD";

    match (is_get, segments.as_slice()) {
        (_, ["login"]) => post_only(method, "login", || login(auth, body, client_ip)),
        (_, ["register"]) => post_only(method, "register", || register(auth, body, client_ip)),
        (_, ["refresh"]) => post_only(method, "refresh", || {
            refresh(auth, headers, body, client_ip)
        }),
        (_, ["logout"]) => post_only(method, "logout", || logout(auth, headers, body)),
        (true, ["me"]) => me(auth, headers),
        (true, ["users"]) => admin_list(auth, headers, query),
        (_, ["users"]) => post_only(method, "users", || admin_create(auth, headers, body)),
        // PATCH ohne Item-ID ist ein Request-Fehler, kein Fallback.
        (_, ["users", user_id]) if method == "PATCH" => admin_patch(auth, headers, body, user_id),
        (_, ["users", _id]) => method_not_allowed("GET, POST"),
        _ => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "unknown auth endpoint; see /_auth/login, /_auth/refresh, /_auth/logout, \
             /_auth/register, /_auth/me, /_auth/users",
        ),
    }
}

/// POST-Endpunkte: jede andere Methode -> 405 mit `Allow: POST`.
fn post_only(method: &str, _name: &str, handler: impl FnOnce() -> Response) -> Response {
    if method == "POST" {
        handler()
    } else {
        method_not_allowed("POST")
    }
}

// --- Handler -----------------------------------------------------------------

fn login(auth: &AppAuth, body: Bytes, ip: Option<IpAddr>) -> Response {
    if let Err(retry_after) = auth
        .limiter()
        .check(Kind::Login, ip, &auth.settings().rate_limit)
    {
        return rate_limited(retry_after);
    }
    let body = match parse_json_body(&body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let (Some(email), Some(password)) = (body_str(&body, "email"), body_str(&body, "password"))
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "body must be JSON with string fields `email` and `password`",
        );
    };
    let use_cookie = body
        .get("use_cookie")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let policy = &auth.settings().password_policy;
    let email = match users::normalize_email(email) {
        Some(email) => email,
        None => {
            auth.dummy().burn(password);
            return invalid_credentials();
        }
    };
    // Passwoerter ueber der Policy-Laenge konnten nie gespeichert worden
    // sein — gleich behandeln wie unbekannte Konten (Burn + 401).
    if password.chars().count() > policy.max_length {
        auth.dummy().burn(password);
        return invalid_credentials();
    }

    let Some(user) = auth.find_user_by_email(&email) else {
        auth.dummy().burn(password);
        tracing::warn!(app = %auth.app_id(), email = %email, "Login abgelehnt: unbekannte E-Mail");
        return invalid_credentials();
    };
    let user_id = user
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if user_id.is_empty() {
        auth.dummy().burn(password);
        return invalid_credentials();
    }

    if users::is_locked(&user, now_unix()) {
        auth.dummy().burn(password);
        tracing::warn!(app = %auth.app_id(), user_id = %user_id, "Login abgelehnt: Konto gesperrt");
        return invalid_credentials();
    }
    let hash = user
        .get("password_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !crate::password::verify_password(password, hash) {
        auth.record_login_failure(&user_id);
        tracing::warn!(app = %auth.app_id(), user_id = %user_id, "Login abgelehnt: falsches Passwort");
        return invalid_credentials();
    }
    if user
        .get("disabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        tracing::warn!(app = %auth.app_id(), user_id = %user_id, "Login abgelehnt: Konto deaktiviert");
        return invalid_credentials();
    }

    auth.reset_login_failures(&user_id);
    let role = user
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("user")
        .to_string();
    let Some(issued) = auth.issue_tokens(&user_id, &role) else {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "token_error",
            "could not issue tokens",
        );
    };
    tracing::info!(app = %auth.app_id(), user_id = %user_id, "Login erfolgreich");
    respond_tokens(auth, issued, use_cookie, false)
}

fn register(auth: &AppAuth, body: Bytes, ip: Option<IpAddr>) -> Response {
    if let Err(retry_after) = auth
        .limiter()
        .check(Kind::Register, ip, &auth.settings().rate_limit)
    {
        return rate_limited(retry_after);
    }
    if !auth.settings().registration_open {
        return error_response(
            StatusCode::FORBIDDEN,
            "registration_closed",
            "self-registration is disabled for this app; ask an admin",
        );
    }
    let body = match parse_json_body(&body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let (Some(email), Some(password)) = (body_str(&body, "email"), body_str(&body, "password"))
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "body must be JSON with string fields `email` and `password`",
        );
    };
    if let Err(violations) = auth.settings().password_policy.check(password) {
        return error_details_response(
            StatusCode::BAD_REQUEST,
            "password_policy",
            "password does not satisfy the configured policy",
            &violations,
        );
    }
    match auth.create_user(email, password, "user") {
        Ok(profile) => json_response(StatusCode::CREATED, &profile),
        Err(UserCreateError::EmailInvalid) => error_response(
            StatusCode::BAD_REQUEST,
            "invalid_email",
            "email must be ASCII with exactly one `@`, non-empty parts, 3..=254 chars",
        ),
        Err(UserCreateError::Duplicate) => error_response(
            StatusCode::CONFLICT,
            "already_exists",
            "a user with this email already exists",
        ),
        Err(UserCreateError::HashFailed) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "hash_error",
            "could not hash the password",
        ),
    }
}

fn refresh(auth: &AppAuth, headers: &HeaderMap, body: Bytes, ip: Option<IpAddr>) -> Response {
    if let Err(retry_after) = auth
        .limiter()
        .check(Kind::Refresh, ip, &auth.settings().rate_limit)
    {
        return rate_limited(retry_after);
    }
    let parsed = match parse_json_body(&body) {
        Ok(body) => body,
        Err(response) => return *response,
    };

    // Token-Vorlage: Body (Bearer-Welt) oder Cookie (Browser-Welt, mit
    // Origin-Check als CSRF-Schutz).
    let (presented, via_cookie) = match body_str(&parsed, "refresh_token") {
        Some(token) => (token.to_string(), false),
        None => match cookies::read_refresh_cookie(headers) {
            Some(token) => match auth.cookie_origins() {
                Some(origins) if cookies::origin_allowed(origins, headers) => (token, true),
                _ => {
                    return error_response(
                        StatusCode::FORBIDDEN,
                        "csrf_rejected",
                        "cookie refresh requires an allowed Origin header",
                    );
                }
            },
            None => {
                return error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_request",
                    "missing refresh token (body field `refresh_token` or auth cookie)",
                );
            }
        },
    };

    match auth.rotate_refresh(&presented) {
        Ok(issued) => respond_tokens(auth, issued, false, via_cookie),
        Err(_) => {
            tracing::warn!(app = %auth.app_id(), "Refresh abgelehnt (ungueltig/gelaufen/Wiederverwendung)");
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_refresh_token",
                "refresh token is invalid, expired or revoked",
            )
        }
    }
}

fn logout(auth: &AppAuth, headers: &HeaderMap, body: Bytes) -> Response {
    let parsed = match parse_json_body(&body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let presented = match body_str(&parsed, "refresh_token") {
        Some(token) => Some(token.to_string()),
        None => match cookies::read_refresh_cookie(headers) {
            // Logout mit Cookie: gleicher Origin-Check — ein CSRF-Logout
            // soll keinem fremden Request gelingen.
            Some(token) => match auth.cookie_origins() {
                Some(origins) if cookies::origin_allowed(origins, headers) => Some(token),
                _ => {
                    return error_response(
                        StatusCode::FORBIDDEN,
                        "csrf_rejected",
                        "cookie logout requires an allowed Origin header",
                    );
                }
            },
            None => None,
        },
    };
    if let Some(token) = presented {
        auth.revoke_refresh(&token);
        tracing::info!(app = %auth.app_id(), "Logout: Refresh-Token widerrufen");
    }

    let mut response = Response::default();
    *response.status_mut() = StatusCode::NO_CONTENT;
    if let Ok(value) = cookies::clear_cookie_value(auth.app_id()).parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    security_headers(response)
}

fn me(auth: &AppAuth, headers: &HeaderMap) -> Response {
    let Ok(user) = require_authenticated(auth, headers) else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid access token",
        );
    };
    json_response(StatusCode::OK, &public_profile(&user))
}

fn admin_list(auth: &AppAuth, headers: &HeaderMap, query: &HashMap<String, String>) -> Response {
    let Ok(admin) = require_admin(auth, headers) else {
        return forbidden_or_unauthorized(auth, headers);
    };
    let page = match parse_usize_param(query.get("page"), 1, 1, u64::MAX as usize) {
        Ok(value) => value,
        Err(message) => return bad_request_param("page", &message),
    };
    let limit = match parse_usize_param(query.get("limit"), 20, 1, MAX_LIST_LIMIT) {
        Ok(value) => value,
        Err(message) => return bad_request_param("limit", &message),
    };
    let (items, total) = auth.list_users(page, limit);
    tracing::debug!(app = %auth.app_id(), admin = %admin["id"], page, limit, "Admin: Benutzerliste");
    json_response(
        StatusCode::OK,
        &json!({ "items": items, "page": page, "limit": limit, "total": total }),
    )
}

fn admin_create(auth: &AppAuth, headers: &HeaderMap, body: Bytes) -> Response {
    if require_admin(auth, headers).is_err() {
        return forbidden_or_unauthorized(auth, headers);
    }
    let parsed = match parse_json_body(&body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let (Some(email), Some(password)) = (body_str(&parsed, "email"), body_str(&parsed, "password"))
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "body must be JSON with string fields `email` and `password`",
        );
    };
    let role = body_str(&parsed, "role").unwrap_or("user").trim();
    if !users::valid_role(role) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_role",
            "role must match [A-Za-z0-9_-] (1..=32 chars)",
        );
    }
    if let Err(violations) = auth.settings().password_policy.check(password) {
        return error_details_response(
            StatusCode::BAD_REQUEST,
            "password_policy",
            "password does not satisfy the configured policy",
            &violations,
        );
    }
    match auth.create_user(email, password, role) {
        Ok(profile) => json_response(StatusCode::CREATED, &profile),
        Err(UserCreateError::EmailInvalid) => error_response(
            StatusCode::BAD_REQUEST,
            "invalid_email",
            "email must be ASCII with exactly one `@`, non-empty parts, 3..=254 chars",
        ),
        Err(UserCreateError::Duplicate) => error_response(
            StatusCode::CONFLICT,
            "already_exists",
            "a user with this email already exists",
        ),
        Err(UserCreateError::HashFailed) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "hash_error",
            "could not hash the password",
        ),
    }
}

fn admin_patch(auth: &AppAuth, headers: &HeaderMap, body: Bytes, user_id: &str) -> Response {
    if require_admin(auth, headers).is_err() {
        return forbidden_or_unauthorized(auth, headers);
    }
    let parsed = match parse_json_body(&body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let role = match body_str(&parsed, "role") {
        None => None,
        Some(role) => {
            let role = role.trim();
            if !users::valid_role(role) {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_role",
                    "role must match [A-Za-z0-9_-] (1..=32 chars)",
                );
            }
            Some(role.to_string())
        }
    };
    let disabled = parsed.get("disabled").and_then(|v| v.as_bool());
    if role.is_none() && disabled.is_none() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "body must set `role` (string) and/or `disabled` (boolean)",
        );
    }
    match auth.patch_user(user_id, role, disabled) {
        Some(profile) => json_response(StatusCode::OK, &profile),
        None => error_response(StatusCode::NOT_FOUND, "not_found", "user not found"),
    }
}

// --- Hilfsbausteine ----------------------------------------------------------

/// `Ok(user)` = authentifiziert UND aktiv (frisch aus dem Store — Sperren
/// und Deaktivierungen greifen sofort, nicht erst beim naechsten Refresh).
fn require_authenticated(auth: &AppAuth, headers: &HeaderMap) -> Result<Arc<Value>, ()> {
    let claims = auth.verify_bearer(headers).ok_or(())?;
    let user = auth.user_by_id(&claims.sub).ok_or(())?;
    if user
        .get("disabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Err(());
    }
    Ok(user)
}

fn require_admin(auth: &AppAuth, headers: &HeaderMap) -> Result<Arc<Value>, ()> {
    let user = require_authenticated(auth, headers)?;
    if user.get("role").and_then(|v| v.as_str()) == Some("admin") {
        Ok(user)
    } else {
        Err(())
    }
}

/// Antwort fuer gescheiterte Admin-Guards: ohne gueltiges Token 401, mit
/// Token aber ohne Admin-Rolle 403 (Rueckstufungen greifen sofort, weil die
/// Rolle frisch aus dem Store kommt).
fn forbidden_or_unauthorized(auth: &AppAuth, headers: &HeaderMap) -> Response {
    match auth.verify_bearer(headers) {
        Some(_) => error_response(StatusCode::FORBIDDEN, "forbidden", "admin role required"),
        None => error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid access token",
        ),
    }
}

/// Token-Antwort: Access-Token immer im Body; Refresh im Body (Bearer-Welt)
/// oder als HttpOnly-Cookie (Browser-Welt, `use_cookie` beim Login bzw.
/// `via_cookie` beim Refresh).
fn respond_tokens(
    auth: &AppAuth,
    issued: IssuedTokens,
    use_cookie: bool,
    via_cookie: bool,
) -> Response {
    let cookie_mode = use_cookie || via_cookie;
    if cookie_mode && auth.cookie_origins().is_none() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "cookie_mode_disabled",
            "cookie mode requires auth.allowed_origins (or concrete cors.allowed_origins)",
        );
    }
    let mut body = json!({
        "access_token": issued.access_token,
        "token_type": "Bearer",
        "expires_in": issued.access_ttl,
    });
    if cookie_mode {
        let mut response = json_response(StatusCode::OK, &body);
        if let Ok(value) =
            cookies::set_cookie_value(auth.app_id(), &issued.refresh_token, issued.refresh_ttl)
                .parse()
        {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        response
    } else {
        body["refresh_token"] = json!(issued.refresh_token);
        body["refresh_expires_in"] = json!(issued.refresh_ttl);
        json_response(StatusCode::OK, &body)
    }
}

fn invalid_credentials() -> Response {
    error_response(
        StatusCode::UNAUTHORIZED,
        "invalid_credentials",
        "invalid credentials",
    )
}

fn rate_limited(retry_after_secs: u64) -> Response {
    let mut response = error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "too many attempts — slow down",
    );
    if let Ok(value) = retry_after_secs.to_string().parse() {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn method_not_allowed(allow: &str) -> Response {
    let mut response = error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "the method is not supported on this auth endpoint",
    );
    if let Ok(value) = allow.parse() {
        response.headers_mut().insert(header::ALLOW, value);
    }
    response
}

/// JSON-Body parsen; leerer Body zaehlt als leeres Objekt (Cookie-Flows
/// senden keinen Body). Ungueltiges JSON -> 400 invalid_json. (`Box`:
/// Response ist gross, sonst meckert clippy::result_large_err.)
fn parse_json_body(body: &Bytes) -> Result<Value, Box<Response>> {
    if body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(body).map_err(|_| {
        Box::new(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "request body must be a JSON object",
        ))
    })
}

fn body_str<'a>(body: &'a Value, field: &str) -> Option<&'a str> {
    match body.get(field) {
        None => None,
        Some(Value::String(value)) => Some(value),
        Some(_) => None,
    }
}

fn parse_usize_param(
    raw: Option<&String>,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, String> {
    match raw {
        None => Ok(default),
        Some(raw) => raw
            .parse::<usize>()
            .ok()
            .filter(|value| *value >= min && *value <= max)
            .ok_or_else(|| format!("must be an integer in {min}..={max}")),
    }
}

fn bad_request_param(name: &str, message: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        &format!("query parameter `{name}` {message}"),
    )
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    security_headers((status, axum::Json(body.clone())).into_response())
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(
        status,
        &json!({ "error": { "code": code, "message": message } }),
    )
}

fn error_details_response(
    status: StatusCode,
    code: &str,
    message: &str,
    details: &[&str],
) -> Response {
    json_response(
        status,
        &json!({ "error": { "code": code, "message": message, "details": details } }),
    )
}

/// Sicherheits-Header auf JEDE Auth-Antwort: Tokens duerfen nirgendwo
/// gecacht werden, MIME-Sniffing und Referrer-Lecks sind hier fehl am Platz.
fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{test_app_auth, test_settings};
    use axum::http::Method;
    use serde_json::json;
    use steadfast_core::AuthSettings;

    /// Aufruf-Helfer: Antwort als (Status, Body-JSON, Header).
    async fn call(
        auth: &AppAuth,
        method: &str,
        path: &str,
        body: Option<&str>,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Value, HeaderMap) {
        let mut header_map = HeaderMap::new();
        for (name, value) in headers {
            header_map.insert(
                name.parse::<axum::http::HeaderName>().unwrap(),
                value.parse().unwrap(),
            );
        }
        let response = route(
            auth,
            path,
            &Method::from_bytes(method.as_bytes()).unwrap(),
            &header_map,
            &HashMap::new(),
            body.map(str::as_bytes)
                .map(Bytes::copy_from_slice)
                .unwrap_or_default(),
            Some("127.0.0.9".parse().unwrap()),
        );
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap_or_default();
        let value = if body.is_empty() {
            json!(null)
        } else {
            serde_json::from_slice(&body).unwrap_or(json!(null))
        };
        (status, value, headers)
    }

    async fn registered(auth: &AppAuth) {
        let (status, body, _) = call(
            auth,
            "POST",
            "register",
            Some(r#"{"email":"u@example.com","password":"Passw0rt!x"}"#),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    async fn login_ok(auth: &AppAuth, use_cookie: bool) -> Value {
        let body = if use_cookie {
            r#"{"email":"u@example.com","password":"Passw0rt!x","use_cookie":true}"#
        } else {
            r#"{"email":"u@example.com","password":"Passw0rt!x"}"#
        };
        let (status, body, _) = call(auth, "POST", "login", Some(body), &[]).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    fn settings_with(mut mutate: impl FnMut(&mut AuthSettings)) -> AuthSettings {
        let mut settings = test_settings();
        mutate(&mut settings);
        settings
    }

    #[tokio::test]
    async fn register_login_me_flow() {
        let auth = test_app_auth();
        registered(&auth).await;

        let login = login_ok(&auth, false).await;
        assert!(login["access_token"].as_str().is_some());
        assert!(login["refresh_token"].as_str().is_some());
        assert_eq!(login["token_type"], json!("Bearer"));

        let token = login["access_token"].as_str().unwrap();
        let (status, me, headers) = call(
            &auth,
            "GET",
            "me",
            None,
            &[("authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(me["email"], json!("u@example.com"));
        assert_eq!(me["role"], json!("user"));
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "no-store",
            "Auth-Antworten werden nie gecacht"
        );
    }

    #[tokio::test]
    async fn login_failures_are_uniform_and_no_enumeration() {
        let auth = test_app_auth();
        registered(&auth).await;

        // Falsches Passwort vs. unbekannte E-Mail vs. kaputte E-Mail:
        // identischer Status UND identischer Fehlercode.
        let cases = [
            r#"{"email":"u@example.com","password":"falsches-Passwort"}"#,
            r#"{"email":"unbekannt@example.com","password":"falsches-Passwort"}"#,
            r#"{"email":"kein-email","password":"falsches-Passwort"}"#,
        ];
        for case in cases {
            let (status, body, _) = call(&auth, "POST", "login", Some(case), &[]).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}: {body}");
            assert_eq!(body["error"]["code"], json!("invalid_credentials"));
        }

        // Fehlende Felder / kaputtes JSON sind Request-Fehler (400).
        let (status, _, _) = call(
            &auth,
            "POST",
            "login",
            Some(r#"{"email":"u@example.com"}"#),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = call(&auth, "POST", "login", Some("nicht json"), &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_policy_violations_list_every_rule() {
        let auth = test_app_auth();
        let (status, body, _) = call(
            &auth,
            "POST",
            "register",
            Some(r#"{"email":"p@example.com","password":"kurz1A!"}"#),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], json!("password_policy"));
        let details = body["error"]["details"].as_array().unwrap();
        assert!(
            details
                .iter()
                .any(|d| d.as_str().unwrap().contains("characters long")),
            "{details:?}"
        );

        // Duplikat -> 409 (Registration ist kein Enumeration-Orakel: die
        // E-Mail gehoert dem Aufrufer selbst, 409 ist hier Standard).
        registered(&auth).await;
        let (status, body, _) = call(
            &auth,
            "POST",
            "register",
            Some(r#"{"email":"U@Example.com","password":"Passw0rt!x"}"#),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], json!("already_exists"));
    }

    #[tokio::test]
    async fn registration_closed_by_default_config() {
        let auth = crate::AppAuth::init(
            "demo",
            settings_with(|s| s.registration_open = false),
            std::sync::Arc::new(steadfast_storage::MemoryStore::new()),
            None,
        )
        .unwrap();
        let (status, body, _) = call(
            &auth,
            "POST",
            "register",
            Some(r#"{"email":"x@example.com","password":"Passw0rt!x"}"#),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["code"], json!("registration_closed"));
    }

    #[tokio::test]
    async fn refresh_rotation_via_body_and_logout() {
        let auth = test_app_auth();
        registered(&auth).await;
        let login = login_ok(&auth, false).await;
        let refresh_token = login["refresh_token"].as_str().unwrap().to_string();

        let (status, rotated, _) = call(
            &auth,
            "POST",
            "refresh",
            Some(&format!(r#"{{"refresh_token":"{refresh_token}"}}"#)),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{rotated}");
        assert!(rotated["refresh_token"].as_str().is_some());

        // Alt-Token ist verbraucht.
        let (status, body, _) = call(
            &auth,
            "POST",
            "refresh",
            Some(&format!(r#"{{"refresh_token":"{refresh_token}"}}"#)),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

        // Logout widerruft das rotierte Token.
        let new_token = rotated["refresh_token"].as_str().unwrap();
        let (status, _, headers) = call(
            &auth,
            "POST",
            "logout",
            Some(&format!(r#"{{"refresh_token":"{new_token}"}}"#)),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(headers.contains_key(header::SET_COOKIE));
        let (status, _, _) = call(
            &auth,
            "POST",
            "refresh",
            Some(&format!(r#"{{"refresh_token":"{new_token}"}}"#)),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cookie_mode_sets_http_only_strict_cookie_and_checks_origin() {
        let auth = crate::AppAuth::init(
            "demo",
            settings_with(|s| {
                s.allowed_origins = Some(vec!["https://app.example.com".to_string()].into());
            }),
            std::sync::Arc::new(steadfast_storage::MemoryStore::new()),
            None,
        )
        .unwrap();
        // Admin-Bootstrap ermoeglicht Register? Nein: registration_open ist an.
        let (status, _, _) = call(
            &auth,
            "POST",
            "register",
            Some(r#"{"email":"u@example.com","password":"Passw0rt!x"}"#),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let login = login_ok(&auth, true).await;
        assert!(
            login.get("refresh_token").is_none(),
            "Cookie-Modus: Refresh-Token NIE im Body"
        );

        // Set-Cookie der Login-Antwort fuer die weiteren Requests nutzen.
        let cookie = {
            let (status, _, headers) = call(
                &auth,
                "POST",
                "login",
                Some(r#"{"email":"u@example.com","password":"Passw0rt!x","use_cookie":true}"#),
                &[],
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            headers
                .get(header::SET_COOKIE)
                .expect("Set-Cookie")
                .to_str()
                .unwrap()
                .to_string()
        };
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("Path=/demo/_auth"));

        // Refresh MIT Cookie und erlaubter Origin: ok, neues Cookie.
        let (status, body, headers) = call(
            &auth,
            "POST",
            "refresh",
            None,
            &[("cookie", &cookie), ("origin", "https://app.example.com")],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("refresh_token").is_none());
        assert!(headers.contains_key(header::SET_COOKIE));

        // Ohne Origin-Header: CSRF-Verdacht -> 403.
        let (status, body, _) = call(&auth, "POST", "refresh", None, &[("cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["code"], json!("csrf_rejected"));

        // Fremde Origin: ebenfalls 403.
        let (status, _, _) = call(
            &auth,
            "POST",
            "refresh",
            None,
            &[("cookie", &cookie), ("origin", "https://evil.example")],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn cookie_mode_without_configured_origins_is_rejected() {
        let auth = test_app_auth(); // allowed_origins = None
        registered(&auth).await;
        let (status, body, _) = call(
            &auth,
            "POST",
            "login",
            Some(r#"{"email":"u@example.com","password":"Passw0rt!x","use_cookie":true}"#),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], json!("cookie_mode_disabled"));
    }

    #[tokio::test]
    async fn admin_endpoints_require_admin_role() {
        let auth = test_app_auth();
        registered(&auth).await; // Rolle "user"
        let user_login = login_ok(&auth, false).await;
        let user_token = user_login["access_token"].as_str().unwrap().to_string();

        // Ohne Token: 401. Mit User-Token: 403.
        let (status, body, _) = call(&auth, "GET", "users", None, &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        let (status, body, _) = call(
            &auth,
            "GET",
            "users",
            None,
            &[("authorization", &format!("Bearer {user_token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["code"], json!("forbidden"));

        // Admin anlegen (Bootstrap) und alle Verwaltungs-Operationen pruefen.
        let auth = crate::AppAuth::init(
            "demo",
            settings_with(|s| {
                s.admin = Some(steadfast_core::AdminBootstrap {
                    email: "admin@example.com".into(),
                    password: "Admin-Passw0rt!".into(),
                });
            }),
            std::sync::Arc::new(steadfast_storage::MemoryStore::new()),
            None,
        )
        .unwrap();
        let admin_login = login_ok_admin(&auth).await;
        let admin_token = admin_login["access_token"].as_str().unwrap().to_string();
        let bearer = format!("Bearer {admin_token}");

        let (status, list, _) = call(
            &auth,
            "GET",
            "users",
            None,
            &[("authorization", bearer.as_str())],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert!(list["total"].as_u64().unwrap() >= 1);

        let (status, created, _) = call(
            &auth,
            "POST",
            "users",
            Some(r#"{"email":"team@example.com","password":"Passw0rt!x","role":"editor"}"#),
            &[("authorization", bearer.as_str())],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let new_id = created["id"].as_str().unwrap().to_string();

        let (status, patched, _) = call(
            &auth,
            "PATCH",
            &format!("users/{new_id}"),
            Some(r#"{"disabled":true}"#),
            &[("authorization", bearer.as_str())],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{patched}");
        assert_eq!(patched["disabled"], json!(true));

        let (status, body, _) = call(
            &auth,
            "PATCH",
            "users/u_gibts_nicht",
            Some(r#"{"role":"admin"}"#),
            &[("authorization", bearer.as_str())],
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        // Ungueltige Rolle und leerer Patch: 400.
        let (status, _, _) = call(
            &auth,
            "PATCH",
            &format!("users/{new_id}"),
            Some(r#"{"role":"bad role!"}"#),
            &[("authorization", bearer.as_str())],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = call(
            &auth,
            "PATCH",
            &format!("users/{new_id}"),
            Some("{}"),
            &[("authorization", bearer.as_str())],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Demoted Admin verliert den Zugriff SOFORT (Rolle frisch gelesen):
        // Admin degradiert sich selbst.
        let (status, list, _) = call(
            &auth,
            "GET",
            "users",
            None,
            &[("authorization", bearer.as_str())],
        )
        .await;
        let admin_id = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|user| user["email"] == json!("admin@example.com"))
            .expect("Admin in der Liste")["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = call(
            &auth,
            "PATCH",
            &format!("users/{admin_id}"),
            Some(r#"{"role":"user"}"#),
            &[("authorization", bearer.as_str())],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = call(
            &auth,
            "GET",
            "users",
            None,
            &[("authorization", bearer.as_str())],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "Degradiert = sofort raus");
    }

    async fn login_ok_admin(auth: &AppAuth) -> Value {
        let (status, body, _) = call(
            auth,
            "POST",
            "login",
            Some(r#"{"email":"admin@example.com","password":"Admin-Passw0rt!"}"#),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    #[tokio::test]
    async fn login_rate_limit_returns_429_with_retry_after() {
        let auth = crate::AppAuth::init(
            "demo",
            settings_with(|s| {
                s.rate_limit.login_per_min = 3;
            }),
            std::sync::Arc::new(steadfast_storage::MemoryStore::new()),
            None,
        )
        .unwrap();
        let body = r#"{"email":"u@example.com","password":"Passw0rt!x"}"#;
        for _ in 0..3 {
            let (status, _, _) = call(&auth, "POST", "login", Some(body), &[]).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let (status, error, headers) = call(&auth, "POST", "login", Some(body), &[]).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{error}");
        assert_eq!(error["error"]["code"], json!("rate_limited"));
        assert!(headers.contains_key(header::RETRY_AFTER));
    }

    #[tokio::test]
    async fn lockout_after_threshold_failed_logins() {
        let auth = test_app_auth();
        registered(&auth).await;
        let wrong = r#"{"email":"u@example.com","password":"falsch-1234"}"#;
        for _ in 0..crate::LOGIN_FAILURE_THRESHOLD {
            let (status, _, _) = call(&auth, "POST", "login", Some(wrong), &[]).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        // Korrektes Passwort: gesperrt -> weiterhin (uniforme) 401.
        let (status, body, _) = call(
            &auth,
            "POST",
            "login",
            Some(r#"{"email":"u@example.com","password":"Passw0rt!x"}"#),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], json!("invalid_credentials"));
    }

    #[tokio::test]
    async fn unknown_paths_and_methods() {
        let auth = test_app_auth();
        let (status, _, headers) = call(&auth, "GET", "login", None, &[]).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers.get(header::ALLOW).unwrap(), "POST");

        let (status, _, _) = call(&auth, "POST", "gibtsnicht", Some("{}"), &[]).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _, _) = call(&auth, "POST", "users/u_1", Some("{}"), &[]).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

        let (status, _, _) = call(&auth, "GET", "", None, &[]).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "/_auth allein ist kein Endpoint"
        );
    }
}
