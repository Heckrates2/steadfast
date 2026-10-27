//! CORS-Middleware: setzt die pro-App-Regeln aus `[apps.<id>.cors]` um.
//!
//! * Preflights (`OPTIONS` + `Access-Control-Request-Method`) werden hier
//!   komplett beantwortet — 204 ohne Auth und ohne Storage-Zugriff, wie es
//!   die Fetch-Spezifikation vorsieht.
//! * Echte Requests mit `Origin` ausserhalb der Allowlist werden mit 403
//!   abgelehnt, statt sie ohne CORS-Header durchlaufen zu lassen — sonst
//!   wuerde der Browser die Antwort zwar blockieren, der Seiteneffekt
//!   (Schreiben!) waere aber schon passiert.
//! * Requests ohne `Origin`-Header (curl, Gateways, Server-to-Server) und
//!   Apps ohne `[cors]`-Sektion bleiben unangetastet — das Verhalten ist
//!   exakt wie vor der CORS-Einfuehrung.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use steadfast_core::{AllowedOrigins, CorsConfig};

use crate::handler;
use crate::state::{AppRoutes, AppState};

pub async fn cors_middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    // Erster Pfadsegment = app_id (`/{app_id}/...`); `/health` und der
    // Fallback matchen keine App und bleiben daher unangetastet.
    let app_id = req
        .uri()
        .path()
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("");
    let Some(cors) = state.app(app_id).and_then(AppRoutes::cors) else {
        return next.run(req).await;
    };

    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let Some(origin) = origin else {
        // Kein Origin-Header: kein Browser-Kontext, keine CORS-Pflicht.
        return next.run(req).await;
    };

    if !cors.origin_allowed(&origin) {
        return cors_rejected(&format!("origin `{origin}` is not allowed for this app"));
    }

    let is_preflight = req.method() == Method::OPTIONS
        && req
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);
    if is_preflight {
        return preflight(cors, &origin, req.headers());
    }

    let mut response = next.run(req).await;
    {
        let parts = response.headers_mut();
        write_common_headers(parts, cors, &origin);
        // Expose-Headers gehoert laut Fetch-Spec nur auf echte Antworten —
        // Preflights beantworten ihn nicht (deshalb fehlt er oben in
        // `preflight` bewusst).
        if let Ok(value) = cors.expose_headers_header().parse() {
            parts.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, value);
        }
    }
    response
}

/// Beantwortet einen bestandenen Preflight vollstaendig (204, leerer Body).
/// Methode und angefragte Header werden gegen die Allowlists geprueft —
/// ein Verstoess endet mit 403, bevor irgendetwas anderes laeuft.
fn preflight(cors: &CorsConfig, origin: &str, headers: &HeaderMap) -> Response {
    let requested_method = headers
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !cors.method_allowed(requested_method) {
        return cors_rejected(&format!(
            "method `{requested_method}` is not in cors.allowed_methods"
        ));
    }
    if let Some(raw) = headers
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|v| v.to_str().ok())
    {
        for name in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if !cors.header_allowed(name) {
                return cors_rejected(&format!("header `{name}` is not in cors.allowed_headers"));
            }
        }
    }

    let mut response = StatusCode::NO_CONTENT.into_response();
    {
        let parts = response.headers_mut();
        write_common_headers(parts, cors, origin);
        if let Ok(value) = cors.allow_methods_header().parse() {
            parts.insert(header::ACCESS_CONTROL_ALLOW_METHODS, value);
        }
        if let Ok(value) = cors.allow_headers_header().parse() {
            parts.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, value);
        }
        if let Some(age) = cors.max_age_secs {
            if let Ok(value) = age.to_string().parse() {
                parts.insert(header::ACCESS_CONTROL_MAX_AGE, value);
            }
        }
    }
    response
}

/// Header, die jede CORS-Antwort traegt (Preflight und echte Antwort):
/// Allow-Origin (Echo der passenden Origin oder `*`), optional
/// Allow-Credentials, plus `Vary: Origin` fuer cache-korrekte Proxies.
fn write_common_headers(parts: &mut axum::http::HeaderMap, cors: &CorsConfig, origin: &str) {
    let allow_origin = match cors.allowed_origins {
        AllowedOrigins::Any => HeaderValue::from_static("*"),
        // Echo des Request-Headers (kleinster gemeinsamer Nenner und Pflicht
        // neben allow_credentials) — der Wert ist bereits als visible-ASCII
        // validiert (`to_str`), das Echo kann also nicht fehlschlagen.
        AllowedOrigins::List(_) => origin.parse().expect("Origin ist visible ASCII"),
    };
    parts.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);
    if cors.allow_credentials {
        parts.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    parts.insert(header::VARY, HeaderValue::from_static("Origin"));
}

fn cors_rejected(reason: &str) -> Response {
    let mut response = handler::error_response(StatusCode::FORBIDDEN, "cors_rejected", reason);
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Origin"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::build_router;
    use crate::state::AppState;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use steadfast_core::EngineConfig;
    use steadfast_storage::MemoryStore;
    use tower::ServiceExt;

    /// Drei Apps: eine mit exakter Origin-Liste (restricted methods), eine
    /// mit Wildcard (eigene Header-Allowlist), eine ganz ohne [cors].
    const TEST_TOML: &str = r#"
[apps.web]
api_key_secret = "web_secret_123_geheim"

  [apps.web.cors]
  allowed_origins = ["https://app.example.com", "http://localhost:3000"]
  allowed_methods = ["GET", "POST"]
  exposed_headers = ["X-Request-Id", "Location"]
  max_age_secs = 600

  [apps.web.endpoints.tasks_get]
  path = "/tasks"
  method = "GET"

  [apps.web.endpoints.tasks_create]
  path = "/tasks"
  method = "POST"
  auth_required = true

[apps.open]

  [apps.open.cors]
  allowed_origins = ["*"]
  allowed_headers = ["content-type", "x-custom"]

  [apps.open.endpoints.items_get]
  path = "/items"
  method = "GET"

[apps.plain]

  [apps.plain.endpoints.things_get]
  path = "/things"
  method = "GET"
"#;

    fn app() -> axum::Router {
        let config = EngineConfig::from_toml(TEST_TOML).expect("test config");
        build_router(
            AppState::build_with_store(config, Arc::new(MemoryStore::new()), None).expect("state"),
        )
    }

    fn cors_req(method: &str, uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn preflight_from_allowed_origin_is_answered_204() {
        let response = send(
            app(),
            cors_req(
                "OPTIONS",
                "/web/tasks",
                &[
                    ("origin", "https://app.example.com"),
                    ("access-control-request-method", "GET"),
                    ("access-control-request-headers", "content-type, x-api-key"),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let h = response.headers();
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://app.example.com"
        );
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_METHODS).unwrap(),
            "GET, POST"
        );
        // Allowlist-Echo lowercase + sortiert.
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_HEADERS).unwrap(),
            "authorization, content-type, x-api-key, x-user-id, x-user-role"
        );
        assert_eq!(h.get(header::ACCESS_CONTROL_MAX_AGE).unwrap(), "600");
        assert_eq!(h.get(header::VARY).unwrap(), "Origin");
        // Expose-Headers gehoert NICHT in Preflight-Antworten (Fetch-Spec).
        assert!(h.get(header::ACCESS_CONTROL_EXPOSE_HEADERS).is_none());
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.is_empty(), "Preflight hat keinen Body");
    }

    #[tokio::test]
    async fn preflight_matches_origins_case_insensitively() {
        let response = send(
            app(),
            cors_req(
                "OPTIONS",
                "/web/tasks",
                &[
                    ("origin", "HTTP://LOCALHOST:3000"),
                    ("access-control-request-method", "POST"),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        // Echo bleibt der Original-Header-Wert des Requests.
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "HTTP://LOCALHOST:3000"
        );
    }

    #[tokio::test]
    async fn preflight_from_disallowed_origin_is_403() {
        let response = send(
            app(),
            cors_req(
                "OPTIONS",
                "/web/tasks",
                &[
                    ("origin", "https://evil.example.net"),
                    ("access-control-request-method", "GET"),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let h = response.headers();
        assert!(h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
        assert_eq!(h.get(header::VARY).unwrap(), "Origin");
    }

    #[tokio::test]
    async fn preflight_rejects_disallowed_method_and_header() {
        // DELETE ist nicht in allowed_methods = ["GET", "POST"].
        let response = send(
            app(),
            cors_req(
                "OPTIONS",
                "/web/tasks",
                &[
                    ("origin", "https://app.example.com"),
                    ("access-control-request-method", "DELETE"),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // x-stripe-signature ist nicht in der Default-Header-Allowlist.
        let response = send(
            app(),
            cors_req(
                "OPTIONS",
                "/web/tasks",
                &[
                    ("origin", "https://app.example.com"),
                    ("access-control-request-method", "POST"),
                    (
                        "access-control-request-headers",
                        "content-type, x-stripe-signature",
                    ),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Gross/kleinschreibung spielt bei Headern keine Rolle.
        let response = send(
            app(),
            cors_req(
                "OPTIONS",
                "/web/tasks",
                &[
                    ("origin", "https://app.example.com"),
                    ("access-control-request-method", "post"),
                    ("access-control-request-headers", "CONTENT-TYPE"),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn actual_request_from_allowed_origin_gets_cors_headers() {
        let response = send(
            app(),
            cors_req(
                "GET",
                "/web/tasks",
                &[("origin", "https://app.example.com")],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let h = response.headers();
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://app.example.com"
        );
        assert_eq!(h.get(header::VARY).unwrap(), "Origin");
        // Eigene Response-Header werden fuer Browser-JS freigegeben
        // (lowercase normalisiert und sortiert).
        assert_eq!(
            h.get(header::ACCESS_CONTROL_EXPOSE_HEADERS).unwrap(),
            "location, x-request-id"
        );
        // Allow-Methods/-Headers/-Max-Age gehoeren nur in Preflight-Antworten.
        assert!(h.get(header::ACCESS_CONTROL_ALLOW_METHODS).is_none());
    }

    #[tokio::test]
    async fn exposed_headers_default_to_location_without_explicit_config() {
        // App `open` hat eine [cors]-Sektion, aber keinen exposed_headers-Key:
        // Default ist `location` (der 201er-Header), damit Browser-JS die
        // Create-URL lesen kann.
        let response = send(
            app(),
            cors_req("GET", "/open/items", &[("origin", "https://any.dev")]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
                .unwrap(),
            "location"
        );
    }

    #[tokio::test]
    async fn actual_write_from_disallowed_origin_is_403_without_side_effect() {
        let router = app();
        // Der Browser wuerde die Antwort zwar blockieren — aber ohne 403
        // waere der Schreib-Side-Effect trotzdem passiert. Die Middleware
        // lehnt stattdessen den ganzen Request ab.
        let response = send(
            router.clone(),
            cors_req(
                "POST",
                "/web/tasks",
                &[
                    ("origin", "https://evil.example.net"),
                    ("content-type", "application/json"),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = send(router, cors_req("GET", "/web/tasks", &[])).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list["total"], 0, "der abgelehnte POST darf nichts anlegen");
    }

    #[tokio::test]
    async fn requests_without_origin_pass_through_untouched() {
        let response = send(app(), cors_req("GET", "/web/tasks", &[])).await;
        assert_eq!(response.status(), StatusCode::OK);
        let h = response.headers();
        assert!(h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
        assert!(h.get(header::VARY).is_none());

        // Auch ein OPTIONS ohne Preflight-Marker laeuft wie bisher in den
        // Handler (405/401 statt CORS-Antwort).
        let response = send(app(), cors_req("OPTIONS", "/web/tasks", &[])).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn app_without_cors_section_is_untouched() {
        let response = send(
            app(),
            cors_req(
                "GET",
                "/plain/things",
                &[("origin", "https://app.example.com")],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }

    #[tokio::test]
    async fn wildcard_app_answers_preflight_with_star() {
        let response = send(
            app(),
            cors_req(
                "OPTIONS",
                "/open/items",
                &[
                    ("origin", "https://anyone.dev"),
                    ("access-control-request-method", "GET"),
                    ("access-control-request-headers", "X-Custom"),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let h = response.headers();
        assert_eq!(h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_HEADERS).unwrap(),
            "content-type, x-custom"
        );
        assert!(h.get(header::ACCESS_CONTROL_MAX_AGE).is_none());
    }

    #[tokio::test]
    async fn health_and_fallback_carry_no_cors_headers() {
        let response = send(
            app(),
            cors_req("GET", "/health", &[("origin", "https://app.example.com")]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );

        let response = send(
            app(),
            cors_req(
                "GET",
                "/no_such_app/tasks",
                &[("origin", "https://app.example.com")],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }

    async fn send(router: axum::Router, request: Request<Body>) -> Response {
        router.oneshot(request).await.unwrap()
    }
}
