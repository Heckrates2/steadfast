//! Router-Aufbau: ein einziger Catch-All fängt alle App-Requests ab,
//! plus Health-Endpoint, Fallback und Request-Tracing-Middleware. Die
//! Trace-Layer sitzt ganz aussen und stempelt jedem Request eine
//! Request-ID auf: Header in der Antwort, Feld in der Log-Zeile.

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{HeaderName, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde_json::json;
use std::time::Instant;
use uuid::Uuid;

use crate::compression;
use crate::cors;
use crate::handler;
use crate::state::AppState;

/// Antwort-Header und Log-Feld fuer die Korrelation von Request und
/// Log-Zeile (Supportfall: ID aus der Fehlermeldung -> grep im Log).
const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Obergrenze fuer uebernommene Gateway-IDs — ein zu langer Wert ist kein
/// brauchbarer Identifier und wuerde Logzeilen aufblaehen.
const MAX_REQUEST_ID_LEN: usize = 128;

pub fn build_router(state: AppState) -> Router {
    let router = Router::new()
        .route("/health", get(health))
        .route("/{app_id}/{*rest}", any(handler::handle))
        .fallback(fallback)
        // N2: Body-Deckel fuer ALLE Endpunkte — auch Requests, deren Auth
        // erst nach dem Body-Extrahieren greift, koennen den Puffer nicht
        // mehr beliebig aufblaehen (413 statt OOM-Angriffsflaeche).
        .layer(DefaultBodyLimit::max(handler::MAX_BODY_BYTES))
        // CORS pro App: Preflights enden hier (204), echte Requests bekommen
        // die Access-Control-*Header bzw. 403 bei unerlaubter Origin.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            cors::cors_middleware,
        ));
    // gzip liegt zwischen CORS und Tracing: Responses tragen damit beide
    // Vary-Werte (Origin per insert in cors.rs, Accept-Encoding per append
    // in compression.rs). Ohne Accept-Encoding: gzip bleibt ein Request
    // unangetastet — Nicht-Browser-Clients sehen also nie gzip.
    let router = if state.compression_enabled() {
        router.layer(middleware::from_fn(compression::compression_middleware))
    } else {
        router
    };
    router
        .layer(middleware::from_fn(trace_request))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok", "mode": "monolith" }))
}

async fn fallback() -> Response {
    handler::error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "unknown route; requests must target /{app_id}/{collection}",
    )
}

/// Strukturiertes Request-Tracing: Request-ID, Methode, Pfad, Status,
/// Dauer in µs. Die ID kommt vom Gateway (`X-Request-Id`, damit die
/// Korrelation dienstuebergreifend erhalten bleibt) oder wird als
/// UUID v4 generiert; in beiden Faellen steht sie in der Antwort.
async fn trace_request(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let started = Instant::now();

    // Nur saubere, druckbare IDs uebernehmen — alles andere (zu lang,
    // Steuerzeichen) wird durch eine frische UUID ersetzt.
    let request_id = req
        .headers()
        .get(&REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|raw| {
            !raw.is_empty()
                && raw.len() <= MAX_REQUEST_ID_LEN
                && raw
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        })
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let mut response = next.run(req).await;
    if let Ok(value) = request_id.parse() {
        response.headers_mut().insert(&REQUEST_ID, value);
    }

    tracing::info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        status = response.status().as_u16(),
        elapsed_us = started.elapsed().as_micros() as u64,
        "request"
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use steadfast_core::EngineConfig;
    use steadfast_storage::MemoryStore;
    use tower::ServiceExt;

    const TEST_TOML: &str = r#"
[apps.plain]

  [apps.plain.endpoints.things_get]
  path = "/things"
  method = "GET"
"#;

    fn request_id_app() -> axum::Router {
        let config = EngineConfig::from_toml(TEST_TOML).expect("test config");
        build_router(
            AppState::build_with_store(config, Arc::new(MemoryStore::new()), None).expect("state"),
        )
    }

    async fn send(app: axum::Router, header: Option<(&str, &str)>) -> Response {
        let mut builder = Request::builder().method("GET").uri("/plain/things");
        if let Some((name, value)) = header {
            builder = builder.header(name, value);
        }
        app.oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn every_response_carries_a_generated_request_id() {
        let response = send(request_id_app(), None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let id = response.headers().get(&REQUEST_ID).expect("request id");
        assert_eq!(id.len(), 36, "generierte ID ist eine UUID v4");
        assert!(Uuid::parse_str(id.to_str().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn gateway_request_id_is_echoed() {
        let response = send(request_id_app(), Some(("x-request-id", "gw-abc-123"))).await;
        assert_eq!(response.headers().get(&REQUEST_ID).unwrap(), "gw-abc-123");
    }

    #[tokio::test]
    async fn unusable_request_ids_are_replaced() {
        // 200 Zeichen: zu lang — der Header wird neu generiert.
        let response = send(request_id_app(), Some(("x-request-id", &"a".repeat(200)))).await;
        let id = response.headers().get(&REQUEST_ID).unwrap();
        assert_ne!(id.len(), 200);
        assert_eq!(id.len(), 36);

        // Steuerzeichen (Tab ist als Header-Wert technisch erlaubt) ebenso.
        let response = send(request_id_app(), Some(("x-request-id", "bad\tid"))).await;
        let id = response.headers().get(&REQUEST_ID).unwrap();
        assert!(Uuid::parse_str(id.to_str().unwrap()).is_ok());
    }
}
