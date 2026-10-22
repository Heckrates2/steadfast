//! Router-Aufbau: ein einziger Catch-All fängt alle App-Requests ab,
//! plus Health-Endpoint, Fallback und Request-Tracing-Middleware.

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde_json::json;
use std::time::Instant;

use crate::handler;
use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/{app_id}/{*rest}", any(handler::handle))
        .fallback(fallback)
        // N2: Body-Deckel fuer ALLE Endpunkte — auch Requests, deren Auth
        // erst nach dem Body-Extrahieren greift, koennen den Puffer nicht
        // mehr beliebig aufblaehen (413 statt OOM-Angriffsflaeche).
        .layer(DefaultBodyLimit::max(handler::MAX_BODY_BYTES))
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

/// Strukturiertes Request-Tracing: Methode, Pfad, Status, Dauer in µs.
async fn trace_request(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let started = Instant::now();

    let response = next.run(req).await;

    tracing::info!(
        method = %method,
        path = %path,
        status = response.status().as_u16(),
        elapsed_us = started.elapsed().as_micros() as u64,
        "request"
    );
    response
}
