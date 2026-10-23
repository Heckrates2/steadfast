//! gzip-Komprimierung fuer grosse JSON-Antworten per Content-Negotiation.
//!
//! Der Layer sitzt zwischen CORS- und Tracing-Middleware (Request-Flow:
//! trace -> compression -> cors -> handler) und komprimiert nur, wenn
//!
//! * der Client `Accept-Encoding: gzip` (oder `*`) schickt,
//! * die Antwort `application/json` ist und
//! * der Body mindestens `MIN_COMPRESS_BYTES` gross ist.
//!
//! Ohne `Accept-Encoding` bleibt ein Request komplett unangetastet (auch
//! kein `Vary`) — curl-Skripte und Gateways sehen also exakt dasselbe wie
//! vor der Einfuehrung. Das ist der Grund, warum die Komprimierung
//! standardmaessig an ist und nur per `--no-compression` abgeschaltet
//! werden muss, nie umgekehrt.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;

use crate::handler;

/// Unter dieser Groesse ist gzip ein Netto-Verlust: Der gzip-Fussabdruck
/// (~20 Bytes Header/Trailer) und die JSON-Struktur kleiner Listen fressen
/// die Ersparnis; Clients sollten solche Antworten lieber unkomprimiert
/// cachen koennen.
const MIN_COMPRESS_BYTES: usize = 1024;

/// Sicherheitsnetz beim Einsammeln des Bodys. Saemtliche Handler-Antworten
/// sind ohnehin vollstaendig gepuffert (`Json` serialisiert in den
/// Speicher), der Wert deckt also auch unrealistisch grosse
/// Listen-Antworten (100 Dokumente an der 1-MiB-Dokumentgrenze) ab.
const MAX_COLLECT_BYTES: usize = 256 * 1024 * 1024;

pub async fn compression_middleware(req: Request, next: Next) -> Response {
    // Kein gzip-Wunsch: unangetastet durchreichen — auch ohne Vary, denn
    // ohne Verhandlung variiert die Antwort nicht nach Client.
    if !accepts_gzip(req.headers()) {
        return next.run(req).await;
    }

    let response = next.run(req).await;
    if !compressible_json(response.headers()) {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_COLLECT_BYTES).await {
        Ok(bytes) if bytes.len() >= MIN_COMPRESS_BYTES => bytes,
        Ok(bytes) => return Response::from_parts(parts, Body::from(bytes)),
        Err(_) => {
            // Praktisch unerreichbar (size_hint ist bei unseren gepufferten
            // Bodies exakt); der Body ist weg, also ehrlicher 500 statt
            // eines korrupten Responses — engine_error_response loggt das
            // als warn.
            return handler::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "internal error",
            );
        }
    };

    match gzip(&bytes) {
        Some(compressed) => {
            parts
                .headers
                .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
            // Content-Length passt nach der Komprimierung nicht mehr —
            // entfernen; axum setzt sie beim Antworten anhand der finalen
            // Body-Groesse neu.
            parts.headers.remove(header::CONTENT_LENGTH);
            // append statt insert: Neben dem `Vary: Origin` der
            // CORS-Middleware (insert dort), damit Caches beide
            // Variations-Achsen sehen.
            parts
                .headers
                .append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
            Response::from_parts(parts, Body::from(compressed))
        }
        None => Response::from_parts(parts, Body::from(bytes)),
    }
}

/// Content-Negotiation: gzip (oder `*`) unter den Offer-Encoding-Tokens,
/// case-insensitive, q=0 zaehlt als explizite Ablehnung (RFC 9110).
fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .any(|value| {
            value.to_str().is_ok_and(|raw| {
                raw.split(',').any(|candidate| {
                    let mut halves = candidate.splitn(2, ';');
                    let token = halves.next().unwrap_or("").trim();
                    if !(token.eq_ignore_ascii_case("gzip") || token == "*") {
                        return false;
                    }
                    // q-Parameter: q=0 bedeutet "nicht akzeptabel".
                    !halves.next().is_some_and(|params| {
                        params.split(';').any(|param| {
                            param
                                .trim()
                                .strip_prefix("q=")
                                .is_some_and(|q| q.trim().parse::<f32>().is_ok_and(|q| q == 0.0))
                        })
                    })
                })
            })
        })
}

/// Nur `application/json` ohne bereits vorhandene Content-Encoding
/// (niemals doppelt komprimieren) kommt infrage. Der Praefix-Vergleich
/// erlaubt Parameter wie `application/json; charset=utf-8`.
fn compressible_json(headers: &HeaderMap) -> bool {
    if headers.contains_key(header::CONTENT_ENCODING) {
        return false;
    }
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|content_type| {
            content_type
                .get(..16)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/json"))
        })
}

/// gzip auf Level 6 (flate2-Default, miniz_oxide-Backend): bester
/// Kompromiss aus Groesse und CPU auf dem Hot Path.
fn gzip(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = GzEncoder::new(
        // JSON gewinnt typischerweise 60-80%; die Startkapazitaet vermeidet
        // das erste Wachstum des Zielvektors.
        Vec::with_capacity(bytes.len() / 4),
        Compression::default(),
    );
    encoder.write_all(bytes).ok()?;
    encoder.finish().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::build_router;
    use crate::state::AppState;
    use axum::body::Body;
    use axum::http::Request;
    use flate2::read::GzDecoder;
    use http_body_util::BodyExt;
    use std::io::Read;
    use std::sync::Arc;
    use steadfast_core::EngineConfig;
    use steadfast_storage::MemoryStore;
    use tower::ServiceExt;

    /// `big` ohne CORS-Sektion (Vary kommt dort nur vom gzip-Layer), `web`
    /// mit CORS fuer den Vary-Koexistenztest.
    const TEST_TOML: &str = r#"
[apps.big]

  [apps.big.endpoints.items_get]
  path = "/items"
  method = "GET"

[apps.web]
api_key_secret = "web_secret_123_geheim"

  [apps.web.cors]
  allowed_origins = ["https://app.example.com"]

  [apps.web.endpoints.items_get]
  path = "/items"
  method = "GET"
"#;

    const MARKER: &[u8] = b"STEADFAST_GZIP_MARKER";

    /// Leerer Store plus ein ~64-KiB-Dokument in `big`: komprimierbar,
    /// aber gut unter der Sammel-Obergrenze.
    fn app_with_big_doc() -> (axum::Router, Arc<MemoryStore>) {
        let store = Arc::new(MemoryStore::new());
        let config = EngineConfig::from_toml(TEST_TOML).expect("test config");
        let router = build_router(
            AppState::build_with_store(config, Arc::clone(&store), None).expect("state"),
        );
        store.insert(
            "big",
            "items",
            "i1",
            serde_json::json!({
                "marker": "STEADFAST_GZIP_MARKER",
                "note": "x".repeat(64 * 1024),
            }),
        );
        (router, store)
    }

    fn get(uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder().method("GET").uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).unwrap()
    }

    async fn send(router: axum::Router, request: Request<Body>) -> Response {
        router.oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn large_json_is_gzipped_when_client_accepts_gzip() {
        let (router, _) = app_with_big_doc();
        let response = send(router, get("/big/items", &[("accept-encoding", "gzip")])).await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers().clone();
        assert_eq!(headers.get(header::CONTENT_ENCODING).unwrap(), "gzip");
        assert_eq!(headers.get(header::VARY).unwrap(), "Accept-Encoding");

        let compressed = response.into_body().collect().await.unwrap().to_bytes();
        // Content-Length passt zum komprimierten Body: Die alte GET-Groesse
        // entfernt die Middleware, axum setzt sie anhand der finalen
        // Body-Groesse neu.
        if let Some(length) = headers.get(header::CONTENT_LENGTH) {
            assert_eq!(length.as_bytes(), compressed.len().to_string().as_bytes());
        }

        let mut plain = Vec::new();
        GzDecoder::new(&compressed[..])
            .read_to_end(&mut plain)
            .unwrap();
        assert!(
            plain.len() > compressed.len(),
            "gzip muss bei 64 KiB Repetition deutlich gewinnen"
        );
        let list: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(list["total"], 1);
        assert!(
            plain.windows(MARKER.len()).any(|w| w == MARKER),
            "dekomprimierter Body muss das Dokument enthalten"
        );
    }

    #[tokio::test]
    async fn no_accept_encoding_means_identity() {
        let (router, _) = app_with_big_doc();
        let response = send(router, get("/big/items", &[])).await;
        assert_eq!(response.status(), StatusCode::OK);
        let h = response.headers();
        assert!(h.get(header::CONTENT_ENCODING).is_none());
        assert!(
            h.get(header::VARY).is_none(),
            "ohne Verhandlung gibt es keine Vary-Pflicht"
        );
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.windows(MARKER.len()).any(|w| w == MARKER));
    }

    #[tokio::test]
    async fn other_encodings_and_q_zero_stay_identity() {
        let (router, _) = app_with_big_doc();
        for accept in ["deflate, br", "identity", "gzip;q=0", "*;q=0"] {
            let response = send(
                router.clone(),
                get("/big/items", &[("accept-encoding", accept)]),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(
                response.headers().get(header::CONTENT_ENCODING).is_none(),
                "`{accept}` darf nicht zu gzip fuehren"
            );
        }
    }

    #[tokio::test]
    async fn responses_below_threshold_stay_uncompressed() {
        let (router, _) = app_with_big_doc();
        // App `web` hat keine Dokumente — die leere Liste ist klein.
        let response = send(router, get("/web/items", &[("accept-encoding", "gzip")])).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::CONTENT_ENCODING).is_none());
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.len() < MIN_COMPRESS_BYTES);
    }

    #[tokio::test]
    async fn cors_and_compression_vary_headers_coexist() {
        let (router, store) = app_with_big_doc();
        store.insert(
            "web",
            "items",
            "w1",
            serde_json::json!({
                "marker": "STEADFAST_GZIP_MARKER",
                "note": "y".repeat(64 * 1024),
            }),
        );
        let response = send(
            router,
            get(
                "/web/items",
                &[
                    ("accept-encoding", "gzip"),
                    ("origin", "https://app.example.com"),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let h = response.headers();
        assert_eq!(h.get(header::CONTENT_ENCODING).unwrap(), "gzip");
        let vary: Vec<_> = h.get_all(header::VARY).iter().collect();
        assert!(
            vary.iter().any(|v| v.as_bytes() == b"Origin"),
            "Vary: Origin (CORS) fehlt: {vary:?}"
        );
        assert!(
            vary.iter().any(|v| v.as_bytes() == b"Accept-Encoding"),
            "Vary: Accept-Encoding (gzip) fehlt: {vary:?}"
        );
    }
}
