//! Authentifizierung und User-Kontext.
//!
//! MVP-Vertrauensmodell (Gateway-Pattern): `X-API-Key` wird gehasht
//! (SHA-256) und die Digests constant-time verglichen; `X-User-Id`/
//! `X-User-Role` werden als User-Metadaten an die Rhai-Logik durchgereicht.
//! Im Enterprise-Modus (Phase 3) setzt der Gateway diese Header aus
//! verifizierten JWT-Claims und entfernt client-seitige Faelschungen.
//!
//! H1'-Haertung: Identitaets-Header duerfen nie mehrfach vorkommen (ein
//! anhaengendes Gateway wuerde sonst den gefaelschten Client-Wert zum
//! ersten Wert machen) — solche Requests werden mit 400 abgelehnt. Und
//! optional (`ENGINE_GATEWAY_SECRET`) werden `X-User-*`-Header nur noch
//! honoring, wenn der Request per `X-Internal-Auth` seine Herkunft vom
//! Gateway beweist.

use axum::http::HeaderMap;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub(crate) const API_KEY_HEADER: &str = "x-api-key";
const USER_ID_HEADER: &str = "x-user-id";
const USER_ROLE_HEADER: &str = "x-user-role";
/// Gateway-Provenienz: Shared Secret, das nur dem Gateway bekannt ist.
pub(crate) const INTERNAL_AUTH_HEADER: &str = "x-internal-auth";

const DEFAULT_USER_ID: &str = "anonymous";
const DEFAULT_USER_ROLE: &str = "user";

const MAX_USER_ID_LEN: usize = 128;
const MAX_USER_ROLE_LEN: usize = 64;

/// Constant-time Vergleich des gelieferten Keys gegen das App-Secret.
/// `None` (Header fehlt) schlaegt immer fehl.
///
/// Beide Seiten werden vorher auf SHA-256 reduziert und die 32-Byte-Digests
/// constant-time verglichen: Der Vergleich ist damit timing-neutral, egal
/// wie lang der gelieferte Key ist. (Rohe `ct_eq` ueber ungleiche
/// Bytelaengen bricht ab, sobald der kuerzere Z.input aufgebraucht ist —
/// ein Remote-Beobachter koennte daraus die Secret-Laenge ablesen.)
pub fn verify_api_key(provided: Option<&str>, secret: &str) -> bool {
    let Some(key) = provided else {
        return false;
    };
    let key_digest = Sha256::digest(key.as_bytes());
    let secret_digest = Sha256::digest(secret.as_bytes());
    bool::from(key_digest.as_slice().ct_eq(secret_digest.as_slice()))
}

/// Constant-time Vergleich des gelieferten Gateway-Secrets gegen das
/// konfigurierte — identisches SHA-256-Digest-Muster wie beim API-Key.
pub fn verify_gateway_secret(provided: Option<&str>, secret: &str) -> bool {
    verify_api_key(provided, secret)
}

/// H1': Liefert den Namen des ersten Identitaets-Headers, der mehrfach im
/// Request vorkommt (`HeaderMap::get` wuerde sonst stillschweigend den
/// ERSTEN Wert nehmen — bei einem Gateway mit Append-Semantik gewinnt so
/// der gefaelschte Client-Wert). Solche Requests sind mehrdeutig und werden
/// an der HTTP-Kante mit 400 abgelehnt, bevor irgendeine Sicherheits-
/// entscheidung auf sie gestuetzt wird.
pub(crate) fn duplicate_identity_header(headers: &HeaderMap) -> Option<&'static str> {
    [
        (API_KEY_HEADER, "x-api-key"),
        (USER_ID_HEADER, "x-user-id"),
        (USER_ROLE_HEADER, "x-user-role"),
        (INTERNAL_AUTH_HEADER, "x-internal-auth"),
    ]
    .into_iter()
    .find(|(name, _)| headers.get_all(*name).into_iter().count() > 1)
    .map(|(_, display)| display)
}

/// Extrahiert den User-Kontext fuer die Rhai-Logik aus den Headern:
/// `user.id` und `user.role` (mit Defaults fuer fehlende Header).
///
/// `identity_trusted == false` (Gateway-Secret konfiguriert, der Request
/// hat seine Herkunft per `X-Internal-Auth` NICHT belegt): Die
/// `X-User-*`-Header werden ignoriert und die Defaults verwendet — ein
/// Direktzugriff auf den Engine-Port kann damit keine Rolle schmieden,
/// selbst wenn der Angreifer Header-Setzung beherrscht.
pub fn extract_user(headers: &HeaderMap, identity_trusted: bool) -> serde_json::Value {
    if !identity_trusted {
        return json!({ "id": DEFAULT_USER_ID, "role": DEFAULT_USER_ROLE });
    }
    let id = header_string(headers, USER_ID_HEADER, DEFAULT_USER_ID, MAX_USER_ID_LEN);
    let role = header_string(headers, USER_ROLE_HEADER, DEFAULT_USER_ROLE, MAX_USER_ROLE_LEN);
    json!({ "id": id, "role": role })
}

fn header_string(headers: &HeaderMap, name: &str, default: &str, max_len: usize) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            if value.len() > max_len {
                let mut truncated = value.to_string();
                truncated.truncate(max_len);
                truncated
            } else {
                value.to_string()
            }
        })
        .unwrap_or_else(|| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn api_key_must_match_exactly() {
        assert!(verify_api_key(Some("secret123"), "secret123"));
        assert!(!verify_api_key(Some("secret124"), "secret123"));
        assert!(!verify_api_key(Some(""), "secret123"));
        assert!(!verify_api_key(Some("secret123 "), "secret123"));
        assert!(!verify_api_key(None, "secret123"));
    }

    #[test]
    fn user_context_defaults_and_limits() {
        let mut headers = HeaderMap::new();
        let user = extract_user(&headers, true);
        assert_eq!(user["id"], json!("anonymous"));
        assert_eq!(user["role"], json!("user"));

        headers.insert("x-user-id", "u1".parse().unwrap());
        headers.insert("x-user-role", "premium".parse().unwrap());
        let user = extract_user(&headers, true);
        assert_eq!(user["id"], json!("u1"));
        assert_eq!(user["role"], json!("premium"));

        // Leer = Default; zu lang = gekuerzt.
        headers.insert("x-user-id", "  ".parse().unwrap());
        headers.insert(
            "x-user-role",
            "x".repeat(500).parse().unwrap(),
        );
        let user = extract_user(&headers, true);
        assert_eq!(user["id"], json!("anonymous"));
        assert_eq!(user["role"].as_str().unwrap().len(), MAX_USER_ROLE_LEN);
    }

    #[test]
    fn untrusted_identity_falls_back_to_defaults() {
        // Gateway-Secret aktiv, Provenienz nicht belegt: gespoofte
        // X-User-*-Header duerfen die Defaults nicht durchdringen.
        let mut headers = HeaderMap::new();
        headers.insert("x-user-id", "attacker".parse().unwrap());
        headers.insert("x-user-role", "premium".parse().unwrap());
        let user = extract_user(&headers, false);
        assert_eq!(user["id"], json!("anonymous"));
        assert_eq!(user["role"], json!("user"));
    }

    #[test]
    fn duplicate_identity_headers_are_detected() {
        let mut headers = HeaderMap::new();
        assert_eq!(duplicate_identity_header(&headers), None);

        headers.insert("x-api-key", "a".parse().unwrap());
        assert_eq!(duplicate_identity_header(&headers), None);

        headers.append("x-api-key", "b".parse().unwrap());
        assert_eq!(duplicate_identity_header(&headers), Some("x-api-key"));

        let mut headers = HeaderMap::new();
        headers.insert("x-user-role", "user".parse().unwrap());
        headers.append("x-user-role", "admin".parse().unwrap());
        assert_eq!(duplicate_identity_header(&headers), Some("x-user-role"));

        let mut headers = HeaderMap::new();
        headers.insert("x-internal-auth", "a".parse().unwrap());
        headers.append("x-internal-auth", "b".parse().unwrap());
        assert_eq!(duplicate_identity_header(&headers), Some("x-internal-auth"));
    }

    #[test]
    fn gateway_secret_must_match_exactly() {
        assert!(verify_gateway_secret(Some("gateway-geheim"), "gateway-geheim"));
        assert!(!verify_gateway_secret(Some("gateway-gehei"), "gateway-geheim"));
        assert!(!verify_gateway_secret(None, "gateway-geheim"));
        assert!(!verify_gateway_secret(Some(""), "gateway-geheim"));
    }
}
