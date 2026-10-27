//! Optionaler Cookie-Modus fuer Browser-Clients.
//!
//! Das Refresh-Token kann statt im Response-Body als Cookie ausgeliefert
//! werden: `HttpOnly` (JS kann es nicht lesen — XSS kann es nicht exfilie-
//! ren), `Secure` (nur HTTPS), `SameSite=Strict` (kein Cross-Site-Mitsenden)
//! und auf `Path=/{app_id}/_auth` begrenzt. Das kurzlebige Access-Token
//! bleibt immer im Body/Header — die Engine liest es aus `Authorization`.
//!
//! CSRF-Schutz: Requests, die das Cookie verwenden (refresh/logout), muessen
//! einen `Origin`-Header tragen, der exakt in der Allowlist steht. Fehlt der
//! Header oder stimmt er nicht: 403. Zusammen mit `SameSite=Strict` deckt
//! das Cross-Site-Requests ab, bevor sie ein Token konsumieren.

use axum::http::HeaderMap;

pub(crate) const REFRESH_COOKIE: &str = "steadfast_refresh";
/// Refresh-Tokens sind 43 Zeichen base64url; Luft nach oben gegen
/// Missbrauch des Cookie-Headers als Datenschleuder.
const MAX_COOKIE_VALUE_LEN: usize = 128;

/// Set-Cookie-Wert fuer ein frisches Refresh-Token.
pub(crate) fn set_cookie_value(app_id: &str, token: &str, max_age_secs: u64) -> String {
    format!(
        "{REFRESH_COOKIE}={token}; Path=/{app_id}/_auth; HttpOnly; Secure; \
         SameSite=Strict; Max-Age={max_age_secs}"
    )
}

/// Set-Cookie-Wert zum Loeschen (Logout).
pub(crate) fn clear_cookie_value(app_id: &str) -> String {
    format!(
        "{REFRESH_COOKIE}=; Path=/{app_id}/_auth; HttpOnly; Secure; \
             SameSite=Strict; Max-Age=0"
    )
}

/// Liest das Refresh-Token aus dem `Cookie`-Header (`name=value`-Paare,
/// `;`-getrennt).
pub(crate) fn read_refresh_cookie(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all(axum::http::header::COOKIE) {
        let raw = value.to_str().ok()?;
        for pair in raw.split(';') {
            let pair = pair.trim();
            if let Some(cookie_value) = pair.strip_prefix(REFRESH_COOKIE) {
                let cookie_value = cookie_value.strip_prefix('=')?.trim();
                if !cookie_value.is_empty() && cookie_value.len() <= MAX_COOKIE_VALUE_LEN {
                    return Some(cookie_value.to_string());
                }
                return None;
            }
        }
    }
    None
}

/// Origin-Check (CSRF-Schutz): Der `Origin`-Header muss vorhanden und exakt
/// (case-insensitive) in der Allowlist sein.
pub(crate) fn origin_allowed(origins: &[String], headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return false;
    };
    origins
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(origin))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn cookie_headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::COOKIE, value.parse().unwrap());
        headers
    }

    #[test]
    fn cookie_attributes_are_complete() {
        let cookie = set_cookie_value("demo", "tok", 1234);
        assert!(cookie.contains("steadfast_refresh=tok"));
        assert!(cookie.contains("Path=/demo/_auth"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Max-Age=1234"));

        let clear = clear_cookie_value("demo");
        assert!(clear.contains("steadfast_refresh=;"));
        assert!(clear.contains("Max-Age=0"));
    }

    #[test]
    fn cookie_parsing_among_other_cookies() {
        let headers = cookie_headers("a=1; steadfast_refresh=abc123; b=2");
        assert_eq!(read_refresh_cookie(&headers).as_deref(), Some("abc123"));

        let headers = cookie_headers("steadfast_refresh=first");
        assert_eq!(read_refresh_cookie(&headers).as_deref(), Some("first"));

        // Leer, zu lang, nicht vorhanden.
        assert_eq!(
            read_refresh_cookie(&cookie_headers("steadfast_refresh=")),
            None
        );
        assert_eq!(
            read_refresh_cookie(&cookie_headers(&format!(
                "steadfast_refresh={}",
                "x".repeat(500)
            ))),
            None
        );
        assert_eq!(read_refresh_cookie(&cookie_headers("other=1")), None);
        assert_eq!(read_refresh_cookie(&HeaderMap::new()), None);
    }

    #[test]
    fn origin_check_requires_exact_known_origin() {
        let origins = vec!["https://app.example.com".to_string()];
        let mut headers = HeaderMap::new();
        assert!(!origin_allowed(&origins, &headers), "ohne Origin: nein");

        headers.insert(
            axum::http::header::ORIGIN,
            "https://app.example.com".parse().unwrap(),
        );
        assert!(origin_allowed(&origins, &headers));
        headers.insert(
            axum::http::header::ORIGIN,
            "HTTPS://APP.EXAMPLE.COM".parse().unwrap(),
        );
        assert!(origin_allowed(&origins, &headers), "case-insensitive");

        headers.insert(
            axum::http::header::ORIGIN,
            "https://evil.example".parse().unwrap(),
        );
        assert!(!origin_allowed(&origins, &headers));
        headers.insert(
            axum::http::header::ORIGIN,
            "https://app.example.com.evil.dev".parse().unwrap(),
        );
        assert!(!origin_allowed(&origins, &headers), "kein Suffix-Match");
        headers.insert(axum::http::header::ORIGIN, "null".parse().unwrap());
        assert!(!origin_allowed(&origins, &headers));
    }
}
