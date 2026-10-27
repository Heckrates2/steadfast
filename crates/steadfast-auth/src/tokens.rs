//! JWT-Access-Tokens (HS256, Secret der jeweiligen App) und der Lebenszyklus
//! der opaken Refresh-Tokens.
//!
//! Refresh-Tokens sind 32 Bytes `OsRng` als base64url; im Store liegt nur der
//! SHA-256-Hash des Tokens als Dokument-ID (Digest-Muster wie beim API-Key —
//! ein Leak des Stores gibt die Tokens nicht frei). Rotation: Jeder Refresh
//! erzeugt ein neues Token und markiert das alte atomar als `revoked`
//! (`patch_merge` unter dem Kollektions-Schreib-Mutex — ein Token kann nur
//! einmal "verbraucht" werden).
//!
//! Wird ein bereits rotiertes Token erneut vorgelegt (Wiederverwendung —
//! Indiz fuer Token-Diebstahl), werden ALLE Refresh-Tokens des Benutzers
//! gesperrt (Cascade) und der Vorfall als Audit-Warnung geloggt; der
//! Angreifer UND das Opfer muessen sich neu einloggen.

use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use sha2::Digest;

use crate::AppAuth;
use crate::now_unix;

/// Wie lange Revocation-Evidence nach Ablauf gehalten wird, bevor der
/// Sweeper die Dokumente loescht (Wiederverwendung auch noch Tage spaeter
/// erkennbar, Store wächst nicht endlos).
const REUSE_EVIDENCE_SECS: u64 = 7 * 24 * 3600;

/// Access-Token-Claims. `iss = "steadfast:<app_id>"` bindet Tokens an ihre
/// App — ein Token von App A faellt bei App B schon am Issuer-D check durch
/// (von der anderen Signatur gar nicht zu sprechen).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Benutzer-ID (`sub`).
    pub sub: String,
    /// Rolle zum Ausstellungszeitpunkt (Admin-Endpunkte pruefen frisch im
    /// Store; hier dient sie Audit/Logging).
    pub role: String,
    pub iat: u64,
    pub exp: u64,
    /// Eindeutige Token-ID (Korrelation im Log).
    pub jti: String,
    pub iss: String,
}

pub(crate) fn issuer(app_id: &str) -> String {
    format!("steadfast:{app_id}")
}

/// Signiert ein Access-Token (HS256, `exp = now + ttl`).
pub(crate) fn encode_access(
    key: &jsonwebtoken::EncodingKey,
    app_id: &str,
    user_id: &str,
    role: &str,
    now_unix: u64,
    ttl_secs: u64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: user_id.to_string(),
        role: role.to_string(),
        iat: now_unix,
        exp: now_unix.saturating_add(ttl_secs),
        jti: uuid::Uuid::new_v4().to_string(),
        iss: issuer(app_id),
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        key,
    )
}

/// Verifizert Signatur (nur HS256 — Algorithmus-Verwirrung ist damit
/// strukturell ausgeschlossen), `exp` und den App-Issuer.
pub(crate) fn decode_access(
    token: &str,
    key: &jsonwebtoken::DecodingKey,
    app_id: &str,
) -> Option<Claims> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    // Issuer manuell pruefen statt ueber die Validation-Struct (Version-
    // stabiler) — decode prueft Signatur + exp, der iss-Vergleich danach.
    jsonwebtoken::decode::<Claims>(token, key, &validation)
        .ok()
        .map(|data| data.claims)
        .filter(|claims| claims.iss == issuer(app_id))
}

/// Frischer Refresh-Token: 32 Bytes OsRng, base64url ohne Padding (43 Zeichen).
pub(crate) fn generate_refresh_token() -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

/// Speicher-ID eines Refresh-Tokens: hex(SHA-256) — nie der Token selbst.
pub(crate) fn refresh_hash(token: &str) -> String {
    let digest = sha2::Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Ergebnis einer Refresh-Rotation.
pub(crate) struct IssuedTokens {
    pub access_token: String,
    pub access_ttl: u64,
    pub refresh_token: String,
    pub refresh_ttl: u64,
}

/// Fehler der Rotation — allesamt 401 beim Aufrufer (einheitliche Meldung,
/// keine Unterscheidung nach Aussen).
#[derive(Debug)]
pub(crate) enum RefreshError {
    /// Unbekannt, abgelaufen oder zwischenzeitlich weggeraeumt.
    Invalid,
    /// Wiederverwendung eines rotierten Tokens — Cascade ist bereits gelaufen.
    Reused,
    /// Benutzer existiert nicht mehr oder ist gesperrt — Cascade gelaufen.
    UserGone,
}

impl AppAuth {
    /// Stellt fuer einen Benutzer ein frisches Token-Paar aus (Login): legt
    /// das Refresh-Dokument an und signiert das Access-Token.
    pub(crate) fn issue_tokens(&self, user_id: &str, role: &str) -> Option<IssuedTokens> {
        let now = now_unix();
        let access_token = encode_access(
            self.encode_key(),
            &self.app_id,
            user_id,
            role,
            now,
            self.settings.access_token_secs,
        )
        .ok()?;
        let refresh_token = generate_refresh_token();
        self.store
            .create(
                &self.app_id,
                crate::REFRESH_COLLECTION,
                &refresh_hash(&refresh_token),
                json!({
                    "user_id": user_id,
                    "created_at": now,
                    "expires_at": now.saturating_add(self.settings.refresh_token_secs),
                    "revoked": false,
                    "replaced_by": serde_json::Value::Null,
                    "revoked_at": 0,
                }),
            )
            .ok()?;
        Some(IssuedTokens {
            access_token,
            access_ttl: self.settings.access_token_secs,
            refresh_token,
            refresh_ttl: self.settings.refresh_token_secs,
        })
    }

    /// Rotiert ein vorgelegtes Refresh-Token atomar: genau ein Aufruf
    /// gewinnt (das alte Dokument wird unter dem Kollektions-Schreib-Mutex
    /// auf `revoked` gesetzt), ein zweiter Versuch mit demselben Token
    /// triggert die Wiederverwendungs-Cascade.
    pub(crate) fn rotate_refresh(&self, presented: &str) -> Result<IssuedTokens, RefreshError> {
        let now = now_unix();
        let hash = refresh_hash(presented);
        let existing = self
            .store
            .get(&self.app_id, crate::REFRESH_COLLECTION, &hash)
            .ok_or(RefreshError::Invalid)?;

        if existing
            .get("expires_at")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            <= now
        {
            // Abgelaufen: sofort loeschen (kein Evidence-Bedarf) und ablehnen.
            self.store
                .delete(&self.app_id, crate::REFRESH_COLLECTION, &hash);
            return Err(RefreshError::Invalid);
        }
        let user_id = existing
            .get("user_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if user_id.is_empty() {
            return Err(RefreshError::Invalid);
        }

        // Neues Token zuerst ziehen: Der atomare Claim auf das alte Dokument
        // traegt den Hash des Nachfolgers als `replaced_by` (Evidence).
        let new_token = generate_refresh_token();
        let new_hash = refresh_hash(&new_token);
        let claim =
            self.store
                .patch_merge(&self.app_id, crate::REFRESH_COLLECTION, &hash, |mut doc| {
                    if doc
                        .get("revoked")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        return Err(());
                    }
                    doc["revoked"] = json!(true);
                    doc["replaced_by"] = json!(new_hash);
                    doc["revoked_at"] = json!(now);
                    Ok(doc)
                });
        match claim {
            steadfast_storage::PatchOutcome::Updated(_) => {}
            steadfast_storage::PatchOutcome::Rejected(()) => {
                tracing::warn!(
                    app = %self.app_id,
                    user_id = %user_id,
                    "Refresh-Token-Wiederverwendung erkannt — alle Tokens des Benutzers gesperrt"
                );
                self.revoke_all_for_user(&user_id, now);
                return Err(RefreshError::Reused);
            }
            steadfast_storage::PatchOutcome::NotFound => return Err(RefreshError::Invalid),
        }

        // Benutzer-Stand frisch pruefen: geloescht/gesperrt -> Cascade.
        let user = match self.user_by_id(&user_id) {
            Some(user)
                if !user
                    .get("disabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false) =>
            {
                user
            }
            _ => {
                tracing::warn!(
                    app = %self.app_id,
                    user_id = %user_id,
                    "Refresh fuer geloeschten/gesperrten Benutzer abgelehnt — Tokens gesperrt"
                );
                self.revoke_all_for_user(&user_id, now);
                return Err(RefreshError::UserGone);
            }
        };
        let role = user
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("user")
            .to_string();

        self.store
            .create(
                &self.app_id,
                crate::REFRESH_COLLECTION,
                &new_hash,
                json!({
                    "user_id": user_id,
                    "created_at": now,
                    "expires_at": now.saturating_add(self.settings.refresh_token_secs),
                    "revoked": false,
                    "replaced_by": serde_json::Value::Null,
                    "revoked_at": 0,
                }),
            )
            .ok(); // Hash-Kollision (praktisch ausgeschlossen): alter Claim bleibt, Nutzer loggt sich neu ein.

        let access_token = encode_access(
            self.encode_key(),
            &self.app_id,
            &user_id,
            &role,
            now,
            self.settings.access_token_secs,
        )
        .map_err(|_| RefreshError::Invalid)?;

        Ok(IssuedTokens {
            access_token,
            access_ttl: self.settings.access_token_secs,
            refresh_token: new_token,
            refresh_ttl: self.settings.refresh_token_secs,
        })
    }

    /// Widerruft genau das vorgelegte Token (Logout). `true`, wenn es
    /// existierte (ob aktiv oder bereits rotiert ist fuer die Antwort
    /// gleichgueltig — Logout ist idempotent).
    pub(crate) fn revoke_refresh(&self, presented: &str) -> bool {
        let now = now_unix();
        let hash = refresh_hash(presented);
        if self
            .store
            .get(&self.app_id, crate::REFRESH_COLLECTION, &hash)
            .is_none()
        {
            return false;
        }
        let outcome: steadfast_storage::PatchOutcome<()> =
            self.store
                .patch_merge(&self.app_id, crate::REFRESH_COLLECTION, &hash, |mut doc| {
                    if doc
                        .get("revoked")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        // Bereits rotiert/revoked: nichts aendern (Evidence
                        // wie replaced_by unangetastet lassen).
                        return Ok(doc);
                    }
                    doc["revoked"] = json!(true);
                    doc["revoked_at"] = json!(now);
                    Ok(doc)
                });
        matches!(outcome, steadfast_storage::PatchOutcome::Updated(_))
    }

    /// Sperrt alle Refresh-Tokens eines Benutzers (Wiederverwendungs-
    /// Cascade, Admin-Deaktivierung). Laeuft ueber den `user_id`-Index.
    pub(crate) fn revoke_all_for_user(&self, user_id: &str, now: u64) {
        use steadfast_storage::ListParams;
        let mut page = 1;
        loop {
            let result = self.store.list(
                &self.app_id,
                crate::REFRESH_COLLECTION,
                ListParams {
                    page,
                    limit: 100,
                    filters: vec![("user_id".to_string(), user_id.to_string())],
                    ranges: Vec::new(),
                    sort: None,
                },
            );
            for doc in &result.items {
                if doc
                    .get("revoked")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    continue;
                }
                let id = doc.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                let _: steadfast_storage::PatchOutcome<()> = self.store.patch_merge(
                    &self.app_id,
                    crate::REFRESH_COLLECTION,
                    id,
                    |mut doc| {
                        doc["revoked"] = json!(true);
                        doc["revoked_at"] = json!(now);
                        Ok(doc)
                    },
                );
            }
            if page * 100 >= result.total {
                break;
            }
            page += 1;
        }
    }

    /// Sweeper: Refresh-Dokmente loeschen, deren letzte relevante Zeit plus
    /// Evidence-Fenster vorbei ist.
    pub(crate) fn sweep_refresh_tokens(&self) {
        use steadfast_storage::ListParams;
        let now = now_unix();
        let cutoff = now.saturating_sub(REUSE_EVIDENCE_SECS);
        let mut page = 1;
        loop {
            let result = self.store.list(
                &self.app_id,
                crate::REFRESH_COLLECTION,
                ListParams {
                    page,
                    limit: 100,
                    filters: Vec::new(),
                    ranges: Vec::new(),
                    sort: None,
                },
            );
            for doc in &result.items {
                let expires = doc.get("expires_at").and_then(|v| v.as_u64()).unwrap_or(0);
                let revoked_at = doc.get("revoked_at").and_then(|v| v.as_u64()).unwrap_or(0);
                let last_relevant = expires.max(revoked_at);
                if last_relevant < cutoff {
                    let id = doc.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                    self.store
                        .delete(&self.app_id, crate::REFRESH_COLLECTION, id);
                }
            }
            if page * 100 >= result.total {
                break;
            }
            page += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::USERS_COLLECTION;
    use std::sync::Arc;
    use steadfast_storage::MemoryStore;

    fn auth_with_user() -> (AppAuth, String) {
        let auth = crate::AppAuth::init(
            "demo",
            crate::tests::test_settings(),
            Arc::new(MemoryStore::new()),
            None,
        )
        .unwrap();
        let user_id = "u_1".to_string();
        auth.store()
            .create(
                "demo",
                USERS_COLLECTION,
                &user_id,
                json!({
                    "id": user_id, "email": "u@example.com", "password_hash": "x",
                    "role": "user", "created_at": 0, "disabled": false,
                    "failed_attempts": 0, "locked_until": 0,
                }),
            )
            .unwrap();
        (auth, user_id)
    }

    #[test]
    fn access_token_roundtrip_and_expiry() {
        let (auth, user_id) = auth_with_user();
        let now = crate::now_unix();
        let token = encode_access(auth.encode_key(), "demo", &user_id, "user", now, 900).unwrap();

        let claims = decode_access(&token, auth.decode_key(), "demo").expect("gueltig");
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.role, "user");
        assert_eq!(claims.exp, now + 900);
        assert_eq!(claims.iss, "steadfast:demo");

        // Anderer Issuer (fremde App): abgelehnt, gleiche Signatur bleibt
        // theoretisch unberuehrt — hier zunaechst der reine Issuer-Check.
        assert!(decode_access(&token, auth.decode_key(), "andere_app").is_none());
    }

    #[test]
    fn tampered_token_is_rejected() {
        let (auth, user_id) = auth_with_user();
        let token =
            encode_access(auth.encode_key(), "demo", &user_id, "admin", 1_000, 900).unwrap();
        // Payload ankratzen (Zeichen im Mittelteil verdrehen).
        let mut bytes: Vec<u8> = token.bytes().collect();
        let mid = bytes.len() / 2;
        bytes[mid] = match bytes[mid] {
            b'a' => b'b',
            other => other.wrapping_add(1),
        };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(decode_access(&tampered, auth.decode_key(), "demo").is_none());
        assert!(decode_access("gar-kein-jwt", auth.decode_key(), "demo").is_none());
    }

    #[test]
    fn tenant_isolation_token_of_other_app_fails() {
        let (auth_a, user_id) = auth_with_user();
        let auth_b = crate::AppAuth::init(
            "app_b",
            crate::tests::test_settings(),
            Arc::new(MemoryStore::new()),
            None,
        )
        .unwrap();
        let token =
            encode_access(auth_a.encode_key(), "demo", &user_id, "user", 1_000, 900).unwrap();
        // Anderer Secret UND anderer Issuer: kein Treffer.
        assert!(decode_access(&token, auth_b.decode_key(), "app_b").is_none());
    }

    #[test]
    fn refresh_rotation_and_reuse_detection_cascade() {
        let (auth, user_id) = auth_with_user();

        let issued = auth.issue_tokens(&user_id, "user").expect("issue");
        let first = issued.refresh_token.clone();

        // Rotation: neues Paar, altes Token bleibt nur noch als Evidence.
        let rotated = auth.rotate_refresh(&first).expect("rotation ok");
        assert_ne!(rotated.refresh_token, first);

        // Wiederverwendung des rotierten Tokens: Reused + ALLE Tokens weg.
        assert!(matches!(
            auth.rotate_refresh(&first),
            Err(RefreshError::Reused)
        ));
        // Auch der Nachfolger ist nach der Cascade unbrauchbar ...
        assert!(matches!(
            auth.rotate_refresh(&rotated.refresh_token),
            Err(RefreshError::Reused)
        ));
        // ... und ein frisches Login-Token waere das einzige Heilmittel.
        let fresh = auth.issue_tokens(&user_id, "user").expect("re-issue");
        assert!(auth.rotate_refresh(&fresh.refresh_token).is_ok());
    }

    #[test]
    fn expired_refresh_is_invalid() {
        let (auth, user_id) = auth_with_user();
        // Refresh-Dokument mit bereits abgelaufener Zeit direct anlegen.
        let token = generate_refresh_token();
        auth.store()
            .create(
                "demo",
                crate::REFRESH_COLLECTION,
                &refresh_hash(&token),
                json!({
                    "user_id": user_id, "created_at": 0, "expires_at": 1,
                    "revoked": false, "replaced_by": serde_json::Value::Null,
                    "revoked_at": 0,
                }),
            )
            .unwrap();
        assert!(matches!(
            auth.rotate_refresh(&token),
            Err(RefreshError::Invalid)
        ));
    }

    #[test]
    fn unknown_and_logout_revoked_tokens_are_invalid() {
        let (auth, user_id) = auth_with_user();
        assert!(matches!(
            auth.rotate_refresh("unbekannt"),
            Err(RefreshError::Invalid)
        ));

        let issued = auth.issue_tokens(&user_id, "user").unwrap();
        assert!(auth.revoke_refresh(&issued.refresh_token));
        assert!(
            matches!(
                auth.rotate_refresh(&issued.refresh_token),
                Err(RefreshError::Reused)
            ),
            "revoked (nicht rotiert) wird ebenfalls als Wiederverwendung behandelt"
        );
        // Logout ist idempotent: nochmal widerrufen meldet weiterhin true,
        // ein drittes Mal (existiert noch) ebenfalls.
        assert!(auth.revoke_refresh(&issued.refresh_token));
    }

    #[test]
    fn disabled_user_cannot_refresh() {
        let (auth, user_id) = auth_with_user();
        let issued = auth.issue_tokens(&user_id, "user").unwrap();
        auth.store()
            .replace(
                "demo",
                USERS_COLLECTION,
                &user_id,
                json!({
                    "id": user_id, "email": "u@example.com", "password_hash": "x",
                    "role": "user", "created_at": 0, "disabled": true,
                    "failed_attempts": 0, "locked_until": 0,
                }),
            )
            .unwrap();
        assert!(matches!(
            auth.rotate_refresh(&issued.refresh_token),
            Err(RefreshError::UserGone)
        ));
    }

    #[test]
    fn sweeper_removes_stale_but_keeps_fresh_evidence() {
        let (auth, user_id) = auth_with_user();
        let now = now_unix();

        // Frisch ausgestellt: bleibt.
        let fresh = auth.issue_tokens(&user_id, "user").unwrap();
        // Vor 8 Tagen abgelaufen (Evidence-Fenster 7 Tage ueberschritten): weg.
        let old_token = generate_refresh_token();
        auth.store()
            .create(
                "demo",
                crate::REFRESH_COLLECTION,
                &refresh_hash(&old_token),
                json!({
                    "user_id": user_id, "created_at": 0,
                    "expires_at": now.saturating_sub(8 * 24 * 3600),
                    "revoked": false, "replaced_by": serde_json::Value::Null,
                    "revoked_at": 0,
                }),
            )
            .unwrap();
        // Vor 3 Tagen abgelaufen: Evidence bleibt.
        let recent_token = generate_refresh_token();
        auth.store()
            .create(
                "demo",
                crate::REFRESH_COLLECTION,
                &refresh_hash(&recent_token),
                json!({
                    "user_id": user_id, "created_at": 0,
                    "expires_at": now.saturating_sub(3 * 24 * 3600),
                    "revoked": false, "replaced_by": serde_json::Value::Null,
                    "revoked_at": 0,
                }),
            )
            .unwrap();

        auth.sweep_refresh_tokens();
        assert!(
            auth.store()
                .get(
                    "demo",
                    crate::REFRESH_COLLECTION,
                    &refresh_hash(&fresh.refresh_token)
                )
                .is_some(),
            "frisches Token bleibt"
        );
        assert!(
            auth.store()
                .get(
                    "demo",
                    crate::REFRESH_COLLECTION,
                    &refresh_hash(&recent_token)
                )
                .is_some(),
            "juengere Evidence bleibt"
        );
        assert!(
            auth.store()
                .get("demo", crate::REFRESH_COLLECTION, &refresh_hash(&old_token))
                .is_none(),
            "alte Evidence wird entfernt"
        );
    }
}
