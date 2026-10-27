//! Benutzer-Verzeichnis einer App-Auth: Dokumente in der reservierten
//! Kollektion `_auth_users` im Namespace der App (Tenant-Isolation durch den
//! Composite-Key des Stores, WAL-Persistenz inklusive).
//!
//! Benutzerdokument: `{id, email, password_hash, role, created_at,
//! disabled, failed_attempts, locked_until}`. Passwoerter liegen ausschliess-
//! lich als Argon2id-PHC-Strings; `password_hash`, `failed_attempts` und
//! `locked_until` verlassen dieses Modul nie (siehe [`public_profile`]).
//!
//! Lockout: Nach [`crate::LOGIN_FAILURE_THRESHOLD`] fehlgeschlagenen Logins
//! sperrt das Konto exponentiell (15 min, dann Verdopplung je 5 weitere
//! Fehlversuche, gedeckelt auf 24 h). Antwort bleibt die generische 401 —
//! ein Angreifer soll die Sperre nicht am Antworttext erkennen koennen.

use serde_json::Value;
use serde_json::json;
use std::sync::Arc;

use crate::{AppAuth, USERS_COLLECTION, now_unix};

/// Rollen-/Zeichenform: gleiche Regeln wie die Config-Validierung
/// (`[A-Za-z0-9_-]{1,32}`) — hier fuer Laufzeit-Eingaben (Admin-Create).
pub(crate) fn valid_role(role: &str) -> bool {
    !role.is_empty()
        && role.len() <= 32
        && role
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Normalisiert und validiert eine E-Mail als Identifikator (kein SMTP):
/// lowercase, ASCII, kein Whitespace, genau ein `@`, beide Seiten nichtleer,
/// 3..=254 Zeichen — dieselben Regeln wie die Config-Validierung, damit
/// Bootstrap und Laufzeit-Eingaben identisch normalisiert werden.
pub(crate) fn normalize_email(email: &str) -> Option<String> {
    let email = email.trim().to_ascii_lowercase();
    let ok = (3..=254).contains(&email.len())
        && email.is_ascii()
        && !email.contains(char::is_whitespace)
        && email.matches('@').count() == 1;
    if !ok {
        return None;
    }
    let (local, domain) = email.split_once('@').expect("genau ein @");
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some(email)
}

/// Client-sichere Sicht auf ein Benutzerdokument: alles, was in Antworten
/// landen darf — keine Passwort-Hashes, keine Lockout-Interna.
pub(crate) fn public_profile(doc: &Value) -> Value {
    json!({
        "id": doc.get("id").cloned().unwrap_or(Value::Null),
        "email": doc.get("email").cloned().unwrap_or(Value::Null),
        "role": doc.get("role").cloned().unwrap_or(Value::Null),
        "disabled": doc.get("disabled").and_then(|v| v.as_bool()).unwrap_or(false),
        "created_at": doc.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
    })
}

/// Fehler beim Anlegen eines Benutzers.
#[derive(Debug)]
pub(crate) enum UserCreateError {
    EmailInvalid,
    Duplicate,
    HashFailed,
}

/// Lockout-Dauer nach `attempts` Fehlversuchen (Sekunden): ab der Schwelle
/// 15 min, je 5 weitere Fehlversuche Verdopplung, gedeckelt auf 24 h.
fn lockout_secs(attempts: u64) -> u64 {
    let extra = attempts
        .saturating_sub(crate::LOGIN_FAILURE_THRESHOLD)
        .saturating_div(5);
    // 900 s << 7 = 36 h, der min()-Deckel zieht auf 24 h herunter.
    (900u64 << extra.min(7)).min(86_400)
}

impl AppAuth {
    /// Benutzer nach ID (Store-Lookup, O(1)).
    pub(crate) fn user_by_id(&self, user_id: &str) -> Option<Arc<Value>> {
        self.store().get(&self.app_id, USERS_COLLECTION, user_id)
    }

    /// Benutzer nach E-Mail — laeuft ueber den deklarierten Sekundaerindex.
    pub(crate) fn find_user_by_email(&self, email: &str) -> Option<Arc<Value>> {
        use steadfast_storage::ListParams;
        let result = self.store().list(
            &self.app_id,
            USERS_COLLECTION,
            ListParams {
                page: 1,
                limit: 2,
                filters: vec![("email".to_string(), email.to_ascii_lowercase())],
                ranges: Vec::new(),
                sort: None,
            },
        );
        // limit 2 statt 1: Ein Duplikat (aussenhalb der user_write-Sperre
        // theoretisch moeglich) faellt hier auf — deterministisch der aelteste.
        result.items.into_iter().next()
    }

    /// Legt einen Benutzer an (E-Mail-Eindeutigkeit atomar unter
    /// `user_write`). Policy-Pruefung macht der Aufrufer (mit Details).
    pub(crate) fn create_user(
        &self,
        email: &str,
        password: &str,
        role: &str,
    ) -> Result<Value, UserCreateError> {
        let email = normalize_email(email).ok_or(UserCreateError::EmailInvalid)?;
        let password_hash =
            crate::password::hash_password(password).map_err(|_| UserCreateError::HashFailed)?;
        let user_id = format!("u_{}", uuid::Uuid::new_v4());

        let guard = self.user_write.lock().expect("user_write Mutex");
        if self.find_user_by_email(&email).is_some() {
            return Err(UserCreateError::Duplicate);
        }
        let doc = json!({
            "id": user_id,
            "email": email,
            "password_hash": password_hash,
            "role": role,
            "created_at": now_unix(),
            "disabled": false,
            "failed_attempts": 0,
            "locked_until": 0,
        });
        let created = self
            .store()
            .create(&self.app_id, USERS_COLLECTION, &user_id, doc)
            .map_err(|_| UserCreateError::Duplicate)?;
        drop(guard);
        Ok(public_profile(&created))
    }

    /// Bootstrap-Admin: anlegen, falls die E-Mail fehlt. Existiert er, wird
    /// nichts angefasst (auch das Passwort nicht ueberschrieben — Rotation
    /// ist Sache des Betreibers/Admin-Endpoints).
    pub(crate) fn bootstrap_admin(&self, email: &str, password: &str) {
        match self.find_user_by_email(email) {
            Some(_) => {
                tracing::debug!(app = %self.app_id, email = %email, "Bootstrap-Admin existiert bereits");
            }
            None => match self.create_user(email, password, "admin") {
                Ok(_) => {
                    tracing::info!(app = %self.app_id, email = %email, "Bootstrap-Admin angelegt");
                }
                Err(err) => {
                    tracing::error!(app = %self.app_id, email = %email, error = ?err, "Bootstrap-Admin nicht anlegbar");
                }
            },
        }
    }

    /// Zaehlt einen fehlgeschlagenen Login hoch und verlaengert/verhaengt
    /// ggf. die Sperre. Antwortet weiterhin der Aufrufer (generische 401).
    pub(crate) fn record_login_failure(&self, user_id: &str) {
        let now = now_unix();
        let outcome: steadfast_storage::PatchOutcome<()> =
            self.store()
                .patch_merge(&self.app_id, USERS_COLLECTION, user_id, |mut doc| {
                    let attempts = doc
                        .get("failed_attempts")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        + 1;
                    doc["failed_attempts"] = json!(attempts);
                    if attempts >= crate::LOGIN_FAILURE_THRESHOLD {
                        let until = now.saturating_add(lockout_secs(attempts));
                        doc["locked_until"] = json!(until);
                    }
                    Ok(doc)
                });
        if let steadfast_storage::PatchOutcome::Updated(doc) = outcome {
            let attempts = doc
                .get("failed_attempts")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if attempts == crate::LOGIN_FAILURE_THRESHOLD {
                tracing::warn!(
                    app = %self.app_id,
                    user_id = %user_id,
                    attempts,
                    lockout_secs = lockout_secs(attempts),
                    "Konto nach wiederholten Fehllogins gesperrt"
                );
            }
        }
    }

    /// Erfolgreicher Login: Zaehler und Sperre zuruecksetzen.
    pub(crate) fn reset_login_failures(&self, user_id: &str) {
        let _: steadfast_storage::PatchOutcome<()> =
            self.store()
                .patch_merge(&self.app_id, USERS_COLLECTION, user_id, |mut doc| {
                    doc["failed_attempts"] = json!(0);
                    doc["locked_until"] = json!(0);
                    Ok(doc)
                });
    }

    /// Admin-PATCH: Rolle und/oder `disabled` aendern (atomar). Eine
    /// Deaktivierung sperrt auch alle Refresh-Tokens des Benutzers.
    pub(crate) fn patch_user(
        &self,
        user_id: &str,
        role: Option<String>,
        disabled: Option<bool>,
    ) -> Option<Value> {
        let now = now_unix();
        let outcome =
            self.store()
                .patch_merge(&self.app_id, USERS_COLLECTION, user_id, |mut doc| {
                    move_doc(&mut doc, role, disabled)
                });
        match outcome {
            steadfast_storage::PatchOutcome::Updated(doc) => {
                if disabled == Some(true) {
                    self.revoke_all_for_user(user_id, now);
                }
                Some(public_profile(&doc))
            }
            _ => None,
        }
    }

    /// Benutzerliste (Admin), Seitenweise; liefert oeffentliche Profile.
    pub(crate) fn list_users(&self, page: usize, limit: usize) -> (Vec<Value>, usize) {
        use steadfast_storage::ListParams;
        let result = self.store().list(
            &self.app_id,
            USERS_COLLECTION,
            ListParams {
                page,
                limit,
                filters: Vec::new(),
                ranges: Vec::new(),
                sort: None,
            },
        );
        (
            result.items.iter().map(|doc| public_profile(doc)).collect(),
            result.total,
        )
    }
}

/// Move-Closure-Hilfe fuer `patch_user` (transform-FnOnce, kein Capture-
/// Konflikt mit dem zweiten Aufruf von `role`/`disabled`).
fn move_doc(doc: &mut Value, role: Option<String>, disabled: Option<bool>) -> Result<Value, ()> {
    if let Some(role) = role {
        doc["role"] = json!(role);
    }
    if let Some(disabled) = disabled {
        doc["disabled"] = json!(disabled);
    }
    Ok(doc.take())
}

/// Prueft, ob ein Benutzerdokument aktuell gesperrt ist.
pub(crate) fn is_locked(doc: &Value, now: u64) -> bool {
    doc.get("locked_until")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        > now
}

/// Test-Hilfe: Passwort-Hash-Digest (nur fuer Asserts gegen Leak in
/// oeffentlichen Profilen — niemals Produktivcode).
#[cfg(test)]
pub(crate) fn password_hash_digest(doc: &Value) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(
        doc.get("password_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .as_bytes(),
    );
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_app_auth;
    use serde_json::json;

    #[test]
    fn email_normalization_rules() {
        assert_eq!(
            normalize_email("  User@Example.COM "),
            Some("user@example.com".to_string())
        );
        assert_eq!(normalize_email("a@b"), Some("a@b".to_string()));
        assert_eq!(normalize_email(""), None, "zu kurz");
        assert_eq!(normalize_email("a@@b"), None, "zwei @");
        assert_eq!(normalize_email("@b"), None, "leerer local part");
        assert_eq!(normalize_email("a@"), None, "leere Domain");
        assert_eq!(normalize_email("a b@c.de"), None, "Whitspace");
        assert_eq!(normalize_email("hansi@exämple.de"), None, "nur ASCII");
        let long = format!("{}@example.com", "a".repeat(300));
        assert_eq!(normalize_email(&long), None, "zu lang");
    }

    #[test]
    fn lockout_backoff_ladder() {
        assert_eq!(lockout_secs(crate::LOGIN_FAILURE_THRESHOLD), 900);
        assert_eq!(lockout_secs(crate::LOGIN_FAILURE_THRESHOLD + 4), 900);
        assert_eq!(lockout_secs(crate::LOGIN_FAILURE_THRESHOLD + 5), 1_800);
        assert_eq!(lockout_secs(crate::LOGIN_FAILURE_THRESHOLD + 10), 3_600);
        assert_eq!(lockout_secs(10_000), 86_400, "Deckel 24 h");
        assert_eq!(lockout_secs(5), 900, "unter der Schwelle (Stillschweigen)");
    }

    #[test]
    fn create_user_normalizes_and_hides_hash() {
        let auth = test_app_auth();
        let profile = auth
            .create_user("User@Example.com", "Passw0rt!xx", "user")
            .unwrap();
        assert_eq!(profile["email"], json!("user@example.com"));
        assert_eq!(profile["role"], json!("user"));
        assert!(profile.get("password_hash").is_none());
        assert!(profile.get("failed_attempts").is_none());
        assert!(profile.get("locked_until").is_none());
        assert!(profile["id"].as_str().unwrap().starts_with("u_"));

        // Der Hash liegt nur im Store-Dokument.
        let stored = auth.user_by_id(profile["id"].as_str().unwrap()).unwrap();
        assert!(
            stored["password_hash"]
                .as_str()
                .unwrap()
                .starts_with("$argon2id$")
        );

        // Duplikat (andere Schreibweise) schlaegt fehl.
        assert!(matches!(
            auth.create_user("USER@example.COM", "Passw0rt!yy", "user"),
            Err(UserCreateError::Duplicate)
        ));
        // Ungueltige E-Mail / kaputtes Rollenformat.
        assert!(matches!(
            auth.create_user("kein-email", "Passw0rt!xx", "user"),
            Err(UserCreateError::EmailInvalid)
        ));
    }

    #[test]
    fn failed_logins_escalate_to_lockout() {
        let auth = test_app_auth();
        let profile = auth
            .create_user("u@example.com", "Passw0rt!xx", "user")
            .unwrap();
        let id = profile["id"].as_str().unwrap().to_string();

        for _ in 0..crate::LOGIN_FAILURE_THRESHOLD {
            auth.record_login_failure(&id);
        }
        let doc = auth.user_by_id(&id).unwrap();
        assert_eq!(
            doc["failed_attempts"],
            json!(crate::LOGIN_FAILURE_THRESHOLD)
        );
        assert!(is_locked(&doc, now_unix()));
        assert!(is_locked(&doc, now_unix() + 899));
        assert!(!is_locked(&doc, now_unix() + 901));

        // Erfolgreicher Login resettet.
        auth.reset_login_failures(&id);
        let doc = auth.user_by_id(&id).unwrap();
        assert_eq!(doc["failed_attempts"], json!(0));
        assert!(!is_locked(&doc, now_unix()));
    }

    #[test]
    fn admin_patch_changes_role_and_disables_with_token_revocation() {
        let auth = test_app_auth();
        let profile = auth
            .create_user("u@example.com", "Passw0rt!xx", "user")
            .unwrap();
        let id = profile["id"].as_str().unwrap().to_string();

        // Aktives Refresh-Token: Deaktivierung muss es gleich mit sperren.
        let issued = auth.issue_tokens(&id, "user").unwrap();

        let patched = auth
            .patch_user(&id, Some("admin".into()), Some(true))
            .unwrap();
        assert_eq!(patched["role"], json!("admin"));
        assert_eq!(patched["disabled"], json!(true));

        let revoked = auth.user_by_id(&id).unwrap()["locked_until"]
            .as_u64()
            .unwrap();
        assert_eq!(revoked, 0, "disabled ist kein Lockout");

        use crate::tokens::RefreshError;
        assert!(
            matches!(
                auth.rotate_refresh(&issued.refresh_token),
                Err(RefreshError::Reused)
            ),
            "Deaktivierung sperrt die Tokens per Cascade — Wiederverwendung"
        );

        // Unbekannter Benutzer: None (404 beim Aufrufer).
        assert!(
            auth.patch_user("u_gibts_nicht", Some("user".into()), None)
                .is_none()
        );
    }

    #[test]
    fn public_profile_never_leaks_internals() {
        let doc = json!({
            "id": "u_1", "email": "a@b.c", "role": "user",
            "password_hash": "$argon2id$geheim", "created_at": 5,
            "disabled": false, "failed_attempts": 3, "locked_until": 99,
        });
        let profile = public_profile(&doc);
        assert_eq!(profile["id"], json!("u_1"));
        assert!(profile.get("password_hash").is_none());
        assert!(profile.get("failed_attempts").is_none());
        assert!(profile.get("locked_until").is_none());
        // Der Hash ist auch nicht anderweitig rekonstruierbar.
        assert_ne!(profile.to_string(), password_hash_digest(&doc));
    }
}
