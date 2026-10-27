//! Passwort-Hashing: Argon2id mit per-User-Salt.
//!
//! Parameter sind die Crate-Defaults (`Argon2::default()`): Argon2id v1.3,
//! 19 MiB Speicher, 2 Iterationen, 1 Lane — die OWASP-Empfehlung. Gespeichert
//! wird der PHC-String (`$argon2id$...`), der Salt und Parameter enthält.
//!
//! Timing-Parität gegen User-Enumeration: Ein Login mit unbekannter E-Mail
//! verifiziert gegen den [`DummyHash`] der App — ein echter Argon2-Lauf mit
//! identischen Kosten, damit die Antwortzeit keinen Rückschluss darauf
//! zulässt, ob das Konto existiert.

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

/// Hasht ein Passwort (Argon2id, frischer Salt) in den PHC-String.
pub(crate) fn hash_password(password: &str) -> Result<String, String> {
    // Salt selbst ziehen (rand 0.9) und base64-Kodierung dem password-hash-
    // Oekosystem ueberlassen — umgeht die rand_core-Versionsmischerei der
    // argon2-0.5-SaltString::generate-Signatur.
    use rand::RngCore;
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|err| err.to_string())?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| err.to_string())
}

/// Verifiziert ein Kandidaten-Passwort gegen einen PHC-String. Jeder Fehler
/// (ungültiges Hash-Format, falsches Passwort) ist schlicht `false` —
/// Unterscheidungen gehören nicht in Antworten oder Logs.
pub(crate) fn verify_password(password: &str, phc: &str) -> bool {
    let Ok(hash) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

/// Vorberechneter Hash eines Zufalls-Passworts: `burn` laeuft einen vollen
/// Argon2-Lauf, ohne dass es ein echtes Konto gibt — fuer konstante
/// Antwortzeiten bei unbekannten E-Mails (und bei Passwoertern, die die
/// Policy-Laenge sprengen, die daher nie gespeichert wurden).
pub(crate) struct DummyHash {
    phc: String,
}

impl DummyHash {
    pub(crate) fn new() -> Self {
        let phc =
            hash_password(&uuid::Uuid::new_v4().to_string()).unwrap_or_else(|_| String::new());
        Self { phc }
    }

    /// Verifiziert gegen den Dummy-Hash und verwirft das Ergebnis —
    /// einzig der Zeitaufwand zaehlt.
    pub(crate) fn burn(&self, candidate: &str) {
        let _ = verify_password(candidate, &self.phc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let phc = hash_password("Korrekt-Pferd-Batterie-1!").unwrap();
        assert!(phc.starts_with("$argon2id$"), "Argon2id-PHC-String: {phc}");
        assert!(verify_password("Korrekt-Pferd-Batterie-1!", &phc));
        assert!(!verify_password("falsches-passwort", &phc));
    }

    #[test]
    fn salts_are_unique_per_hash() {
        let a = hash_password("dasselbe").unwrap();
        let b = hash_password("dasselbe").unwrap();
        assert_ne!(a, b, "Salt muss pro Hash frisch gezogen werden");
    }

    #[test]
    fn malformed_hash_verifies_false() {
        assert!(!verify_password("x", "kein-phc-string"));
        assert!(!verify_password("x", ""));
    }

    #[test]
    fn dummy_burn_always_succeeds_quietly() {
        let dummy = DummyHash::new();
        dummy.burn("irgendwas");
        dummy.burn("");
    }
}
