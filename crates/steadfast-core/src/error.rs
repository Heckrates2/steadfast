//! Einheitlicher Fehlertyp der Engine mit HTTP-Mapping.

/// Alle Fehler, die beim Laden der Konfiguration oder bei der Request-
/// Verarbeitung entstehen koennen. Der Server mappt [`EngineError::status`]
/// und [`EngineError::code`] direkt auf die HTTP-Antwort.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EngineError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("script compile error in endpoint `{endpoint}`: {message}")]
    ScriptCompile { endpoint: String, message: String },

    #[error("{0}")]
    BadRequest(String),

    #[error("missing or invalid API key")]
    Unauthorized,

    #[error("resource not found")]
    NotFound,

    /// Das Skript hat die Verarbeitung aktiv abgelehnt (`throw`) —
    /// Verantwortung des Clients, daher 422.
    #[error("{0}")]
    ScriptRejected(String),

    /// Operations-/Groessenlimit oder Deadline der Sandbox erreicht.
    #[error("script exceeded its execution budget: {0}")]
    ScriptLimit(String),

    /// Das Skript lief, aber das Ergebnis ist unbrauchbar (kein Objekt,
    /// nicht JSON-repraesentierbar) — Config-Bug, daher 500.
    #[error("script returned an invalid result: {0}")]
    ScriptOutput(String),

    #[error("invalid JSON payload: {0}")]
    InvalidJson(String),
}

impl EngineError {
    /// Empfohlener HTTP-Statuscode.
    pub fn status(&self) -> u16 {
        match self {
            EngineError::Config(_)
            | EngineError::ScriptCompile { .. }
            | EngineError::ScriptLimit(_)
            | EngineError::ScriptOutput(_) => 500,
            EngineError::BadRequest(_) | EngineError::InvalidJson(_) => 400,
            EngineError::Unauthorized => 401,
            EngineError::NotFound => 404,
            EngineError::ScriptRejected(_) => 422,
        }
    }

    /// Maschinenlesbarer Fehlercode fuer den JSON-Fehlerbody.
    pub fn code(&self) -> &'static str {
        match self {
            EngineError::Config(_) => "config_error",
            EngineError::ScriptCompile { .. } => "script_compile_error",
            EngineError::BadRequest(_) => "bad_request",
            EngineError::Unauthorized => "unauthorized",
            EngineError::NotFound => "not_found",
            EngineError::ScriptRejected(_) => "script_rejected",
            EngineError::ScriptLimit(_) => "script_limit_exceeded",
            EngineError::ScriptOutput(_) => "script_invalid_output",
            EngineError::InvalidJson(_) => "invalid_json",
        }
    }

    /// Menschenlesbare Meldung fuer den JSON-Fehlerbody.
    pub fn message(&self) -> String {
        match self {
            EngineError::Config(m)
            | EngineError::BadRequest(m)
            | EngineError::ScriptRejected(m)
            | EngineError::ScriptLimit(m)
            | EngineError::ScriptOutput(m)
            | EngineError::InvalidJson(m) => m.clone(),
            EngineError::ScriptCompile { endpoint, message } => format!("{endpoint}: {message}"),
            EngineError::Unauthorized => self.to_string(),
            EngineError::NotFound => self.to_string(),
        }
    }

    /// Client-sichere Meldung fuer den JSON-Fehlerbody (N3): Interne Details
    /// (serde-Fehlertexte, Sandbox-Interna, Konfigurationspfade) gehen ins
    /// Log, nicht an den Client. `BadRequest` (aus validierten Client-Inputs
    /// konstruiert) und `ScriptRejected` (bewusst client-gerichte Business-
    /// Meldung des Skripts) bleiben wie `message()`.
    pub fn client_message(&self) -> String {
        match self {
            EngineError::Config(_) | EngineError::ScriptCompile { .. } => {
                "internal configuration error".into()
            }
            EngineError::ScriptLimit(_) => "script exceeded its execution budget".into(),
            EngineError::ScriptOutput(_) => "script returned an invalid result".into(),
            EngineError::InvalidJson(_) => "request body must be valid JSON".into(),
            EngineError::BadRequest(m) | EngineError::ScriptRejected(m) => m.clone(),
            EngineError::Unauthorized | EngineError::NotFound => self.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_and_code_mapping() {
        assert_eq!(EngineError::Unauthorized.status(), 401);
        assert_eq!(EngineError::Unauthorized.code(), "unauthorized");
        assert_eq!(EngineError::ScriptRejected("nope".into()).status(), 422);
        assert_eq!(
            EngineError::ScriptRejected("nope".into()).code(),
            "script_rejected"
        );
        assert_eq!(EngineError::NotFound.status(), 404);
        assert_eq!(EngineError::ScriptLimit("ops".into()).status(), 500);
    }

    #[test]
    fn rejected_message_is_client_facing() {
        let err = EngineError::ScriptRejected("Titel darf nicht leer sein.".into());
        assert_eq!(err.message(), "Titel darf nicht leer sein.");
    }

    #[test]
    fn internal_details_stay_out_of_client_messages() {
        // N3: Interne Details (serde-Text, Sandbox-Interna, Config-Pfade)
        // duerfen den Client-Body nie erreichen.
        let err = EngineError::InvalidJson(
            "expected value at line 1 column 3: /etc/engine/secrets.toml".into(),
        );
        assert_eq!(err.client_message(), "request body must be valid JSON");
        assert!(
            err.message().contains("/etc/engine/secrets.toml"),
            "Log-Detail bleibt erhalten"
        );

        let err = EngineError::ScriptLimit("Rhai-Engine: 20000 iterations at fn on_request".into());
        assert_eq!(err.client_message(), "script exceeded its execution budget");
        assert!(err.message().contains("20000 iterations"));

        let err = EngineError::ScriptCompile {
            endpoint: "app/endpoint".into(),
            message: "syntax error at line 42".into(),
        };
        assert_eq!(err.client_message(), "internal configuration error");

        // Client-gerichtete Meldungen bleiben unangetastet.
        let err = EngineError::ScriptRejected("Titel darf nicht leer sein.".into());
        assert_eq!(err.client_message(), "Titel darf nicht leer sein.");
        let err = EngineError::BadRequest("invalid `page` value `abc`".into());
        assert_eq!(err.client_message(), "invalid `page` value `abc`");
    }
}
