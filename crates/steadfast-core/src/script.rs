//! Rhai-Integration: Vorkompilieren der Business-Logik in einen `rhai::AST`
//! beim Start und sandboxierte Ausfuehrung im Hot Path.
//!
//! Sicherheits-Leitplanken (gegen Endlosschleifen und Ressourcen-Exzesse):
//! * max. Operationsanzahl pro Skriptaufruf
//! * Wall-Clock-Deadline (5 ms) via `on_progress`
//! * Groessenlimits fuer Strings/Arrays/Maps und rekursive Aufruftiefe
//!
//! Bedrohungsmodell: Der Skript-Autor ist der Config-Owner (vertrauenswuerdig);
//! Endnutzer liefern ausschliesslich Daten. Payload und User-Kontext werden als
//! JSON in die Sandbox gegeben und bleiben dort strukturierte Werte — Nutzerein-
//! gaben werden nie als Skript-Code interpretiert (keine Skript-Injection).

use std::time::{Duration, Instant};

use rhai::{Dynamic, Engine, EvalAltResult, Scope};

use crate::error::EngineError;

/// Erwarteter Einstiegspunkt in jedem Business-Logik-Skript.
pub const HOOK_NAME: &str = "on_request";

const MAX_OPERATIONS: u64 = 20_000;
const MAX_CALL_LEVELS: usize = 64;
const MAX_STRING_SIZE: usize = 65_536;
const MAX_ARRAY_SIZE: usize = 10_000;
const MAX_MAP_SIZE: usize = 10_000;
const MAX_EXPR_DEPTH: usize = 64;
const MAX_FUNCTION_EXPR_DEPTH: usize = 32;
const EXECUTION_DEADLINE: Duration = Duration::from_millis(5);

/// Ein beim Start vorkompiliertes Skript. `rhai::AST` ist `Clone + Send + Sync`
/// und wird zur Laufzeit nur gelesen — kein Text-Parsing im Hot Path.
#[derive(Debug)]
pub struct CompiledScript {
    pub ast: rhai::AST,
}

/// Fabrik fuer Kompilierung und sandboxierte Ausfuehrung.
pub struct ScriptRuntime;

impl ScriptRuntime {
    /// Kompiliert ein Skript und prueft, dass der Hook `on_request(payload, user)`
    /// existiert. Wird beim Engine-Start aufgerufen; Fehler brechen den Start ab.
    pub fn compile(endpoint: &str, source: &str) -> Result<CompiledScript, EngineError> {
        let compile_error = |message: String| EngineError::ScriptCompile {
            endpoint: endpoint.to_string(),
            message,
        };

        let engine = Engine::new();
        let ast = engine
            .compile(source)
            .map_err(|e| compile_error(e.to_string()))?;

        let hook = ast
            .iter_functions()
            .find(|f| f.name == HOOK_NAME)
            .ok_or_else(|| {
                compile_error(format!(
                    "must define `fn {HOOK_NAME}(payload, user)`"
                ))
            })?;
        if hook.params.len() != 2 {
            return Err(compile_error(format!(
                "`{HOOK_NAME}` must take exactly 2 parameters (payload, user), found {}",
                hook.params.len()
            )));
        }

        Ok(CompiledScript { ast })
    }

    /// Fuehrt den Hook `on_request(payload, user)` aus und gibt das transformierte
    /// JSON-Dokument zurueck. Das Skript MUSS den (modifizierten) Payload als
    /// JSON-Objekt zurueckgeben.
    pub fn exec(
        script: &CompiledScript,
        payload: serde_json::Value,
        user: serde_json::Value,
    ) -> Result<serde_json::Value, EngineError> {
        let mut engine = sandbox_engine();

        let payload_arg = rhai::serde::to_dynamic(&payload).map_err(|e| {
            EngineError::ScriptOutput(format!("payload is not representable in the sandbox: {e}"))
        })?;
        let user_arg = rhai::serde::to_dynamic(&user).map_err(|e| {
            EngineError::ScriptOutput(format!(
                "user context is not representable in the sandbox: {e}"
            ))
        })?;

        let started = Instant::now();
        engine.on_progress(move |_ops| {
            (started.elapsed() >= EXECUTION_DEADLINE)
                .then(|| Dynamic::from("execution deadline exceeded"))
        });

        match engine.call_fn::<Dynamic>(
            &mut Scope::new(),
            &script.ast,
            HOOK_NAME,
            (payload_arg, user_arg),
        ) {
            Ok(result) => {
                if !result.is_map() {
                    return Err(EngineError::ScriptOutput(format!(
                        "`{HOOK_NAME}` must return the payload object, got `{}`",
                        result.type_name()
                    )));
                }
                rhai::serde::from_dynamic(&result)
                    .map_err(|e| EngineError::ScriptOutput(format!("script result is not valid JSON: {e}")))
            }
            Err(err) => Err(map_eval_error(*err)),
        }
    }
}

/// Frische, limitierte Sandbox-Engine pro Aufruf (die Deadline via `on_progress`
/// benoetigt `&mut Engine`; `Engine::new` ist trivial, der teure Teil — das
/// Parsen — steckt bereits im vorkompilierten AST).
fn sandbox_engine() -> Engine {
    let mut engine = Engine::new();
    engine.set_max_operations(MAX_OPERATIONS);
    engine.set_max_call_levels(MAX_CALL_LEVELS);
    engine.set_max_string_size(MAX_STRING_SIZE);
    engine.set_max_array_size(MAX_ARRAY_SIZE);
    engine.set_max_map_size(MAX_MAP_SIZE);
    engine.set_max_expr_depths(MAX_EXPR_DEPTH, MAX_FUNCTION_EXPR_DEPTH);
    engine
}

fn map_eval_error(err: EvalAltResult) -> EngineError {
    match err {
        // `throw "..."` im Skript: aktive Ablehnung des Requests -> 422.
        EvalAltResult::ErrorRuntime(thrown, pos) => {
            let message = match thrown.into_string() {
                Ok(s) => s,
                Err(other) => other.to_string(),
            };
            let at = pos
                .line()
                .map(|l| format!(" (script line {l})"))
                .unwrap_or_default();
            EngineError::ScriptRejected(format!("{message}{at}"))
        }
        EvalAltResult::ErrorTooManyOperations(_) => {
            EngineError::ScriptLimit("max operation count exceeded".into())
        }
        other => {
            let text = other.to_string();
            // Fallback-Heuristik fuer limit-bedingte Abbrueche (Deadline,
            // Groessenlimits, Rekursionstiefe) unabhaengig von der Variantenform.
            if text.contains("too many operations")
                || text.contains("terminated")
                || text.contains("too large")
                || text.contains("depth")
            {
                EngineError::ScriptLimit(text)
            } else {
                EngineError::ScriptOutput(text)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user() -> serde_json::Value {
        json!({"id": "user_1", "role": "premium"})
    }

    #[test]
    fn transforms_payload() {
        let script = ScriptRuntime::compile(
            "test/echo",
            r#"
            fn on_request(payload, user) {
                payload.mark = user.role;
                payload.count = payload.items.len();
                return payload;
            }
            "#,
        )
        .expect("script must compile");

        let result = ScriptRuntime::exec(
            &script,
            json!({"items": ["a", "b"]}),
            user(),
        )
        .expect("exec must succeed");

        assert_eq!(result["mark"], json!("premium"));
        assert_eq!(result["count"], json!(2));
    }

    #[test]
    fn throw_maps_to_script_rejected() {
        let script = ScriptRuntime::compile(
            "test/throw",
            r#"
            fn on_request(payload, user) {
                throw "Nur Premium-Nutzer erlaubt!";
            }
            "#,
        )
        .expect("script must compile");

        let err = ScriptRuntime::exec(&script, json!({}), user())
            .expect_err("throw must fail");
        match err {
            EngineError::ScriptRejected(message) => {
                assert!(message.contains("Nur Premium-Nutzer erlaubt!"), "{message}");
            }
            other => panic!("expected ScriptRejected, got: {other:?}"),
        }
    }

    #[test]
    fn blueprint_script_enforces_premium_rule() {
        let script = ScriptRuntime::compile(
            "test/blueprint",
            r#"
            fn on_request(payload, user) {
                if user.role != "premium" && payload.is_priority == true {
                    throw "Nur Premium-Nutzer koennen Prioritaets-Tasks erstellen!";
                }
                if payload.title.len() == 0 {
                    throw "Titel darf nicht leer sein.";
                }
                payload.created_by = user.id;
                payload.status = "offen";
                return payload;
            }
            "#,
        )
        .expect("blueprint script must compile");

        // Premium + Prioritaet: erlaubt, Felder werden gesetzt.
        let ok = ScriptRuntime::exec(
            &script,
            json!({"title": "Task", "is_priority": true}),
            user(),
        )
        .expect("premium user passes");
        assert_eq!(ok["created_by"], json!("user_1"));
        assert_eq!(ok["status"], json!("offen"));

        // Nicht-Premium + Prioritaet: abgelehnt.
        let rejected = ScriptRuntime::exec(
            &script,
            json!({"title": "Task", "is_priority": true}),
            json!({"id": "user_2", "role": "free"}),
        )
        .expect_err("non-premium must be rejected");
        assert!(matches!(rejected, EngineError::ScriptRejected(_)));

        // Leerer Titel: abgelehnt.
        let rejected = ScriptRuntime::exec(
            &script,
            json!({"title": ""}),
            user(),
        )
        .expect_err("empty title must be rejected");
        assert!(matches!(rejected, EngineError::ScriptRejected(_)));
    }

    #[test]
    fn missing_hook_fails_compile() {
        let err = ScriptRuntime::compile("test/no_hook", "fn other() { 42 }")
            .expect_err("missing hook must fail");
        assert!(err.message().contains("on_request"), "{err}");
    }

    #[test]
    fn wrong_arity_fails_compile() {
        let err = ScriptRuntime::compile(
            "test/arity",
            "fn on_request(payload) { return payload; }",
        )
        .expect_err("wrong arity must fail");
        assert!(err.message().contains("2 parameters"), "{err}");
    }

    #[test]
    fn infinite_loop_hits_execution_budget() {
        let script = ScriptRuntime::compile(
            "test/loop",
            r#"
            fn on_request(payload, user) {
                while payload.len() >= 0 {
                    let x = 1;
                }
                return payload;
            }
            "#,
        )
        .expect("script must compile");

        let err = ScriptRuntime::exec(&script, json!({}), user())
            .expect_err("infinite loop must be terminated");
        assert!(
            matches!(err, EngineError::ScriptLimit(_)),
            "expected ScriptLimit, got: {err:?}"
        );
    }

    #[test]
    fn non_object_return_is_invalid_output() {
        let script = ScriptRuntime::compile(
            "test/scalar",
            "fn on_request(payload, user) { return 42; }",
        )
        .expect("script must compile");

        let err = ScriptRuntime::exec(&script, json!({}), user())
            .expect_err("scalar return must fail");
        assert!(matches!(err, EngineError::ScriptOutput(_)), "{err:?}");
    }
}
