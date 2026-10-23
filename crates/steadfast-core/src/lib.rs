//! steadfast-core: HTTP-freier Kern der REST-Engine.
//!
//! * [`config`] — parsen und validieren der `apps.toml`, Vorkompilieren der
//!   Rhai-Skripte in `rhai::AST` beim Engine-Start (Fail-Fast).
//! * [`script`] — sandboxierte Ausfuehrung der vorkompilierten Skripte mit
//!   harten Limits (Operationsanzahl, Wall-Clock-Deadline, Groessenlimits).
//! * [`error`] — einheitlicher Fehlertyp inkl. HTTP-Status/Code-Mapping.

pub mod config;
pub mod error;
pub mod schema;
pub mod script;

pub use config::{
    AllowedOrigins, AppConfigRuntime, CorsConfig, EndpointRuntime, EngineConfig, HttpMethod,
    MAX_CORS_MAX_AGE_SECS, MAX_PAGE_SIZE, MIN_API_KEY_SECRET_LEN,
};
pub use error::EngineError;
pub use schema::{EndpointSchema, FieldType};
pub use script::{CompiledScript, ScriptRuntime};
