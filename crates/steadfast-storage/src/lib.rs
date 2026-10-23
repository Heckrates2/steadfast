//! steadfast-storage: schemaloser In-Memory-Datenspeicher der Engine.
//!
//! Dokumente werden als `serde_json::Value` unter einem Composite-Key
//! `app / collection / id` gehalten. Die Implementierung ist strikt
//! In-Memory: Filter sind einfache Gleichheitsvergleiche auf Top-Level-
//! Feldern — es gibt keine Abfragesprache und damit strukturell keine
//! Injection-Flaeche.
//!
//! Phase 2 ergaenzt den asynchronen WAL-Worker: Alle Mutationen landen
//! sequenziell in `wal-*.log`-Segmenten (`mod wal` haelt Binaerformat und
//! Replay), regelmaessig wird nach `snapshot.bin` kompaktiert und rotiert
//! (`mod persist` haelt Worker-Thread und Rotationsprotokoll). Beim Start
//! spielt [`wal::replay_data_dir`] Snapshot + Segmente ein — vor
//! [`Persistence::start`], damit Replay-Operationen nicht re-loggt werden.

mod cold;
mod persist;
mod store;
mod wal;

pub use cold::{ColdKey, ColdTier};
pub use persist::{Persistence, PersistenceConfig};
pub use store::{
    CollectionDump, CreateConflict, ListParams, ListResult, MemoryStore, PatchOutcome, RangeOp,
    SortSpec,
};
// Encode-/Header-Helfer sind oeffentlich, damit Werkzeuge (Backups,
// Migrationen) gueltige WAL-Segmente und Snapshots schreiben koennen.
pub use wal::{
    ReplayReport, WAL_MAGIC, WalError, WalOp, encode_wal_op, replay_data_dir, replay_data_dir_full,
    wal_file_path, write_file_header, write_snapshot_file,
};
