//! steadfast-server: Monolith-Binary der REST-Engine.
//!
//! Startup: `apps.toml` laden -> validieren -> Rhai-ASTs vorkompilieren ->
//! Route-Tabellen bauen -> Axum-Server starten. Hot Path pro Request:
//! O(1)-Config-Lookup -> Auth -> Rhai-Sandbox -> schemaloses Speichern.

mod auth;
mod compression;
mod cors;
mod handler;
mod router;
mod state;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tracing_subscriber::EnvFilter;

use steadfast_core::{EngineConfig, MIN_API_KEY_SECRET_LEN};
use steadfast_storage::{MemoryStore, Persistence, PersistenceConfig, replay_data_dir_full};

use crate::state::AppState;

/// H1': Umgebungsvariable mit dem Shared Secret des Gateways. Setzt der
/// Betreiber sie, werden `X-User-*`-Header nur noch honoring, wenn der
/// Request per `X-Internal-Auth` seine Herkunft vom Gateway belegt —
/// "hinter dem Gateway" wird damit zur vom Code erzwungenen Bedingung.
const GATEWAY_SECRET_ENV: &str = "ENGINE_GATEWAY_SECRET";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Flag-Argumente (--data-dir, --snapshot-interval, --max-docs,
    // --wal-max-segment-mb, --no-compression) plus die klassischen
    // Positionsargumente (CONFIG, BIND), deren Reihenfolge erhalten bleibt.
    let mut positional: Vec<String> = Vec::new();
    let mut data_dir: Option<PathBuf> = None;
    let mut snapshot_secs: u64 = 60;
    // RAM-Obergrenze heisser Dokumente je Kollektion (Tiering). 0 = Default
    // = unbegrenzt; > 0 aktiviert LRU-Eviction + Fetch-on-Miss.
    let mut max_docs: usize = 0;
    // WAL-Groessentrigger in MiB: Das aktive Segment wird rotiert, sobald es
    // diese Groesse ueberschreitet — auch mitten im Intervall. Haelt Segmente
    // und damit den Replay-Umfang handhabbar. 0 = unbegrenzt (nur Zeit-Tick).
    let mut wal_max_segment_mb: u64 = 256;
    // gzip fuer grosse JSON-Antworten (Content-Negotiation via
    // Accept-Encoding). Default an; --no-compression schaltet ab.
    let mut compression = true;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data-dir" => match args.next() {
                Some(dir) => data_dir = Some(PathBuf::from(dir)),
                None => {
                    eprintln!("error: --data-dir erwartet ein Verzeichnis");
                    return ExitCode::FAILURE;
                }
            },
            arg if arg.starts_with("--data-dir=") => {
                data_dir = Some(PathBuf::from(&arg["--data-dir=".len()..]));
            }
            "--max-docs" => match args.next() {
                Some(raw) => match raw.parse::<usize>() {
                    Ok(n) => max_docs = n,
                    Err(_) => {
                        eprintln!("error: --max-docs erwartet eine Anzahl, bekommen: {raw}");
                        return ExitCode::FAILURE;
                    }
                },
                None => {
                    eprintln!("error: --max-docs erwartet eine Anzahl");
                    return ExitCode::FAILURE;
                }
            },
            arg if arg.starts_with("--max-docs=") => {
                let raw = &arg["--max-docs=".len()..];
                match raw.parse::<usize>() {
                    Ok(n) => max_docs = n,
                    Err(_) => {
                        eprintln!("error: --max-docs erwartet eine Anzahl, bekommen: {raw}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--snapshot-interval" => match args.next() {
                Some(raw) => match raw.parse::<u64>() {
                    Ok(secs) => snapshot_secs = secs,
                    Err(_) => {
                        eprintln!(
                            "error: --snapshot-interval erwartet eine Sekundenzahl, bekommen: {raw}"
                        );
                        return ExitCode::FAILURE;
                    }
                },
                None => {
                    eprintln!("error: --snapshot-interval erwartet eine Sekundenzahl");
                    return ExitCode::FAILURE;
                }
            },
            arg if arg.starts_with("--snapshot-interval=") => {
                let raw = &arg["--snapshot-interval=".len()..];
                match raw.parse::<u64>() {
                    Ok(secs) => snapshot_secs = secs,
                    Err(_) => {
                        eprintln!(
                            "error: --snapshot-interval erwartet eine Sekundenzahl, bekommen: {raw}"
                        );
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--wal-max-segment-mb" => match args.next() {
                Some(raw) => match raw.parse::<u64>() {
                    Ok(mib) => wal_max_segment_mb = mib,
                    Err(_) => {
                        eprintln!(
                            "error: --wal-max-segment-mb erwartet eine MiB-Zahl, bekommen: {raw}"
                        );
                        return ExitCode::FAILURE;
                    }
                },
                None => {
                    eprintln!("error: --wal-max-segment-mb erwartet eine MiB-Zahl");
                    return ExitCode::FAILURE;
                }
            },
            arg if arg.starts_with("--wal-max-segment-mb=") => {
                let raw = &arg["--wal-max-segment-mb=".len()..];
                match raw.parse::<u64>() {
                    Ok(mib) => wal_max_segment_mb = mib,
                    Err(_) => {
                        eprintln!(
                            "error: --wal-max-segment-mb erwartet eine MiB-Zahl, bekommen: {raw}"
                        );
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--no-compression" => compression = false,
            arg if arg.starts_with("--") => {
                eprintln!(
                    "error: unbekanntes Argument `{arg}` — erwartet: \
                     [--data-dir <VERZEICHNIS>] [--snapshot-interval <SEKUNDEN>] \
                     [--max-docs <ANZAHL>] [--wal-max-segment-mb <MIB>] \
                     [--no-compression] [CONFIG] [BIND]"
                );
                return ExitCode::FAILURE;
            }
            _ => positional.push(arg),
        }
    }
    let config_path = positional
        .first()
        .cloned()
        .unwrap_or_else(|| "apps.toml".to_string());
    let bind_addr = positional
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let config = match EngineConfig::load(&config_path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    // H1': Optionales Gateway-Secret aus der Umgebung (nie auf der Kommando-
    // zeile — die ist in Prozesslisten sichtbar). Fail-Fast bei leer/zuvor
    // kurz, gleiche Mindestlaenge wie App-Secrets.
    let gateway_secret = match std::env::var(GATEWAY_SECRET_ENV) {
        Ok(raw) => {
            if raw.chars().count() < MIN_API_KEY_SECRET_LEN {
                eprintln!(
                    "error: {GATEWAY_SECRET_ENV} ist gesetzt, aber kuerzer als \
                     {MIN_API_KEY_SECRET_LEN} Zeichen — nicht starten, sondern ein \
                     brauchbares Secret setzen oder die Variable entfernen"
                );
                return ExitCode::FAILURE;
            }
            tracing::info!(
                "Gateway-Provenienzpruefung aktiv: X-User-*-Header zaehlen nur mit \
                 gueltigem X-Internal-Auth (H1')"
            );
            Some(raw)
        }
        Err(std::env::VarError::NotPresent) => {
            tracing::info!(
                "{GATEWAY_SECRET_ENV} ist nicht gesetzt — X-User-Id/X-User-Role werden \
                 unverifiziert honoring (Gateway-Vertrauensmodell); hinter einem Gateway \
                 mit Header-Sanitisierung betreiben oder die Variable setzen, um die \
                 Provenienzpruefung zu erzwingen"
            );
            None
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            eprintln!("error: {GATEWAY_SECRET_ENV} enthaelt keine gueltigen Unicode-Daten");
            return ExitCode::FAILURE;
        }
    };

    // Persistenz: Replay VOR dem WAL-Start (der Store hat bis dahin keine
    // WAL-Senke, Replay-Operationen werden also nicht re-loggt), dann Worker
    // und Route-Tabelle auf denselben Store binden. Das Replay liefert das
    // Kalt-Tier mit (Offset-Indizes ueber Snapshot + Segmente) — der Store
    // kann ab dem ersten Request kalte Dokumente nachladen.
    let store = Arc::new(MemoryStore::new());
    store.set_hot_cap(max_docs);
    let persistence = match &data_dir {
        Some(dir) => {
            // Erster Start: Das Verzeichnis gibt es noch nicht — anlegen,
            // statt das Replay auf einen fehlenden Pfad laufen zu lassen.
            if let Err(err) = std::fs::create_dir_all(dir) {
                eprintln!(
                    "error: Datenverzeichnis {} nicht anlegbar: {err}",
                    dir.display()
                );
                return ExitCode::FAILURE;
            }
            let cold = match replay_data_dir_full(&store, dir) {
                Ok((report, cold)) => {
                    tracing::info!(
                        snapshot_docs = report.snapshot_docs,
                        wal_files = report.wal_files,
                        wal_records = report.wal_records,
                        stopped_early = report.stopped_early.as_deref(),
                        "WAL-Replay abgeschlossen"
                    );
                    Arc::new(cold)
                }
                Err(err) => {
                    eprintln!("error: Replay des Datenverzeichnisses fehlgeschlagen: {err}");
                    return ExitCode::FAILURE;
                }
            };
            store.set_cold(Arc::clone(&cold));
            match Persistence::start(
                &store,
                PersistenceConfig {
                    data_dir: dir.clone(),
                    snapshot_interval: Duration::from_secs(snapshot_secs),
                    max_segment_bytes: wal_max_segment_mb.saturating_mul(1024 * 1024),
                },
                cold,
            ) {
                Ok(persistence) => Some(persistence),
                // M4: Doppelstart auf demselben data-dir — die Lock-Meldung
                // erklaert das Problem selbst, kein technischer Praefix noetig.
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
                Err(err) => {
                    eprintln!("error: WAL-Worker nicht startbar: {err}");
                    return ExitCode::FAILURE;
                }
            }
        }
        None => None,
    };
    // M3: Default 0 = unbegrenzt heisse Dokumente pro Kollektion. Der
    // Mechanismus existiert, aber stillschweigend unbegrenzt zu starten ist
    // die unsichere Wahl — laut sichtbar machen.
    if max_docs == 0 {
        tracing::warn!(
            "--max-docs nicht gesetzt (0 = unbegrenzt) — ein schreibender Client kann \
             den RAM vollschreiben, bis das Tiering (--max-docs N) eine Obergrenze \
             erzwingt; produktiv eine Kollektions-Obergrenze setzen"
        );
    }

    let state = match AppState::build_with_store(config, Arc::clone(&store), gateway_secret) {
        Ok(state) => state,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    if !compression {
        state.set_compression_enabled(false);
        tracing::info!("gzip-Komprimierung per --no-compression deaktiviert");
    }

    let (apps, endpoints) = state.summary();
    tracing::info!(
        %config_path,
        apps,
        endpoints,
        "configuration loaded and scripts precompiled"
    );

    let app = router::build_router(state);
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("error: cannot bind {bind_addr}: {err}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(%bind_addr, "steadfast listening (monolith mode)");

    // H1: Der Default-Bind ist die Loopback-Schnittstelle. Ein oeffentlicher
    // Bind ist der Normalbetrieb, verdient aber einen sichtbaren Hinweis auf
    // die Grenzen des Sicherheitsmodells (spoofbare X-User-Header, kein
    // Rate-Limiting im MVP). Hostnamen ("localhost:8080") parst SocketAddr
    // nicht — sie bleiben ohne Warnung, was harmlos ist.
    if let Ok(addr) = bind_addr.parse::<std::net::SocketAddr>() {
        if !addr.ip().is_loopback() {
            tracing::warn!(
                %bind_addr,
                "binding to a non-loopback address — die Engine vertraut den Headern \
                 X-User-Id/X-User-Role und hat im Monolith-Modus kein Rate-Limiting; \
                 im Netzwerkbetrieb nur hinter einem Gateway einsetzen, das diese \
                 Header aus Client-Requests entfernt"
            );
        }
    }

    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        if let Some(persistence) = persistence {
            let _ = persistence.shutdown(&store);
        }
        eprintln!("error: server failure: {err}");
        return ExitCode::FAILURE;
    }
    if let Some(persistence) = persistence {
        if let Err(err) = persistence.shutdown(&store) {
            eprintln!("error: WAL-Herunterfahren fehlgeschlagen: {err}");
            return ExitCode::FAILURE;
        }
    }
    tracing::info!("shutdown complete");
    ExitCode::SUCCESS
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
