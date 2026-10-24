//! End-to-End-Tests fuer WAL + Snapshot + Replay: echte Worker-Threads und
//! echte Dateien in temporaeren Verzeichnissen. Abgedeckt sind der
//! Roundtrip inkl. Listenordnung, Crash-Semantik (torn tail, CRC, kurze
//! Header), die Snapshot-Rotation des Workers und die Idempotenz bei
//! ueberlappenden Snapshot-/WAL-Quellen.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use steadfast_storage::{
    ColdTier, ListParams, MemoryStore, Persistence, PersistenceConfig, WAL_MAGIC, WalOp,
    encode_wal_op, replay_data_dir, replay_data_dir_full, wal_file_path, write_file_header,
    write_snapshot_file,
};
use tempfile::TempDir;

fn persistence_cfg(dir: &Path, interval: Duration) -> PersistenceConfig {
    PersistenceConfig {
        data_dir: dir.to_path_buf(),
        snapshot_interval: interval,
        max_segment_bytes: 0,
    }
}

/// Wartet, bis `cond` erstmals wahr ist (Poll alle 20 ms), und scheitert
/// mit Assert nach `deadline`. Blinde sleeps waeren hier ein Wettrennen
/// gegen den WAL-Worker — auf gedrosselten CI-Runnern mit langsamer Platte
/// (fsync im Rotationspfad) verlieren sie das. Lokal greift meist der
/// erste Poll, die Tests bleiben also schnell.
fn wait_until(deadline: Duration, mut cond: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !cond() {
        assert!(
            start.elapsed() < deadline,
            "Zustand nach {deadline:?} nicht erreicht — Worker haengt oder Platte zu langsam"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn list_ids(store: &MemoryStore, app: &str, collection: &str) -> Vec<String> {
    store
        .list(
            app,
            collection,
            ListParams {
                page: 1,
                limit: 1000,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        )
        .items
        .iter()
        .map(|doc| doc["id"].as_str().unwrap().to_string())
        .collect()
}

/// Neustes WAL-Segment (hoechste Epoch) im Verzeichnis.
fn newest_segment(dir: &Path) -> PathBuf {
    let mut best: Option<(u64, PathBuf)> = None;
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(raw) = name
            .strip_prefix("wal-")
            .and_then(|n| n.strip_suffix(".log"))
        else {
            continue;
        };
        let epoch: u64 = raw.parse().unwrap();
        if best.as_ref().is_none_or(|(e, _)| epoch > *e) {
            best = Some((epoch, entry.path()));
        }
    }
    best.expect("mindestens ein WAL-Segment").1
}

fn segment_count(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("wal-") && n.ends_with(".log"))
        })
        .count()
}

#[test]
fn replay_of_empty_data_dir_is_clean() {
    let dir = TempDir::new().unwrap();
    let restored = MemoryStore::new();
    let report = replay_data_dir(&restored, dir.path()).unwrap();
    assert_eq!(report.snapshot_docs, 0);
    assert_eq!(report.wal_files, 0);
    assert_eq!(report.wal_records, 0);
    assert!(report.stopped_early.is_none());
}

#[test]
fn persistence_roundtrip_preserves_state_and_order() {
    let dir = TempDir::new().unwrap();
    let source = Arc::new(MemoryStore::new());
    let persistence = Persistence::start(
        &source,
        persistence_cfg(dir.path(), Duration::ZERO),
        Arc::new(ColdTier::new()),
    )
    .unwrap();

    source.insert("app", "tasks", "a", json!({"n": "a"}));
    source.insert("app", "tasks", "b", json!({"n": "b"}));
    source.insert("app", "tasks", "c", json!({"n": "c"}));
    source
        .replace("app", "tasks", "a", json!({"n": "a2"}))
        .unwrap();
    source.delete("app", "tasks", "b").unwrap();
    source.insert("app", "tasks", "d", json!({"n": "d"}));
    persistence.shutdown(&source).unwrap();

    let restored = MemoryStore::new();
    let report = replay_data_dir(&restored, dir.path()).unwrap();
    assert_eq!(
        report.wal_records, 6,
        "3 Upserts + Replace + Delete + Upsert"
    );
    assert!(report.stopped_early.is_none());

    // Replace schiebt `a` ans Ende, `b` ist weg, `d` kam zuletzt.
    assert_eq!(list_ids(&restored, "app", "tasks"), vec!["c", "a", "d"]);
    assert_eq!(restored.get("app", "tasks", "a").unwrap()["n"], json!("a2"));
    assert!(restored.get("app", "tasks", "b").is_none());
}

#[test]
fn torn_tail_replays_the_prefix() {
    let dir = TempDir::new().unwrap();
    let source = Arc::new(MemoryStore::new());
    let persistence = Persistence::start(
        &source,
        persistence_cfg(dir.path(), Duration::ZERO),
        Arc::new(ColdTier::new()),
    )
    .unwrap();
    source.insert("app", "tasks", "first", json!({"n": 1}));
    source.insert("app", "tasks", "second", json!({"n": 2}));
    persistence.shutdown(&source).unwrap();

    // Abgebrochener Record mitten im Schreiben: vollstaendiges Laengenfeld,
    // aber abgeschnittener Body — der klassische Crash-Nachlauf.
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(newest_segment(dir.path()))
        .unwrap();
    file.write_all(&500u32.to_le_bytes()).unwrap();
    file.write_all(&[0u8; 10]).unwrap();
    drop(file);

    let restored = MemoryStore::new();
    let report = replay_data_dir(&restored, dir.path()).unwrap();
    assert!(
        report.stopped_early.is_none(),
        "torn tail ist ein gueltiges Dateiende"
    );
    assert_eq!(list_ids(&restored, "app", "tasks"), vec!["first", "second"]);
}

#[test]
fn crc_corruption_stops_the_file_but_keeps_the_prefix() {
    let dir = TempDir::new().unwrap();
    let source = Arc::new(MemoryStore::new());
    let persistence = Persistence::start(
        &source,
        persistence_cfg(dir.path(), Duration::ZERO),
        Arc::new(ColdTier::new()),
    )
    .unwrap();
    source.insert("app", "tasks", "first", json!({"n": 1}));
    source.insert("app", "tasks", "second", json!({"n": 2}));
    persistence.shutdown(&source).unwrap();

    // Letzten Record gezielt korrumpieren: Framing walken, Payload-Byte
    // flippen. Die CRC-Pruefung muss genau diesen Record verwerfen.
    let path = newest_segment(dir.path());
    let mut bytes = std::fs::read(&path).unwrap();
    let mut offset = 6usize; // Header
    let mut last_payload: Option<std::ops::Range<usize>> = None;
    while offset + 8 <= bytes.len() {
        let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let start = offset + 8;
        if start + len > bytes.len() {
            break;
        }
        last_payload = Some(start..start + len);
        offset = start + len;
    }
    let range = last_payload.expect("mindestens ein Record");
    bytes[range.end - 1] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();

    // Den Shutdown-Snapshot entfernen, damit die WAL alleinige Quelle ist —
    // sonst gaebe der Snapshot das korrumpierte Dokument ohnehin her.
    std::fs::remove_file(dir.path().join("snapshot.bin")).unwrap();

    let restored = MemoryStore::new();
    let report = replay_data_dir(&restored, dir.path()).unwrap();
    assert!(
        report.stopped_early.is_some(),
        "CRC-Abweichung muss gemeldet werden"
    );
    assert_eq!(report.wal_records, 1, "nur der Record vor der Korruption");
    assert!(restored.get("app", "tasks", "first").is_some());
    assert!(restored.get("app", "tasks", "second").is_none());
}

#[test]
fn short_wal_files_are_skipped() {
    let dir = TempDir::new().unwrap();
    // Crash beim Schreiben des Headers: weniger als 6 Bytes.
    std::fs::write(dir.path().join("wal-00000000000000000001.log"), b"RWA").unwrap();

    let restored = MemoryStore::new();
    let report = replay_data_dir(&restored, dir.path()).unwrap();
    assert_eq!(
        report.wal_files, 0,
        "halb geschriebener Header = leere Datei"
    );
}

#[test]
fn worker_rotation_writes_snapshot_and_deletes_old_segments() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(MemoryStore::new());
    let persistence = Persistence::start(
        &store,
        persistence_cfg(dir.path(), Duration::from_millis(50)),
        Arc::new(ColdTier::new()),
    )
    .unwrap();

    store.insert("app", "tasks", "a", json!({"n": 1}));
    wait_until(Duration::from_secs(15), || {
        dir.path().join("snapshot.bin").exists()
    });
    store.insert("app", "tasks", "b", json!({"n": 2}));
    persistence.shutdown(&store).unwrap();

    assert_eq!(
        segment_count(dir.path()),
        1,
        "alte Segmente muessen nach der Rotation geloescht sein"
    );

    let restored = MemoryStore::new();
    replay_data_dir(&restored, dir.path()).unwrap();
    assert_eq!(restored.get("app", "tasks", "a").unwrap()["n"], json!(1));
    assert_eq!(restored.get("app", "tasks", "b").unwrap()["n"], json!(2));
}

#[test]
fn overlapping_snapshot_and_wal_replay_to_final_state() {
    let dir = TempDir::new().unwrap();

    // 1) Snapshot aus einem frueheren Store-Zustand (nur `a`) — genau das,
    //    was der Worker bei der Rotation hinterlaesst.
    let old_state = MemoryStore::new();
    old_state.insert("app", "tasks", "a", json!({"n": 1}));
    let dumps = old_state.dump_collections().unwrap();
    write_snapshot_file(
        &dir.path().join("snapshot.tmp"),
        &dir.path().join("snapshot.bin"),
        &dumps,
    )
    .unwrap();

    // 2) WAL-Segment mit ueberlappenden Ops: `a` erneut + das neuere `b`.
    let mut wal = BufWriter::new(File::create(wal_file_path(dir.path(), 2)).unwrap());
    write_file_header(&mut wal, &WAL_MAGIC).unwrap();
    encode_wal_op(
        &mut wal,
        &WalOp::Upsert {
            app: "app".into(),
            collection: "tasks".into(),
            id: "a".into(),
            doc: Arc::new(json!({"n": 1})),
        },
    )
    .unwrap();
    encode_wal_op(
        &mut wal,
        &WalOp::Upsert {
            app: "app".into(),
            collection: "tasks".into(),
            id: "b".into(),
            doc: Arc::new(json!({"n": 2})),
        },
    )
    .unwrap();
    wal.flush().unwrap();

    // 3) Beide Quellen ueberlappen sich — das Replay muss trotzdem im
    //    korrekten Endzustand landen (idempotente Voll-Upserts).
    let restored = MemoryStore::new();
    let report = replay_data_dir(&restored, dir.path()).unwrap();
    assert_eq!(report.snapshot_docs, 1);
    assert_eq!(report.wal_records, 2);
    assert_eq!(list_ids(&restored, "app", "tasks"), vec!["a", "b"]);
}

#[test]
fn corrupt_snapshot_magic_is_a_hard_error() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("snapshot.bin"), b"JUNKJUNK").unwrap();

    let restored = MemoryStore::new();
    let err = replay_data_dir(&restored, dir.path());
    assert!(err.is_err(), "falscher Snapshot-Magic muss Fail-Fast sein");
}

#[test]
fn store_works_without_attached_wal() {
    // Ohne Senke (Replay-Phase, Tests) duerfen Mutationen nicht blockieren.
    let store = MemoryStore::new();
    store.insert("app", "tasks", "t1", json!({"n": 1}));
    assert_eq!(list_ids(&store, "app", "tasks"), vec!["t1"]);
}

#[test]
fn tiering_eviction_and_cold_fetch_roundtrip() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(MemoryStore::new());
    store.set_hot_cap(4);
    let cold = Arc::new(ColdTier::new());
    store.set_cold(Arc::clone(&cold));
    let persistence = Persistence::start(
        &store,
        persistence_cfg(dir.path(), Duration::from_millis(50)),
        Arc::clone(&cold),
    )
    .unwrap();

    for i in 0..10u64 {
        let status = if i % 2 == 0 { "offen" } else { "erledigt" };
        store.insert(
            "app",
            "tasks",
            &format!("t{i}"),
            json!({"n": i, "status": status}),
        );
    }
    // Der Worker hat rotiert und evictiert: die 6 aeltesten Dokumente sind
    // kalt gestellt, Gesamtzahl und Liste bleiben aber vollstaendig.
    wait_until(Duration::from_secs(15), || {
        store.hot_doc_counts("app", "tasks") == Some((10, 6))
    });

    // Direktzugriff auf das aelteste (kalte) Dokument, bevor irgendeine
    // Liste alles warmliest: Muss aus dem Tier nachladen und promoten.
    let doc = store.get("app", "tasks", "t0").expect("t0 existiert");
    assert_eq!(doc["n"], json!(0));
    assert_eq!(
        store.hot_doc_counts("app", "tasks"),
        Some((10, 5)),
        "Fetch auf kaltem Dokument muss laden und promoten"
    );

    // Mutationen auf Kaltstaenden greifen ueber das Tier.
    store
        .replace(
            "app",
            "tasks",
            "t1",
            json!({"n": 100, "status": "erledigt"}),
        )
        .expect("t1 existiert");
    assert!(store.delete("app", "tasks", "t2").is_some());

    assert_eq!(
        list_ids(&store, "app", "tasks"),
        vec!["t0", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t1"],
        "Liste bleibt trotz kalten Dokumenten vollstaendig und sortiert"
    );
    persistence.shutdown(&store).unwrap();

    // Phase 2: Neustart auf demselben Verzeichnis. Das Replay laedt den
    // Shutdown-Snapshot (9 Docs) und baut das Kalt-Tier aus Segment- und
    // Snapshot-Tiers wieder auf.
    let store2 = Arc::new(MemoryStore::new());
    store2.set_hot_cap(4);
    let (report, tier) = replay_data_dir_full(&store2, dir.path()).unwrap();
    assert_eq!(
        report.snapshot_docs, 9,
        "Shutdown-Snapshot haelt den Endzustand"
    );
    assert_eq!(
        report.wal_records, 2,
        "Replace t1 + Delete t2 aus dem Segment"
    );
    let cold2 = Arc::new(tier);
    store2.set_cold(Arc::clone(&cold2));
    let persistence2 = Persistence::start(
        &store2,
        persistence_cfg(dir.path(), Duration::from_millis(50)),
        Arc::clone(&cold2),
    )
    .unwrap();

    // Eine Mutation bringt den Worker zum Rotieren — erst danach evictiert
    // er erneut (Rotation ist an dirty Records gekoppelt).
    store2
        .replace("app", "tasks", "t0", json!({"n": 0, "status": "offen"}))
        .expect("t0 existiert");
    wait_until(Duration::from_secs(15), || {
        store2
            .hot_doc_counts("app", "tasks")
            .is_some_and(|(_, cold)| cold > 0)
    });

    // Jedes Dokument muss mit korrektem Payload lesbar sein — die kalten
    // kommen aus dem rekonstruierten Tier; das geloeschte Segment-File
    // (delete_segments_before) ueberspringt der Fetch via NotFound.
    for i in 0..10u64 {
        let id = format!("t{i}");
        let Some(doc) = store2.get("app", "tasks", &id) else {
            assert_eq!(id, "t2", "nur t2 wurde geloescht");
            continue;
        };
        let expected_n = if id == "t1" { 100 } else { i };
        assert_eq!(doc["n"], json!(expected_n), "Payload von {id}");
    }

    assert_eq!(
        list_ids(&store2, "app", "tasks"),
        vec!["t3", "t4", "t5", "t6", "t7", "t8", "t9", "t1", "t0"],
        "Reihenfolge ueberlebt Replay + Tiering; t0 rueckt durch den Replace ans Ende"
    );
    persistence2.shutdown(&store2).unwrap();
}

#[test]
fn double_start_on_same_data_dir_fails_and_relock_succeeds_after_shutdown() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(MemoryStore::new());
    let persistence = Persistence::start(
        &store,
        persistence_cfg(dir.path(), Duration::ZERO),
        Arc::new(ColdTier::new()),
    )
    .unwrap();
    store.insert("app", "tasks", "a", json!({"n": 1}));

    // Zweite Instanz auf demselben data-dir: muss hart scheitern, bevor sie
    // WAL oder Snapshot anfasst.
    let second_store = Arc::new(MemoryStore::new());
    let err = Persistence::start(
        &second_store,
        persistence_cfg(dir.path(), Duration::ZERO),
        Arc::new(ColdTier::new()),
    )
    .expect_err("Doppelstart auf demselben data-dir muss fehlschlagen");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::AlreadyExists,
        "unerwarteter Fehler: {err:?}"
    );
    assert!(err.to_string().contains("engine.lock") || err.to_string().contains("belegt"));

    // Nach sauberem Herunterfahren ist das Verzeichnis wieder freigebbar —
    // der Neustart (der Normalfall) darf durch die Sperre nicht leiden.
    persistence.shutdown(&store).unwrap();
    let second_store = Arc::new(MemoryStore::new());
    let second = Persistence::start(
        &second_store,
        persistence_cfg(dir.path(), Duration::ZERO),
        Arc::new(ColdTier::new()),
    )
    .expect("Nach dem Shutdown muss der data-dir wieder startbar sein");
    second.shutdown(&second_store).unwrap();
}

#[test]
fn cold_tier_fetch_matches_replay_semantics() {
    let dir = TempDir::new().unwrap();

    // Snapshot aus einem frueheren Zustand: t-up v1 und t-gone v1.
    let old_state = MemoryStore::new();
    old_state.insert("app", "tasks", "t-up", json!({"v": 1}));
    old_state.insert("app", "tasks", "t-gone", json!({"v": 1}));
    let dumps = old_state.dump_collections().unwrap();
    write_snapshot_file(
        &dir.path().join("snapshot.tmp"),
        &dir.path().join("snapshot.bin"),
        &dumps,
    )
    .unwrap();

    // WAL-Segment mit neueren Ops: t-up auf v2, t-gone geloescht, t-new v3.
    let mut wal = BufWriter::new(File::create(wal_file_path(dir.path(), 2)).unwrap());
    write_file_header(&mut wal, &WAL_MAGIC).unwrap();
    for op in [
        WalOp::Upsert {
            app: "app".into(),
            collection: "tasks".into(),
            id: "t-up".into(),
            doc: Arc::new(json!({"v": 2})),
        },
        WalOp::Delete {
            app: "app".into(),
            collection: "tasks".into(),
            id: "t-gone".into(),
        },
        WalOp::Upsert {
            app: "app".into(),
            collection: "tasks".into(),
            id: "t-new".into(),
            doc: Arc::new(json!({"v": 3})),
        },
    ] {
        encode_wal_op(&mut wal, &op).unwrap();
    }
    wal.flush().unwrap();

    let restored = MemoryStore::new();
    let (report, tier) = replay_data_dir_full(&restored, dir.path()).unwrap();
    assert_eq!(report.snapshot_docs, 2);
    assert_eq!(report.wal_records, 3);

    assert_eq!(restored.get("app", "tasks", "t-up").unwrap()["v"], json!(2));
    assert!(restored.get("app", "tasks", "t-gone").is_none());
    assert_eq!(
        restored.get("app", "tasks", "t-new").unwrap()["v"],
        json!(3)
    );

    // Und das Kalt-Tier entscheidet fuer dieselben Schluessel identisch:
    // das erste Tier mit Treffer gewinnt — ein Delete terminiert die Suche,
    // aeltere Snapshot-Versionen duerfen nicht aufleben.
    let doc = tier
        .fetch("app", "tasks", "t-up")
        .unwrap()
        .expect("t-up muss im Tier auffindbar sein");
    assert_eq!(doc["v"], json!(2));
    assert!(
        tier.fetch("app", "tasks", "t-gone").unwrap().is_none(),
        "Delete im Segment darf nicht vom Snapshot ueberholt werden"
    );
    let doc = tier
        .fetch("app", "tasks", "t-new")
        .unwrap()
        .expect("t-new muss im Tier auffindbar sein");
    assert_eq!(doc["v"], json!(3));
}

/// M3: Der Groessentrigger rotiert schon waehrend des Betriebs, ohne dass
/// ein Zeit-Tick gefeuert hat. Bei `snapshot_interval = 0` kann allein der
/// Trigger eine Rotation ausloesen — ein existierender Snapshot beweist
/// also genau das. Danach: Korrektheit des Replays ueber die rotierten
/// Segmente hinweg (alte Segmente geloescht, alles im Snapshot/neuen Segment).
#[test]
fn size_trigger_rotates_mid_run_and_replay_stays_correct() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(MemoryStore::new());
    let persistence = Persistence::start(
        &store,
        PersistenceConfig {
            data_dir: dir.path().to_path_buf(),
            snapshot_interval: Duration::ZERO,
            // Jedes Segment ist nach dem ersten Record "voll".
            max_segment_bytes: 1,
        },
        Arc::new(ColdTier::new()),
    )
    .unwrap();

    for id in ["a", "b", "c"] {
        store.insert("app", "tasks", id, json!({ "id": id }));
    }
    // Dem Worker Zeit geben, die Ops zu schreiben und den Groessentrigger
    // zu bedienen (Rotation inkl. Snapshot und Loeschung alter Segmente).
    wait_until(Duration::from_secs(15), || {
        dir.path().join("snapshot.bin").exists() && segment_count(dir.path()) == 1
    });

    let snapshot = dir.path().join("snapshot.bin");
    assert!(
        snapshot.exists(),
        "Groessentrigger muss waehrend des Betriebs rotieren \
         (snapshot_interval = 0 => nur der Trigger kann einen Snapshot erzeugen)"
    );
    assert_eq!(
        segment_count(dir.path()),
        1,
        "nach erfolgreicher Rotation ist nur das neue Segment uebrig"
    );

    persistence.shutdown(&store).unwrap();

    let restored = MemoryStore::new();
    replay_data_dir_full(&restored, dir.path()).unwrap();
    let mut ids = list_ids(&restored, "app", "tasks");
    ids.sort();
    assert_eq!(ids, vec!["a", "b", "c"]);
}
