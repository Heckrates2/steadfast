//! Store-Level-Benchmark fuer Phase 2b: Sekundaerindizes und Tiering.
//!
//! Misst nacheinander an derselben Datenmenge:
//!   1. Schreib-Durchsatz (Upserts)
//!   2. Gefilterte Liste per Vollscan (ohne Index)
//!   3. Gefilterte Liste ueber den Sekundaerindex
//!   4. Tiering: LRU-Eviction auf eine RAM-Obergrenze, danach Einzelgets
//!      auf heissen und auf kalten Dokumenten (Fetch-on-Miss)
//!   5. Gefilterte Liste mit Index, wenn ein Teil der Treffer kalt ist
//!
//! Absichtlich ohne criterion o.a. — std::Instant und Percentile reichen
//! fuer Groessenordnungsaussagen ("10-Euro-Server"-Geist). Laeuft am
//! besten mit `cargo run --release -p steadfast-storage --example bench_tiering`.
//! Ueber Umgebungsvariablen anpassbar: BENCH_DOCS, BENCH_HOT_CAP, BENCH_QUERIES.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use steadfast_storage::{ColdTier, ColdKey, ListParams, MemoryStore, write_snapshot_file};
use serde_json::json;

struct Config {
    docs: u64,
    hot_cap: usize,
    queries: usize,
}

fn config() -> Config {
    let env_num = |name: &str, default: u64| -> u64 {
        std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
    };
    Config {
        docs: env_num("BENCH_DOCS", 200_000),
        hot_cap: env_num("BENCH_HOT_CAP", 50_000) as usize,
        queries: env_num("BENCH_QUERIES", 200) as usize,
    }
}

fn percentile(sorted: &[u128], p: u64) -> u128 {
    let index = ((p as f64 / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn fmt_us(micros: u128) -> String {
    if micros >= 1_000 {
        format!("{:.2} ms", micros as f64 / 1_000.0)
    } else {
        format!("{micros} us")
    }
}

fn report(label: &str, latencies: &mut Vec<u128>, wall: Duration) {
    latencies.sort_unstable();
    let total = latencies.len();
    let per_sec = total as f64 / wall.as_secs_f64().max(f64::EPSILON);
    println!(
        "{label:<52} {:>9} Ops  {:>10}/s  p50 {:>9}  p99 {:>9}",
        total,
        format!("{per_sec:.0}"),
        fmt_us(percentile(latencies, 50)),
        fmt_us(percentile(latencies, 99)),
    );
}

fn main() {
    let cfg = config();
    println!(
        "bench_tiering: {} Docs, Hot-Cap {}, {} Queries",
        cfg.docs, cfg.hot_cap, cfg.queries
    );
    let store = MemoryStore::new();

    // 1) Schreib-Durchsatz -------------------------------------------------------
    let mut latencies = Vec::with_capacity(cfg.docs as usize);
    let start = Instant::now();
    for i in 0..cfg.docs {
        let t0 = Instant::now();
        store.insert(
            "bench",
            "tasks",
            &format!("d{i}"),
            json!({"n": i, "status": if i % 2 == 0 { "offen" } else { "erledigt" }, "prio": i % 10}),
        );
        latencies.push(t0.elapsed().as_micros());
    }
    let wall = start.elapsed();
    println!("\n--- 1) Schreiben (Upserts) ---");
    report("insert", &mut latencies, wall);

    // 2) Gefilterte Liste per Vollscan -------------------------------------------
    let params = || ListParams {
        page: 1,
        limit: 100,
        filters: vec![("status".to_string(), "offen".to_string())],
        ranges: Vec::new(),
        sort: None,
    };
    let mut latencies = Vec::with_capacity(cfg.queries);
    let mut totals: Option<usize> = None;
    let start = Instant::now();
    for _ in 0..cfg.queries {
        let t0 = Instant::now();
        let result = store.list("bench", "tasks", params());
        latencies.push(t0.elapsed().as_micros());
        totals = Some(result.total);
    }
    let wall = start.elapsed();
    println!("\n--- 2) Gefilterte Liste, Vollscan (status=offen, total {:?}) ---", totals);
    report("list scan", &mut latencies, wall);

    // 3) Gefilterte Liste ueber den Sekundaerindex -------------------------------
    store.declare_indexes("bench", "tasks", &["status".to_string()]);
    let mut latencies = Vec::with_capacity(cfg.queries);
    let start = Instant::now();
    for _ in 0..cfg.queries {
        let t0 = Instant::now();
        let result = black_box(store.list("bench", "tasks", params()));
        latencies.push(t0.elapsed().as_micros());
        assert_eq!(result.total, totals.unwrap(), "Index muss denselben total liefern");
    }
    let wall = start.elapsed();
    println!("\n--- 3) Gefilterte Liste, Sekundaerindex ---");
    report("list indexed", &mut latencies, wall);

    // 4) Tiering: Snapshot -> Kalt-Tier -> Eviction -> heisse/kalte Gets ---------
    let data_dir = std::env::temp_dir().join("rust-api-bench-tiering");
    std::fs::create_dir_all(&data_dir).unwrap();
    let dumps = store.dump_collections().unwrap();
    let index: HashMap<ColdKey, (u64, u32)> = write_snapshot_file(
        &data_dir.join("snapshot.tmp"),
        &data_dir.join("snapshot.bin"),
        &dumps,
    )
    .unwrap();
    let cold = ColdTier::new();
    cold.install_snapshot(data_dir.join("snapshot.bin"), index);
    store.set_cold(Arc::new(cold));
    store.set_hot_cap(cfg.hot_cap);
    store.run_eviction();
    let (total, cold_count) = store.hot_doc_counts("bench", "tasks").unwrap();
    println!(
        "\n--- 4) Tiering: Hot-Cap {}/{}, kalt gestellt: {} ---",
        cfg.hot_cap, total, cold_count
    );

    let mut hot_lat = Vec::with_capacity(2_000);
    let mut cold_lat = Vec::with_capacity(2_000);
    for i in 0..2_000u64 {
        // Heiss: juengste Ticks ueberleben die Eviction (Ende der Insertions-
        // ordnung); kalt: aelteste Dokumente sind mit Sicherheit evictiert.
        let hot_id = format!("d{}", cfg.docs - 1 - i);
        let cold_id = format!("d{i}");

        let t0 = Instant::now();
        let doc = store.get("bench", "tasks", &hot_id).expect("heisses Doc muss lesbar sein");
        hot_lat.push(t0.elapsed().as_micros());
        assert_eq!(doc["n"], json!(cfg.docs - 1 - i));

        let t0 = Instant::now();
        let doc = store.get("bench", "tasks", &cold_id).expect("kaltes Doc muss aus dem Tier kommen");
        cold_lat.push(t0.elapsed().as_micros());
        assert_eq!(doc["n"], json!(i));
    }
    // Bei den ineinander verschachtelten Gets ist keine Wanduhrzeit je
    // Klasse definiert — die Summe der Einzellatenzen ist die ehrliche
    // "beschaeftigungsbezogene" Durchsatzbasis.
    let busy = |lat: &[u128]| Duration::from_micros(lat.iter().sum::<u128>() as u64);
    let hot_wall = busy(&hot_lat);
    let cold_wall = busy(&cold_lat);
    report("get heiss", &mut hot_lat, hot_wall);
    report("get kalt (Fetch-on-Miss + Promote)", &mut cold_lat, cold_wall);
    let (_, cold_after) = store.hot_doc_counts("bench", "tasks").unwrap();
    println!(
        "  -> {}/2.000 kalt gelesen und promotiert (Restkalt: {cold_after})",
        cold_count.saturating_sub(cold_after).min(2_000)
    );

    // 5) Gefilterte Liste mit Index bei kalten Treffern --------------------------
    let mut latencies = Vec::with_capacity(cfg.queries);
    let start = Instant::now();
    for _ in 0..cfg.queries {
        let t0 = Instant::now();
        let result = black_box(store.list("bench", "tasks", params()));
        latencies.push(t0.elapsed().as_micros());
        assert_eq!(result.total, totals.unwrap(), "Tiering darf total nicht veraendern");
        assert_eq!(result.items.len(), 100);
    }
    let wall = start.elapsed();
    println!("\n--- 5) Gefilterte Liste mit Index, Treffer teils kalt ---");
    report("list indexed (kalte Payloads)", &mut latencies, wall);

    let _ = std::fs::remove_dir_all(&data_dir);
    println!("\nfertig.");
}
