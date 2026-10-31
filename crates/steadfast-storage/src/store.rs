//! In-Memory-Store mit drei Indizes pro Kollektion:
//!
//! - `by_id`: `DashMap<String, Stored>` fuer O(1)-Item-Zugriffe (GET/PUT/
//!   PATCH/DELETE per ID).
//! - `by_seq`: `RwLock<BTreeMap<u64, SeqSlot>>` fuer die Listenordnung —
//!   Paging springt per `BTreeMap` direkt zum Seitenanfang (O(log n)), ohne
//!   die Kollektion zu sortieren. Der Index bleibt bei Eviction vollstaendig
//!   (Payload `None`), damit List-Totals und Paging-Positionen stabil
//!   bleiben.
//! - `indexes`: Fuer deklarierte Felder (Union der `filter_fields` aller
//!   Endpunkte eines Pfades, siehe [`MemoryStore::declare_indexes`]) haelt
//!   jede Kollektion `Feld -> Wert-Schluessel -> (seq -> id)`. Gefilterte
//!   Listen greifen dann selektivitaetsbegrenzt per BTreeMap zu statt alle
//!   Dokumente zu scannen; die Schluessel spiegeln die [`value_matches`]-
//!   Semantik exakt (typgetrennte Namespaces `s:`/`b:`/`i:`/`u:`/`f:`). Die
//!   Indizes halten nur `(seq, ID)` und sind daher von der Eviction
//!   unberuehrt.
//!
//! Tiering: Pro Kollektion gibt es eine RAM-Obergrenze fuer heisse
//! Dokumente ([`MemoryStore::set_hot_cap`]). Der WAL-Worker ruft nach jeder
//! Rotation [`MemoryStore::run_eviction`] auf: Die aeltesten Zugriffs-Ticks
//! (globale Naeherung von LRU, aehnlich Redis) werden eviciert — der
//! Payload wird freigegeben, `(seq, ID)` bleiben in allen Indizes. Bei einem
//! Miss ([`MemoryStore::get`] oder Listen-Payload-Aufloesung) wird das
//! Dokument aus dem Kalt-Tier ([`crate::cold::ColdTier`], Offset-Indizes
//! ueber WAL-Segmente + Snapshot) einzeln nachgeladen und promotiert.
//!
//! Die Dokumente selbst liegen genau einmal im RAM (als `Arc<Value>`); alle
//! Indizes teilen sich denselben Referenzzähler. Listen liefern daher nur
//! Refcount-Bumps statt Deep-Copies, und Item-Responses serialisieren über
//! die schreibgeschützte Referenz — kein Memory Churn im Hot Path.
//!
//! Lock-Reihenfolge (gegen Deadlocks): immer erst `by_id` (DashMap-Shard),
//! dann `by_seq`, dann `indexes`, und Mutationen halten vorher den per-
//! Kollektion-Schreib-Mutex — nie die umgekehrte Reihenfolge. Die deklarierte
//! Feldmenge wird nur als geklonter `Arc` gelesen (kurzer DashMap-Guard),
//! damit sich Deklaration und Mutation nicht gegenseitig verklemmen.
//!
//! Randfall Kaltstand unlesbar (Fetch-Fehler): Mutationen auf solchen
//! Dokumenten raeumen die alten Indexpostings ueber die seq auf (statt ueber
//! die unbekannten Feldwerte) und liefern beim Delete `None` (404), obwohl
//! die Loeschung durchgefuehrt wurde. In einem gesunden System (Dateien
//! vorhanden, CRC ok) ist der Fall ausgeschlossen.

use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap};
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;

use dashmap::DashMap;
use serde_json::Value;

use crate::cold::ColdTier;
use crate::wal::WalOp;

/// Gruppierungsschluessel einer Kollektion.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CollectionKey {
    app: String,
    collection: String,
}

/// Gespeichertes Dokument inkl. Monotone-Nummer fuer stabile Listenordnung
/// (Einfuege-/Aktualisierungsreihenfolge) ueber alle Shards hinweg.
/// `data = None` heisst eviciert: Der Eintrag (und seine Postings in allen
/// Indizes) bleiben bestehen, der Payload kommt bei Bedarf aus dem Kalt-Tier.
/// `access` ist der letzte globale Zugriffs-Tick (LRU-Naeherung).
#[derive(Debug)]
struct Stored {
    seq: u64,
    data: Option<Arc<Value>>,
    access: AtomicU64,
}

/// Ordnungseintrag: die ID (fuer Payload-Aufloesung beim Paging) + Payload
/// (`None` = eviciert; der Eintrag bleibt fuer stabile Totals bestehen).
#[derive(Debug)]
struct SeqSlot {
    id: String,
    doc: Option<Arc<Value>>,
}

/// Sekundaerindex eines Feldes: kanonischer Wert-Schluessel (siehe
/// [`index_key_for_doc`]) -> seq -> ID. BTreeMap, damit Treffer bereits
/// seq-sortiert vorliegen (Listenordnung ohne Nachsortieren).
type FieldIndex = HashMap<String, BTreeMap<u64, String>>;

/// Innere Struktur einer Kollektion: Item-Index + Ordnungsindex + optionaler
/// Sekundaerindizes + Schreib-Mutex, der alle drei Indizes gemeinsam
/// konsistent haelt.
#[derive(Debug, Default)]
struct CollectionInner {
    by_id: DashMap<String, Stored>,
    by_seq: RwLock<BTreeMap<u64, SeqSlot>>,
    /// Anzahl evicierter (payload-loser) Eintraege: `by_id.len() - cold` ist
    /// die residente (heisse) Menge, Evictionsziel ist der Hot-Cap.
    cold: AtomicU64,
    /// Deklarierte Sekundaerindex-Felder (Union der `filter_fields` aller
    /// GET-Endpunkte dieses Pfades). Hinter RwLock als `Arc`: Mutationen
    /// klonen den Zaehler unter dem Schreib-Mutex, ohne die Menge zu halten.
    declared: RwLock<Arc<BTreeSet<String>>>,
    /// Feldname -> Wert-Schluessel -> (seq -> ID). Nur gepflegt fuer
    /// deklarierte Felder; Werte ohne Schluessel (Objekte/Arrays/null)
    /// tauchen nicht auf — sie matchen auch im Scan nie.
    indexes: RwLock<HashMap<String, FieldIndex>>,
    /// Serialisiert Mutationen, damit die Indizes nie auseinanderlaufen
    /// (z. B. Geistereintraege bei INSERT mit doppelter Client-ID).
    write: Mutex<()>,
}

/// Bereichs-Operator eines Range-Filters: `Gte`/`Lte` inklusiv (Grenze
/// trifft mit), `Gt`/`Lt` exklusiv. Vergleichssemantik siehe
/// [`value_in_range`] — der Rohwert wird nur als Datum verglichen, nie
/// interpretiert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeOp {
    Gte,
    Lte,
    Gt,
    Lt,
}

/// Sortier-Vorgabe fuer Listen: Feldname + Richtung (Default aufsteigend).
/// Die Gesamtordnung ueber gemischten JSON-Typen liefert
/// [`cmp_sort_values`]; Bindungen bleiben per seq stabil — in beiden
/// Richtungen, damit Paging ohne Dubletten/Luecken durchwandert werden
/// kann.
#[derive(Debug, Clone)]
pub struct SortSpec {
    pub field: String,
    pub descending: bool,
}

/// Parameter fuer `MemoryStore::list`.
#[derive(Debug, Clone)]
pub struct ListParams {
    /// 1-basiert.
    pub page: usize,
    pub limit: usize,
    /// Gleichheits-Filter auf Top-Level-Feldern: (Feldname, erwarteter Rohwert).
    pub filters: Vec<(String, String)>,
    /// Bereichs-Filter: (Feldname, Operator, Rohwert der Grenze). Alle
    /// Bereiche werden UND-verknuepft; siehe [`value_in_range`].
    pub ranges: Vec<(String, RangeOp, String)>,
    /// Sortierung ueber die gesamte Treffermenge vor dem Paging; `None`
    /// haelt die natuerliche seq-Ordnung (Einfuege-/Aktualisierungsfolge).
    pub sort: Option<SortSpec>,
}

/// Ergebnis von `MemoryStore::list`.
#[derive(Debug)]
pub struct ListResult {
    /// Gesamtzahl der Treffer (nach Filter, vor Paging).
    pub total: usize,
    pub page: usize,
    pub limit: usize,
    /// Seite der Dokumente (inkl. `id`-Feld) in Listenordnung — geteilte
    /// Referenzen auf die gespeicherten Dokumente, keine Kopien.
    pub items: Vec<Arc<Value>>,
}

/// Snapshot-Auszug einer Kollektion: `(ID, Dokument)` in seq-Reihenfolge.
#[derive(Debug)]
pub struct CollectionDump {
    pub app: String,
    pub collection: String,
    pub entries: Vec<(String, Arc<Value>)>,
}

/// Konfliktfall von [`MemoryStore::create`]: Die ID existiert bereits.
/// `existing` ist der aktuelle Stand (sofern lesbar; ein unlesbarer
/// Kaltstand bleibt `None` — der Konflikt besteht trotzdem).
#[derive(Debug)]
pub struct CreateConflict {
    pub existing: Option<Arc<Value>>,
}

/// Ergebnis von [`MemoryStore::patch_merge`].
#[derive(Debug)]
pub enum PatchOutcome<E> {
    /// ID (oder deren lesbarer Stand) nicht gefunden — keine Aenderung.
    NotFound,
    /// Die Transformation hat abgelehnt (z. B. Validierungs-/Skriptfehler) —
    /// keine Aenderung, kein WAL-Op.
    Rejected(E),
    /// Merge + Transformation erfolgreich und atomar committed.
    Updated(Arc<Value>),
}

/// Zaehler eines atomaren Sammel-Patches. `matched` zaehlt die Dokumente,
/// die zum Commit-Zeitpunkt alle Filter erfuellen; `patched` die davon
/// tatsaechlich neu geschriebenen — ein No-op-Merge (`set` enthaelt nur
/// schon vorhandene Werte) wird nicht committet, daher kann `patched`
/// unter `matched` liegen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BulkPatchReport {
    pub matched: usize,
    pub patched: usize,
}

/// Ergebnis von [`MemoryStore::patch_merge_bulk`].
#[derive(Debug)]
pub enum BulkPatchOutcome<E> {
    /// Mindestens eine Transformation hat abgelehnt — NICHTS wurde
    /// committet (All-or-Nothing), kein WAL-Op, keine neue seq.
    Rejected(E),
    /// Alle Transformationen akzeptiert; der Commit ist abgeschlossen.
    Completed(BulkPatchReport),
}

/// Schemaloser In-Memory-Speicher. Klonbar (`Arc`-Semantik ueber DashMap)
/// und von beliebig vielen Tokio-Workern gleichzeitig nutzbar. Mutationen
/// werden zusaetzlich in die angehaengte WAL-Senke eingereiht (siehe
/// [`crate::persist`]): RAM zuerst, Log danach — innerhalb des per-
/// Kollektion-Schreib-Mutex, damit Log-Reihenfolge == Commit-Reihenfolge.
#[derive(Debug, Default)]
pub struct MemoryStore {
    collections: DashMap<CollectionKey, Arc<CollectionInner>>,
    next_seq: AtomicU64,
    /// Globaler Zaehler fuer LRU-Zugriffs-Ticks (Naeherung, aehnlich Redis:
    /// kein per-Dokument-Link-Tracking, sondern monotone Ticks + Stichprobe).
    next_tick: AtomicU64,
    /// RAM-Obergrenze heisser Dokumente je Kollektion (0 = unbegrenzt).
    hot_cap: AtomicU64,
    /// Hoechste seq, die beim letzten Snapshot schon fertig angelegt war.
    /// Eviction fasst nur Dokumente mit seq <= Marke an — deren aktuelle
    /// Version liegt sicher im Snapshot bzw. im gerade geschlossenen Segment.
    snapshot_seq_watermark: AtomicU64,
    /// Kalt-Tier fuer Fetch-on-Miss; nach dem Replay angehaengt.
    cold: RwLock<Option<Arc<ColdTier>>>,
    /// WAL-Senke; selten angebunden/geloest, pro Mutation nur gelesen.
    wal: RwLock<Option<SyncSender<WalOp>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Legt ein Dokument an (bzw. ueberschreibt eine vorhandene ID) und
    /// erzwingt das `id`-Feld im Dokument. Gibt das gespeicherte Dokument
    /// als geteilte Referenz zurueck.
    pub fn insert(&self, app: &str, collection: &str, id: &str, mut data: Value) -> Arc<Value> {
        if let Value::Object(map) = &mut data {
            map.insert("id".to_string(), Value::String(id.to_string()));
        }
        let data = Arc::new(data);
        let inner = self.collection_for_write(app, collection);
        // Altstand eines evtl. evicierten Eintrags vorher aufloesen: Die
        // Indexpflege braucht die alten Feldwerte (oder mindestens die alte
        // seq, wenn der Kaltstand unlesbar ist).
        self.ensure_hot(&inner, app, collection, id);
        let _write = lock_write(&inner.write);
        // seq erst im Schreib-Mutex ziehen: Zusammen mit dem Snapshot-
        // Wasserzeichen (siehe dump_collections) garantiert das, dass jede
        // evictierbare Version beim Snapshot-Zeitpunkt schon sichtbar war.
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        // Client-seitige IDs koennen bereits existieren: den alten Ordnungs-
        // eintrag entfernen, sonst erscheint die ID doppelt in der Liste.
        let old = inner
            .by_id
            .get(id)
            .map(|slot| (slot.seq, slot.data.as_ref().map(Arc::clone)));
        if let Some((old_seq, _)) = &old {
            lock_seq_write(&inner.by_seq).remove(old_seq);
        }
        let fields = declared_fields(&inner);
        inner.by_id.insert(
            id.to_string(),
            Stored {
                seq,
                data: Some(Arc::clone(&data)),
                access: AtomicU64::new(self.tick()),
            },
        );
        lock_seq_write(&inner.by_seq).insert(
            seq,
            SeqSlot {
                id: id.to_string(),
                doc: Some(Arc::clone(&data)),
            },
        );
        if let Some((old_seq, old_doc)) = &old {
            match old_doc {
                Some(doc) => index_remove(&inner, fields.as_ref(), *old_seq, doc),
                None => {
                    // Kaltstand unlesbar geblieben (Fetch-Fehler): Postings
                    // ueber die seq saeubern, cold-Zaehler korrigieren.
                    index_remove_by_seq(&inner, fields.as_ref(), *old_seq);
                    inner.cold.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
        index_add(&inner, fields.as_ref(), seq, id, &data);
        self.log_wal(WalOp::Upsert {
            app: app.to_string(),
            collection: collection.to_string(),
            id: id.to_string(),
            doc: Arc::clone(&data),
        });
        data
    }

    /// Legt ein Dokument an und erzwingt das `id`-Feld. Existiert die ID
    /// bereits, wird nichts veraendert (kein WAL-Op) und der aktuelle Stand
    /// als Konflikt gemeldet — POST ist create-if-absent. Das Upsert-
    /// Verhalten von [`MemoryStore::insert`] bleibt dem WAL-Replay und
    /// internen Pfaden vorbehalten.
    pub fn create(
        &self,
        app: &str,
        collection: &str,
        id: &str,
        mut data: Value,
    ) -> Result<Arc<Value>, CreateConflict> {
        if let Value::Object(map) = &mut data {
            map.insert("id".to_string(), Value::String(id.to_string()));
        }
        let data = Arc::new(data);
        let inner = self.collection_for_write(app, collection);
        // Altstand eines evtl. evicierten Eintrags vorher aufloesen, damit
        // der Konfliktfall den gueltigen Payload melden kann.
        self.ensure_hot(&inner, app, collection, id);
        let _write = lock_write(&inner.write);
        if let Some(slot) = inner.by_id.get(id) {
            return Err(CreateConflict {
                existing: slot.data.as_ref().map(Arc::clone),
            });
        }
        // seq erst im Schreib-Mutex ziehen (siehe `insert`).
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let fields = declared_fields(&inner);
        inner.by_id.insert(
            id.to_string(),
            Stored {
                seq,
                data: Some(Arc::clone(&data)),
                access: AtomicU64::new(self.tick()),
            },
        );
        lock_seq_write(&inner.by_seq).insert(
            seq,
            SeqSlot {
                id: id.to_string(),
                doc: Some(Arc::clone(&data)),
            },
        );
        index_add(&inner, fields.as_ref(), seq, id, &data);
        self.log_wal(WalOp::Upsert {
            app: app.to_string(),
            collection: collection.to_string(),
            id: id.to_string(),
            doc: Arc::clone(&data),
        });
        Ok(data)
    }

    /// Liest ein Dokument als geteilte Referenz (Refcount-Bump, kein Clone).
    /// Kalte Dokumente werden aus dem Kalt-Tier nachgeladen und promotiert.
    pub fn get(&self, app: &str, collection: &str, id: &str) -> Option<Arc<Value>> {
        let inner = self.collection_for_read(app, collection)?;
        self.resolve_payload(&inner, app, collection, id)
    }

    /// Ersetzt ein Dokument vollstaendig (`id` wird erzwungen). `None`, wenn
    /// die ID nicht existiert (kein Upsert). Gibt das NEUE Dokument zurueck;
    /// der alte Ordnungseintrag wandert ans Listenende (neue seq).
    pub fn replace(
        &self,
        app: &str,
        collection: &str,
        id: &str,
        mut data: Value,
    ) -> Option<Arc<Value>> {
        let inner = self.collection_for_read(app, collection)?;
        if let Value::Object(map) = &mut data {
            map.insert("id".to_string(), Value::String(id.to_string()));
        }
        let data = Arc::new(data);
        self.ensure_hot(&inner, app, collection, id);
        let _write = lock_write(&inner.write);
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let (old_seq, old_doc) = {
            let mut slot = inner.by_id.get_mut(id)?;
            let old_seq = slot.seq;
            let old_doc = slot.data.as_ref().map(Arc::clone);
            slot.seq = seq;
            slot.data = Some(Arc::clone(&data));
            slot.access.store(self.tick(), Ordering::Relaxed);
            (old_seq, old_doc)
        };
        let fields = declared_fields(&inner);
        {
            let mut order = lock_seq_write(&inner.by_seq);
            order.remove(&old_seq);
            order.insert(
                seq,
                SeqSlot {
                    id: id.to_string(),
                    doc: Some(Arc::clone(&data)),
                },
            );
        }
        match old_doc {
            Some(doc) => index_remove(&inner, fields.as_ref(), old_seq, &doc),
            None => {
                index_remove_by_seq(&inner, fields.as_ref(), old_seq);
                inner.cold.fetch_sub(1, Ordering::Relaxed);
            }
        }
        index_add(&inner, fields.as_ref(), seq, id, &data);
        self.log_wal(WalOp::Upsert {
            app: app.to_string(),
            collection: collection.to_string(),
            id: id.to_string(),
            doc: Arc::clone(&data),
        });
        Some(data)
    }

    /// Loescht ein Dokument und gibt es zurueck. Bei einem unlesbaren
    /// Kaltstand wird trotzdem geloescht, aber `None` geliefert (der
    /// Aufrufer antwortet 404) — siehe Moduldokumentation.
    pub fn delete(&self, app: &str, collection: &str, id: &str) -> Option<Arc<Value>> {
        let inner = self.collection_for_read(app, collection)?;
        self.ensure_hot(&inner, app, collection, id);
        let _write = lock_write(&inner.write);
        let (_, stored) = inner.by_id.remove(id)?;
        let fields = declared_fields(&inner);
        lock_seq_write(&inner.by_seq).remove(&stored.seq);
        match stored.data {
            Some(ref doc) => index_remove(&inner, fields.as_ref(), stored.seq, doc),
            None => {
                index_remove_by_seq(&inner, fields.as_ref(), stored.seq);
                inner.cold.fetch_sub(1, Ordering::Relaxed);
            }
        }
        self.log_wal(WalOp::Delete {
            app: app.to_string(),
            collection: collection.to_string(),
            id: id.to_string(),
        });
        stored.data
    }

    /// Atomarer PATCH: liest den aktuellen Stand, wendet `transform` darauf
    /// an (Shallow-Merge + Business-Logik beim Aufrufer) und committet das
    /// Ergebnis unter demselben Schreib-Mutex. Ein nebenlaeufiges Replace/
    /// Delete zwischen Lesen und Schreiben ist damit ausgeschlossen (kein
    /// Lost Update); die neue Version erhaelt eine neue seq und wandert wie
    /// bei `replace` ans Listenende.
    ///
    /// `transform` laeuft unter der Sperre und sollte kurz sein — im Server
    /// deckelt das Rhai-Deadline-Limit (5 ms) die Laufzeit.
    pub fn patch_merge<E>(
        &self,
        app: &str,
        collection: &str,
        id: &str,
        transform: impl FnOnce(Value) -> Result<Value, E>,
    ) -> PatchOutcome<E> {
        let Some(inner) = self.collection_for_read(app, collection) else {
            return PatchOutcome::NotFound;
        };
        // Kalten Stand vorher aufloesen (ausserhalb des Mutex, siehe
        // `ensure_hot`), damit der Merge den gueltigen Payload sieht.
        self.ensure_hot(&inner, app, collection, id);
        let _write = lock_write(&inner.write);
        let (old_seq, current) = {
            let Some(slot) = inner.by_id.get(id) else {
                return PatchOutcome::NotFound;
            };
            let Some(current) = slot.data.as_ref().map(Arc::clone) else {
                // Unlesbarer Kaltstand (Fetch-Fehler): wie GET 404 — es gibt
                // keinen Stand, auf den der Merge sinnvoll anwendbar waere.
                return PatchOutcome::NotFound;
            };
            (slot.seq, current)
        };

        let mut merged = match transform((*current).clone()) {
            Ok(doc) => doc,
            Err(err) => return PatchOutcome::Rejected(err),
        };
        if let Value::Object(map) = &mut merged {
            map.insert("id".to_string(), Value::String(id.to_string()));
        }
        let merged = Arc::new(merged);

        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        {
            let mut slot = inner
                .by_id
                .get_mut(id)
                .expect("Eintrag verschwand unter dem Schreib-Mutex");
            slot.seq = seq;
            slot.data = Some(Arc::clone(&merged));
            slot.access.store(self.tick(), Ordering::Relaxed);
        }
        let fields = declared_fields(&inner);
        {
            let mut order = lock_seq_write(&inner.by_seq);
            order.remove(&old_seq);
            order.insert(
                seq,
                SeqSlot {
                    id: id.to_string(),
                    doc: Some(Arc::clone(&merged)),
                },
            );
        }
        index_remove(&inner, fields.as_ref(), old_seq, &current);
        index_add(&inner, fields.as_ref(), seq, id, &merged);
        self.log_wal(WalOp::Upsert {
            app: app.to_string(),
            collection: collection.to_string(),
            id: id.to_string(),
            doc: Arc::clone(&merged),
        });
        PatchOutcome::Updated(merged)
    }

    /// Atomarer Sammel-Patch: wendet `transform` (Shallow-Merge + Business-
    /// Logik beim Aufrufer) auf ALLE Dokumente an, die `filters`/`ranges`
    /// erfuellen — unter EINEM Schreib-Mutex-Acquisition. Ein nebenlaeufiger
    /// Single-Patch auf ein Treffer-Dokument blockiert bis zum Commit des
    /// Sammel-Patches und merged dann auf dessen neuem Stand; umgekehrt kann
    /// der Sammel-Patch kein Dokument ueberschreiben, das der Single-Patch
    /// committet hat. Nichts geht verloren.
    ///
    /// Zwei Phasen, damit die Deadlock-Regel des Moduls gilt (Kaltauflösung
    /// niemals unter dem Schreib-Mutex — `resolve_payload` nimmt ihn fuer
    /// Promotionen selbst): Phase 0 snapshottet die Kandidatenmenge
    /// (Sekundaerindex bzw. `by_seq`-Read-Lock) und waermt alle Kalt-Payloads.
    /// Phase A+B evaluiert unter der Sperre jeden Kandidaten FRISCH gegen die
    /// Filter (zwischenzeitlich geaenderte Dokumente matchen nicht mehr),
    /// wendet ALLE Transformationen an — die erste Ablehnung bricht ab,
    /// bevor auch nur ein Commit passiert ist (All-or-Nothing) — und
    /// committet dann in Kandidatenordnung (seq-aufsteigend, deterministisch
    /// in neuen seqs und WAL-Ops).
    ///
    /// Die Kandidatenmenge ist ein Snapshot: Dokumente, die zwischen Snapshot
    /// und Commit entstehen oder passend werden, gehoeren nicht dazu (dieselbe
    /// Semantik wie die Index-Treffermenge von `list`). No-op-Merges werden
    /// nicht committet; `patched` kann daher unter `matched` liegen.
    pub fn patch_merge_bulk<E>(
        &self,
        app: &str,
        collection: &str,
        filters: &[(String, String)],
        ranges: &[(String, RangeOp, String)],
        transform: impl Fn(Value) -> Result<Value, E>,
    ) -> BulkPatchOutcome<E> {
        let Some(inner) = self.collection_for_read(app, collection) else {
            return BulkPatchOutcome::Completed(BulkPatchReport {
                matched: 0,
                patched: 0,
            });
        };

        // Phase 0: Kandidaten + Kaltauflösung — bewusst VOR dem Schreib-Mutex
        // (resolve_payload nimmt ihn fuer Promotionen selbst).
        let candidates: Vec<String> = match index_lookup(&inner, filters) {
            Some(matched) => matched.into_iter().map(|(_, id)| id).collect(),
            None => lock_seq_read(&inner.by_seq)
                .values()
                .map(|slot| slot.id.clone())
                .collect(),
        };
        for id in &candidates {
            self.resolve_payload(&inner, app, collection, id);
        }

        let _write = lock_write(&inner.write);
        let mut matched = 0usize;
        // Phase A: alle Transformationen auswerten, bevor der erste Commit
        // passiert — die erste Ablehnung bricht ohne jede Aenderung ab.
        let mut staged: Vec<(String, u64, Arc<Value>, Arc<Value>)> = Vec::new();
        for id in &candidates {
            let (old_seq, current) = {
                let Some(slot) = inner.by_id.get(id) else {
                    continue; // zwischenzeitlich geloescht
                };
                let Some(current) = slot.data.as_ref().map(Arc::clone) else {
                    continue; // unlesbarer Kaltstand: wie list ueberspringen
                };
                (slot.seq, current)
            };
            if !filters
                .iter()
                .all(|(field, raw)| value_matches(&current, field, raw))
                || !ranges
                    .iter()
                    .all(|(field, op, raw)| value_in_range(&current, field, *op, raw))
            {
                continue;
            }
            let mut merged = match transform((*current).clone()) {
                Ok(doc) => doc,
                Err(err) => return BulkPatchOutcome::Rejected(err),
            };
            if let Value::Object(map) = &mut merged {
                map.insert("id".to_string(), Value::String(id.to_string()));
            }
            matched += 1;
            if merged == *current {
                continue; // No-op: kein Commit, kein WAL-Op, keine neue seq
            }
            staged.push((id.clone(), old_seq, current, Arc::new(merged)));
        }

        // Phase B: committen — dieselben Invarianten wie `patch_merge`, nur
        // sequenziell ueber die gesamte Treffermenge unter derselben Sperre.
        let mut patched = 0usize;
        for (id, old_seq, current, merged) in staged {
            let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
            {
                let mut slot = inner
                    .by_id
                    .get_mut(&id)
                    .expect("Eintrag verschwand unter dem Schreib-Mutex");
                slot.seq = seq;
                slot.data = Some(Arc::clone(&merged));
                slot.access.store(self.tick(), Ordering::Relaxed);
            }
            let fields = declared_fields(&inner);
            {
                let mut order = lock_seq_write(&inner.by_seq);
                order.remove(&old_seq);
                order.insert(
                    seq,
                    SeqSlot {
                        id: id.clone(),
                        doc: Some(Arc::clone(&merged)),
                    },
                );
            }
            index_remove(&inner, fields.as_ref(), old_seq, &current);
            index_add(&inner, fields.as_ref(), seq, &id, &merged);
            self.log_wal(WalOp::Upsert {
                app: app.to_string(),
                collection: collection.to_string(),
                id,
                doc: merged,
            });
            patched += 1;
        }
        BulkPatchOutcome::Completed(BulkPatchReport { matched, patched })
    }

    /// Gepingerte, gefilterte, optional sortierte Liste. Filter sind reine
    /// Gleichheitsvergleiche ([`value_matches`]), Bereiche typsichere
    /// Vergleiche gegen eine Grenze ([`value_in_range`]) — es gibt keine
    /// Abfragesprache, Werte werden nie als Code interpretiert.
    ///
    /// Ohne Filter/Bereich/Sortierung: O(log n) Sprung zum Seitenanfang,
    /// `limit` Payload-Aufloesungen. Mit reinen Gleichheitsfiltern: Wenn
    /// alle Filterfelder deklariert sind, liefert der Sekundaerindex die
    /// Treffermenge als (seq, ID)-Paare — nur die Seiten-Payloads werden
    /// geholt (Indizes sind von der Eviction unberuehrt).
    ///
    /// Mit Bereichs- und/oder Sortierkriterien wird zwingend die komplette
    /// Treffermenge aufgeloest (der Vergleich bzw. die Ordnung haengt am
    /// Dokumentinhalt): bei erklaerten Gleichheitsfiltern per Sekundaer-
    /// index vorselektiert, sonst per Scan. Kalte Dokumente werden dafuer
    /// alle nachgeladen — Range/Sort sind damit bewusst teurer als
    /// Gleichheitslisten (Phase-3-Kandidat: gepflegte Bereichs-/Sorti-
    /// indizes).
    pub fn list(&self, app: &str, collection: &str, params: ListParams) -> ListResult {
        let page = params.page.max(1);
        let limit = params.limit.max(1);
        let skip = (page - 1).saturating_mul(limit);

        let Some(inner) = self.collection_for_read(app, collection) else {
            return ListResult {
                total: 0,
                page,
                limit,
                items: Vec::new(),
            };
        };

        if params.ranges.is_empty() && params.sort.is_none() {
            if params.filters.is_empty() {
                let (total, page_ids) = {
                    let order = lock_seq_read(&inner.by_seq);
                    let ids: Vec<String> = order
                        .values()
                        .skip(skip)
                        .take(limit)
                        .map(|slot| slot.id.clone())
                        .collect();
                    (order.len(), ids)
                };
                let items = page_ids
                    .into_iter()
                    .filter_map(|id| self.resolve_payload(&inner, app, collection, &id))
                    .collect();
                return ListResult {
                    total,
                    page,
                    limit,
                    items,
                };
            }

            if let Some(matched) = index_lookup(&inner, &params.filters) {
                // matched ist seq-aufsteigend sortiert (Vereinigung und Schnitt
                // seq-sortierter BTreeMaps bleiben sortiert).
                let total = matched.len();
                let items = matched
                    .into_iter()
                    .skip(skip)
                    .take(limit)
                    .filter_map(|(_, id)| self.resolve_payload(&inner, app, collection, &id))
                    .collect();
                return ListResult {
                    total,
                    page,
                    limit,
                    items,
                };
            }
        }

        // Wertpfad: Kandidatenmenge bestimmen — bei Gleichheitsfiltern, die
        // vollstaendig deklariert sind, per Sekundaerindex vorselektiert
        // (der Range-/Sort-Vergleich braucht eh jeden Payload, der Index
        // spart nur den Collection-Scan), sonst voller Scan. Der Schluessel-
        // stand kommt unter kurzem Read-Lock, Kaltpayloads werden danach
        // ohne Sperren nachgeladen.
        let slots: Vec<(u64, String, Option<Arc<Value>>)> =
            match index_lookup(&inner, &params.filters) {
                Some(matched) => matched
                    .into_iter()
                    .map(|(seq, id)| (seq, id, None))
                    .collect(),
                None => {
                    let order = lock_seq_read(&inner.by_seq);
                    order
                        .iter()
                        .map(|(seq, slot)| {
                            (*seq, slot.id.clone(), slot.doc.as_ref().map(Arc::clone))
                        })
                        .collect()
                }
            };
        let mut matched: Vec<(u64, Arc<Value>)> = Vec::new();
        for (seq, id, doc) in slots {
            let doc = match doc {
                Some(doc) => doc,
                None => match self.resolve_payload(&inner, app, collection, &id) {
                    Some(doc) => doc,
                    None => continue, // zwischenzeitlich geloescht/unlesbar
                },
            };
            if params
                .filters
                .iter()
                .all(|(field, raw)| value_matches(&doc, field, raw))
                && params
                    .ranges
                    .iter()
                    .all(|(field, op, raw)| value_in_range(&doc, field, *op, raw))
            {
                matched.push((seq, doc));
            }
        }

        // Sortierung ueber die gesamte Treffermenge, bevor gepagint wird.
        // Der seq-Tiebreak bleibt in beiden Richtungen aufsteigend, damit
        // sortierte Seiten ohne Dubletten/Luecken durchwanderbar sind.
        if let Some(sort) = &params.sort {
            let descending = sort.descending;
            matched.sort_by(|(seq_a, doc_a), (seq_b, doc_b)| {
                let primary = cmp_sort_values(
                    doc_a.get(sort.field.as_str()),
                    doc_b.get(sort.field.as_str()),
                );
                let primary = if descending {
                    primary.reverse()
                } else {
                    primary
                };
                primary.then_with(|| seq_a.cmp(seq_b))
            });
        }

        let total = matched.len();
        let items = matched
            .into_iter()
            .skip(skip)
            .take(limit)
            .map(|(_, doc)| doc)
            .collect();
        ListResult {
            total,
            page,
            limit,
            items,
        }
    }

    /// Deklariert die sekundaer-indexierten Felder einer Kollektion (der
    /// Server ruft dies beim Start mit der Union der `filter_fields` aller
    /// GET-Endpunkte eines Pfades auf). Bestehende Dokumente werden
    /// nachgetragen; ab jetzt pflegen insert/replace/delete die Indizes
    /// inkrementell. Eine leere Liste raeumt die Deklaration auf.
    ///
    /// Laeuft unter dem Schreib-Mutex der Kollektion: Der Backfill liest den
    /// vollstaendigen Bestand, waehrend keine Mutation dazwischenfunken kann.
    pub fn declare_indexes(&self, app: &str, collection: &str, fields: &[String]) {
        let inner = self.collection_for_write(app, collection);
        let _write = lock_write(&inner.write);
        let set: Arc<BTreeSet<String>> = Arc::new(fields.iter().cloned().collect());
        *inner.declared.write().expect("index declaration poisoned") = Arc::clone(&set);
        // Backfill: Indizes fuer alle deklarierten Felder neu aus dem
        // Bestand aufbauen — pauschal, also verschwinden auch leere Buckets
        // einer frueheren Deklaration mit. Kalt dokuments gibt es hier nicht
        // (Deklaration laeuft beim Start vor der ersten Eviction), aber der
        // Code ist defensiv: Ohne Payload kein Posting, der Fetch im Betrieb
        // vervollstaendigt die Indizes nicht nach (Scan-Fallback bleibt
        // korrekt, nur langsamer).
        let mut fresh: HashMap<String, FieldIndex> = HashMap::with_capacity(set.len());
        for field in set.iter() {
            fresh.insert(field.clone(), HashMap::new());
        }
        for slot in inner.by_id.iter() {
            let Some(doc) = slot.data.as_ref() else {
                continue;
            };
            for (field, map) in fresh.iter_mut() {
                if let Some(key) = index_key_for_doc(doc.get(field)) {
                    map.entry(key)
                        .or_default()
                        .insert(slot.seq, slot.key().clone());
                }
            }
        }
        *inner.indexes.write().expect("secondary indexes poisoned") = fresh;
    }

    /// Haengt die WAL-Senke an (vor `Persistence::start`). Alle folgenden
    /// Mutationen werden in den Kanal eingereiht.
    pub fn attach_wal(&self, sink: SyncSender<WalOp>) {
        *self.wal.write().expect("wal slot poisoned") = Some(sink);
    }

    /// Loest die WAL-Senke (`Persistence::shutdown`), damit der Worker das
    /// Kanal-Ende als Herunterfahr-Signal sieht.
    pub fn detach_wal(&self) -> Option<SyncSender<WalOp>> {
        self.wal.write().expect("wal slot poisoned").take()
    }

    /// Enqueue eines WAL-Events. Blockiert bei vollem Kanal (Rueckstau statt
    /// Datenverlust); ohne angehaengte Senke (Replay-Phase) ein No-op. Ein
    /// zerbrochener Kanal (Worker tot) verliert das Event still — der Worker
    /// loggt Schreibfehler selbst.
    fn log_wal(&self, op: WalOp) {
        if let Some(sink) = self.wal.read().expect("wal slot poisoned").as_ref() {
            let _ = sink.send(op);
        }
    }

    /// Setzt die RAM-Obergrenze heisser Dokumente je Kollektion (0 =
    /// unbegrenzt, der Default). Eviction greift erst nach der naechsten
    /// WAL-Rotation (siehe [`MemoryStore::run_eviction`]).
    pub fn set_hot_cap(&self, cap: usize) {
        self.hot_cap.store(cap as u64, Ordering::Relaxed);
    }

    /// Haengt das Kalt-Tier an (nach dem WAL-Replay, vor dem ersten Traffic).
    pub fn set_cold(&self, cold: Arc<ColdTier>) {
        *self.cold.write().expect("cold slot poisoned") = Some(cold);
    }

    /// Naechster globaler LRU-Zugriffs-Tick (billig, monotone Naeherung).
    fn tick(&self) -> u64 {
        self.next_tick.fetch_add(1, Ordering::Relaxed)
    }

    /// `(Gesamt, kalt)` einer Kollektion fuer Tests und Betrieb; `None`, wenn
    /// die Kollektion unbekannt ist.
    pub fn hot_doc_counts(&self, app: &str, collection: &str) -> Option<(usize, usize)> {
        let inner = self.collection_for_read(app, collection)?;
        let total = inner.by_id.len();
        let cold = (inner.cold.load(Ordering::Relaxed) as usize).min(total);
        Some((total, cold))
    }

    /// Stellt bei Bedarf sicher, dass ein Eintrag vor der Mutation einen
    /// lesbaren Payload hat: Ein Kaltstand wird hier (vor dem Schreib-Mutex)
    /// nachgeladen und promotiert. Unlesbare Kaltstaende (Fetch-Fehler)
    /// bleiben stehen — die Mutationen raeumen sie ueber die seq auf
    /// (siehe Moduldokumentation).
    fn ensure_hot(&self, inner: &CollectionInner, app: &str, collection: &str, id: &str) {
        let Some(slot) = inner.by_id.get(id) else {
            return;
        };
        if inner.cold.load(Ordering::Relaxed) == 0 || slot.data.is_some() {
            return;
        }
        drop(slot);
        self.resolve_payload(inner, app, collection, id);
    }

    /// Payload eines Eintrags mit Fetch-on-Miss: Heisse Payloads werden als
    /// Refcount-Bump geliefert (und der LRU-Tick gebumpt); kalte aus dem
    /// Kalt-Tier geholt, unter dem Schreib-Mutex promotiert (nur, wenn der
    /// Eintrag noch kalt ist — ein concurrent Writer haette sonst Vorrang)
    /// und in beide Indizes zurueckgetragen.
    fn resolve_payload(
        &self,
        inner: &CollectionInner,
        app: &str,
        collection: &str,
        id: &str,
    ) -> Option<Arc<Value>> {
        // Heisser Pfad: Der Lese-Guard des DashMap-Shards lebt bewusst nur
        // in diesem Block — weiter unten nimmt get_mut(id) dieselbe Shard-
        // Sperre schreibend; ein laenger lebender Guard blockiert sich selbst.
        let hot = {
            let slot = inner.by_id.get(id)?;
            slot.access.store(self.tick(), Ordering::Relaxed);
            slot.data.as_ref().map(Arc::clone)
        };
        if let Some(doc) = hot {
            return Some(doc);
        }
        let tier = Arc::clone(self.cold.read().expect("cold slot poisoned").as_ref()?);
        let doc = match tier.fetch(app, collection, id) {
            Ok(Some(doc)) => doc,
            Ok(None) => {
                tracing::debug!(
                    app,
                    collection,
                    id,
                    "kaltes Dokument nicht im Kalt-Tier gefunden"
                );
                return None;
            }
            Err(err) => {
                tracing::warn!(%err, app, collection, id, "Kaltladen fehlgeschlagen");
                return None;
            }
        };
        // Promotieren — nur, wenn der Eintrag noch kalt ist.
        let _write = lock_write(&inner.write);
        let seq = {
            let mut slot = inner.by_id.get_mut(id)?;
            if let Some(existing) = slot.data.as_ref() {
                return Some(Arc::clone(existing));
            }
            slot.data = Some(Arc::clone(&doc));
            slot.access.store(self.tick(), Ordering::Relaxed);
            inner.cold.fetch_sub(1, Ordering::Relaxed);
            slot.seq
        };
        if let Some(entry) = lock_seq_write(&inner.by_seq).get_mut(&seq) {
            entry.doc = Some(Arc::clone(&doc));
        }
        Some(doc)
    }

    /// Eviction nach WAL-Rotation: Pro Kollektion die aeltesten Zugriffs-
    /// Ticks freigeben, bis der Hot-Cap-Unterlauf (Low Water ~95 %) erreicht
    /// ist. Bewusst erst hier — nach der Rotation liegt jede residente
    /// Version entweder im frisch geschlossenen Segment oder im Snapshot,
    /// ein Evicierter ist also immer wieder beschaffbar. Indizes und
    /// Ordnungsindex bleiben vollstaendig; nur der Payload geht verloren.
    ///
    /// `snapshot_seq_watermark` schuetzt Dokumente, die NACH dem letzten
    /// Snapshot geschrieben wurden (seq > Marke): deren Version koennte noch
    /// nur im ungeflusheten aktiven Segment liegen.
    pub fn run_eviction(&self) {
        let cap = self.hot_cap.load(Ordering::Relaxed) as usize;
        if cap == 0 {
            return;
        }
        let low_water = cap.saturating_sub(cap / 20).max(1); // ~95 % des Caps
        for entry in self.collections.iter() {
            let inner = entry.value();
            loop {
                let cold = inner.cold.load(Ordering::Relaxed) as usize;
                let resident = inner.by_id.len().saturating_sub(cold);
                if resident <= low_water {
                    break;
                }
                let need = resident - low_water;
                // Stichprobe: ein Heap ueber die aeltesten Zugriffs-Ticks
                // (kleinste Tick-Zahl = am laengsten nicht angefasst).
                let mut heap: BinaryHeap<(u64, String)> = BinaryHeap::with_capacity(need);
                for slot in inner.by_id.iter() {
                    if slot.data.is_some() {
                        let cand = (slot.access.load(Ordering::Relaxed), slot.key().clone());
                        if heap.len() < need {
                            heap.push(cand);
                        } else if heap.peek().is_some_and(|&(worst, _)| cand.0 < worst) {
                            heap.pop();
                            heap.push(cand);
                        }
                    }
                }
                if heap.is_empty() {
                    break;
                }
                let watermark = self.snapshot_seq_watermark.load(Ordering::SeqCst);
                let _write = lock_write(&inner.write);
                while let Some((_, id)) = heap.pop() {
                    let cold_now = inner.cold.load(Ordering::Relaxed) as usize;
                    if inner.by_id.len().saturating_sub(cold_now) <= low_water {
                        break;
                    }
                    let Some(mut slot) = inner.by_id.get_mut(&id) else {
                        continue;
                    };
                    if slot.data.is_none() || slot.seq > watermark {
                        continue;
                    }
                    slot.data = None;
                    let seq = slot.seq;
                    drop(slot);
                    if let Some(entry) = lock_seq_write(&inner.by_seq).get_mut(&seq) {
                        entry.doc = None;
                    }
                    inner.cold.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Vollstaendiger Auszug aller Kollektionen fuer den Snapshot. Setzt
    /// zuerst das Snapshot-Wasserzeichen (hoechste bereits vergebene seq):
    /// Alles mit seq <= Marke ist beim Schreiben des Snapshots sichtbar,
    /// alles Spaetere ist per Definition noch nicht evicierbar. Kalte
    /// Dokumente werden aus dem Kalt-Tier nachgeladen — ein Snapshot ohne
    /// sie wuerde sie bei der naechsten Compaction verlieren. Fehler (kein
    /// Tier angehaengt, Datei unlesbar) brechen den Snapshot ab; die WAL
    /// bleibt autoritativ und die Rotation wird beim naechsten Intervall
    /// erneut versucht.
    pub fn dump_collections(&self) -> io::Result<Vec<CollectionDump>> {
        self.snapshot_seq_watermark
            .store(self.next_seq.load(Ordering::SeqCst), Ordering::SeqCst);
        let cold = self
            .cold
            .read()
            .expect("cold slot poisoned")
            .as_ref()
            .map(Arc::clone);
        let mut dumps = Vec::with_capacity(self.collections.len());
        for entry in self.collections.iter() {
            let key = entry.key();
            let mut staged: Vec<(u64, String, Option<Arc<Value>>)> = entry
                .value()
                .by_id
                .iter()
                .map(|slot| {
                    (
                        slot.seq,
                        slot.key().clone(),
                        slot.data.as_ref().map(Arc::clone),
                    )
                })
                .collect();
            staged.sort_unstable_by_key(|(seq, _, _)| *seq);
            let mut entries = Vec::with_capacity(staged.len());
            for (_seq, id, doc) in staged {
                let doc = match doc {
                    Some(doc) => doc,
                    None => {
                        let tier = cold.as_ref().ok_or_else(|| {
                            io::Error::other(format!(
                                "kaltes Dokument {}/{} aber kein Kalt-Tier angehaengt",
                                key.app, key.collection
                            ))
                        })?;
                        tier.fetch(&key.app, &key.collection, &id)?.ok_or_else(|| {
                            io::Error::other(format!(
                                "kaltes Dokument {}/{}/{} nicht im Kalt-Tier auffindbar",
                                key.app, key.collection, id
                            ))
                        })?
                    }
                };
                entries.push((id, doc));
            }
            dumps.push(CollectionDump {
                app: key.app.clone(),
                collection: key.collection.clone(),
                entries,
            });
        }
        Ok(dumps)
    }

    fn collection_for_write(&self, app: &str, collection: &str) -> Arc<CollectionInner> {
        self.collections
            .entry(CollectionKey {
                app: app.to_string(),
                collection: collection.to_string(),
            })
            .or_insert_with(|| Arc::new(CollectionInner::default()))
            .clone()
    }

    fn collection_for_read(&self, app: &str, collection: &str) -> Option<Arc<CollectionInner>> {
        let key = CollectionKey {
            app: app.to_string(),
            collection: collection.to_string(),
        };
        self.collections.get(&key).map(|entry| Arc::clone(&entry))
    }
}

fn lock_write(mutex: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    mutex.lock().expect("write mutex poisoned")
}

fn lock_seq_write(
    order: &RwLock<BTreeMap<u64, SeqSlot>>,
) -> std::sync::RwLockWriteGuard<'_, BTreeMap<u64, SeqSlot>> {
    order.write().expect("seq index poisoned")
}

fn lock_seq_read(
    order: &RwLock<BTreeMap<u64, SeqSlot>>,
) -> std::sync::RwLockReadGuard<'_, BTreeMap<u64, SeqSlot>> {
    order.read().expect("seq index poisoned")
}

// --- Sekundaerindizes -----------------------------------------------------------

/// Aktuelle Deklaration als geklonter `Arc` (kurzer Read-Guard, damit sich
/// `declare_indexes` und Mutationen nicht gegenseitig verklemmen).
fn declared_fields(inner: &CollectionInner) -> Arc<BTreeSet<String>> {
    Arc::clone(&inner.declared.read().expect("index declaration poisoned"))
}

/// Traegt ein Dokument unter allen deklarierten Feldern in die Sekundaer-
/// indizes ein. Muss unter dem Schreib-Mutex der Kollektion laufen.
fn index_add(inner: &CollectionInner, fields: &BTreeSet<String>, seq: u64, id: &str, doc: &Value) {
    if fields.is_empty() {
        return;
    }
    let mut indexes = inner.indexes.write().expect("secondary indexes poisoned");
    for field in fields {
        if let Some(key) = index_key_for_doc(doc.get(field)) {
            indexes
                .entry(field.clone())
                .or_default()
                .entry(key)
                .or_default()
                .insert(seq, id.to_string());
        }
    }
}

/// Entfernt die Postings einer Dokumentversion (seq + alter Dokumentstand)
/// aus allen deklarierten Indizes; leere Buckets werden aufgeraeumt. Muss
/// unter dem Schreib-Mutex der Kollektion laufen.
fn index_remove(inner: &CollectionInner, fields: &BTreeSet<String>, seq: u64, doc: &Value) {
    if fields.is_empty() {
        return;
    }
    let mut indexes = inner.indexes.write().expect("secondary indexes poisoned");
    for field in fields {
        let Some(key) = index_key_for_doc(doc.get(field)) else {
            continue;
        };
        if let Some(postings) = indexes.get_mut(field) {
            if let Some(bucket) = postings.get_mut(&key) {
                bucket.remove(&seq);
                if bucket.is_empty() {
                    postings.remove(&key);
                }
            }
        }
    }
}

/// Entfernt alle Postings einer seq aus allen deklarierten Indizes — ohne
/// die Feldwerte zu kennen. Faellt in Mutationen zurueck, wenn der alte
/// Stand eviciert UND unlesbar war: Eine seq steht in genau den Buckets,
/// auf die ihre Dokumentversion abgebildet hat, das Entfernen ueber die seq
/// ist also exakt (nur etwas teurer). Muss unter dem Schreib-Mutex laufen.
fn index_remove_by_seq(inner: &CollectionInner, fields: &BTreeSet<String>, seq: u64) {
    if fields.is_empty() {
        return;
    }
    let mut indexes = inner.indexes.write().expect("secondary indexes poisoned");
    for field in fields {
        let Some(postings) = indexes.get_mut(field) else {
            continue;
        };
        postings.retain(|_, bucket| {
            bucket.remove(&seq);
            !bucket.is_empty()
        });
    }
}

/// Treffermenge einer Filterliste per Sekundaerindex — `None`, wenn ein
/// Filterfeld nicht deklariert ist (dann Scan-Fallback). Pro Filter wird
/// die Vereinigung aller moeglichen Wert-Schluessel gebildet (ein Rohwert
/// kann je Dokumenttyp unterschiedliche Branches treffen), ueber Filter
/// wird die Schnittmenge genommen. Ergebnis seq-aufsteigend sortiert.
fn index_lookup(
    inner: &CollectionInner,
    filters: &[(String, String)],
) -> Option<Vec<(u64, String)>> {
    let fields = declared_fields(inner);
    if fields.is_empty() {
        return None;
    }
    let indexes = inner.indexes.read().expect("secondary indexes poisoned");
    let mut acc: Option<BTreeMap<u64, String>> = None;
    for (field, raw) in filters {
        if !fields.contains(field) {
            return None;
        }
        let Some(field_map) = indexes.get(field) else {
            // Deklariert, aber keine Postings: entweder leerer Bestand oder
            // kein Dokument traegt einen indexierbaren Wert unter dem Feld.
            return Some(Vec::new());
        };
        let mut union: BTreeMap<u64, String> = BTreeMap::new();
        for key in index_query_keys(raw) {
            if let Some(postings) = field_map.get(&key) {
                for (seq, id) in postings {
                    union.insert(*seq, id.clone());
                }
            }
        }
        match acc.as_mut() {
            None => acc = Some(union),
            Some(prev) => prev.retain(|seq, _| union.contains_key(seq)),
        }
        if acc.as_ref().is_some_and(|m| m.is_empty()) {
            return Some(Vec::new());
        }
    }
    acc.map(|m| m.into_iter().collect())
}

/// Kanonisierter Index-Schluessel eines Dokumentwerts. Die Branches spiegeln
/// [`value_matches`] exakt (erst i64, dann u64, dann f64) und sind
/// typgetrennt, damit z. B. die Zahl 1 und der String "1" nicht kollidieren.
/// Objekte/Arrays/null liefern `None` — sie matchen auch im Scan nie.
fn index_key_for_doc(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(format!("s:{s}")),
        Value::Bool(true) => Some("b:true".to_string()),
        Value::Bool(false) => Some("b:false".to_string()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(format!("i:{i}"))
            } else if let Some(u) = n.as_u64() {
                Some(format!("u:{u}"))
            } else {
                n.as_f64().map(|f| format!("f:{f}"))
            }
        }
        Value::Object(_) | Value::Array(_) | Value::Null => None,
    }
}

/// Alle Index-Schluessel, die ein Rohwert aus dem Query-String potentiell
/// matchen kann: der String-Vergleich immer, Bool-Schluessel bei "true"/
/// "false", Zahl-Schluessel gemaess parse-Faehigkeit (i64/u64-Branches
/// schliessen sich wie in [`value_matches`] gegenseitig aus, der f64-Branch
/// bleibt davon unberuehrt).
fn index_query_keys(raw: &str) -> Vec<String> {
    let mut keys = vec![format!("s:{raw}")];
    if raw == "true" {
        keys.push("b:true".to_string());
    } else if raw == "false" {
        keys.push("b:false".to_string());
    }
    if let Ok(i) = raw.parse::<i64>() {
        keys.push(format!("i:{i}"));
    } else if let Ok(u) = raw.parse::<u64>() {
        keys.push(format!("u:{u}"));
    }
    if let Ok(f) = raw.parse::<f64>() {
        keys.push(format!("f:{f}"));
    }
    keys
}

/// Typsicherer Gleichheitsvergleich eines Rohwert-Strings (aus dem Query-
/// String) gegen einen JSON-Wert. Der Rohwert wird NUR als Datum verglichen,
/// nie als Ausdruck interpretiert: String bleibt String-Vergleich, Zahlen/
/// Bools werden geparst und typgleich verglichen. Alles andere matcht nicht.
fn value_matches(doc: &Value, field: &str, raw: &str) -> bool {
    let Some(value) = doc.get(field) else {
        return false;
    };
    match value {
        Value::String(s) => s == raw,
        Value::Bool(b) => (raw == "true" && *b) || (raw == "false" && !*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                raw.parse::<i64>().is_ok_and(|parsed| parsed == i)
            } else if let Some(u) = n.as_u64() {
                raw.parse::<u64>().is_ok_and(|parsed| parsed == u)
            } else if let Some(f) = n.as_f64() {
                raw.parse::<f64>().is_ok_and(|parsed| parsed == f)
            } else {
                false
            }
        }
        // Objekte/Arrays/null sind als Filterziel nicht vorgesehen.
        _ => false,
    }
}

/// Typsicherer Bereichsvergleich eines Rohwert-Strings (aus dem Query-
/// String) gegen einen JSON-Wert. Die Grenze klassifiziert den Vergleich:
/// Parse sie als endliche f64-Zahl → numerischer Bereich, und NUR Zahl-
/// Dokumente vergleichen numerisch (Werte oberhalb 2^53 verlieren
/// Praezision — dokumentierte Grenze; nicht-endliche Grenzen wie "NaN",
/// "inf", "1e400" matchen nie). Jede andere Zeichenkette → byte-lexiko-
/// graphischer Bereich, und NUR String-Dokumente vergleichen lexiko-
/// graphisch (ISO-8601-Zeitstempel sortieren damit korrekt). Grenze und
/// Dokumentwert unterschiedlicher Klasse matchen bewusst nicht — ein
/// numerischer Filter zieht keine String-Dokumente herein. Bools/Objekte/
/// Arrays/null und fehlende Felder matchen nie. Der Rohwert wird auch hier
/// ausschliesslich verglichen, nie als Ausdruck interpretiert.
pub fn value_in_range(doc: &Value, field: &str, op: RangeOp, raw: &str) -> bool {
    let Some(value) = doc.get(field) else {
        return false;
    };
    let numeric_bound = raw.parse::<f64>().ok().filter(|b| b.is_finite());
    match value {
        Value::Number(n) => {
            let Some(v) = n.as_f64() else { return false };
            let Some(bound) = numeric_bound else {
                return false;
            };
            match op {
                RangeOp::Gte => v >= bound,
                RangeOp::Lte => v <= bound,
                RangeOp::Gt => v > bound,
                RangeOp::Lt => v < bound,
            }
        }
        Value::String(s) => {
            if numeric_bound.is_some() {
                return false;
            }
            match op {
                RangeOp::Gte => s.as_str() >= raw,
                RangeOp::Lte => s.as_str() <= raw,
                RangeOp::Gt => s.as_str() > raw,
                RangeOp::Lt => s.as_str() < raw,
            }
        }
        // Bools/Objekte/Arrays/null sind als Bereichsziel nicht vorgesehen.
        _ => false,
    }
}

/// Rang eines Sortierschluessels ueber Typgrenzen: fehlend/null/Objekt/
/// Array (0) < Bool (1) < Zahl (2) < String (3). Dokumente unterschiedlichen
/// Typs unter demselben Sortierfeld sind damit total geordnet statt
/// willkuerlich.
fn sort_key_rank(value: Option<&Value>) -> u8 {
    match value {
        None | Some(Value::Null) | Some(Value::Object(_)) | Some(Value::Array(_)) => 0,
        Some(Value::Bool(_)) => 1,
        Some(Value::Number(_)) => 2,
        Some(Value::String(_)) => 3,
    }
}

/// Gesamtordnung zweier Sortierschluessel: erst der Typ-Rang (siehe
/// [`sort_key_rank`]), innerhalb des Rangs boolsche Ordnung, Zahlen per
/// `total_cmp` (total inkl. NaN-Randfaelle) und Strings byte-lexiko-
/// graphisch. Der Vergleich ist total — `sort_by` kann nicht straucheln.
fn cmp_sort_values(a: Option<&Value>, b: Option<&Value>) -> std::cmp::Ordering {
    let ord = sort_key_rank(a).cmp(&sort_key_rank(b));
    if ord.is_ne() {
        return ord;
    }
    match (a, b) {
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x.cmp(y),
        (Some(Value::Number(x)), Some(Value::Number(y))) => x
            .as_f64()
            .unwrap_or(f64::NAN)
            .total_cmp(&y.as_f64().unwrap_or(f64::NAN)),
        (Some(Value::String(x)), Some(Value::String(y))) => x.cmp(y),
        _ => std::cmp::Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cold::ColdTier;
    use serde_json::json;
    use tempfile::TempDir;

    fn store() -> MemoryStore {
        MemoryStore::new()
    }

    /// Snapshot schreiben und als Kalt-Tier anhaengen — genau das, was der
    /// Worker nach jeder Rotation tut (inkl. Wasserzeichen-Setzung im Dump).
    fn attach_snapshot_tier(s: &MemoryStore, dir: &std::path::Path) {
        let dumps = s.dump_collections().expect("Snapshot-Dump muss klappen");
        let index = crate::wal::write_snapshot_file(
            &dir.join("snapshot.tmp"),
            &dir.join("snapshot.bin"),
            &dumps,
        )
        .expect("Snapshot schreiben muss klappen");
        let cold = ColdTier::new();
        cold.install_snapshot(dir.join("snapshot.bin"), index);
        s.set_cold(Arc::new(cold));
    }

    #[test]
    fn insert_forces_id_and_returns_document() {
        let s = store();
        let doc = s.insert("app", "tasks", "t1", json!({"title": "a"}));
        assert_eq!(doc["id"], json!("t1"));
        assert_eq!(doc["title"], json!("a"));

        let read_back = s.get("app", "tasks", "t1").unwrap();
        assert_eq!(read_back["id"], json!("t1"));
    }

    #[test]
    fn get_missing_returns_none() {
        let s = store();
        assert!(s.get("app", "tasks", "missing").is_none());
        // Unbekannte Kollektion/App ebenfalls.
        assert!(s.get("other-app", "tasks", "missing").is_none());
    }

    #[test]
    fn replace_overwrites_and_keeps_id() {
        let s = store();
        s.insert("app", "tasks", "t1", json!({"title": "a", "keep": true}));
        let replaced = s
            .replace("app", "tasks", "t1", json!({"title": "b", "id": "HACK"}))
            .unwrap();

        assert_eq!(replaced["title"], json!("b"), "replace returns the new doc");
        let now = s.get("app", "tasks", "t1").unwrap();
        assert_eq!(now["title"], json!("b"));
        assert_eq!(now["id"], json!("t1"), "id must be forced to the path id");
        assert!(now.get("keep").is_none(), "replace must not merge");
    }

    #[test]
    fn replace_missing_is_none() {
        let s = store();
        assert!(
            s.replace("app", "tasks", "nope", json!({"a": 1})).is_none(),
            "replace must not upsert"
        );
    }

    #[test]
    fn create_is_create_if_absent_and_reports_the_conflict() {
        let s = store();
        let made = s
            .create("app", "tasks", "t1", json!({"title": "a"}))
            .unwrap();
        assert_eq!(made["id"], json!("t1"));
        s.insert("app", "tasks", "t0", json!({"title": "zuerst"}));

        // Konflikt auf t1 (vorderster Listenposition): der Bestand bleibt
        // unveraendert — kein Upsert, keine neue seq, kein zweiter Eintrag.
        // Ein fehlgeleitetes Upsert wuerde t1 ans Ende ruecken.
        let conflict = s
            .create("app", "tasks", "t1", json!({"title": "HACK"}))
            .unwrap_err();
        assert_eq!(conflict.existing.unwrap()["title"], json!("a"));
        assert_eq!(s.get("app", "tasks", "t1").unwrap()["title"], json!("a"));

        let list = s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 10,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(
            list.total, 2,
            "Konflikt-Create darf weder duplizieren noch umordnen"
        );
        assert_eq!(
            list.items[0]["title"],
            json!("a"),
            "Konflikt darf keine seq ziehen"
        );
        assert_eq!(list.items[1]["title"], json!("zuerst"));
    }

    #[test]
    fn patch_merge_commits_atomically_and_updates_indexes() {
        let s = store();
        s.insert(
            "app",
            "tasks",
            "t1",
            json!({"title": "a", "status": "offen"}),
        );
        s.insert(
            "app",
            "tasks",
            "t2",
            json!({"title": "b", "status": "offen"}),
        );
        s.declare_indexes("app", "tasks", &["status".to_string()]);

        let outcome = s.patch_merge("app", "tasks", "t1", |mut current| {
            if let Value::Object(ref mut map) = current {
                map.insert("status".to_string(), json!("erledigt"));
                // Der Merge ueberschreibt die ID boese — der Store muss sie
                // auf die Pfad-ID zurueckzwingen.
                map.insert("id".to_string(), json!("HACK"));
            }
            Ok::<_, &str>(current)
        });
        let PatchOutcome::Updated(doc) = outcome else {
            panic!("PATCH auf existierender ID muss Updated liefern");
        };
        assert_eq!(doc["status"], json!("erledigt"));
        assert_eq!(doc["id"], json!("t1"), "die ID wird auf den Pfad erzwungen");
        assert_eq!(
            doc["title"],
            json!("a"),
            "Merge muss den Reststand erhalten"
        );

        // Replace-Semantik fuer die Ordnung: wandert ans Listenende.
        let list = s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 10,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        );
        let ids: Vec<&str> = list
            .items
            .iter()
            .map(|d| d["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["t2", "t1"]);
        // Und der Sekundaerindex folgt (kein Geistereintrag in "offen").
        let mut offen = s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 10,
                filters: vec![("status".to_string(), "offen".to_string())],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(offen.total, 1);
        assert_eq!(offen.items.pop().unwrap()["id"], json!("t2"));
    }

    #[test]
    fn rejected_patch_leaves_document_and_order_untouched() {
        let s = store();
        s.insert("app", "tasks", "t1", json!({"title": "a", "n": 1}));
        let outcome = s.patch_merge("app", "tasks", "t1", |_current| Err("abgelehnt"));
        assert!(matches!(outcome, PatchOutcome::Rejected("abgelehnt")));

        let doc = s.get("app", "tasks", "t1").unwrap();
        assert_eq!(doc["n"], json!(1), "abgelehnter PATCH darf nichts aendern");

        // Keine neue seq: ein nachfolgender Insert bleibt hinter dem
        // unveraenderten Dokument.
        s.insert("app", "tasks", "t2", json!({"title": "b"}));
        let list = s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 10,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        );
        let ids: Vec<&str> = list
            .items
            .iter()
            .map(|d| d["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["t1", "t2"]);
    }

    #[test]
    fn patch_merge_on_missing_id_and_collection_is_not_found() {
        let s = store();
        s.insert("app", "tasks", "t1", json!({"n": 1}));
        assert!(matches!(
            s.patch_merge("app", "tasks", "missing", |_| Ok::<_, ()>(json!({}))),
            PatchOutcome::NotFound
        ));
        assert!(matches!(
            s.patch_merge("other-app", "tasks", "t1", |_| Ok::<_, ()>(json!({}))),
            PatchOutcome::NotFound
        ));
    }

    // --- Sammel-Patch (patch_merge_bulk) ----------------------------------------

    /// Transform, der `feld = wert` flach ins Dokument setzt (dieselbe
    /// Merge-Semantik wie der Handler, hier ohne Script).
    fn set_field(field: &str, value: Value) -> impl Fn(Value) -> Result<Value, String> {
        let field = field.to_string();
        move |mut current| {
            if let Value::Object(ref mut map) = current {
                map.insert(field.clone(), value.clone());
            }
            Ok(current)
        }
    }

    fn filters(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(field, raw)| (field.to_string(), raw.to_string()))
            .collect()
    }

    #[test]
    fn bulk_patch_updates_all_matches_and_reports_counters() {
        let s = store();
        s.insert("app", "ledger", "a", json!({"person": "ann", "paid": true}));
        s.insert("app", "ledger", "b", json!({"person": "bob", "paid": true}));
        s.insert("app", "ledger", "c", json!({"person": "ann", "paid": true}));

        let outcome = s.patch_merge_bulk(
            "app",
            "ledger",
            &filters(&[("person", "ann")]),
            &[],
            set_field("paid", json!(false)),
        );
        let BulkPatchOutcome::Completed(report) = outcome else {
            panic!("Sammel-Patch muss durchlaufen");
        };
        assert_eq!(report.matched, 2);
        assert_eq!(report.patched, 2);

        assert_eq!(s.get("app", "ledger", "a").unwrap()["paid"], json!(false));
        assert_eq!(
            s.get("app", "ledger", "b").unwrap()["paid"],
            json!(true),
            "Nicht-Matcher bleibt unberuehrt"
        );
        assert_eq!(s.get("app", "ledger", "c").unwrap()["paid"], json!(false));
    }

    #[test]
    fn bulk_patch_counts_noops_and_empty_matches() {
        let s = store();
        s.insert("app", "ledger", "a", json!({"amount": 50, "paid": true}));
        s.insert("app", "ledger", "b", json!({"amount": 150, "paid": true}));
        s.insert("app", "ledger", "c", json!({"amount": 200, "paid": false}));

        // Bereich amount_min=100: b und c matchen; b aendert sich, c ist
        // bereits im Zielzustand (No-op — zaehlt als matched, wird aber
        // nicht neu geschrieben und erzeugt keinen WAL-Op).
        let ranges = vec![("amount".to_string(), RangeOp::Gte, "100".to_string())];
        let outcome = s.patch_merge_bulk(
            "app",
            "ledger",
            &[],
            &ranges,
            set_field("paid", json!(false)),
        );
        let BulkPatchOutcome::Completed(report) = outcome else {
            panic!("Sammel-Patch muss durchlaufen");
        };
        assert_eq!(report.matched, 2);
        assert_eq!(report.patched, 1, "No-op-Matches werden nicht committet");

        // Filter ohne Treffer: 0/0 statt Fehler — auch fuer unbekannte
        // Kollektionen (die Engine kennt den Bestand nicht vorab).
        for (app, collection, filter) in [
            ("app", "ledger", filters(&[("person", "niemand")])),
            ("app", "fehlt", filters(&[("paid", "true")])),
        ] {
            let outcome = s.patch_merge_bulk(
                app,
                collection,
                &filter,
                &[],
                set_field("paid", json!(false)),
            );
            let BulkPatchOutcome::Completed(report) = outcome else {
                panic!("Sammel-Patch muss durchlaufen");
            };
            assert_eq!((report.matched, report.patched), (0, 0));
        }
    }

    #[test]
    fn bulk_patch_rejection_commits_nothing() {
        let s = store();
        s.insert("app", "ledger", "a", json!({"person": "ann", "paid": true}));
        s.insert(
            "app",
            "ledger",
            "b",
            json!({"person": "boom", "paid": true}),
        );
        s.insert("app", "ledger", "c", json!({"person": "cat", "paid": true}));

        // Phase A wertet ALLE Transformationen aus, bevor der erste Commit
        // passiert — ein Fehler bei `b` muss a und c unberuehrt lassen.
        let outcome = s.patch_merge_bulk(
            "app",
            "ledger",
            &filters(&[("paid", "true")]),
            &[],
            |current| {
                if current["person"] == json!("boom") {
                    Err("abgelehnt".to_string())
                } else {
                    set_field("paid", json!(false))(current)
                }
            },
        );
        assert!(matches!(
            outcome,
            BulkPatchOutcome::Rejected(err) if err == "abgelehnt"
        ));

        for id in ["a", "b", "c"] {
            assert_eq!(
                s.get("app", "ledger", id).unwrap()["paid"],
                json!(true),
                "{id} darf vom abgebrochenen Sammel-Patch nichts sehen"
            );
        }
    }

    #[test]
    fn bulk_patch_keeps_secondary_indexes_consistent() {
        let s = store();
        s.insert("app", "ledger", "a", json!({"person": "ann", "paid": true}));
        s.insert("app", "ledger", "b", json!({"person": "bob", "paid": true}));
        s.insert(
            "app",
            "ledger",
            "c",
            json!({"person": "cat", "paid": false}),
        );
        s.declare_indexes("app", "ledger", &["paid".to_string(), "person".to_string()]);

        let outcome = s.patch_merge_bulk(
            "app",
            "ledger",
            &filters(&[("paid", "true")]),
            &[],
            set_field("paid", json!(false)),
        );
        let BulkPatchOutcome::Completed(report) = outcome else {
            panic!("Sammel-Patch muss durchlaufen");
        };
        assert_eq!((report.matched, report.patched), (2, 2));

        // Die gefilterte Liste laeuft nach der Deklaration ausschliesslich
        // ueber den Sekundaerindex (ohne Re-Check der Dokumente) — ein
        // Geistereintrag unter b:true oder ein fehlender unter b:false
        // wuerde hier sofort sichtbar.
        let paid_true = s.list(
            "app",
            "ledger",
            ListParams {
                page: 1,
                limit: 10,
                filters: filters(&[("paid", "true")]),
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(paid_true.total, 0, "b:true muss leer sein");
        let paid_false = s.list(
            "app",
            "ledger",
            ListParams {
                page: 1,
                limit: 10,
                filters: filters(&[("paid", "false")]),
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(paid_false.total, 3, "alle drei unter b:false");
    }

    #[test]
    fn bulk_patch_and_concurrent_single_patch_do_not_lose_updates() {
        use std::time::Duration;
        let s = Arc::new(store());
        s.insert(
            "app",
            "ledger",
            "t1",
            json!({"person": "ann", "paid": true, "note": ""}),
        );

        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        // Der Sammel-Patch signalisiert aus seiner Transformation heraus —
        // die laeuft UNTER dem Schreib-Mutex. Der daneben gestartete
        // Single-Patch kann daher nur vor Phase 0 oder nach dem Commit
        // ansetzen; zwischen Lesen und Schreiben des Sammel-Patches gibt es
        // keinen Platz fuer ihn.
        let s_bulk = Arc::clone(&s);
        let bulk = std::thread::spawn(move || {
            let outcome = s_bulk.patch_merge_bulk(
                "app",
                "ledger",
                &filters(&[("paid", "true")]),
                &[],
                |mut current| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    if let Value::Object(ref mut map) = current {
                        map.insert("paid".to_string(), json!(false));
                    }
                    Ok::<_, ()>(current)
                },
            );
            assert!(matches!(outcome, BulkPatchOutcome::Completed(_)));
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("Sammel-Patch muss den Schreib-Mutex halten");

        let s_single = Arc::clone(&s);
        let single = std::thread::spawn(move || {
            let outcome = s_single.patch_merge("app", "ledger", "t1", |mut current| {
                if let Value::Object(ref mut map) = current {
                    map.insert("note".to_string(), json!("single"));
                }
                Ok::<_, ()>(current)
            });
            assert!(matches!(outcome, PatchOutcome::Updated(_)));
        });

        // Erst jetzt darf der Sammel-Patch weiterlaufen — der Single-Patch
        // ist entweder schon am Mutex oder kommt gleich an; beide Reihen-
        // folgen enden im selben Ergebnis (Single-Patch liest erst UNTER
        // dem Mutex).
        release_tx.send(()).unwrap();
        bulk.join().unwrap();
        single.join().unwrap();

        let doc = s.get("app", "ledger", "t1").unwrap();
        assert_eq!(doc["paid"], json!(false), "Bulk-Effekt muss ueberleben");
        assert_eq!(
            doc["note"],
            json!("single"),
            "Single-Patch muss auf dem Bulk-Stand aufsetzen, nicht verlieren"
        );
    }

    #[test]
    fn delete_returns_document_then_404_semantics() {
        let s = store();
        s.insert("app", "tasks", "t1", json!({"title": "a"}));
        let deleted = s.delete("app", "tasks", "t1").unwrap();
        assert_eq!(deleted["title"], json!("a"));
        assert!(s.delete("app", "tasks", "t1").is_none());
    }

    #[test]
    fn list_orders_by_insertion_and_pages() {
        let s = store();
        for i in 0..5 {
            s.insert("app", "tasks", &format!("t{i}"), json!({"n": i}));
        }

        let page1 = s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 2,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(page1.total, 5);
        assert_eq!(page1.items.len(), 2);
        assert_eq!(page1.items[0]["n"], json!(0));

        let page3 = s.list(
            "app",
            "tasks",
            ListParams {
                page: 3,
                limit: 2,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(page3.items.len(), 1);
        assert_eq!(page3.items[0]["n"], json!(4));

        // Seite weit hinter dem Ende: leere Seite, total bleibt korrekt.
        let page99 = s.list(
            "app",
            "tasks",
            ListParams {
                page: 99,
                limit: 2,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(page99.total, 5);
        assert!(page99.items.is_empty());
    }

    #[test]
    fn insert_overwrite_leaves_no_ghost_entries_in_list() {
        let s = store();
        s.insert("app", "tasks", "same", json!({"n": 1}));
        s.insert("app", "tasks", "same", json!({"n": 2}));

        let list = s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 10,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(
            list.total, 1,
            "doppelte Client-ID darf nicht doppelt auftauchen"
        );
        assert_eq!(list.items[0]["n"], json!(2));
    }

    #[test]
    fn list_filters_by_equality_across_types() {
        let s = store();
        s.insert(
            "app",
            "tasks",
            "t1",
            json!({"status": "offen", "prio": 1, "flag": true}),
        );
        s.insert(
            "app",
            "tasks",
            "t2",
            json!({"status": "erledigt", "prio": 2, "flag": false}),
        );
        s.insert(
            "app",
            "tasks",
            "t3",
            json!({"status": "offen", "prio": 2.5}),
        );

        let params = |filters: Vec<(&str, &str)>| {
            s.list(
                "app",
                "tasks",
                ListParams {
                    page: 1,
                    limit: 100,
                    filters: filters
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                    ranges: Vec::new(),
                    sort: None,
                },
            )
        };

        assert_eq!(params(vec![("status", "offen")]).total, 2);
        assert_eq!(params(vec![("status", "erledigt")]).total, 1);
        // Injection-artige Rohwerte matchen schlicht nichts.
        assert_eq!(params(vec![("status", "offen' OR 1=1 --")]).total, 0);
        assert_eq!(params(vec![("prio", "1")]).total, 1);
        assert_eq!(params(vec![("prio", "2.5")]).total, 1);
        assert_eq!(params(vec![("flag", "true")]).total, 1);
        // Kombinierte Filter.
        assert_eq!(params(vec![("status", "offen"), ("prio", "1")]).total, 1);
        // Existiert das Feld nicht, matcht der Filter nichts.
        assert_eq!(params(vec![("nope", "x")]).total, 0);
    }

    #[test]
    fn filtered_list_pages_like_unfiltered() {
        let s = store();
        for i in 0..5 {
            s.insert(
                "app",
                "tasks",
                &format!("t{i}"),
                json!({"n": i, "even": i % 2 == 0}),
            );
        }

        let list = s.list(
            "app",
            "tasks",
            ListParams {
                page: 2,
                limit: 1,
                filters: vec![("even".to_string(), "true".to_string())],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(list.total, 3);
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.items[0]["n"], json!(2));
    }

    #[test]
    fn list_is_isolated_between_apps_and_collections() {
        let s = store();
        s.insert("app1", "tasks", "t1", json!({}));
        s.insert("app2", "tasks", "t2", json!({}));
        s.insert("app1", "notes", "n1", json!({}));

        assert_eq!(
            s.list(
                "app1",
                "tasks",
                ListParams {
                    page: 1,
                    limit: 10,
                    filters: vec![],
                    ranges: Vec::new(),
                    sort: None
                }
            )
            .total,
            1
        );
        assert_eq!(
            s.list(
                "app2",
                "tasks",
                ListParams {
                    page: 1,
                    limit: 10,
                    filters: vec![],
                    ranges: Vec::new(),
                    sort: None
                }
            )
            .total,
            1
        );
        assert_eq!(
            s.list(
                "app1",
                "notes",
                ListParams {
                    page: 1,
                    limit: 10,
                    filters: vec![],
                    ranges: Vec::new(),
                    sort: None
                }
            )
            .total,
            1
        );
        assert_eq!(
            s.list(
                "app3",
                "tasks",
                ListParams {
                    page: 1,
                    limit: 10,
                    filters: vec![],
                    ranges: Vec::new(),
                    sort: None
                }
            )
            .total,
            0
        );
    }

    #[test]
    fn list_orders_by_update_on_replace() {
        let s = store();
        s.insert("app", "tasks", "a", json!({"n": "a"}));
        s.insert("app", "tasks", "b", json!({"n": "b"}));
        s.replace("app", "tasks", "a", json!({"n": "a2"}));

        let list = s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 10,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(
            list.items[0]["n"],
            json!("b"),
            "replaced doc moves to the end"
        );
    }

    #[test]
    fn replace_and_delete_keep_both_indexes_consistent() {
        let s = store();
        s.insert("app", "tasks", "a", json!({"n": "a"}));
        s.insert("app", "tasks", "b", json!({"n": "b"}));
        s.replace("app", "tasks", "a", json!({"n": "a2"}));
        s.delete("app", "tasks", "b");

        let list = s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 10,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(list.total, 1);
        assert_eq!(list.items[0]["n"], json!("a2"));
        assert!(s.get("app", "tasks", "b").is_none());
    }

    #[test]
    fn concurrent_writes_are_consistent() {
        let s = Arc::new(store());
        let mut handles = Vec::new();
        for worker in 0..4 {
            let s = Arc::clone(&s);
            handles.push(std::thread::spawn(move || {
                for i in 0..100 {
                    s.insert(
                        "app",
                        "tasks",
                        &format!("w{worker}-{i}"),
                        json!({"worker": worker, "i": i}),
                    );
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(
            s.list(
                "app",
                "tasks",
                ListParams {
                    page: 1,
                    limit: 1000,
                    filters: vec![],
                    ranges: Vec::new(),
                    sort: None
                }
            )
            .total,
            400
        );
    }

    #[test]
    fn concurrent_mixed_operations_keep_indexes_consistent() {
        let s = Arc::new(store());
        s.insert("app", "tasks", "anchor", json!({"n": 0}));
        let mut handles = Vec::new();
        for worker in 0..4 {
            let s = Arc::clone(&s);
            handles.push(std::thread::spawn(move || {
                for i in 0..100 {
                    let id = format!("w{worker}-{i}");
                    s.insert("app", "tasks", &id, json!({"worker": worker, "i": i}));
                    s.replace(
                        "app",
                        "tasks",
                        &id,
                        json!({"worker": worker, "i": i, "v2": true}),
                    );
                    if i % 2 == 0 {
                        s.delete("app", "tasks", &id);
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        let list = s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 1000,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        );
        // 4 x 50 uebrig gebliebene IDs + der Anker.
        assert_eq!(list.total, 201);
        // Jedes uebrig gebliebene Worker-Dokument ist per ID auffindbar und
        // traegt die Replace-Version — kein Eintrag haengt in nur einem Index.
        for doc in &list.items {
            let id = doc["id"].as_str().unwrap();
            if id == "anchor" {
                continue;
            }
            let by_id = s.get("app", "tasks", id).unwrap();
            assert_eq!(by_id["v2"], json!(true));
        }
    }

    // --- Sekundaerindizes -------------------------------------------------------

    /// Batterie aus Filteranfragen, gegen die beide Pfade (Index und Scan)
    /// identische Ergebnisse liefern muessen.
    fn filter_battery() -> Vec<Vec<(&'static str, &'static str)>> {
        vec![
            vec![("status", "offen")],
            vec![("status", "erledigt")],
            vec![("status", "1")],
            vec![("status", "true")],
            vec![("status", "offen' OR 1=1 --")],
            vec![("prio", "1")],
            vec![("prio", "2")],
            vec![("prio", "2.5")],
            vec![("prio", "1.0")],
            vec![("prio", "-7")],
            vec![("prio", "9223372036854775807")],
            vec![("big", "9223372036854775808")],
            vec![("big", "9223372036854775808.0")],
            vec![("flag", "true")],
            vec![("flag", "false")],
            vec![("meta", "x")],
            vec![("missing", "x")],
            vec![("status", "offen"), ("prio", "1")],
            vec![("status", "offen"), ("flag", "true")],
            vec![("prio", "2"), ("flag", "false")],
            vec![("status", "offen"), ("prio", "999999")],
        ]
    }

    fn query_ids(
        s: &MemoryStore,
        filters: &[(&str, &str)],
        ranges: &[(&str, RangeOp, &str)],
        sort: Option<(&str, bool)>,
    ) -> Vec<String> {
        s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 1000,
                filters: filters
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                ranges: ranges
                    .iter()
                    .map(|(k, op, v)| (k.to_string(), *op, v.to_string()))
                    .collect(),
                sort: sort.map(|(field, descending)| SortSpec {
                    field: field.to_string(),
                    descending,
                }),
            },
        )
        .items
        .iter()
        .map(|doc| doc["id"].as_str().unwrap().to_string())
        .collect()
    }

    fn list_ids(s: &MemoryStore, filters: &[(&str, &str)]) -> Vec<String> {
        query_ids(s, filters, &[], None)
    }

    fn seed_mixed_docs(s: &MemoryStore) {
        s.insert(
            "app",
            "tasks",
            "a",
            json!({"status": "offen", "prio": 1, "flag": true}),
        );
        s.insert(
            "app",
            "tasks",
            "b",
            json!({"status": "erledigt", "prio": 2, "flag": false}),
        );
        s.insert("app", "tasks", "c", json!({"status": "offen", "prio": 2.5}));
        s.insert("app", "tasks", "d", json!({"status": 1, "prio": -7}));
        s.insert(
            "app",
            "tasks",
            "e",
            json!({"status": "1", "big": 9223372036854775808u64}),
        );
        s.insert(
            "app",
            "tasks",
            "f",
            json!({"status": "offen", "meta": {"nested": 1}}),
        );
        s.insert(
            "app",
            "tasks",
            "g",
            json!({"prio": 2, "flag": false, "status": null}),
        );
        s.insert(
            "app",
            "tasks",
            "h",
            json!({"status": "offen", "prio": 9223372036854775807i64}),
        );
    }

    #[test]
    fn indexed_list_matches_scan_semantics_exactly() {
        let scanned = store();
        seed_mixed_docs(&scanned);
        let indexed = store();
        seed_mixed_docs(&indexed);
        indexed.declare_indexes(
            "app",
            "tasks",
            &[
                "status".to_string(),
                "prio".to_string(),
                "flag".to_string(),
                "big".to_string(),
                "meta".to_string(),
            ],
        );

        for filters in filter_battery() {
            assert_eq!(
                list_ids(&scanned, &filters),
                list_ids(&indexed, &filters),
                "Index und Scan weichen ab bei Filter {filters:?}"
            );
        }

        // Totals ueber die Paginierungsgrenze hinweg identisch.
        let params = |page: usize, limit: usize, filters: Vec<(&str, &str)>| {
            let p = |s: &MemoryStore| {
                s.list(
                    "app",
                    "tasks",
                    ListParams {
                        page,
                        limit,
                        filters: filters
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect(),
                        ranges: Vec::new(),
                        sort: None,
                    },
                )
            };
            (p(&scanned).total, p(&indexed).total)
        };
        assert_eq!(params(1, 2, vec![("status", "offen")]), (4, 4));
    }

    #[test]
    fn indexed_list_pages_in_seq_order() {
        let s = store();
        for i in 0..10 {
            s.insert(
                "app",
                "tasks",
                &format!("t{i}"),
                json!({"bucket": i % 3, "n": i}),
            );
        }
        s.declare_indexes("app", "tasks", &["bucket".to_string()]);

        let page1 = s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 2,
                filters: vec![("bucket".to_string(), "0".to_string())],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(page1.total, 4);
        let nums: Vec<i64> = page1
            .items
            .iter()
            .map(|d| d["n"].as_i64().unwrap())
            .collect();
        assert_eq!(nums, vec![0, 3], "Index-Treffer folgen der seq-Ordnung");

        let page3 = s.list(
            "app",
            "tasks",
            ListParams {
                page: 3,
                limit: 2,
                filters: vec![("bucket".to_string(), "0".to_string())],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(page3.items.len(), 0, "Seite hinter dem Ende bleibt leer");
        assert_eq!(page3.total, 4);
    }

    #[test]
    fn index_tracks_replace_delete_and_overwrite() {
        let s = store();
        s.declare_indexes("app", "tasks", &["status".to_string()]);
        s.insert("app", "tasks", "a", json!({"status": "offen"}));
        s.insert("app", "tasks", "b", json!({"status": "offen"}));
        assert_eq!(list_ids(&s, &[("status", "offen")]), vec!["a", "b"]);

        // Replace aendert den Wert: a wandert in den anderen Bucket.
        s.replace("app", "tasks", "a", json!({"status": "erledigt"}));
        assert_eq!(list_ids(&s, &[("status", "offen")]), vec!["b"]);
        assert_eq!(list_ids(&s, &[("status", "erledigt")]), vec!["a"]);

        // replace ohne Feldaenderung: bleibt im selben Bucket, keine Dubletten.
        s.replace("app", "tasks", "a", json!({"status": "erledigt", "v": 2}));
        assert_eq!(list_ids(&s, &[("status", "erledigt")]), vec!["a"]);

        // Overwrite per insert (Client-ID existiert schon): alter Eintrag weg.
        s.insert("app", "tasks", "b", json!({"status": "erledigt"}));
        assert_eq!(list_ids(&s, &[("status", "offen")]), Vec::<String>::new());
        assert_eq!(list_ids(&s, &[("status", "erledigt")]), vec!["a", "b"]);

        // Feld verschwindet im Replace: kein Treffer mehr ueber den Index.
        s.replace("app", "tasks", "b", json!({"other": 1}));
        assert_eq!(list_ids(&s, &[("status", "erledigt")]), vec!["a"]);

        s.delete("app", "tasks", "a");
        assert_eq!(
            list_ids(&s, &[("status", "erledigt")]),
            Vec::<String>::new()
        );
        assert_eq!(list_ids(&s, &[("status", "offen")]), Vec::<String>::new());
    }

    #[test]
    fn declare_indexes_backfills_existing_documents() {
        let s = store();
        s.insert("app", "tasks", "a", json!({"status": "offen"}));
        s.insert("app", "tasks", "b", json!({"status": "erledigt"}));
        // Erst Daten, dann Deklaration: der Backfill muss den Bestand erfassen.
        s.declare_indexes("app", "tasks", &["status".to_string()]);
        assert_eq!(list_ids(&s, &[("status", "offen")]), vec!["a"]);
        assert_eq!(list_ids(&s, &[("status", "erledigt")]), vec!["b"]);
    }

    #[test]
    fn undeclared_field_falls_back_to_scan() {
        let s = store();
        s.declare_indexes("app", "tasks", &["status".to_string()]);
        s.insert("app", "tasks", "a", json!({"status": "offen", "tag": "x"}));
        s.insert("app", "tasks", "b", json!({"status": "offen", "tag": "y"}));
        // "tag" ist nicht deklariert — das Ergebnis muss trotzdem korrekt sein
        // (Scan-Fallback statt Index).
        assert_eq!(list_ids(&s, &[("tag", "y")]), vec!["b"]);
        assert_eq!(
            list_ids(&s, &[("tag", "x"), ("status", "offen")]),
            vec!["a"]
        );
    }

    #[test]
    fn clearing_declaration_keeps_results_correct() {
        let s = store();
        s.declare_indexes("app", "tasks", &["status".to_string()]);
        s.insert("app", "tasks", "a", json!({"status": "offen"}));
        s.declare_indexes("app", "tasks", &[]);
        assert_eq!(
            list_ids(&s, &[("status", "offen")]),
            vec!["a"],
            "Scan liefert weiter korrekte Treffer"
        );
    }

    #[test]
    fn concurrent_writes_keep_secondary_index_consistent() {
        let s = Arc::new(store());
        s.declare_indexes("app", "tasks", &["worker".to_string(), "phase".to_string()]);
        s.insert("app", "tasks", "anchor", json!({"worker": 0, "phase": 2}));
        let mut handles = Vec::new();
        for worker in 0..4 {
            let s = Arc::clone(&s);
            handles.push(std::thread::spawn(move || {
                for i in 0..100 {
                    let id = format!("w{worker}-{i}");
                    s.insert("app", "tasks", &id, json!({"worker": worker, "phase": 1}));
                    s.replace("app", "tasks", &id, json!({"worker": worker, "phase": 2}));
                    if i % 2 == 0 {
                        s.delete("app", "tasks", &id);
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        let params = |filters: Vec<(&str, &str)>| {
            s.list(
                "app",
                "tasks",
                ListParams {
                    page: 1,
                    limit: 1000,
                    filters: filters
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                    ranges: Vec::new(),
                    sort: None,
                },
            )
        };
        assert_eq!(
            params(vec![("phase", "1")]).total,
            0,
            "nach Replace + Delete bleibt nichts in Phase 1 haengen"
        );
        assert_eq!(
            params(vec![("phase", "2")]).total,
            201,
            "4 x 50 Worker-Dokumente + Anker"
        );
        assert_eq!(params(vec![("worker", "1"), ("phase", "2")]).total, 50);
    }

    // --- Tiering (Eviction + Fetch-on-Miss) -------------------------------------

    #[test]
    fn eviction_promotes_on_miss_and_keeps_list_stable() {
        let dir = TempDir::new().unwrap();
        let s = store();
        s.set_hot_cap(4);
        for i in 0..10 {
            s.insert("app", "tasks", &format!("t{i}"), json!({"n": i}));
        }
        attach_snapshot_tier(&s, dir.path());

        s.run_eviction();
        let (total, cold) = s.hot_doc_counts("app", "tasks").unwrap();
        assert_eq!(total, 10, "Eviction darf nichts loeschen");
        assert_eq!(cold, 6, "Hot-Cap 4 (Low Water 4) => 6 kalt gestellt");

        // Liste bleibt vollstaendig: Totals stabil, kalte Seiten-Payloads
        // werden transparent nachgeladen.
        let list = s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 100,
                filters: vec![],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(list.total, 10);
        let ns: Vec<i64> = list
            .items
            .iter()
            .map(|d| d["n"].as_i64().unwrap())
            .collect();
        assert_eq!(ns, (0..10).collect::<Vec<_>>());

        // Paging durch alles = alles promotet.
        let (_, cold_after) = s.hot_doc_counts("app", "tasks").unwrap();
        assert_eq!(
            cold_after, 0,
            "vollstaendiges Lesen muss alles heiss machen"
        );
    }

    #[test]
    fn get_of_cold_document_fetches_and_promotes() {
        let dir = TempDir::new().unwrap();
        let s = store();
        s.set_hot_cap(2);
        s.insert("app", "tasks", "t1", json!({"n": "eins"}));
        s.insert("app", "tasks", "t2", json!({"n": "zwei"}));
        s.insert("app", "tasks", "t3", json!({"n": "drei"}));
        attach_snapshot_tier(&s, dir.path());
        s.run_eviction();
        assert_eq!(
            s.hot_doc_counts("app", "tasks").unwrap().1,
            1,
            "t1 als aeltester kalt"
        );

        let doc = s.get("app", "tasks", "t1").unwrap();
        assert_eq!(
            doc["n"],
            json!("eins"),
            "Payload muss aus dem Kalt-Tier kommen"
        );
        assert_eq!(
            s.hot_doc_counts("app", "tasks").unwrap().1,
            0,
            "Fetch muss promotieren"
        );
    }

    #[test]
    fn indexed_filtered_list_resolves_cold_page_payloads() {
        let dir = TempDir::new().unwrap();
        let s = store();
        s.declare_indexes("app", "tasks", &["status".to_string()]);
        s.set_hot_cap(3);
        for i in 0..10 {
            let status = if i % 2 == 0 { "offen" } else { "erledigt" };
            s.insert(
                "app",
                "tasks",
                &format!("t{i}"),
                json!({"n": i, "status": status}),
            );
        }
        attach_snapshot_tier(&s, dir.path());
        s.run_eviction();
        let cold_before = s.hot_doc_counts("app", "tasks").unwrap().1;
        assert!(cold_before > 0);

        // Indexpfad: (seq, ID)-Treffer, Seiten-Payloads aus dem Kalt-Tier.
        let list = s.list(
            "app",
            "tasks",
            ListParams {
                page: 1,
                limit: 2,
                filters: vec![("status".to_string(), "offen".to_string())],
                ranges: Vec::new(),
                sort: None,
            },
        );
        assert_eq!(list.total, 5, "Indizes bleiben von der Eviction unberuehrt");
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[0]["n"], json!(0));
        assert_eq!(list.items[1]["n"], json!(2));
        let cold_after = s.hot_doc_counts("app", "tasks").unwrap().1;
        assert_eq!(
            cold_after,
            cold_before - 2,
            "nur die zwei Seiten-Payloads werden geladen"
        );
    }

    #[test]
    fn dump_fails_when_cold_documents_cannot_be_resolved() {
        let s = store();
        s.set_hot_cap(2);
        for i in 0..4 {
            s.insert("app", "tasks", &format!("t{i}"), json!({"n": i}));
        }
        // Wasserzeichen setzen + evicten, OHNE Kalt-Tier: der Dump muss
        // abbrechen (ohne Tier wuerde die naechste Compaction Docs verlieren).
        s.dump_collections().unwrap();
        s.run_eviction();
        assert_eq!(s.hot_doc_counts("app", "tasks").unwrap().1, 2);
        assert!(
            s.dump_collections().is_err(),
            "kalte Docs ohne Tier muessen den Dump abbrechen"
        );

        // Tier angehaengt, aber leer: ebenfalls Fehler statt stiller Luecke.
        s.set_cold(Arc::new(ColdTier::new()));
        assert!(s.dump_collections().is_err());
    }

    #[test]
    fn mutations_on_cold_documents_match_between_scan_and_index() {
        let scan_dir = TempDir::new().unwrap();
        let index_dir = TempDir::new().unwrap();
        let scanned = store();
        let indexed = store();
        indexed.declare_indexes("app", "tasks", &["status".to_string(), "prio".to_string()]);
        scanned.set_hot_cap(3);
        indexed.set_hot_cap(3);

        let seed = |s: &MemoryStore| {
            for i in 0..6 {
                let status = if i % 2 == 0 { "offen" } else { "erledigt" };
                s.insert(
                    "app",
                    "tasks",
                    &format!("t{i}"),
                    json!({"n": i, "status": status, "prio": i}),
                );
            }
        };
        seed(&scanned);
        seed(&indexed);
        attach_snapshot_tier(&scanned, scan_dir.path());
        attach_snapshot_tier(&indexed, index_dir.path());
        scanned.run_eviction();
        indexed.run_eviction();
        assert!(scanned.hot_doc_counts("app", "tasks").unwrap().1 > 0);

        // Replace (Feldwert aendert sich), Delete und Insert-Overwrite auf
        // kalten Dokumenten — beide Pfade muessen identisch landen.
        let mutations = |s: &MemoryStore| {
            s.replace(
                "app",
                "tasks",
                "t0",
                json!({"n": 0, "status": "erledigt", "prio": 0}),
            )
            .unwrap();
            s.delete("app", "tasks", "t1").unwrap();
            s.insert(
                "app",
                "tasks",
                "t2",
                json!({"n": "neu", "status": "offen", "prio": 42}),
            );
        };
        mutations(&scanned);
        mutations(&indexed);

        let ids_of = |s: &MemoryStore, filters: Vec<(&str, &str)>| -> Vec<String> {
            s.list(
                "app",
                "tasks",
                ListParams {
                    page: 1,
                    limit: 100,
                    filters: filters
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                    ranges: Vec::new(),
                    sort: None,
                },
            )
            .items
            .iter()
            .map(|d| d["id"].as_str().unwrap().to_string())
            .collect()
        };

        for filters in [
            vec![("status", "offen")],
            vec![("status", "erledigt")],
            vec![("prio", "42")],
            vec![("prio", "1")],
            vec![("status", "offen"), ("prio", "42")],
        ] {
            assert_eq!(
                ids_of(&scanned, filters.clone()),
                ids_of(&indexed, filters.clone()),
                "Index- und Scan-Pfad weichen nach Kalt-Mutationen ab bei {filters:?}"
            );
        }
        // Vollstaendiger Stand inkl. Reihenfolge: Replace/Overwrite schieben
        // ans Ende, Delete entfernt.
        assert_eq!(ids_of(&scanned, vec![]), ids_of(&indexed, vec![]));
        assert_eq!(
            scanned.get("app", "tasks", "t0").unwrap()["status"],
            json!("erledigt")
        );
        assert_eq!(
            indexed.get("app", "tasks", "t0").unwrap()["status"],
            json!("erledigt")
        );
        assert!(scanned.get("app", "tasks", "t1").is_none());
    }

    // --- Range-Filter (von/bis) und Sortierung -----------------------------------

    fn seed_range_docs(s: &MemoryStore) {
        s.insert(
            "app",
            "tasks",
            "a",
            json!({"n": 5, "name": "apfel", "when": "2024-01-01"}),
        );
        s.insert(
            "app",
            "tasks",
            "b",
            json!({"n": 10, "name": "birne", "when": "2024-06-15"}),
        );
        s.insert(
            "app",
            "tasks",
            "c",
            json!({"n": 2.5, "name": "cashew", "when": "2023-12-31"}),
        );
        s.insert("app", "tasks", "d", json!({"n": -3, "flag": true}));
        s.insert(
            "app",
            "tasks",
            "e",
            json!({"n": "sieben", "nested": {"x": 1}}),
        );
        s.insert("app", "tasks", "f", json!({"n": null}));
    }

    #[test]
    fn range_filters_compare_numbers_strings_and_reject_the_rest() {
        let s = store();
        seed_range_docs(&s);

        // Zahlen: _min/_max inklusive, _gt/_lt exklusiv (hier direkt als Ops).
        assert_eq!(
            query_ids(&s, &[], &[("n", RangeOp::Gte, "5")], None),
            vec!["a", "b"]
        );
        assert_eq!(
            query_ids(&s, &[], &[("n", RangeOp::Lte, "5")], None),
            vec!["a", "c", "d"]
        );
        assert_eq!(
            query_ids(&s, &[], &[("n", RangeOp::Gt, "5")], None),
            vec!["b"]
        );
        assert_eq!(
            query_ids(&s, &[], &[("n", RangeOp::Lt, "2.5")], None),
            vec!["d"],
            "exklusive Grenze schliesst 2.5 aus"
        );
        assert_eq!(
            query_ids(
                &s,
                &[],
                &[("n", RangeOp::Gte, "2.5"), ("n", RangeOp::Lte, "10")],
                None
            ),
            vec!["a", "b", "c"]
        );

        // Strings: Byte-lexikographisch — ISO-Daten sortieren damit korrekt.
        assert_eq!(
            query_ids(&s, &[], &[("name", RangeOp::Gt, "apfel")], None),
            vec!["b", "c"]
        );
        assert_eq!(
            query_ids(
                &s,
                &[],
                &[
                    ("when", RangeOp::Gte, "2024-01-01"),
                    ("when", RangeOp::Lte, "2024-12-31")
                ],
                None
            ),
            vec!["a", "b"]
        );

        // Bools/Objekte/null/fehlende Felder sind nicht bereichsfaehig.
        assert_eq!(
            query_ids(&s, &[], &[("flag", RangeOp::Gte, "true")], None),
            Vec::<String>::new()
        );
        assert_eq!(
            query_ids(&s, &[], &[("nested", RangeOp::Gte, "1")], None),
            Vec::<String>::new()
        );
        assert_eq!(
            query_ids(&s, &[], &[("missing", RangeOp::Gte, "1")], None),
            Vec::<String>::new()
        );
        // Typ-Strengtheit: String-Dokumente nehmen an numerischen Bereichen
        // nicht teil und umgekehrt ("sieben" ist keine 7).
        assert_eq!(
            query_ids(&s, &[], &[("n", RangeOp::Gte, "a")], None),
            vec!["e"]
        );
        assert_eq!(
            query_ids(
                &s,
                &[],
                &[("n", RangeOp::Gte, "0"), ("n", RangeOp::Lte, "100")],
                None
            ),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn range_bounds_are_data_and_never_interpreted() {
        let s = store();
        s.insert("app", "tasks", "m1", json!({"n": 5}));
        s.insert("app", "tasks", "m2", json!({"n": 10}));
        s.insert("app", "tasks", "m3", json!({"n": 2.5}));

        // Nicht-endliche bzw. nicht parsbare Grenzen matchen nichts — inkl.
        // Injection-artiger Rohwerte, die wie jede andere Zeichenkette am
        // Parse scheitern. Es gibt keine Ausdruckssprache, die man truken
        // koennte: verglichen wird nur.
        for bound in [
            "NaN",
            "inf",
            "-inf",
            "1e400",
            "0x10",
            "5) OR (1=1",
            "5; DROP tasks",
            "5' --",
        ] {
            assert_eq!(
                query_ids(&s, &[], &[("n", RangeOp::Gte, bound)], None),
                Vec::<String>::new(),
                "Grenze {bound} darf nichts matchen"
            );
            assert_eq!(
                query_ids(&s, &[], &[("n", RangeOp::Lte, bound)], None),
                Vec::<String>::new(),
                "Grenze {bound} darf nichts matchen"
            );
        }
    }

    #[test]
    fn sort_orders_across_types_deterministically() {
        let s = store();
        s.insert("app", "tasks", "s1", json!({"v": "zeta"}));
        s.insert("app", "tasks", "s2", json!({"v": "apfel"}));
        s.insert("app", "tasks", "s3", json!({"v": null}));
        s.insert("app", "tasks", "s4", json!({"v": 2.5}));
        s.insert("app", "tasks", "s5", json!({"other": 1}));
        s.insert("app", "tasks", "s6", json!({"v": "birne"}));
        s.insert("app", "tasks", "s7", json!({"v": 40}));
        s.insert("app", "tasks", "s8", json!({"v": -5}));
        s.insert("app", "tasks", "s9", json!({"v": false}));
        s.insert("app", "tasks", "s10", json!({"v": true}));

        // Aufsteigend: fehlt/null < bool < Zahl < String; Gleichstand nach seq.
        let asc = query_ids(&s, &[], &[], Some(("v", false)));
        assert_eq!(
            asc,
            vec!["s3", "s5", "s9", "s10", "s8", "s4", "s7", "s2", "s6", "s1"]
        );

        // Absteigend dreht NUR den Primaerschluessel, nicht den seq-Tiebreak:
        // sortierte Seiten bleiben in beide Richtungen ohne Dubletten/Luecken
        // durchwanderbar.
        let desc = query_ids(&s, &[], &[], Some(("v", true)));
        assert_eq!(
            desc,
            vec!["s1", "s6", "s2", "s7", "s4", "s8", "s10", "s9", "s3", "s5"]
        );
    }

    #[test]
    fn sorted_paging_covers_every_document_exactly_once() {
        let s = store();
        for i in 0..10 {
            // Absichtlich in umgekehrter Reihenfolge inserted: die Sortierung
            // muss die seq-Ordnung schlagen.
            s.insert("app", "tasks", &format!("t{i}"), json!({"n": 9 - i}));
        }

        let mut asc_pages = Vec::new();
        for page in 1..=4 {
            let list = s.list(
                "app",
                "tasks",
                ListParams {
                    page,
                    limit: 3,
                    filters: vec![],
                    ranges: Vec::new(),
                    sort: Some(SortSpec {
                        field: "n".to_string(),
                        descending: false,
                    }),
                },
            );
            assert_eq!(list.total, 10, "total bleibt ueber alle Seiten stabil");
            asc_pages.extend(list.items.iter().map(|d| d["n"].as_i64().unwrap()));
        }
        assert_eq!(asc_pages, (0..10).collect::<Vec<_>>());

        let mut desc_pages = Vec::new();
        for page in 1..=4 {
            let list = s.list(
                "app",
                "tasks",
                ListParams {
                    page,
                    limit: 3,
                    filters: vec![],
                    ranges: Vec::new(),
                    sort: Some(SortSpec {
                        field: "n".to_string(),
                        descending: true,
                    }),
                },
            );
            desc_pages.extend(list.items.iter().map(|d| d["n"].as_i64().unwrap()));
        }
        assert_eq!(desc_pages, (0..10).rev().collect::<Vec<_>>());
    }

    #[test]
    fn range_and_sort_results_match_between_index_prefilter_and_scan() {
        let scanned = store();
        seed_mixed_docs(&scanned);
        let indexed = store();
        seed_mixed_docs(&indexed);
        indexed.declare_indexes(
            "app",
            "tasks",
            &["status".to_string(), "prio".to_string(), "flag".to_string()],
        );

        let ranges: Vec<(&str, RangeOp, &str)> = vec![
            ("prio", RangeOp::Gte, "2"),
            ("prio", RangeOp::Lte, "2.5"),
            ("prio", RangeOp::Gt, "0"),
            ("prio", RangeOp::Lt, "0"),
            ("prio", RangeOp::Gte, "-7"),
            ("big", RangeOp::Gte, "9223372036854775808"),
            ("status", RangeOp::Gte, "m"),
            ("prio", RangeOp::Gte, "NaN"),
            ("missing", RangeOp::Gte, "1"),
        ];
        let sorts = vec![
            None,
            Some(("prio", false)),
            Some(("prio", true)),
            Some(("status", false)),
            Some(("flag", true)),
            Some(("missing", false)),
        ];

        for filters in filter_battery() {
            for range in &ranges {
                for sort in &sorts {
                    assert_eq!(
                        query_ids(&scanned, &filters, &[*range], *sort),
                        query_ids(&indexed, &filters, &[*range], *sort),
                        "Index-Vorselektion und Scan weichen ab bei {filters:?} {range:?} {sort:?}"
                    );
                }
            }
        }

        // Semantik-Anker ueber beide Pfade: Filter + Bereich + Sortierung
        // kombiniert (status offen UND prio >= 2 → c, h; absteigend nach prio).
        assert_eq!(
            query_ids(
                &scanned,
                &[("status", "offen")],
                &[("prio", RangeOp::Gte, "2")],
                Some(("prio", false))
            ),
            vec!["c", "h"]
        );
        assert_eq!(
            query_ids(
                &indexed,
                &[("status", "offen")],
                &[("prio", RangeOp::Gte, "2")],
                Some(("prio", true))
            ),
            vec!["h", "c"]
        );
    }
}
