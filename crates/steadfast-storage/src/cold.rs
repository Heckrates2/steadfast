//! Kalt-Tier: Offset-Indizes ueber geschlossene WAL-Segmente und den
//! Snapshot, damit evicierte Dokumente bei einem Miss einzeln aus der
//! Platte nachgeladen werden koennen (Fetch-on-Miss), ohne die Segmente
//! linear zu scannen.
//!
//! Aufbau: Der WAL-Worker indiziert jeden Record, den er schreibt
//! ([`ColdTier::record`], Schluessel = `(app, collection, id)` → Record-
//! start + Payload-Laenge), und markiert nach jedem Flush, bis wohin die
//! Datei lesbar ist ([`ColdTier::advance_flushed`]). Bei der Rotation wird
//! der Index des aktiven Segments als geschlossenes Tier veroeffentlicht
//! ([`ColdTier::rotate_to`]), der frische Snapshot wird als niedrigst-
//! priores Tier installiert ([`ColdTier::install_snapshot`]) und Indizes
//! unterhalb der Kompaktionsgrenze entfernt (ebenfalls [`ColdTier::rotate_to`]).
//!
//! Lookup-Reihenfolge bei [`ColdTier::fetch`]: aktives Segment (nur Records
//! bis zur geflushten Grenze) → geschlossene Segmente (neueste zuerst) →
//! Snapshot. Der erste zum Schluessel passende Record entscheidet (Upsert
//! liefert das Dokument, Delete terminiert die Suche mit "nicht gefunden").
//! Da das Replay exakt denselben Prefix-Regeln folgt (torn tail/CRC-Bruch
//! beenden beide), liefert der Fetch immer die Version, die auch im RAM
//! liegen wuerde.
//!
//! Konsistenz mit der Eviction: Eviciert wird nur direkt nach einer
//! Rotation (siehe `MemoryStore::run_eviction`) und nur Dokumente, deren
//! aktuelle Version schon im Snapshot bzw. im gerade geschlossenem Segment
//! liegt. Ein eviciertes Dokument ist daher per Definition ueber mindestens
//! ein Tier auffindbar — sein neuester Record ist nie im ungeflushten Teil
//! des aktiven Segments.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use serde_json::Value;

use crate::wal::{LoggedOp, parse_snapshot_body, parse_wal_body};

/// Schluessel eines Kalt-Records. Tuple statt zusammengesetzter String, damit
/// IDs mit Pfadseparatoren nicht kollidieren koennen.
pub type ColdKey = (String, String, String);

/// Eine abgeschlossene Index-Einheit: geschlossenes WAL-Segment oder
/// Snapshot. Unveraenderlich nach Veroeffentlichung (daher `Arc`-Share
/// ohne Lock im Fetch-Pfad).
#[derive(Debug)]
struct TierFile {
    epoch: Option<u64>,
    path: PathBuf,
    kind: TierKind,
    /// Record-Start-Offset + Payload-Laenge je Schluessel.
    index: HashMap<ColdKey, (u64, u32)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TierKind {
    Segment,
    Snapshot,
}

/// Das noch geschriebene aktive Segment: Index waechst mit jedem Record,
/// `flushed` ist die bis zu der die Datei lesbar ist.
#[derive(Debug)]
struct ActiveSegment {
    path: PathBuf,
    index: HashMap<ColdKey, (u64, u32)>,
    flushed: u64,
}

/// Handle auf das Kalt-Tier; vom Store (Fetch-on-Miss), vom Worker
/// (Index-Pflege) und vom Replay (Erstbefuellung) gemeinsam genutzt.
#[derive(Debug, Default)]
pub struct ColdTier {
    /// Geschlossene Tiers, Lookup-Reihenfolge: vorne = am neuesten. Der
    /// Snapshot liegt immer hinten (niedrigste Prioritaet, aber immer
    /// vollstaendig).
    tiers: RwLock<Vec<Arc<TierFile>>>,
    active: Mutex<Option<ActiveSegment>>,
}

impl ColdTier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Legt das aktive Segment fest (beim Worker-Start). `start_offset` ist
    /// die Laenge einer evtl. bereits vorhandenen Datei.
    pub fn open_active(&self, path: PathBuf, start_offset: u64) {
        let mut active = self.active.lock().expect("cold active poisoned");
        *active = Some(ActiveSegment {
            path,
            index: HashMap::new(),
            flushed: start_offset,
        });
    }

    /// Der Worker hat einen Record geschrieben: Start-Offset + Payload-
    /// Laenge unter dem Schluessel merken.
    pub fn record(&self, key: ColdKey, start: u64, payload_len: u32) {
        let mut active = self.active.lock().expect("cold active poisoned");
        if let Some(active) = active.as_mut() {
            active.index.insert(key, (start, payload_len));
        }
    }

    /// Nach einem Flush: alles bis `pos` ist in der Datei lesbar.
    pub fn advance_flushed(&self, pos: u64) {
        let mut active = self.active.lock().expect("cold active poisoned");
        if let Some(active) = active.as_mut() {
            active.flushed = pos;
        }
    }

    /// Rotation: das bisher aktive Segment wird als geschlossenes Tier
    /// veroeffentlicht (alles geflusht), das neue Segment wird aktiv.
    /// Indizes von Segmenten unterhalb der Kompaktionsgrenze verschwinden.
    pub fn rotate_to(&self, new_path: PathBuf, new_epoch: u64, new_start_offset: u64) {
        let mut tiers = self.tiers.write().expect("cold tiers poisoned");
        let mut active = self.active.lock().expect("cold active poisoned");
        if let Some(old) = active.take() {
            let epoch = old
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix("wal-"))
                .and_then(|n| n.strip_suffix(".log"))
                .and_then(|n| n.parse::<u64>().ok());
            tiers.insert(
                0,
                Arc::new(TierFile {
                    epoch,
                    path: old.path,
                    kind: TierKind::Segment,
                    index: old.index,
                }),
            );
        }
        *active = Some(ActiveSegment {
            path: new_path,
            index: HashMap::new(),
            flushed: new_start_offset,
        });
        tiers.retain(|tier| tier.epoch.is_none_or(|e| e >= new_epoch));
    }

    /// Snapshot installieren (ersetzt den vorherigen; niedrigste Lookup-
    /// Prioritaet, aber immer der vollstaendige Dokumentbestand).
    pub fn install_snapshot(&self, path: PathBuf, index: HashMap<ColdKey, (u64, u32)>) {
        let mut tiers = self.tiers.write().expect("cold tiers poisoned");
        tiers.retain(|tier| tier.kind != TierKind::Snapshot);
        tiers.push(Arc::new(TierFile {
            epoch: None,
            path,
            kind: TierKind::Snapshot,
            index,
        }));
    }

    /// Geschlossenes Segment direkt publizieren (Replay-Erstbefuellung).
    /// Kein Pruning hier: Beim Replay werden Segmente in aufsteigender
    /// Epoch-Reihenfolge gepusht, und jeder Index bleibt die einzige Quelle
    /// fuer Schluessel, die in keinen der neueren Standaende mehr liegen.
    pub fn push_closed_segment(
        &self,
        epoch: u64,
        path: PathBuf,
        index: HashMap<ColdKey, (u64, u32)>,
    ) {
        let mut tiers = self.tiers.write().expect("cold tiers poisoned");
        tiers.push(Arc::new(TierFile {
            epoch: Some(epoch),
            path,
            kind: TierKind::Segment,
            index,
        }));
        // Neueste zuerst: Segmente absteigend nach Epoch, Snapshot hinten.
        tiers.sort_by_key(|tier| match (tier.kind, tier.epoch) {
            (TierKind::Snapshot, _) => u64::MAX,
            (_, Some(e)) => u64::MAX - e,
            (_, None) => u64::MAX,
        });
    }

    /// Einzeldokument nachladen: `Ok(Some(doc))` = gefunden, `Ok(None)` =
    /// nicht auffindbar oder als geloescht terminiert (erstes Tier mit
    /// Treffer entscheidet). I/O-Fehler (ausser "Datei weg waehrend der
    /// Rotation") werden als `Err` durchgereicht.
    pub fn fetch(&self, app: &str, collection: &str, id: &str) -> io::Result<Option<Arc<Value>>> {
        let key: ColdKey = (app.to_string(), collection.to_string(), id.to_string());

        // Kandidaten unter kurzen Locks einsammeln; das eigentliche Lesen
        // laeuft frei von Sperren.
        let (active_cand, tiers) = {
            let tiers = self.tiers.read().expect("cold tiers poisoned");
            let active = self.active.lock().expect("cold active poisoned");
            let cand = active.as_ref().and_then(|a| {
                a.index
                    .get(&key)
                    .copied()
                    .map(|(start, len)| (a.path.clone(), a.flushed, start, len))
            });
            (cand, tiers.clone())
        };

        if let Some((path, flushed, start, len)) = active_cand {
            // Nur vollstaendig geflushte Records sind verlaesslich lesbar;
            // fuer juengere Docs ist der RAM sowieso massgeblich.
            if start + 8 + len as u64 <= flushed {
                if let Some(hit) = read_segment_record(&path, start, len, &key)? {
                    return Ok(hit);
                }
            }
        }
        for tier in &tiers {
            let Some(&(start, len)) = tier.index.get(&key) else {
                continue;
            };
            let hit = match tier.kind {
                TierKind::Segment => read_segment_record(&tier.path, start, len, &key)?,
                TierKind::Snapshot => read_snapshot_record(&tier.path, start, len, &key)?,
            };
            if let Some(doc) = hit {
                return Ok(doc);
            }
        }
        Ok(None)
    }
}

/// Liest genau einen WAL-Record an bekannter Position und prueft CRC sowie
/// Schluessel. Rueckgabe: `Some(Some(doc))` Upsert-Treffer, `Some(None)`
/// Delete-Treffer, `None` = Schluessel passt nicht (kann nach Rotation
/// kurzzeitig passieren — dann sucht das naechste Tier weiter).
fn read_segment_record(
    path: &Path,
    start: u64,
    len: u32,
    key: &ColdKey,
) -> io::Result<Option<Option<Arc<Value>>>> {
    let body = match read_record_payload(path, start, len)? {
        Some(body) => body,
        None => return Ok(None),
    };
    // Op-Byte + Schluessel pruefen, ohne das Dokument zu parsen, wenn der
    // Record einem anderen Schluessel gehoert.
    match parse_wal_body(&body) {
        Ok(LoggedOp::Upsert {
            app,
            collection,
            id,
            doc,
        }) if (app.as_str(), collection.as_str(), id.as_str())
            == (key.0.as_str(), key.1.as_str(), key.2.as_str()) =>
        {
            Ok(Some(Some(Arc::new(doc))))
        }
        Ok(LoggedOp::Delete {
            app,
            collection,
            id,
        }) if (app.as_str(), collection.as_str(), id.as_str())
            == (key.0.as_str(), key.1.as_str(), key.2.as_str()) =>
        {
            Ok(Some(None))
        }
        _ => Ok(None),
    }
}

/// Analog fuer Snapshot-Records (immer Upsert-Semantik).
fn read_snapshot_record(
    path: &Path,
    start: u64,
    len: u32,
    key: &ColdKey,
) -> io::Result<Option<Option<Arc<Value>>>> {
    let body = match read_record_payload(path, start, len)? {
        Some(body) => body,
        None => return Ok(None),
    };
    match parse_snapshot_body(&body) {
        Ok((app, collection, id, doc))
            if (app.as_str(), collection.as_str(), id.as_str())
                == (key.0.as_str(), key.1.as_str(), key.2.as_str()) =>
        {
            Ok(Some(Some(Arc::new(doc))))
        }
        _ => Ok(None),
    }
}

/// Offsets `start`: `len | crc | payload`. Liefert `None`, wenn die Datei
/// inzwischen geloescht ist (Kompaktions-Rennen waehrend der Rotation) —
/// dann sucht das naechste Tier weiter.
fn read_record_payload(path: &Path, start: u64, len: u32) -> io::Result<Option<Vec<u8>>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let mut reader = BufReader::with_capacity(8 + len as usize, file);
    reader.seek(SeekFrom::Start(start))?;
    let mut header = [0u8; 8];
    reader.read_exact(&mut header)?;
    let record_len = u32::from_le_bytes(header[..4].try_into().unwrap());
    if record_len != len {
        // Index und Datei passen nicht zusammen (sollte nicht passieren;
        // defensiv nicht raten).
        return Ok(None);
    }
    let crc = u32::from_le_bytes(header[4..].try_into().unwrap());
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body)?;
    if crc32fast::hash(&body) != crc {
        return Ok(None);
    }
    Ok(Some(body))
}
