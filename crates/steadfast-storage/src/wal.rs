//! Write-Ahead-Log: Binaerformat, Encoder/Decoder und Replay.
//!
//! Layout einer Log- bzw. Snapshot-Datei:
//!
//! ```text
//! Header:  Magic (4 Bytes)          — "RWAL" (WAL) bzw. "RSNP" (Snapshot)
//!          Version (u16 LE)
//! Record:  len  (u32 LE)            — Laenge der Payload
//!          crc  (u32 LE)            — CRC32 ueber die Payload
//!          payload
//! ```
//!
//! WAL-Payload: `op (u8)` | `app | collection | id` | `[Dokument-JSON]` —
//! Strings laengenpraefixiert (u32 LE + UTF-8-Bytes), `op` ist 1 = Upsert,
//! 2 = Delete. Snapshot-Payload: `app | collection | id | Dokument-JSON`.
//!
//! Crash-Semantik: Ein unvollstaendig geschriebener Record am Dateiende
//! (torn tail) wird beim Replay wie Dateiende behandelt — der Praefix der
//! Datei bleibt voll gueltig. Eine CRC-Abweichung bricht das Replay der
//! jeweiligen Datei ab (der Rest wird verworfen, das Replay laeuft mit der
//! naechsten Datei weiter) und wird im [`ReplayReport`] gemeldet; nur ein
//! falscher Magic/Version-Header ist ein harter Fehler (Fail-Fast).
//!
//! Alle Mutationen sind volle Upserts bzw. Deletes und damit idempotent:
//! Snapshot und WAL duerfen sich ueberschneiden, das Replay wendet sie in
//! Dateireihenfolge an und landet immer im korrekten Endzustand.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use thiserror::Error;

use crate::cold::{ColdKey, ColdTier};
use crate::store::{CollectionDump, MemoryStore};

pub const WAL_MAGIC: [u8; 4] = *b"RWAL";
pub const SNAPSHOT_MAGIC: [u8; 4] = *b"RSNP";
pub const FORMAT_VERSION: u16 = 1;
/// Header: Magic + Version.
pub const HEADER_LEN: u64 = 6;
/// Harte Obergrenze fuer eine Record-Payload; alles darueber ist Korruption.
pub const MAX_RECORD_LEN: u32 = 64 * 1024 * 1024;
pub const SNAPSHOT_FILE_NAME: &str = "snapshot.bin";
pub const SNAPSHOT_TMP_NAME: &str = "snapshot.tmp";

const OP_UPSERT: u8 = 1;
const OP_DELETE: u8 = 2;

#[derive(Debug, Error)]
pub enum WalError {
    #[error("I/O-Fehler im Persistenzlayer: {0}")]
    Io(#[from] io::Error),
    #[error("JSON-Fehler im Persistenzlayer: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "ununterstuetztes Dateiformat (Magic `{magic}`, Version {version}) in {path}: \
             bitte Datenverzeichnis pruefen — es wird nicht automatisch geloescht"
    )]
    UnsupportedFormat {
        magic: String,
        version: u16,
        path: PathBuf,
    },
    #[error("korrupter Snapshot-Record in {path}: {reason}")]
    CorruptSnapshot { path: PathBuf, reason: String },
}

/// Eine zu loggende Mutation. `doc` als `Arc<Value>`: der Hot Path gibt nur
/// seine bestehende Referenz an den Kanal weiter — kopiert wird erst im
/// Worker-Thread beim Serialisieren.
#[derive(Debug)]
pub enum WalOp {
    Upsert {
        app: String,
        collection: String,
        id: String,
        doc: Arc<Value>,
    },
    Delete {
        app: String,
        collection: String,
        id: String,
    },
}

/// Ergebnis eines Replays: Wie viele Dokumente/Records restoringriffen sind
/// und ob eine WAL-Datei vorzeitig endete (torn tail oder CRC-Abweichung).
#[derive(Debug, Default, Clone)]
pub struct ReplayReport {
    pub snapshot_docs: u64,
    pub wal_files: u64,
    pub wal_records: u64,
    /// Grund, wenn eine WAL-Datei nicht bis zum Ende gelesen werden konnte.
    pub stopped_early: Option<String>,
}

/// Wie [`replay_data_dir`], liefert aber zusaetzlich einen befuellten
/// [`ColdTier`]: Jeder sauber gelesene Record wird unter seinem Schluessel
/// und Datei-Offset indiziert, exakt nach denselben Prefix-Regeln wie das
/// Replay selbst (torn tail/CRC-Bruch beenden beides an derselben Stelle).
/// Damit stimmen RAM-Zustand und Kalt-Tier ab dem ersten Request überein.
pub fn replay_data_dir_full(
    store: &MemoryStore,
    dir: &Path,
) -> Result<(ReplayReport, ColdTier), WalError> {
    let mut report = ReplayReport::default();
    let cold = ColdTier::new();

    let snapshot_path = dir.join(SNAPSHOT_FILE_NAME);
    if snapshot_path.exists() {
        let file = File::open(&snapshot_path)?;
        let mut reader = BufReader::new(file);
        read_header(&mut reader, &SNAPSHOT_MAGIC, &snapshot_path)?;
        let mut index = HashMap::new();
        let mut pos = HEADER_LEN;
        let mut step = 0u64;
        loop {
            match next_record(&mut reader)? {
                Step::Eof => break,
                Step::Bad(reason) => {
                    return Err(WalError::CorruptSnapshot {
                        path: snapshot_path,
                        reason,
                    });
                }
                Step::Record(body) => {
                    let (app, collection, id, doc) =
                        parse_snapshot_body(&body).map_err(|reason| WalError::CorruptSnapshot {
                            path: snapshot_path.clone(),
                            reason,
                        })?;
                    index.insert(
                        (app.clone(), collection.clone(), id.clone()),
                        (pos, body.len() as u32),
                    );
                    pos += 8 + body.len() as u64;
                    store.insert(&app, &collection, &id, doc);
                    step += 1;
                }
            }
        }
        report.snapshot_docs = step;
        cold.install_snapshot(snapshot_path, index);
    }

    for (epoch, path) in wal_segments(dir)? {
        // Halb geschriebener Header nach einem Crash: Die Datei ist zu kurz
        // fuer den 6-Byte-Header — nichts lesbar, aber auch nichts verloren
        // (sie kann keine Records enthalten). Ueberspringen statt Fail-Fast.
        if path.metadata()?.len() < HEADER_LEN {
            continue;
        }
        report.wal_files += 1;
        let mut index = HashMap::new();
        let replayed = replay_wal_file(store, &path, &mut index)?;
        cold.push_closed_segment(epoch, path.clone(), index);
        report.wal_records += replayed.records;
        if let Some(reason) = replayed.stopped_early {
            report.stopped_early = Some(format!(
                "wal-{epoch} endete vorzeitig nach {} Records: {reason}",
                replayed.records
            ));
        }
    }

    Ok((report, cold))
}

/// Kompatibilitaets-Wrapper fuer Aufrufer ohne Kalt-Tier-Bedarf.
pub fn replay_data_dir(store: &MemoryStore, dir: &Path) -> Result<ReplayReport, WalError> {
    replay_data_dir_full(store, dir).map(|(report, _)| report)
}

struct FileReplay {
    records: u64,
    stopped_early: Option<String>,
}

fn replay_wal_file(
    store: &MemoryStore,
    path: &Path,
    index: &mut HashMap<ColdKey, (u64, u32)>,
) -> Result<FileReplay, WalError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    read_header(&mut reader, &WAL_MAGIC, path)?;
    let mut result = FileReplay {
        records: 0,
        stopped_early: None,
    };
    let mut pos = HEADER_LEN;
    loop {
        match next_record(&mut reader)? {
            Step::Eof => break,
            Step::Bad(reason) => {
                result.stopped_early = Some(reason);
                break;
            }
            Step::Record(body) => match parse_wal_body(&body) {
                Ok(LoggedOp::Upsert {
                    app,
                    collection,
                    id,
                    doc,
                }) => {
                    index.insert(
                        (app.clone(), collection.clone(), id.clone()),
                        (pos, body.len() as u32),
                    );
                    pos += 8 + body.len() as u64;
                    store.insert(&app, &collection, &id, doc);
                    result.records += 1;
                }
                Ok(LoggedOp::Delete {
                    app,
                    collection,
                    id,
                }) => {
                    index.insert(
                        (app.clone(), collection.clone(), id.clone()),
                        (pos, body.len() as u32),
                    );
                    pos += 8 + body.len() as u64;
                    store.delete(&app, &collection, &id);
                    result.records += 1;
                }
                Err(reason) => {
                    result.stopped_early = Some(reason);
                    break;
                }
            },
        }
    }
    Ok(result)
}

/// Alle WAL-Segmente im Verzeichnis, numerisch nach Epoch sortiert.
/// Dateien mit unparsbarem Namen werden ignoriert (keine unsere).
fn wal_segments(dir: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let mut segments: Vec<(u64, PathBuf)> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(raw) = name
            .strip_prefix("wal-")
            .and_then(|n| n.strip_suffix(".log"))
        else {
            continue;
        };
        if let Ok(epoch) = raw.parse::<u64>() {
            segments.push((epoch, entry.path()));
        }
    }
    segments.sort_by_key(|(epoch, _)| *epoch);
    Ok(segments)
}

pub fn wal_file_path(dir: &Path, epoch: u64) -> PathBuf {
    dir.join(format!("wal-{epoch:020}.log"))
}

pub(crate) fn epoch_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Schreibt den Snapshot atomar: temporaere Datei, fsync, Umbenennung.
/// Rueckgabe: Offset-Index ueber alle geschriebenen Records (fuer das
/// Kalt-Tier); die finale Datei liegt garantiert unter `final_path`.
pub fn write_snapshot_file(
    tmp_path: &Path,
    final_path: &Path,
    dumps: &[CollectionDump],
) -> io::Result<HashMap<ColdKey, (u64, u32)>> {
    let file = File::create(tmp_path)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(&SNAPSHOT_MAGIC)?;
    writer.write_all(&FORMAT_VERSION.to_le_bytes())?;
    let mut index = HashMap::new();
    let mut pos = HEADER_LEN;
    for dump in dumps {
        for (id, doc) in &dump.entries {
            let mut body = Vec::with_capacity(64);
            put_kstr(&mut body, &dump.app);
            put_kstr(&mut body, &dump.collection);
            put_kstr(&mut body, id);
            serde_json::to_writer(&mut body, doc.as_ref())?;
            write_record(&mut writer, &body)?;
            index.insert(
                (dump.app.clone(), dump.collection.clone(), id.clone()),
                (pos, body.len() as u32),
            );
            pos += 8 + body.len() as u64;
        }
    }
    writer.flush()?;
    let file = writer.into_inner().map_err(io::Error::from)?;
    file.sync_all()?;
    fs::rename(tmp_path, final_path)?;
    Ok(index)
}

// --- Rahmung (Records) -----------------------------------------------------------

enum Step {
    Record(Vec<u8>),
    /// Sauberes Dateiende oder torn tail (unvollstaendig geschriebener
    /// letzter Record nach einem Crash) — beides gueltige Endpunkte.
    Eof,
    /// Vollstaendiger Record, aber Inhalt unbrauchbar (CRC/Struktur).
    Bad(String),
}

fn next_record<R: Read>(reader: &mut R) -> io::Result<Step> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        // Entweder sauberes EOF oder abgebrochenes Schreiben des
        // Laengenfelds — beides ist ein gueltiger Endpunkt.
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(Step::Eof),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_RECORD_LEN {
        return Ok(Step::Bad(format!(
            "Record-Laenge {len} ueberschreitet das Limit von {MAX_RECORD_LEN} Bytes"
        )));
    }
    let mut crc_buf = [0u8; 4];
    if reader.read_exact(&mut crc_buf).is_err() {
        // Torn tail zwischen Laengen- und CRC-Feld.
        return Ok(Step::Eof);
    }
    let mut body = vec![0u8; len as usize];
    if let Err(e) = reader.read_exact(&mut body) {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            // Torn tail: der Record wurde nie vollstaendig geschrieben.
            return Ok(Step::Eof);
        }
        return Err(e);
    }
    if crc32fast::hash(&body) != u32::from_le_bytes(crc_buf) {
        return Ok(Step::Bad("CRC-Pruefsumme stimmt nicht".into()));
    }
    Ok(Step::Record(body))
}

fn write_record(out: &mut impl Write, body: &[u8]) -> io::Result<usize> {
    out.write_all(&(body.len() as u32).to_le_bytes())?;
    out.write_all(&crc32fast::hash(body).to_le_bytes())?;
    out.write_all(body)?;
    // Rahmen (len + crc) + Payload — insgesamt fortgezeichnete Bytes.
    Ok(8 + body.len())
}

fn read_header<R: Read>(
    reader: &mut R,
    expected_magic: &[u8; 4],
    path: &Path,
) -> Result<(), WalError> {
    let mut header = [0u8; HEADER_LEN as usize];
    reader.read_exact(&mut header)?;
    let magic = String::from_utf8_lossy(&header[..4]).into_owned();
    let version = u16::from_le_bytes([header[4], header[5]]);
    if header[..4] != *expected_magic || version != FORMAT_VERSION {
        return Err(WalError::UnsupportedFormat {
            magic,
            version,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

pub fn write_file_header(out: &mut impl Write, magic: &[u8; 4]) -> io::Result<()> {
    out.write_all(magic)?;
    out.write_all(&FORMAT_VERSION.to_le_bytes())
}

// --- Kodierung -------------------------------------------------------------------

fn put_kstr(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// Rueckgabe: Insgesamt fortgezeichnete Bytes (8-Byte-Rahmen + Payload) —
/// der Worker verrechnet damit seine Datei-Offsets fuer das Kalt-Tier.
pub fn encode_wal_op(out: &mut impl Write, op: &WalOp) -> io::Result<usize> {
    let mut body = Vec::with_capacity(96);
    match op {
        WalOp::Upsert {
            app,
            collection,
            id,
            doc,
        } => {
            body.push(OP_UPSERT);
            put_kstr(&mut body, app);
            put_kstr(&mut body, collection);
            put_kstr(&mut body, id);
            serde_json::to_writer(&mut body, doc.as_ref())?;
        }
        WalOp::Delete {
            app,
            collection,
            id,
        } => {
            body.push(OP_DELETE);
            put_kstr(&mut body, app);
            put_kstr(&mut body, collection);
            put_kstr(&mut body, id);
        }
    }
    write_record(out, &body)
}

// --- Dekodierung -----------------------------------------------------------------

pub(crate) enum LoggedOp {
    Upsert {
        app: String,
        collection: String,
        id: String,
        doc: Value,
    },
    Delete {
        app: String,
        collection: String,
        id: String,
    },
}

struct Cursor<'a> {
    body: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> Result<u8, String> {
        let byte = *self
            .body
            .get(self.pos)
            .ok_or_else(|| "unerwartetes Record-Ende".to_string())?;
        self.pos += 1;
        Ok(byte)
    }

    fn kstr(&mut self) -> Result<String, String> {
        if self.body.len() < self.pos + 4 {
            return Err("unerwartetes Record-Ende im Laengenpraefix".into());
        }
        let len =
            u32::from_le_bytes(self.body[self.pos..self.pos + 4].try_into().unwrap()) as usize;
        self.pos += 4;
        if self.body.len() < self.pos + len {
            return Err("unerwartetes Record-Ende im String".into());
        }
        let s = std::str::from_utf8(&self.body[self.pos..self.pos + len])
            .map_err(|_| "ungueltiges UTF-8 im Record".to_string())?
            .to_owned();
        self.pos += len;
        Ok(s)
    }

    fn json(&mut self) -> Result<Value, String> {
        serde_json::from_slice(&self.body[self.pos.min(self.body.len())..])
            .map_err(|err| format!("ungueltiges Dokument-JSON: {err}"))
    }
}

pub(crate) fn parse_wal_body(body: &[u8]) -> Result<LoggedOp, String> {
    let mut cur = Cursor { body, pos: 0 };
    match cur.byte()? {
        OP_UPSERT => {
            let app = cur.kstr()?;
            let collection = cur.kstr()?;
            let id = cur.kstr()?;
            let doc = cur.json()?;
            Ok(LoggedOp::Upsert {
                app,
                collection,
                id,
                doc,
            })
        }
        OP_DELETE => {
            let app = cur.kstr()?;
            let collection = cur.kstr()?;
            let id = cur.kstr()?;
            Ok(LoggedOp::Delete {
                app,
                collection,
                id,
            })
        }
        other => Err(format!("unbekannte Operation `{other}`")),
    }
}

pub(crate) fn parse_snapshot_body(body: &[u8]) -> Result<(String, String, String, Value), String> {
    let mut cur = Cursor { body, pos: 0 };
    let app = cur.kstr()?;
    let collection = cur.kstr()?;
    let id = cur.kstr()?;
    let doc = cur.json()?;
    Ok((app, collection, id, doc))
}
