//! Asynchroner WAL-Worker: nimmt Mutationen ueber einen Begrenzten Kanal
//! entgegen, haengt sie sequenziell an das aktive WAL-Segment an und rotiert
//! regelmaessig in einen kompaktierten Snapshot.
//!
//! Durability-Modell: Der Store wendet Mutationen sofort im RAM an und reiht
//! sie in den Kanal ein (blockierender Send = Rueckstau statt Datenverlust).
//! Der Worker schreibt mit gepuffertem I/O auf die SSD; fsync passiert bei
//! jeder Rotation, beim sauberen Herunterfahren und nicht pro Record. Ein
//! Absturz kann daher die letzten Records verlieren — dafuer bleibt der Hot
//! Path frei von synchroner Festplatten-I/O (dokumentiertes Phase-2-Kompromiss).
//!
//! Rueckstau bis zur Platte: Scheitert der Flush des Workers (z. B. volle
//! Platte), nimmt er KEINE Ops mehr aus dem Kanal an, sondern retryt in
//! festem Takt. Der Kanal laeuft voll, der blockierende Send staut die
//! schreibenden Requests ab — es geht kein Record verloren, die Engine wird
//! fuer Schreibzugriffe nur langsam, nie lueckenhaft.
//!
//! Rotationsprotokoll (korrekt ohne Store-Sperren, weil alle Mutationen
//! idempotente Vollzuege sind; der Worker ist single-threaded, also warten
//! waehrend der Rotation neue Ops im Kanal und landen nach dem Umschalten
//! direkt im neuen Segment). Rotiert wird am Zeit-Tick und sobald das
//! aktive Segment die Groessen-Obergrenze erreicht:
//! 1. Snapshot aus dem aktuellen Store-Zustand (atomar via Rename).
//! 2. Neues WAL-Segment oeffnen, Writer umschalten, altes Segment fsyncen.
//! 3. Alte Segmente loeschen. Ein Crash zwischendurch hinterlaesst nur
//!    ueberschneidende Quellen (Snapshot + mehrere Segmente) — das Replay
//!    wendet alles in Epoch-Reihenfolge an und landet korrekt.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::cold::ColdTier;
use crate::store::MemoryStore;
use crate::wal::{self, WalOp};
use fs2::FileExt;

/// Kanaltiefe: Bei vollem Kanal blockiert der Schreiber (Rueckstau), es
/// geht kein Record verloren. 65.536 Ops = erheblich mehr, als eine SSD
/// im Schnitt nachkommt.
const WAL_CHANNEL_CAPACITY: usize = 65_536;
const WAL_BUF_CAPACITY: usize = 256 * 1024;

/// Takt des Flush-Retrys im Rueckstau-Modus: Nach einem fehlgeschlagenen
/// Flush versucht der Worker alle 200 ms erneut zu schreiben und nimmt bis
/// dahin keine Ops aus dem Kanal.
const WAL_FLUSH_RETRY: Duration = Duration::from_millis(200);

/// Abstraktion ueber die WAL-Zieldatei: gepuffertes Anhaengen plus fsync und
/// Laengenabfrage bei Rotation/Abschluss. Der Trait existiert, damit Tests
/// einen fehlertoleranten Writer unterschieben koennen (Fault Injection fuer
/// den Rueckstau-Pfad), ohne die Produktionslogik zu kopieren.
trait WalSink: Write {
    fn wal_sync(&self) -> io::Result<()>;
    fn wal_len(&self) -> io::Result<u64>;
}

impl WalSink for File {
    fn wal_sync(&self) -> io::Result<()> {
        self.sync_all()
    }
    fn wal_len(&self) -> io::Result<u64> {
        self.metadata().map(|m| m.len())
    }
}

#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    pub data_dir: PathBuf,
    /// Zeit zwischen Snapshot-Rotationen. `Duration::ZERO` snapshotet nur
    /// beim sauberen Herunterfahren.
    pub snapshot_interval: Duration,
    /// Groessentrigger: Das aktive Segment wird rotiert, sobald es so viele
    /// Bytes ueberschreitet — auch mitten im Intervall (Burst-Lasten drehen
    /// nicht erst am Tick). `0` = unbegrenzt, dann rotiert nur der Zeit-Tick.
    pub max_segment_bytes: u64,
}

/// Handle auf den laufenden WAL-Worker. Beendet wird ueber
/// [`Persistence::shutdown`] — der Store loest dabei seine WAL-Senke, der
/// Worker leert Puffer + schreibt den finalen Snapshot.
#[derive(Debug)]
pub struct Persistence {
    worker: Option<JoinHandle<()>>,
    #[allow(dead_code)] // Dokumentation/Fehlerbilder; Freigabe via shutdown
    data_dir: PathBuf,
    /// Beratende Sperre auf `<data-dir>/engine.lock`: Solange dieses Handle
    /// lebt, scheitert der Start einer zweiten Engine-Instanz auf demselben
    /// Datenverzeichnis (Doppelstart-Schutz). Freigabe durch Drop.
    #[allow(dead_code)]
    lock_file: File,
    /// Fordert den Worker zum Beenden auf. Noetig, weil ein Worker im
    /// Rueckstau-Modus (fehlgeschlagener Flush) den Kanal nicht mehr liest
    /// und ein Shutdown ihn sonst nie erreichen wuerde.
    shutdown_flag: Arc<AtomicBool>,
}

impl Persistence {
    /// Oeffnet (bzw. legt an) das aktive WAL-Segment und startet den Worker.
    /// Vor dem Aufruf muss [`wal::replay_data_dir_full`] gelaufen sein; das
    /// dabei entstandene Kalt-Tier wird hier uebergeben und ab jetzt vom
    /// Worker weitergepflegt.
    pub fn start(
        store: &Arc<MemoryStore>,
        config: PersistenceConfig,
        cold: Arc<ColdTier>,
    ) -> io::Result<Persistence> {
        fs::create_dir_all(&config.data_dir)?;
        // Doppelstart-Schutz: beratende Exclusive-Lock auf dem Daten-
        // verzeichnis, bevor irgendein WAL-Zustand angefasst wird. Die Sperre
        // stirbt mit dem Handle (Crash = OS gibt frei), also kein toter Lock
        // nach einem Absturz.
        let lock_file = acquire_data_dir_lock(&config.data_dir)?;
        let active_epoch = wal::epoch_ms_now();
        let active_path = wal::wal_file_path(&config.data_dir, active_epoch);
        // Datei frueh anlegen: Fail-Fast bei Rechte-/Plattenproblemen statt
        // mitten im Betrieb.
        let writer = open_wal_segment(&active_path)?;
        // Records starten hinter einem evtl. wiederverwendeten Dateibestand
        // (Crash-Rest) — das Kalt-Tier muss dieselben Offsets sehen.
        let start_offset = writer.get_ref().wal_len()?;
        cold.open_active(active_path, start_offset);

        let (sender, receiver) = sync_channel::<WalOp>(WAL_CHANNEL_CAPACITY);
        store.attach_wal(sender);

        let worker_store = Arc::clone(store);
        let cfg = config.clone();
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let worker_flag = Arc::clone(&shutdown_flag);
        let worker = std::thread::Builder::new()
            .name("wal-worker".into())
            .spawn(move || {
                worker_loop(
                    worker_store,
                    receiver,
                    cfg,
                    writer,
                    start_offset,
                    cold,
                    worker_flag,
                )
            })?;

        Ok(Persistence {
            worker: Some(worker),
            data_dir: config.data_dir,
            lock_file,
            shutdown_flag,
        })
    }

    /// Sauberes Herunterfahren: WAL-Senke aus dem Store loesen (danach
    /// konnten keine Requests mehr loggen), Kanal schliessen und auf den
    /// finalen Snapshot des Workers warten. Das Shutdown-Flag wird zuerst
    /// gesetzt, damit auch ein im Rueckstau-Modus festsitzender Worker zum
    /// Abschluss kommt (finaler Snapshot ist dann Best-Effort).
    pub fn shutdown(mut self, store: &MemoryStore) -> io::Result<()> {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        drop(store.detach_wal());
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("wal-worker panicked"))?;
        }
        Ok(())
    }
}

/// Einen Record kodieren und den Kalt-Tier-Index fuehren; liefert die neue
/// Schreibposition (Ende des Records). `n` ist die komplette Framing-Laenge.
fn write_record(
    writer: &mut BufWriter<Box<dyn WalSink + Send>>,
    cold: &Arc<ColdTier>,
    offset: u64,
    op: &WalOp,
) -> u64 {
    let key = match op {
        WalOp::Upsert {
            app,
            collection,
            id,
            ..
        }
        | WalOp::Delete {
            app,
            collection,
            id,
        } => (app.clone(), collection.clone(), id.clone()),
    };
    match wal::encode_wal_op(writer, op) {
        Ok(n) => {
            cold.record(key, offset, (n - 8) as u32);
            offset + n as u64
        }
        Err(err) => {
            tracing::error!(%err, "WAL-Schreibfehler — Record ging verloren");
            offset
        }
    }
}

fn worker_loop(
    store: Arc<MemoryStore>,
    rx: Receiver<WalOp>,
    cfg: PersistenceConfig,
    writer: BufWriter<Box<dyn WalSink + Send>>,
    start_offset: u64,
    cold: Arc<ColdTier>,
    shutdown: Arc<AtomicBool>,
) {
    let mut writer = writer;
    // Interval 0 => praktisch nie ticken; der finale Snapshot beim Shutdown
    // bleibt davon unberuehrt.
    let tick = if cfg.snapshot_interval.is_zero() {
        Duration::from_secs(30 * 24 * 60 * 60)
    } else {
        cfg.snapshot_interval
    };
    let mut next_tick = Instant::now() + tick;
    let mut dirty: usize = 0;
    // Aktuelle Schreibposition (Ende des letzten vollstaendigen Records).
    let mut offset = start_offset;
    // Rueckstau-Modus: gesetzt nach einem fehlgeschlagenen Flush, solange
    // aktiv nimmt der Worker keine Ops aus dem Kanal (kein stiller
    // Record-Verlust — der Send im Store blockiert stattdessen).
    let mut flush_failed = false;

    loop {
        // Rueckstau-Modus vor allem anderen: den haengenden Flush aufarbeiten.
        // Die bereits kodierten Records liegen weiterhin im Puffer (der
        // BufWriter behaelt ungeschriebene Reste bei Fehlern) und werden
        // hier retryt.
        if flush_failed {
            std::thread::sleep(WAL_FLUSH_RETRY);
            match writer.flush() {
                Ok(()) => {
                    flush_failed = false;
                    cold.advance_flushed(offset);
                    tracing::warn!(
                        "WAL-Flush nach Fehler wieder erfolgreich — Rueckstau wird abgebaut"
                    );
                }
                Err(_) => {
                    if shutdown.load(Ordering::Relaxed) {
                        // Not-Aus im Rueckstau: Verbleibende Ops wenigstens
                        // in den Puffer ziehen (der Epilog flusht, sofern
                        // die Platte bis dahin wieder mitmacht).
                        // dirty ist hier egal: Nach dem Break folgt der
                        // Epilog, der per Snapshot ohnehin alles sichert.
                        while let Ok(op) = rx.try_recv() {
                            offset = write_record(&mut writer, &cold, offset, &op);
                        }
                        break;
                    }
                }
            }
            continue;
        }

        // Rotation am Zeit-Tick oder sobald das aktive Segment die Groessen-
        // obergrenze erreicht (Bursts muessen nicht aufs Intervall warten).
        let time_hit = Instant::now() >= next_tick;
        if time_hit {
            // Tick verbrauchen — auch ohne dirty Records, sonst bleibt er
            // ueberfaellig und dreht in dem Moment Zwangsrotation, in dem
            // nach langer Ruhe die naechste Mutation eintraf.
            next_tick = Instant::now() + tick;
        }
        let size_hit = cfg.max_segment_bytes > 0 && offset >= cfg.max_segment_bytes;
        if dirty > 0 && (time_hit || size_hit) {
            let rotated = rotate(&store, &cfg.data_dir, &mut writer, &mut offset, &cold);
            if rotated {
                // Erst jetzt ist jede residente Version im geschlossenen
                // Segment bzw. Snapshot beschaffbar — Eviction-Fenster.
                store.run_eviction();
            } else {
                // Rotation kann an einer inzwischen vollen Platte scheitern;
                // die Puffer-Records sind dann evtl. nicht mehr geflushed.
                // Ab in den Rueckstau-Modus, bis der Retry Erfolg meldet.
                flush_failed = true;
            }
            dirty = 0;
        }

        if shutdown.load(Ordering::Relaxed) {
            // Das Flag wird vor dem Loesen der Senke gesetzt: Alles, was
            // Mutationen bis dahin in den Kanal gestellt haben, muss noch
            // auf die Platte, bevor der Abschluss-Snapshot entsteht.
            while let Ok(op) = rx.try_recv() {
                offset = write_record(&mut writer, &cold, offset, &op);
            }
            break;
        }

        let remaining = next_tick.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(op) => {
                let mut current = Some(op);
                // Kleiner Batch-Lauf: was bereitliegt mitnehmen, dann einmal
                // flushen (weniger Syscalls unter Last).
                while let Some(op) = current {
                    offset = write_record(&mut writer, &cold, offset, &op);
                    dirty += 1;
                    current = rx.try_recv().ok();
                }
                match writer.flush() {
                    Ok(()) => cold.advance_flushed(offset),
                    Err(err) => {
                        flush_failed = true;
                        tracing::error!(
                            %err,
                            "WAL-Flush fehlgeschlagen — Worker stoppt den Ops-Konsum \
                             (Backpressure), Retry alle {WAL_FLUSH_RETRY:?}"
                        );
                    }
                }
            }
            // Rotation passiert am Schleifenanfang; der Timeout dient nur als
            // Aufwach-Signal.
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    // Abschluss (Disconnect oder Shutdown-Flag): der RAM-Zustand ist final —
    // letzter Stand als Snapshot sichern.
    match snapshot_now(&store, &cfg.data_dir, &cold) {
        Ok(docs) => tracing::info!(docs, "finaler Snapshot beim Herunterfahren geschrieben"),
        Err(err) => {
            tracing::error!(%err, "finaler Snapshot fehlgeschlagen — WAL bleibt massgeblich")
        }
    }
    let _ = writer.flush();
    let _ = writer.get_ref().wal_sync();
}

/// Snapshot schreiben, Writer auf ein neues Segment umschalten (das alte
/// wird zuvor geflusht + gefsynced), alte Segmente loeschen. Liefert `true`,
/// wenn die Rotation komplett durchlief (erst dann evictiert der Worker).
/// Fehler sind unkritisch: Der alte Writer bleibt unangetastet, die WAL
/// laeuft einfach weiter (naechster Trigger versucht es erneut) — nur die
/// Snapshot-Datei ist dann veraltet. Scheitert der Flush des alten Segments
/// (z. B. Platte voll geworden), wird die Rotation abgebrochen: Die im
/// Puffer stehenden Records duerfen nicht mit dem alten Writer verloren
/// gehen — der Aufrufer wechselt in den Rueckstau-Modus.
fn rotate(
    store: &MemoryStore,
    dir: &Path,
    writer: &mut BufWriter<Box<dyn WalSink + Send>>,
    offset: &mut u64,
    cold: &Arc<ColdTier>,
) -> bool {
    // Zuerst der Snapshot (braucht die kalten Docs aus dem Kalt-Tier, um
    // nichts zu verlieren); schlaegt er fehl, wird nichts rotiert.
    if let Err(err) = snapshot_now(store, dir, cold) {
        tracing::error!(%err, "Snapshot fehlgeschlagen — WAL laeuft ohne Rotation weiter");
        return false;
    }
    // Alten Stand sauber abschliessen (ab hier ist das gesamte alte Segment
    // lesbar), dann umschalten.
    if let Err(err) = writer.flush() {
        tracing::warn!(
            %err,
            "Flush des alten WAL-Segments fehlgeschlagen — Rotation abgebrochen, \
             Records bleiben im Puffer"
        );
        return false;
    }
    cold.advance_flushed(*offset);
    let new_epoch = wal::epoch_ms_now();
    let new_path = wal::wal_file_path(dir, new_epoch);
    let new_writer = match open_wal_segment(&new_path) {
        Ok(w) => w,
        Err(err) => {
            tracing::error!(%err, "neues WAL-Segment nicht anlegbar — WAL laeuft im alten Segment weiter");
            return false;
        }
    };
    let old = std::mem::replace(writer, new_writer);
    let _ = old.get_ref().wal_sync();
    let _ = writer.flush();
    let new_start = writer.get_ref().wal_len().unwrap_or(wal::HEADER_LEN);
    // Aktives Tier wechselt: altes Segment als geschlossenes Tier
    // veroeffentlichen, Segmente unterhalb der Kompaktionsgrenze vergessen.
    cold.rotate_to(new_path, new_epoch, new_start);
    *offset = new_start;
    delete_segments_before(dir, new_epoch);
    tracing::info!(epoch = new_epoch, "WAL rotiert, Snapshot geschrieben");
    true
}

/// Konsistenter Dump aus dem Store (kurze Locks, Kaltauflösung ohne Sperren)
/// und atomarer Snapshot-Schreibvorgang; der entstandene Offset-Index geht
/// ins Kalt-Tier. Liefert die Gesamtzahl der Dokumente.
fn snapshot_now(store: &MemoryStore, dir: &Path, cold: &Arc<ColdTier>) -> io::Result<u64> {
    let dumps = store.dump_collections()?;
    let docs = dumps.iter().map(|d| d.entries.len() as u64).sum();
    let tmp = dir.join(wal::SNAPSHOT_TMP_NAME);
    let final_path = dir.join(wal::SNAPSHOT_FILE_NAME);
    let index = wal::write_snapshot_file(&tmp, &final_path, &dumps)?;
    cold.install_snapshot(final_path, index);
    Ok(docs)
}

/// Belegt `<dir>/engine.lock` exklusiv (beratende Sperre). Liefert das
/// File-Handle zurueck — die Sperre gilt, bis das Handle gedroppt wird.
fn acquire_data_dir_lock(dir: &Path) -> io::Result<File> {
    let lock_path = dir.join("engine.lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    if let Err(err) = file.try_lock_exclusive() {
        // "Bereits gesperrt" kommt plattformverschieden an: WouldBlock
        // (Unix flock) oder der rohe Windows-Code 33 (ERROR_LOCK_VIOLATION,
        // von std als Uncategorized durchgereicht).
        let already_locked =
            err.kind() == io::ErrorKind::WouldBlock || err.raw_os_error() == Some(33);
        return Err(if already_locked {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Datenverzeichnis {} ist bereits von einer laufenden Engine-Instanz belegt ({}). \
                     Ein zweiter Prozess auf demselben data-dir wuerde WAL und Snapshot korrompieren.",
                    dir.display(),
                    lock_path.display()
                ),
            )
        } else {
            err
        });
    }
    Ok(file)
}

/// Oeffnet ein Segment zum Anhaengen; ein leeres/neues File bekommt den
/// Header (idempotent — halb geschriebene Header nach einem Crash sind
/// < 6 Bytes und werden beim Replay uebersprungen). Der Writer kommt als
/// Trait-Objekt zurueck: rotate() tauscht den BufWriter komplett aus und
/// braucht dafuer einen konkreten Typ; Tests unterschieben ueber denselben
/// Mechanismus ihren Fault-Injection-Writer (Rueckstau-Test).
fn open_wal_segment(path: &Path) -> io::Result<BufWriter<Box<dyn WalSink + Send>>> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let sink: Box<dyn WalSink + Send> = Box::new(file);
    if sink.wal_len()? < wal::HEADER_LEN {
        let mut writer = BufWriter::with_capacity(WAL_BUF_CAPACITY, sink);
        wal::write_file_header(&mut writer, &wal::WAL_MAGIC)?;
        writer.flush()?;
        Ok(writer)
    } else {
        Ok(BufWriter::with_capacity(WAL_BUF_CAPACITY, sink))
    }
}

fn delete_segments_before(dir: &Path, epoch: u64) {
    if let Ok(segments) = fs::read_dir(dir) {
        for entry in segments.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(raw) = name
                .strip_prefix("wal-")
                .and_then(|n| n.strip_suffix(".log"))
            else {
                continue;
            };
            let Ok(segment_epoch) = raw.parse::<u64>() else {
                continue;
            };
            if segment_epoch < epoch {
                // Best effort: Inhalt ist zu diesem Zeitpunkt im Snapshot
                // bzw. im neuen Segment; ein Fehlschlag kostet nur Platz.
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fault-Injection-Writer: delegiert auf eine echte Datei, liefert aber
    /// solange `fail` gesetzt ist bei jedem Schreibversuch einen ENOSPC-
    /// Fehler (simulierte volle Platte).
    struct FaultyWriter {
        file: File,
        fail: Arc<AtomicBool>,
    }

    impl Write for FaultyWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail.load(Ordering::Relaxed) {
                return Err(io::Error::from_raw_os_error(28)); // ENOSPC
            }
            self.file.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail.load(Ordering::Relaxed) {
                return Err(io::Error::from_raw_os_error(28));
            }
            self.file.flush()
        }
    }

    impl WalSink for FaultyWriter {
        fn wal_sync(&self) -> io::Result<()> {
            self.file.sync_all()
        }
        fn wal_len(&self) -> io::Result<u64> {
            self.file.metadata().map(|m| m.len())
        }
    }

    fn op(id: &str) -> WalOp {
        WalOp::Upsert {
            app: "demo".into(),
            collection: "tasks".into(),
            id: id.into(),
            doc: Arc::new(serde_json::json!({ "id": id })),
        }
    }

    /// M3-Rueckstau: Nach fehlgeschlagenem Flush nimmt der Worker keine Ops
    /// mehr aus dem Kanal (der blockierende Send im Store staut ab), nach
    /// erfolgreicher Erholung werden alle gestauten Ops vollstaendig
    /// nachgeschrieben — es geht kein Record verloren.
    #[test]
    fn flush_failure_backpressures_instead_of_losing_records() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(MemoryStore::new());
        let cold = Arc::new(ColdTier::new());
        // Aktives Segment von Hand anlegen (Header wie im Produktionspfad,
        // damit das Replay am Ende die Records lesen kann) — der FaultyWriter
        // braucht das rohe File, open_wal_segment boxt dagegen schon.
        let active_path = wal::wal_file_path(dir.path(), 1);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active_path)
            .unwrap();
        let mut header = BufWriter::new(file);
        wal::write_file_header(&mut header, &wal::WAL_MAGIC).unwrap();
        header.flush().unwrap();
        let file = header.into_inner().unwrap();
        let start_offset = file.metadata().unwrap().len();
        cold.open_active(active_path, start_offset);

        // Kleiner Kanal (2), damit der Rueckstau im Test beobachtbar wird.
        let (tx, rx) = sync_channel::<WalOp>(2);
        let cfg = PersistenceConfig {
            data_dir: dir.path().to_path_buf(),
            snapshot_interval: Duration::ZERO,
            max_segment_bytes: 0,
        };
        let fail = Arc::new(AtomicBool::new(true));
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_store = Arc::clone(&store);
        let worker_cold = Arc::clone(&cold);
        let worker_fail = Arc::clone(&fail);
        let worker_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            worker_loop(
                worker_store,
                rx,
                cfg,
                BufWriter::with_capacity(
                    4096,
                    Box::new(FaultyWriter {
                        file,
                        fail: worker_fail,
                    }) as Box<dyn WalSink + Send>,
                ),
                start_offset,
                worker_cold,
                worker_shutdown,
            )
        });

        // Der Worker nimmt die ersten beiden Ops und scheitert am Flush.
        tx.send(op("a")).unwrap();
        tx.send(op("b")).unwrap();
        std::thread::sleep(4 * WAL_FLUSH_RETRY);

        // Rueckstau-Modus: a/b sind konsumiert (aber im Puffer), der Kanal
        // ist leer. c/d fuellen ihn wieder — und der Worker konsumiert
        // nichts mehr, der dritte Send scheitert mit try_send.
        tx.send(op("c")).unwrap();
        tx.send(op("d")).unwrap();
        std::thread::sleep(2 * WAL_FLUSH_RETRY);
        assert!(
            tx.try_send(op("e")).is_err(),
            "Worker darf im Rueckstau-Modus keine Ops aus dem Kanal nehmen"
        );

        // Platte frei: der Retry-Flush gelingt, die gestauten Ops werden
        // nachgeschrieben und der Kanal ist wieder aufnahmefaehig.
        fail.store(false, Ordering::Relaxed);
        std::thread::sleep(4 * WAL_FLUSH_RETRY);
        tx.try_send(op("f"))
            .expect("nach Erholung muss der Worker den Rueckstau abarbeiten");

        drop(tx);
        handle.join().unwrap();

        // Replay ueber Snapshot (0 Docs — der Store war im Test leer) und
        // WAL-Segmente: alle fuenf Ops muessen angekommen sein.
        let restored = MemoryStore::new();
        let (report, _) = crate::replay_data_dir_full(&restored, dir.path()).unwrap();
        assert_eq!(report.wal_records, 5);
        let mut ids: Vec<String> = restored
            .list(
                "demo",
                "tasks",
                crate::ListParams {
                    page: 1,
                    limit: 100,
                    filters: vec![],
                    ranges: Vec::new(),
                    sort: None,
                },
            )
            .items
            .iter()
            .map(|doc| doc["id"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["a", "b", "c", "d", "f"]);
    }
}
