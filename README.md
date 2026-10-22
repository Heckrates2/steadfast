# Steadfast

**Steadfast** ist eine datengetriebene, hochverfügbare REST-Engine in Rust: vollwertige,
isolierte CRUD-APIs fuer beliebig viele Applikationen — rein ueber eine
Konfigurationsdatei (`apps.toml`), ohne dass man auch nur eine Zeile Endpunkt-Code
schreiben muss.

## Kernidee

* **Catch-All-Routing:** Axum faengt alle Requests ueber `/{app_id}/{*path}` ab.
* **Config-Lookup im RAM:** Beim Start wird `apps.toml` geladen, validiert und in eine
  fluette Route-Tabellen uebersetzt (O(1)-Lookup pro Request).
* **Vorkompilierte Business-Logik:** Rhai-Skripte werden beim Start einmalig in einen
  `rhai::AST` kompiliert — kein Text-Parsing zur Laufzeit. Sandboxed mit harten Limits
  (max. 20.000 Operationen, 5 ms Deadline, Groessenlimits).
* **Schemaloses Speichern:** JSON-Dokumente landen ohne Migrationen im In-Memory-Store
  (`DashMap`), doppelt indiziert — `by_id` fuer O(1)-Item-Zugriffe, `by_seq` fuer
  listenreihenfolge; Dokumente werden als `Arc<Value>` geteilt, sodass Lese-Pfade
  ohne Clone/Kopie arbeiten.
* **Persistenz ab Werk:** Asynchroner WAL-Worker schreibt jede Mutation in ein
  CRC-gesichertes Log (`--data-dir`), Rotation (Zeit-Intervall oder Segmentgroesse)
  erzeugt per Snapshot einen kompakten Stand, der Start repliziert Snapshot + Log
  in den RAM (siehe "Persistenz").
* **Security-Haertung:** API-Key-Pruefung als SHA-256-Digest-Vergleich in konstanter
  Zeit (`subtle`, ohne Laengen-Leak), POST strikt create-if-absent (`409` statt stiller
  Upsert), PATCH atomar unter dem Schreib-Mutex, Secrets mit Mindestlaenge und
  `${ENV_VAR}`-Indirection, Advisory-Lock gegen Doppelstart auf demselben `--data-dir`,
  Identitaets-Header (`X-API-Key`/`X-User-*`) nur einfach erlaubt (Duplikate -> 400),
  optionale Gateway-Provenienzpruefung per `ENGINE_GATEWAY_SECRET`, Body-Limit 1 MiB,
  Gleichheits-Filter rein In-Memory (keine Query-Sprache -> strukturell keine Injection),
  DoS-Grenzen fuer Query-Parameter (max. 16 Filter, 256 Bytes pro Key/Value, Limit-Cap 100).

## Architektur (Cargo Workspace)

| Crate | Zweck | Phase |
|---|---|---|
| `crates/steadfast-core` | `apps.toml`-Parsing, Validierung, Rhai-AST-Precompile + Sandbox (HTTP-frei) | MVP |
| `crates/steadfast-storage` | In-Memory-Store (`DashMap`, Dual-Index, `Arc<Value>`) + WAL/Snapshot-Persistenz + Tiering/Sekundaerindizes | MVP + 2a + 2b |
| `crates/steadfast-server` | Monolith-Binary: Axum-Routing, Auth, Hot Path, Persistenz-Anbindung | MVP + 2a + 2b |
| `engine-gateway` / `engine-worker` / `engine-proto` | Enterprise-Modus (gRPC via `tonic`, Redis/Dragonfly) | Phase 3 |

## Quickstart (Monolith-Modus)

```bash
cargo run --release
# Engine lauscht auf http://127.0.0.1:8080
```

Beispiel-Requests gegen die mitgelieferte `todo_app`:

```bash
# Task anlegen (auth_required): Skript setzt created_by/status, prueft Premium-Regel
curl -X POST http://127.0.0.1:8080/todo_app/tasks ^
  -H "x-api-key: super_geheimes_todo_salt_123" ^
  -H "x-user-id: user_1" -H "x-user-role: premium" ^
  -H "content-type: application/json" ^
  -d "{\"title\": \"Erste Aufgabe\", \"is_priority\": true}"

# Offene Liste (offen, mit Paging + Gleichheits-Filter)
curl "http://127.0.0.1:8080/todo_app/tasks?status=offen&limit=10"

# Einzelnes Item lesen / ersetzen / patchen / loeschen
curl http://127.0.0.1:8080/todo_app/tasks/<id>
curl -X PUT http://127.0.0.1:8080/todo_app/tasks/<id> -H "x-api-key: super_geheimes_todo_salt_123" ^
  -H "content-type: application/json" -d "{\"title\": \"Neu\", \"status\": \"offen\"}"
curl -X PATCH http://127.0.0.1:8080/todo_app/tasks/<id> -H "x-api-key: super_geheimes_todo_salt_123" ^
  -H "content-type: application/json" -d "{\"status\": \"erledigt\"}"
curl -X DELETE http://127.0.0.1:8080/todo_app/tasks/<id> -H "x-api-key: super_geheimes_todo_salt_123"

# Health
curl http://127.0.0.1:8080/health
```

Konfigurationspfad und Bind-Adresse sind als Argumente ueberschreibbar:
`cargo run --release -- pfad/apps.toml 0.0.0.0:8080`.

Mit `--data-dir` wird aus dem fluechtigen Speicher eine persistente Engine, die
Neustarts und Abstuerze ueberlebt:

```bash
cargo run --release -- --data-dir data --snapshot-interval 60
# Optional: Segment-Obergrenze in MiB (Default 256, 0 = unbegrenzt) — --wal-max-segment-mb 64
# Docs anlegen, Server hart killen, neu starten — alles ist wieder da.
```

## `apps.toml`-Referenz (MVP)

| Feld | Ebene | Bedeutung |
|---|---|---|
| `api_key_secret` | App | Secret fuer `X-API-Key`-Pruefung (Pflicht, sobald ein Endpunkt `auth_required = true` hat). Mindestlaenge 16 Zeichen. `${ENV_VAR}`-Indirection: `api_key_secret = "\${TODO_APP_SECRET}"` liest den Wert beim Start aus der Umgebungsvariable (Fail-Fast bei fehlender/leerer Variable) statt im Klartext in der Datei zu liegen |
| `endpoints.<name>.path` | Endpunkt | Kollektions-Pfad, genau ein Segment (`/tasks`) |
| `endpoints.<name>.method` | Endpunkt | `GET`, `POST`, `PUT`, `PATCH` oder `DELETE` |
| `endpoints.<name>.auth_required` | Endpunkt | Default `false`; `true` -> 401 ohne gueltigen `X-API-Key` |
| `endpoints.<name>.paging_default` | Endpunkt | Default-Seitengroesse fuer GET-Listen (1..=100, Default 20) |
| `endpoints.<name>.filter_fields` | Endpunkt | Optionale Allowlist filterbarer Felder; gilt auch fuer Bereichsfilter (Basisname) und `sort`. Ohne sie sind alle Top-Level-Felder filterbar/sortierbar |
| `endpoints.<name>.business_logic` | Endpunkt | Rhai-Skript mit Hook `fn on_request(payload, user) -> payload` (laeuft bei POST/PUT/PATCH vor dem Speichern; `throw` -> HTTP 422) |

### CRUD-Semantik

* `GET /<app>/<coll>` — Liste mit Paging, Gleichheits-/Bereichs-Filtern und
  Sortierung (Details unten).
* `GET /<app>/<coll>/{id}` — Item oder 404.
* `POST /<app>/<coll>` — Skript -> Engine setzt fehlende `id` (UUID v4) -> `201` + `Location`.
  Existiert die `id` bereits (z. B. vom Skript gesetzt), liefert POST `409 already_exists` —
  POST ist strikt create-if-absent, der Bestand bleibt unangetastet.
* `PUT /<app>/<coll>/{id}` — Volles Ersetzen (`id` wird erzwungen), 404 wenn fehlend.
* `PATCH /<app>/<coll>/{id}` — Shallow-Merge, danach Skript auf dem Ergebnis; Merge,
  Skript und Commit laufen atomar unter dem Schreib-Mutex der Kollektion (nebenlaeufige
  PATCHes auf dasselbe Dokument ueberschreiben sich nicht gegenseitig; ein
  Skript-`throw` bricht ohne jede Aenderung ab).
* `DELETE /<app>/<coll>/{id}` — `204`.

User-Metadaten fuer die Skripte kommen im MVP aus `X-User-Id` (Default `anonymous`) und
`X-User-Role` (Default `user`) — im Enterprise-Modus setzt sie der Gateway aus verifizierten
JWT-Claims. Fehlerbild: 404 unbekannte App/Item, 401 Auth-Fehlschlag (auch bei unbekannten
Pfaden/Methoden einer App mit `api_key_secret`, solange kein gueltiger `X-API-Key` vorliegt —
kein Enumeration-Oracle), 400 ungueltiges JSON/Query oder mehrfach gesendete
Identitaets-Header, 405 (+ `Allow`) bei nicht konfigurierter Methode, 413 Body ueber 1 MiB,
422 Skript-`throw`, 500 Sandbox-Limit ueberschritten (generische Client-Meldung, Detail im
Log). `HEAD` wird auf GET-Endpunkten wie GET behandelt (gleiche Header, kein Body).

### Listen-Abfragen: Filter, Bereiche, Sortierung

Reservierte Query-Parameter sind `page`, `limit`, `sort` und `order`. Alles andere
ist ein Filter.

* **Gleichheit:** `?status=offen` — exakter typgleicher Vergleich gegen Top-Level-Felder.
* **Bereiche:** `?feld_min=…` / `?feld_max=…` (inklusive), `?feld_gt=…` / `?feld_lt=…`
  (exklusiv). Kombinierbar: `?summe_min=10&summe_max=50`.
  Die Semantik ist typstreng und am Bound orientiert:
  - Parse der Bound als endliche Zahl -> numerischer Bereich; verglichen werden nur
    Dokumente, deren Feld eine Zahl ist. Grenzen jenseits von 2^53 verlieren f64-Genauigkeit;
    nicht parsebare/nicht endliche Bounds wie `NaN` oder `1e400` matchen nichts.
  - Jede andere Bound -> byte-lexikografischer String-Bereich; verglichen werden nur
    String-Dokumente (ISO-8601-Daten wie `2024-03-01` sortieren damit korrekt).
  - Passen Feld- und Bound-Typ nicht zusammen (`?n_min=5` gegen `"sieben"`), matcht das
    Dokument nie. Bool/Objekt/Array/Null/fehlend nehmen nie an Bereichen teil.
  - Ein Suffix wird nur abgeschnitten, wenn der Basisname ein gueltiger Feldname ist —
    ein Feld, das wirklich `x_min` heisst, bleibt per `x_min=…` als Gleichheitsfilter
    addressierbar.
* **Sortierung:** `?sort=<feld>` mit `order=asc|desc` (Default asc; `order` ohne `sort`
  ist ein 400). Die Gesamtordnung ist typstabil: fehlend/null/Objekt/Array < bool <
  Zahl (`total_cmp`, NaN inklusive) < String (byte-lexikografisch). Gleichstand bricht
  nach Einfuege-Sequenz aufsteigend — Paging bleibt dadurch in beide Richtungen
  deterministisch (jedes Dokument genau einmal).
* **Grenzen:** max. 16 Filter-/Bereichs-Parameter, Values/Bounds max. 256 Bytes,
  Feldnamen max. 64 Bytes. `limit` bleibt auf 100 gecappt.

**Injection-Garantie per URL:** Feldnamen muessen `[A-Za-z0-9_]{1,64}` entsprechen —
alles andere (Leerzeichen, Klammern, Quotes, Operator-Artefakte wie `album[$gt]` oder
`al'bum`) wird an der HTTP-Kante mit 400 abgelehnt, statt stillschweigend nichts zu
matchen. Werte und Bounds sind und bleiben reine Daten: Sie werden ausschliesslich
verglichen (`value_matches`/`value_in_range`), nie als Ausdruck geparst oder in eine
Abfrage konkateniert — es gibt schlicht keine Abfragesprache, in die man injizieren
koennte. Ist eine `filter_fields`-Allowlist gesetzt, gelten Filter (Basisnamen bei
Bereichen) und `sort`-Feld nur innerhalb der Allowlist (sonst 400).

**Performance-Hinweis:** Gleichheits-Filter auf deklarierten Feldern laufen ueber
Sekundaerindizes. Bereichsfilter und Sortierung werten die Treffermenge im Speicher
aus (Index-Vorfilter bei gemischten Abfragen, sonst Snapshot-Scan) — bei sehr grossen
Kollektionen lohnt die Beschraenkung ueber `filter_fields` plus Paging. Gepflegte
Range-/Sortier-Indizes sind ein Phase-3-Kandidat.

## Persistenz (Phase 2a)

Ohne `--data-dir` bleibt die Engine rein fluechtig. Mit `--data-dir <VERZEICHNIS>`
laeuft sie mit Write-Ahead-Log und Snapshots:

* **Datenlayout:** `<dir>/wal-<epoch_ms>.log` (segmentierte Logs) und
  `<dir>/snapshot.bin`. Das Format ist ein handgeschriebenes Binaerformat: 6-Byte-Header
  (`RWAL`/`RSNP` + Version), danach Records aus `Laenge | CRC32 | Payload`. Reihenfolge
  beim Replay: Snapshot zuerst, dann alle Log-Segmente nach Epoch aufsteigend.
* **Durability-Modell (bewusster Tradeoff):** Mutationen landen sofort im RAM und werden
  innerhalb des Schreib-Mutex in einen begrenzten Kanal (65.536 Ops, Rueckstau statt
  Verlust) eingereiht; ein eigener `wal-worker`-Thread schreibt sie gebuffert auf SSD.
  `fsync` passiert bei Rotation und sauberem Herunterfahren — ein Absturz kann die
  letzten Records kosten, der Hot Path bleibt aber frei von synchroner Disk-I/O.
  Scheitert das Schreiben dauerhaft (z. B. volle Platte), konsumiert der Worker keine
  Ops mehr, sondern retryt alle 200 ms: Der Kanal fuellt sich, Schreib-Requests stocken
  (Rueckstau bis zur Platte statt stiller Datenverlust), Lese-Requests bleiben bedienbar.
* **Rotation/Compaction:** Alle `--snapshot-interval <SEKUNDEN>` (Default 60) oder
  sobald das aktive Segment `--wal-max-segment-mb <MIB>` (Default 256, `0` = unbegrenzt)
  erreicht, schreibt der Worker den aktuellen Stand atomar als Snapshot
  (`snapshot.tmp` -> `fsync` -> `rename`) und loescht danach alle aelteren Log-Segmente.
  Clean-Shutdown macht dasselbe final. Alte Segmente werden nur nach erfolgreichem
  Snapshot geloescht — wachsende Logs ohne funktionierenden Snapshot sind damit
  strukturell ausgeschlossen.
* **Crash-Toleranz beim Replay:** Abgerissene Dateienden (torn tail) gelten als sauberes
  Ende — der Prefix bleibt voll wertbar. CRC-Fehler mitten in einer Datei stoppen genau
  diese Datei (Protokoll im Startup-Log via `stopped_early`); halb geschriebene Header
  (< 6 Bytes) werden uebersprungen. Kaputte Snapshots sind ein harter Fehler (sie werden
  nur atomar benannt angelegt).
* **Doppelstart-Schutz:** Die Engine belegt das Datenverzeichnis beim Start mit einer
  beratenden Dateisystem-Sperre (`<dir>/engine.lock`). Eine zweite Instanz auf
  demselben Verzeichnis scheitert hart mit klarer Meldung, bevor sie WAL oder
  Snapshot anfassen kann (ein Doppelstart wuerde beide korrompieren).
* **Idempotenz:** Alle Mutationen sind vollstaendige Upserts/Deletes — Snapshot und WAL
  duerfen sich beliebig ueberlappen, das Replay landet immer im korrekten Endzustand.
* **Nachweis:** 21.800+ RPS POST-Last (32 Verbindungen) mit und ohne aktivierter
  Persistenz messbar gleich schnell (p99 ~2,8 ms); 218.776 Records/10 s landeten dabei
  als 44 MB Log auf SSD.

## Tiering & Sekundaerindizes (Phase 2b)

Zwei Erweiterungen fuer Datenmengen jenseits des RAM: Gleichheits-Filter ueber
Sekundaerindizes statt linearem Scan, und eine RAM-Obergrenze pro Kollektion mit
automatischem Nachladen kalter Dokumente aus der Persistenz.

### Sekundaerindizes fuer `filter_fields`

* Beim Start deklariert der Server fuer jeden Kollektions-Pfad die Union der
  `filter_fields` aller GET-Endpunkte als Sekundaerindizes
  (`Feld -> Wert -> BTreeMap<seq, id>`); insert/replace/delete pflegen sie inkrementell.
* Gleichheits-Filter auf deklarierten Feldern greifen direkt ueber den Index — exaktes
  `total`, seq-aufsteigende Reihenfolge, stabiles Paging. Filter auf nicht deklarierten
  Feldern fallen automatisch auf den linearen Scan zurueck.
* `filter_fields` ist damit zweifach: Security-Allowlist **und** Performance-Schalter.
  Die Indizes halten nur `(seq, id)`-Paare und sind von der Eviction unberuehrt.

### Tiering (`--max-docs N`)

* `--max-docs N` begrenzt je Kollektion die Zahl der heissen (im RAM liegenden)
  Dokumente. Default 0 = unbegrenzt (Verhalten wie Phase 2a).
* Direkt nach jeder erfolgreichen WAL-Rotation — dem einzigen garantiert sicheren
  Punkt, da jede residente Dokumentversion dort im Snapshot oder im geschlossenen
  Segment liegt — verstoesst die Engine die aeltesten Dokumente (LRU-Naeherung ueber
  Access-Ticks) bis auf ~95 % der Obergrenze aus dem RAM. Ohne Schreibverkehr gibt es
  keine Rotation und damit keine Eviction.
* Kalte Dokumente bleiben in `by_seq`/`by_id` und allen Sekundaerindizes sichtbar —
  `total` und Paging bleiben exakt stabil.
* Bei Zugriff (Item-GET oder Listen-Item) laedt Fetch-on-Miss das Dokument aus dem
  Kalt-Tier nach, in dieser Reihenfolge: aktives WAL-Segment -> geschlossene Segmente
  (juengste zuerst) -> Snapshot. Der erste Treffer entscheidet: Upsert = Dokument,
  Delete = terminiert — ein Delete wird nie von einem aelteren Snapshot wiederbelebt.
  Nachgeladene Dokumente werden sofort wieder heiss (Promote-on-Read).
* Korrektheitskette: `dump_collections` schreibt auch kalte Dokumente in den Snapshot,
  bevor Segmente entfernt werden; ein Seq-Watermark schuetzt Dokumente, die zwischen
  Snapshot und Eviction geschrieben wurden.

### Benchmark

```bash
cargo run --release -p steadfast-storage --example bench_tiering
# konfigurierbar per Umgebungsvariable: BENCH_DOCS, BENCH_HOT_CAP, BENCH_QUERIES
```

Gemessen (200.000 Docs, Hot-Cap 50.000, Release):

| Messung | Wert |
|---|---|
| Insert-Durchsatz | ~495.000/s (p50 1 us, p99 6 us) |
| Gefilterte Liste, Scan ohne Index | 66 ms p50 |
| Gefilterte Liste mit Sekundaerindex | 21 ms p50 (3,2x schneller) |
| Eviction bei Hot-Cap 50.000/200.000 | 152.500 Docs kalt gestellt |
| GET heiss | p50 <1 us, p99 1 us |
| GET kalt (Fetch-on-Miss + Promote, Disk) | p50 102 us, p99 158 us |
| Indizierte Liste mit kalten Payloads | 21 ms p50 (unveraendert, total exakt) |

HTTP-Smoke-Test (`--max-docs 100`, 301 Docs, 32 Verbindungen, 8 s Last): Item-GET
50.755 RPS (p50 592 us), gefilterte Liste 35.728 RPS (p50 832 us) — jeweils 0
Verbindungsfehler, 100 % 2xx. Nach hartem Kill (`taskkill /F`, Crash-Simulation)
restaurierte der Neustart alle 301 Dokumente; der aelteste Task war zu dem Zeitpunkt
evicted und wurde per Fetch-on-Miss korrekt aus Snapshot/WAL nachgeladen.

Listen-Pfade mit Bereichsfilter/Sortierung (Release, 5.000 Docs im RAM, 32
Verbindungen, je 10 s, Generator auf derselben Maschine — siehe `perf.toml`):

| Szenario | RPS | p50 | p99 |
|---|---|---|---|
| Basis-Liste `?limit=20` (Fast Path) | 49.541 | 611 us | 1,41 ms |
| Gleichheit `?grp=g2` (Sekundaerindex, Fast Path) | 33.256 | 931 us | 1,84 ms |
| Bereich `?summe_min=30` (Scan 5.000 Docs) | 8.422 | 3,73 ms | 6,76 ms |
| Sortierung `?sort=summe` (Scan + Sort) | 7.717 | 4,06 ms | 7,51 ms |
| Kombiniert `?grp=g2&summe_max=45&sort=summe&order=desc` (Index-Vorfilter auf 1.000) | 14.880 | 2,09 ms | 4,01 ms |

Bereichsfilter/Sortierung werten die Treffermenge im Speicher aus und liegen damit
erwartbar unter den Index-Fast-Paths; ein Gleichheitsfilter auf deklariertem Feld
vorab (Index-Vorfilter) halbiert die Arbeit messbar.

**Re-Test nach den Security-Fixes (Audit V2.2, gleiche Methodik/Maschine):** Fast
Paths unverändert — Basis-Liste 49.613 RPS (p50 610 us, p99 1,40 ms), Gleichheit
32.391 RPS (p50 949 us), POST ohne Persistenz 48.314 RPS (p99 1,61 ms); die
Scan-Pfade (Bereich 6.894 RPS, Sortierung 6.452 RPS, kombiniert 13.905 RPS) lagen
im Streubereich zwischen Läufen. Die neuen Checks sind dafür zu billig, um sich
messbar zu machen: Duplicate-Header-Prüfung = 4 Headermap-Lookups, Body-Limit =
Layer-Policy, N1-Prüfung läuft nur auf Fehlerpfaden, Gateway-Provenance = 1 SHA-256
pro Request (nur bei gesetztem `ENGINE_GATEWAY_SECRET`).

## Security-Modell

Bewusstes Threat-Modell des Monolith-Modus — was die Engine schuetzt und was in der
Verantwortung des Betreibers liegt.

**Abgedeckt:**

* **API-Key-Vergleich:** SHA-256-Digests werden in konstanter Zeit verglichen (`subtle`)
  — keine Timing-Leakage, egal wie lang der gelieferte Key ist. Secrets muessen mind.
  16 Zeichen lang sein und koennen per `${ENV_VAR}` aus der Umgebung geladen werden
  (Fail-Fast, wenn die Variable beim Start fehlt oder leer ist).
* **Keine doppelten Identitaets-Header:** `X-API-Key`, `X-User-Id`, `X-User-Role` und
  `X-Internal-Auth` duerfen nur einfach vorkommen — mehrfach gesendete Header werden
  mit `400 duplicate_header` abgelehnt, bevor irgendeine Sicherheitsentscheidung auf
  sie gestuetzt wird (sonst wuerde bei einem Gateway mit Anhaeng-Semantik der
  gefaelschte Client-Wert gewinnen).
* **Optionale Gateway-Provenienz (`ENGINE_GATEWAY_SECRET`):** Ist diese Umgebungs-
  variable gesetzt (mind. 16 Zeichen), werden `X-User-Id`/`X-User-Role` nur noch
  honoring, wenn der Request per `X-Internal-Auth: <Secret>` seine Herkunft vom
  Gateway belegt — andernfalls fallen sie auf `anonymous`/`user` zurueck. Ein
  Direktzugriff auf den Engine-Port kann damit keine Rolle schmieden, selbst wenn
  der Angreifer die Header-Setzung beherrscht.
* **POST ist create-if-absent:** Eine bereits vorhandene ID liefert `409` — es gibt
  keinen stillen Upsert, der fremde Dokumente ueberschreibt.
* **PATCH ist atomar:** Merge, Skript und Commit laufen unter dem Schreib-Mutex der
  Kollektion; nebenlaeufige Mutationen desselben Dokuments gehen nicht verloren.
* **Rhai-Sandbox** mit harten Limits (20.000 Ops, 5 ms Deadline, Groessenlimits);
  Payload und User sind immer strukturierte Daten, nie Code.
* **Keine Abfragesprache:** Filter, Bereiche und Sortierung sind reine Vergleiche im
  Speicher. Zusätzlich validiert die Engine alle Query-Feldnamen an der HTTP-Kante
  (`[A-Za-z0-9_]{1,64}`) und liefert 400 fuer alles, was kein Feldname sein kann —
  Injection per URL ist strukturell ausgeschlossen, nicht nur wirkungslos.
* **Body-Limit 1 MiB:** Bodies ueber 1 MiB sterben als `413`, bevor Logik oder
  Skript laufen — auch unautorisierte Requests koennen den Puffer nicht aufblaehen.
* **Kein Enumeration-Oracle:** Fuer Apps mit `api_key_secret` antworten unbekannte
  Pfade und unkonfigurierte Methoden unauthentifizierten Requests mit `401`, nicht
  mit `404`/`405` — die Pfadstruktur sieht erst, wer den App-Key hat.
* **Generische interne Fehlermeldungen:** Interne Details (serde-Fehlertexte,
  Sandbox-Interna, Konfigurationspfade) gehen ins Log, nie in den Client-Body.
* **Sichtbare Fehlkonfiguration:** Schreibende Endpoints ohne `auth_required = true`,
  Binds an Nicht-Loopback-Adressen und ein nicht gesetztes `--max-docs` erzeugen
  beim Start eine WARNING im Log.

**Betreiber-Verantwortung (Gateway-Vertrag):**

1. **Header-Sanitisierung (MUSS):** Das Gateway MUSS client-seitige `X-API-Key`,
   `X-User-Id`, `X-User-Role` und `X-Internal-Auth` **entfernen und aus der
   verifizierten Identita neu setzen — ersetzen, niemals anhaengen**. (Die Engine
   lehnt Duplikate zwar ab, aber ersetzen ist trotzdem die richtige Proxy-Semantik.)
   Das dafuer noetige `X-Internal-Auth`-Secret teilt sich das Gateway mit der Engine
   per `ENGINE_GATEWAY_SECRET`.
2. **Netzwerk-Isolation (MUSS):** Der Engine-Port MUSS ausschliesslich fuer das
   Gateway erreichbar sein (Loopback-Bind, Network Policy, Security Group). Jeder
   direkte Zugriff umgeht Gateway-Auth und Rate-Limits; ohne gesetztes
   `ENGINE_GATEWAY_SECRET` gilt dann das reine Header-Vertrauensmodell.
3. **Rate-Limits/Request-Timeouts** pro Client und App am Gateway ergaenzen, wenn
   die Engine (per Gateway) fuer Externe erreichbar ist; inkl. eigener Body-Size-
   Limits (die Engine deckelt selbst bei 1 MiB).
4. **TLS-Terminierung** vor dem Gateway.
5. WAL/Snapshot schuetzen per CRC32 vor Korruption durch Abstuerze, nicht vor
   gezieltem Manipulieren der Dateien — Datentraeger-Verschluesselung und Backups
   wie ueblich betreiben. Es gibt keinen Audit-Trail (Phase 3).

## Roadmap

1. **Phase 2a — Persistenz (fertig):** WAL-Format + Replay, asynchroner wal-worker,
   Snapshot-Rotation, `--data-dir`/`--snapshot-interval`, Crash-Test-Suite.
2. **Phase 2b — Tiering & Indizes (fertig):** Sekundaerindizes fuer `filter_fields`
   (Union je Kollektions-Pfad, inkrementell gepflegt, exaktes `total`), RAM-Obergrenze
   pro Kollektion via `--max-docs`, LRU-Eviction nach WAL-Rotation, Fetch-on-Miss +
   Promote-on-Read aus WAL-Segmenten/Snapshot, `bench_tiering`-Example.
3. **Phase 3 — Enterprise-Modus:** `engine-proto` (tonic/gRPC-Vertraege), stateless
   `engine-gateway`, `engine-worker`, verteilter In-Memory-Layer via Redis/Dragonfly
   (RedisJSON/JSONPath) — dort auch Rate-Limiting/Request-Timeouts, Audit-Trail und
   HMAC-gesicherte Persistenz-Segmente. Security-Vermerk: JSONPath/Query-Strings dort
   nie per Konkatenation mit Nutzereingaben bauen — Feldnamen strikt validieren oder
   Filter im Worker im Speicher ausfuehren.
