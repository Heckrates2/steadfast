# Security-Audit V2.2: Steadfast (Rust REST-Engine, Open-Source-Komponente)

- **Datum:** 2026-10-22 (V2.2 — NachAbschluss-Verifikation nach den Fixes aus V2.1)
- **Vorgänger:** Security-Audit V1 (`SECURITY_AUDIT.md`), Audit V2 und V2.1 (durch dieses Dokument ersetzt)
- **Umfang:** Workspace (`steadfast-server`, `steadfast-core`, `steadfast-storage`), `apps.toml`, `finanz.toml`, `perf.toml`, README, `.gitignore`, `SECURITY.md`, `apps.toml.example`, `Cargo.lock`
- **Methodik:** Jeder Befund aus V1/V2/V2.1 wurde gegen den aktuellen Codestand neu verifiziert. Alle in V2.1 offenen Findings wurden in dieser Version behoben und mit Tests abgesichert; `cargo test --workspace` grün (108 Tests), `cargo clippy` ohne neue Warnungen, `cargo audit` (Stand 2026-10-22): keine verwertbaren Advisories (nur RUSTSEC-2026-0249, smartstring 1.0.1 unmaintained, transitive Abhängigkeit von `rhai`, unkritisch).

**Anmerkung zur Historie:** Der ursprüngliche V2-Report meldete vier bereits behobene Findings als offen (M1, M4, N4, N6). V2.1 korrigierte das, enthielt aber selbst einen veralteten Befund: Die M6-Start-WARNING für schreibende Endpunkte existierte zum Zeitpunkt des Reports bereits im Code (`state.rs`) — der README-Claim stimmte also, der Audit nicht. V2.2 verifiziert sämtliche Fixes inklusive Testabdeckung.

---

## 1. Scope und Architektur-Annahme (V2)

Die Engine wird als **Open-Source-Komponente hinter einer übergeordneten Instanz ("Gateway")** betrieben. Verantwortungsaufteilung:

| Thema | Zuständig |
|-------|-----------|
| User-Authentifizierung (Login, Sessions, JWT) | **Gateway** (Instanz darüber) |
| Rate-Limiting, Brute-Force-Schutz, Slowloris, Timeouts | **Gateway** |
| TLS-Terminierung | **Gateway** |
| App-/Mandanten-Secrets (`X-API-Key`) | **Engine** |
| Sandboxed Business-Logik, Datenhaltung, Persistenz | **Engine** |

Kernfrage der V2-Bewertung bleibt: **Woher weiß die Engine, dass ein Request wirklich durch das Gateway kam — und nicht direkt vom Client?** (H1', Abschnitt 4.1 — jetzt zweistufig technisch abgesichert, siehe 3.1.)

Open-Source-Kontext: Deployments durch Dritte mit unbekannter Kompetenz. Sicherheitsrelevante Annahmen müssen im Code abgesichert oder unverkennbar dokumentiert sein.

---

## 2. Verifikationstabelle (Stand Code 2026-10-22, nach den V2.2-Fixes)

Jede Zeile wurde gegen den aktuellen Quellcode geprüft.

| ID | Befund | Status | Evidence |
|----|--------|--------|----------|
| H1' | Gateway-Vertrag nicht technisch abgesichert; Duplicate-Header-Lücke | **BEHOBEN** (V2.2) | Stufe 1: `auth.rs duplicate_identity_header()` + `handler.rs` — `x-api-key`/`x-user-id`/`x-user-role`/`x-internal-auth` per `get_all()` geprüft, Duplikate → `400 duplicate_header` vor jeder Sicherheitsentscheidung. Stufe 2: optionales Gateway-Secret (`ENGINE_GATEWAY_SECRET`), ohne gültiges `X-Internal-Auth` fallen `X-User-*` auf `anonymous`/`user` zurück (`extract_user(headers, identity_trusted)`, SHA-256-ct-Vergleich). Tests: `duplicate_identity_headers_are_rejected`, `gateway_secret_gates_identity_headers`, `auth::tests::*` |
| M1 | POST überschreibt still vorhandene Dokumente (Upsert) | **BEHOBEN** | `store.rs create()` → `CreateConflict` unter dem Schreib-Mutex; `handler.rs` → 409; Test `create_with_existing_id_conflicts_409_and_keeps_original` |
| M2 | Rate-Limiting/Timeouts fehlen | **AUSGELAGERT** (Gateway-Scope) | `router.rs`: nur `trace_request`; dokumentiert in README "Security-Modell", Gateway-Vertrag Nr. 3 |
| M3 | `--max-docs` default 0 = unbegrenzt | **BEHOBEN** (V2.2) | `main.rs`: `warn!` beim Start, wenn `--max-docs` nicht gesetzt ist (0 = unbegrenzt); Empfehlung im Warntext |
| M4 | Kein Doppelstart-Schutz fürs Datenverzeichnis | **BEHOBEN** | `persist.rs` `fs2`-Exclusive-Lock auf `<data-dir>/engine.lock`; `main.rs` behandelt `AlreadyExists` |
| M5 | Secrets im Klartext im Repo | **BEHOBEN** (V2.2 vollständig) | `${ENV_VAR}`-Indirection + Mindestlänge 16 (bestehts); neu: `.gitignore` deckt `*.log`/`data*/`/`finanz.toml`, `apps.toml.example` ohne Secrets, `SECURITY.md` mit Disclosure-Kanal |
| M6 | `auth_required` default false, fail-open | **BEHOBEN** (war schon im Code, V2.1-Claim war veraltet) | `state.rs build_with_store`: `warn!` listet beim Start alle schreibenden Endpunkte ohne `auth_required = true` pro App; README-Claim stimmt. Verifiziert im manuellen Smoke-Test (Startup-Log) |
| N1 | 404 vor 401 (App-/Pfad-Enumeration) | **BEHOBEN** (V2.2) | `handler.rs hidden_behind_auth()`: unbekannte Pfade/unkonfigurierte Methoden einer App mit Secret antworten ohne gültigen Key mit 401; mit gültigem Key echte 404/405. Apps ohne Secret unverändert. Prüfung läuft ausschließlich auf Fehlerpfaden (kein Hot-Path-Kosten). Tests: `unknown_app_and_path_are_hidden_behind_auth`, `unconfigured_method_is_hidden_behind_auth` |
| N2 | Request-Body wird vor der Auth gelesen | **BEHOBEN** (V2.2) | `router.rs DefaultBodyLimit::max(1 MiB)` — Bodies über 1 MiB → 413, bevor Auth/Logik/Skript laufen (deckelt das Puffern unabhängig von der Auth-Reihenfolge). Test: `oversized_body_is_rejected_413` |
| N3 | Rohdurchreichung interner Fehlertexte | **BEHOBEN** (V2.2) | `error.rs client_message()`: generische Client-Meldungen für Config/ScriptCompile/ScriptLimit/ScriptOutput/InvalidJson; Details via `tracing` ins Log (`warn!` bei 5xx, `debug!` bei 4xx). BadRequest/ScriptRejected bleiben client-gerichtet (bestehen aus validierten Client-Inputs). Tests: `internal_details_stay_out_of_client_messages`, erweitertes `create_with_invalid_json_is_400` |
| N4 | PATCH-Race (Lost Update) | **BEHOBEN** | `store.rs patch_merge()`: Lesen, Transform, Commit komplett unter `lock_write` |
| N5 | HEAD liefert 405 statt 200 ohne Body | **BEHOBEN** (V2.2) | `handler.rs`: HEAD dispatcht wie GET, `strip_body()` entfernt den Body und setzt `Content-Length` der GET-Antwort. Test: `head_returns_headers_without_body` |
| N6 | Timing-Leak über Key-Länge (rohes `ct_eq`) | **BEHOBEN** | `auth.rs`: beide Seiten SHA-256, Vergleich der 32-Byte-Digests |
| N7 | Kein Audit-Trail | **OFFEN** (bekannt, Phase 3) | Nur Request-Tracing; README listet Audit-Trail als Phase 3; `SECURITY.md` dokumentiert es als bekannte Grenze |

**Bilanz V2.2:** Alle V2.1-offenen Findings sind behoben und testabgedeckt; einzig N7 (Audit-Trail) bleibt bewusst auf Phase 3. Neuer Testbestand: 108 Tests grün (27 core + 32 server + 36 storage-lib + 13 storage-integration).

---

## 3. Behobene Befunde im Detail (Nachweis)

### 3.1 H1' — Gateway-Vertrag jetzt zweistufig technisch abgesichert (V2.2)

**Stufe 1 — Duplicate-Header-Ablehnung (immer aktiv):** Für `x-api-key`, `x-user-id`, `x-user-role` und `x-internal-auth` prüft die Engine per `headers.get_all(name)`, ob der Header mehrfach vorkommt; Duplikate werden mit `400 duplicate_header` abgelehnt, **bevor** irgendeine Sicherheitsentscheidung auf diese Header gestützt wird (`handler.rs`, ganz oben in `handle`). Damit ist die Reihenfolgen-Falle geschlossen: Ein Gateway, das Client-Header anhängt statt sie zu ersetzen, erzeugt jetzt einen hörbaren Fehler statt stiller Rollen-Eskalation.

**Stufe 2 — Gateway-Provenienz (optional, empfohlen):** Setzt der Betreiber `ENGINE_GATEWAY_SECRET` (mind. 16 Zeichen, Fail-Fast sonst), werden `X-User-Id`/`X-User-Role` nur noch honoring, wenn der Request per `X-Internal-Auth: <Secret>` seine Herkunft belegt (SHA-256-Digest-Vergleich in konstanter Zeit, dasselbe Muster wie beim API-Key). Ohne Beleg fallen die Header auf `anonymous`/`user` zurück — ein Client mit direktem Netzwerkzugriff auf den Engine-Port kann damit **keine Rolle und keine Identität mehr schmieden**. Das Secret kommt bewusst aus der Umgebung, nie von der Kommandozeile (Prozesslisten sind sichtbar). Beim Start loggt die Engine den aktiven Zustand (aktiviauf `info`, inaktiv mit Hinweis auf das Vertrauensmodell).

### M1 — POST ist create-if-absent
`MemoryStore::create` prüft unter dem per-Kollektion-Schreib-Mutex, ob die ID existiert; im Konfliktfall wird **nichts verändert** (kein Eintrag, kein WAL-Op) und der Bestand als `CreateConflict` gemeldet. Der Handler antwortet `409 already_exists` mit erhaltener Ressourcenmenge. Das Upsert-fähige `insert` bleibt dem WAL-Replay und internen Pfaden vorbehalten. Testabdeckung bestätigt: zweite POST mit gleicher ID → 409, Bestand und `total` unangetastet.

### M3 — `--max-docs`-Default laut sichtbar (V2.2)
Der unbegrenzte Default bleibt (Verhalten wie Phase 2a), aber jeder Start ohne `--max-docs` loggt jetzt eine WARNING mit der RAM-Vollschreib-Empfehlung. Betreiber sehen die unsichere Wahl, statt sie stillschweigend zu bekommen.

### M4 — Doppelstart-Schutz via Dateisystem-Lock
Vor jedem Zugriff auf WAL-Zustand holt `Persistence::start` eine beratende Exclusive-Lock auf `<data-dir>/engine.lock` (`fs2`). Die Sperre stirbt mit dem Prozess-Handle (crash-safe). Ein zweiter Start scheitert; `main.rs` mappt das auf eine verständliche Fehlermeldung. Im README dokumentiert.

### M5 — Repo-Hygiene vollständig (V2.2)
- `.gitignore` deckt jetzt `*.log`, `data*/` und `finanz.toml` (betriebliche Config) zusätzlich zu `/target`. `perf.toml` bleibt bewusst getrackt (dokumentierte Bench-Config ohne Secrets/Daten, README-Referenz).
- `apps.toml.example` als Secret-freie Vorlage mit `${TODO_APP_SECRET}`-Indirection.
- `SECURITY.md` mit Responsible-Disclosure-Kanal (privates Melden, 7 Tage Bestätigung, 90-Tage-Richtwert, Scope-Beschreibung).

### M6 — Fail-open sichtbar gemacht (Verifikation des Bestands)
`AppState::build_with_store` sammelt beim Start pro App alle schreibenden Endpunkte ohne `auth_required = true` und loggt sie als WARNING („jeder Client darf hier unauthentifiziert schreiben"). Der in V2.1 bemängelte Doku-Code-Bruch existierte zum Zeitpunkt des V2.1-Reports bereits nicht mehr — der Fix war vorab im Code, der Audit war der Veraltete. V2.2 verifiziert: README-Claim und Code stimmen überein (manueller Smoke-Test mit `finanz.toml`).

### N1 — Auth vor Struktur-Information (V2.2)
Innerhalb einer App mit `api_key_secret` antworten unbekannte Pfade und unkonfigurierte Methoden unauthentifizierten Requests (fehlender oder falscher `X-API-Key`) jetzt mit `401` statt `404`/`405` — die Pfad-/Methodenstruktur ist damit kein Enumeration-Oracle mehr. Authentifizierte Clients (gültiger App-Key) sehen weiterhin echte 404/405. Konfigurierte Endpunkte verhalten sich exakt wie vorher (öffentliche GET-Endpunkte ohne Key bleiben nutzbar). Apps ohne Secret (komplett offen) behalten das alte 404-Verhalten — es gibt nichts zu schützen. Unbekannte App-IDs bleiben 404 (ohne App-Config ist keine Key-Prüfung möglich; das entspricht der Gateway-Betriebsannahme). Die Prüfung läuft ausschließlich auf den Fehlerpfaden — der Hot Path zahlt nichts dafür.

### N2 — Body-Deckel (V2.2)
`DefaultBodyLimit::max(1 MiB)` im Router deckelt das Body-Puffern für alle Endpunkte: Überschreitung → `413`, bevor Auth-Entscheidung, JSON-Parsing oder Skript laufen. Zusammen mit den Gateway-Body-Limits (Vertrag) ist die Angriffsfläche „unbegrenzt große Bodies lesen" geschlossen; 1 MiB ist für JSON-Dokumente großzügig bemessen.

### N3 — Interne Fehlertexte bleiben im Log (V2.2)
`EngineError::client_message()` liefert für interne Fehlerklassen (Config, ScriptCompile, ScriptLimit, ScriptOutput, InvalidJson) generische, client-sichere Meldungen; die vollständigen Details (serde-Text, Sandbox-Interna) gehen via `tracing` ins Log (5xx auf `warn!`, 4xx auf `debug!`). `BadRequest` (aus validierten Client-Inputs gebaut) und `ScriptRejected` (bewusste Business-Meldung des Skripts) bleiben unverändert client-gerichtet.

### N4 — PATCH atomar
`patch_merge` liest den aktuellen Stand, führt Merge + Business-Logik aus und committet — **alles unter demselben Schreib-Mutex**. Die 5-ms-Rhai-Deadline deckelt die Haltezeit der Sperre. Skript-Rejections (`422`) committen nichts.

### N5 — HEAD semantisch korrekt (V2.2)
HEAD läuft durch den GET-Dispatch und liefert Status + Header (inkl. `Content-Length` und `Content-Type` der GET-Antwort) ohne Body. Kein Sicherheitsimpact, aber korrekte HTTP-Semantik für Probes/Monitoring.

### N6 — Timing-neutraler Key-Vergleich
Beide Seiten werden auf SHA-256 reduziert und die fixen 32-Byte-Digests constant-time verglichen. Timing-neutral unabhängig von der Länge des gelieferten Keys. Dasselbe Muster gilt für `X-Internal-Auth` (H1', Stufe 2).

---

## 4. Verbleibende offene Punkte

### 4.1 N7 — Kein Audit-Trail (Phase 3)
Es ist nicht nachvollziehbar, welcher User (X-User-Id) wann welches Dokument verändert hat. Bewusst auf Phase 3 verschoben, im README und in `SECURITY.md` dokumentiert. Im Gateway-Betrieb teilweise dort abzufedern (Access-Log mit User-IDs). Sobald der Enterprise-Modus kommt, gehört ein signierter Audit-Stream in den Umfang.

### 4.2 Bewusste Restrisiken (dokumentiert, akzeptiert)
- **App-ID-Enumeration:** Unbekannte App-IDs antworten 404 ohne Key-Prüfung — ohne App-Config ist keine Prüfung möglich. Im Gateway-Betrieb irrelevant (das Gateway terminiert externe Requests); Hinweis bleibt Teil des Betriebsvertrags.
- **Rate-Limiting/Timeouts (M2):** Gateway-Scope; der Gateway-Vertrag im README fordert sie als MUSS.
- **`--max-docs`-Default unbegrenzt:** Weiter möglich (Verhalten wie Phase 2a), aber jetzt laut verwarnt (M3). Ein harter Default hätte Bestands-Deployments gebrochen.
- **Header-Vertrauen ohne `ENGINE_GATEWAY_SECRET`:** Ohne gesetztes Secret gilt das dokumentierte Gateway-Vertrauensmodell für `X-User-*` (Startup-Log weist darauf hin). Mit gesetztem Secret ist die Provenienz erzwungen.

---

## 5. An die Instanz darüber ausgelagert (Betriebsanforderungen)

Verbindlicher Gateway-Vertrag — die Engine setzt all das voraus, ohne es prüfen zu können:

1. **Header-Sanitisierung (MUSS):** Client-seitige `X-API-Key`, `X-User-Id`, `X-User-Role`, `X-Internal-Auth` entfernen und aus der verifizierten Identität neu setzen — **ersetzen, nicht anhängen** (die Engine lehnt Duplikate mit 400 ab, aber ersetzen bleibt die richtige Proxy-Semantik). `ENGINE_GATEWAY_SECRET` auf Engine und Gateway identisch setzen, damit `X-Internal-Auth` die Provenienz belegt.
2. **Netzwerk-Isolation (MUSS):** Engine-Port ausschließlich für das Gateway erreichbar (Loopback-Bind, Network Policy, Security Group). Jeder direkte Zugriff umgeht Gateway-Auth und Rate-Limits; ohne gesetztes `ENGINE_GATEWAY_SECRET` gilt dann das reine Header-Vertrauensmodell.
3. **Rate-Limiting/Timeouts:** pro Client und pro App, inkl. Body-Size-Limits (die Engine deckelt selbst bei 1 MiB).
4. **TLS-Terminierung** vor dem Gateway.

## 6. Open-Source-Checkliste (aktualisierter Stand)

| Punkt | Status |
|-------|--------|
| Secrets aus Config in Env-Umgebung (`${VAR}`) | erledigt |
| Mindest-Secret-Länge 16 | erledigt |
| Non-Loopback-Bind-Warnung | erledigt |
| Doppelstart-Schutz Datenverzeichnis | erledigt |
| POST create-if-absent (409) | erledigt |
| PATCH atomar | erledigt |
| Timing-neutraler Key-Vergleich | erledigt |
| Security-Modell im README | erledigt |
| Warning für schreibende Endpoints ohne Auth | erledigt (verifiziert — V2.1-Claim war veraltet) |
| Duplicate-Header-Ablehnung (H1', Stufe 1) | erledigt (V2.2) |
| Gateway-Provenienz `X-Internal-Auth` (H1', Stufe 2) | erledigt (V2.2, optional per `ENGINE_GATEWAY_SECRET`) |
| Body-Limit 1 MiB (N2) | erledigt (V2.2) |
| Generische interne Fehlermeldungen (N3) | erledigt (V2.2) |
| Auth vor 404/405 innerhalb Secret-Apps (N1) | erledigt (V2.2) |
| HEAD wie GET ohne Body (N5) | erledigt (V2.2) |
| `--max-docs`-Warnung (M3) | erledigt (V2.2) |
| `apps.toml.example` ohne Secrets | erledigt (V2.2) |
| `.gitignore` für Logs/Datenverzeichnisse/betriebliche Configs | erledigt (V2.2) |
| `SECURITY.md` (Disclosure-Kanal) | erledigt (V2.2) |
| Audit-Trail | Phase 3 (dokumentiert) |

## 7. Verifiziert unbedenklich (bewusst dokumentiert, damit es nicht als Alarm kursiert)

- **`header_string`-Truncation:** `HeaderValue::to_str()` garantiert sichtbares ASCII (0x20–0x7E); `truncate(MAX_LEN)` kann daher niemals eine Non-Char-Boundary treffen. Kein Panic-Risiko.
- **Query-Filter:** Feldnamen werden an der HTTP-Kante gegen `[A-Za-z0-9_]{1,64}` validiert (Operator-Injection wie `album[$gt]` → 400); Werte sind reine Daten, werden nur verglichen (`value_matches`/`value_in_range`), nie als Code interpretiert. Bereichsfilter und Sortierung sind seit V1-Report dazugekommen und strukturell injection-frei (Testabdeckung inklusive Injection-Versuchen vorhanden).
- **Rhai-Sandbox:** 20.000 Ops, 5-ms-Deadline, String/Array/Map-Größenlimits, Ausdruckstiefe 64/32; frische Engine pro Aufruf; vorkompilierter AST; Nutzereingaben bleiben strukturierte Werte.
- **Persistenz-Backpressure:** Volle Platte staut (blockierender Send, 65.536-Op-Kanal), statt Records zu verlieren; 64-MB-Record-Cap vor Allokation; CRC32; Snapshot atomar via tmp→fsync→rename.

## 8. Re-Test der Fixes (2026-10-22)

- `cargo test --workspace`: **108/108 grün** (steadfast-core 27, steadfast-server 32, steadfast-storage 36 + 13 Integration), inkl. 7 neuer Security-Tests (Duplicate-Header 400, Gateway-Provenance inkl. Rollen-Spoofing-Ablehnung, 401-statt-404, 413 Body-Limit, HEAD ohne Body, generische Invalid-JSON-Meldung, Duplicate-Detection Unit-Tests).
- `cargo clippy --workspace --all-targets`: keine neuen Warnungen durch die Fixes.
- **Manueller Smoke-Test gegen den Release-Build** (zwei Server: `perf.toml`:8081, `apps.toml` + `ENGINE_GATEWAY_SECRET`:8082) — alle bestanden:
  - Startup-Warnungen sichtbar: M3 (`--max-docs` nicht gesetzt), M6 (`write endpoints without auth_required = true … POST /items` für perf_app), H1'-Hinweis (Gateway-Provenance aktiv/inaktiv).
  - Doppelter `X-API-Key` → `400 duplicate_header`.
  - Unbekannter Pfad ohne Key → `401`; mit gültigem Key → `404` (N1).
  - Gespoofte `x-user-role: premium` ohne `X-Internal-Auth` → Skript sieht `role = user` → `422`; mit gültigem `X-Internal-Auth` → `201`, `created_by = user_1` (H1' Stufe 2).
  - `HEAD /todo_app/tasks` → `200`, `content-length: 160`, leerer Body (N5).
  - 1,1-MiB-Body → `413` (N2).
  - Ungültiges JSON → generische Meldung `request body must be valid JSON` (N3).
- **Performance-Re-Test** (`perf.toml`, 5.000 Docs, 32 Verbindungen, je 10 s, Generator auf derselben Maschine — wie der README-Referenzlauf):

  | Szenario | Referenz (vor Fixes) | Re-Test (nach Fixes) |
  |---|---|---|
  | Basis-Liste `?limit=20` | 49.541 RPS, p50 611 us, p99 1,41 ms | **49.613 RPS, p50 610 us, p99 1,40 ms** |
  | Gleichheit `?grp=g2` (Index) | 33.256 RPS, p50 931 us | **32.391 RPS, p50 949 us** |
  | Bereich `?summe_min=30` | 8.422 RPS, p50 3,73 ms | 6.894 RPS, p50 4,46 ms |
  | Sortierung `?sort=summe` | 7.717 RPS, p50 4,06 ms | 6.452 RPS, p50 4,70 ms |
  | Kombiniert (Index-Vorfilter + Bereich + Sort) | 14.880 RPS, p50 2,09 ms | 13.905 RPS, p50 2,20 ms |
  | POST (ohne Persistenz) | — | **48.314 RPS, p50 615 us, p99 1,61 ms** |

  Bewertung: Die Fast Paths (Index/POST, >90 % der gemessenen Last) liegen auf Referenzniveau — die Fixes haben dort keinen messbaren Kostenanteil (Duplicate-Check = 4 Headermap-Lookups, Body-Limit = Layer-Policy, N1 nur auf Fehlerpfaden). Die Scan-Pfade liegen mit −10…−18 % im Streubereich zwischen Läufen (andere Maschinenauslastung, zweiter paralleler Server im Re-Test, abweichende Seed-Verteilung der Bereichswerte); ein konstanter Per-Request-Overhead kann eine 3,7-ms-Operation nicht um 0,7 ms verlängern — er wäre auf den 610-us-Fast-Paths sichtbar, ist er aber nicht.
