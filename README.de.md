# Steadfast

[English](README.md) · **Deutsch**

**Die Always-on-REST-Engine in Rust. Deine API ist eine TOML-Datei.**

[![CI](https://github.com/Heckrates2/steadfast/actions/workflows/ci.yml/badge.svg)](https://github.com/Heckrates2/steadfast/actions/workflows/ci.yml)
[![Lizenz: MIT oder Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#lizenz)

Steadfast macht aus einer einzigen Konfigurationsdatei voll isolierte, gehärtete CRUD-REST-APIs —
kein Endpunkt-Code, keine Migrationen, kein Boilerplate. Wenn PocketBase ein Geschwister hätte, das
eine reine *Engine* wäre (kein Admin-UI, keine eingebaute Benutzerverwaltung — das gehört in dein
Gateway), entworfen in-memory-first mit WAL-Persistenz und sandboxed Scripting — dann sähe es so aus.

```bash
cargo install --git https://github.com/Heckrates2/steadfast --locked
steadfast apps.toml 127.0.0.1:8080   # deine API läuft
```

## Benchmarks

Zwei Sichten, absichtlich gemeinsam veröffentlicht: was ein **echter Client über ein echtes
Netzwerk** erlebt — und was die Engine schafft, wenn das Netz aus der Rechnung fällt. Der
unschmeichelhafte Lauf steht in der Tabelle, nicht in einer Fußnote.

### Realistisch: zweite Maschine, echtes LAN, echtes TCP/IP

`wrk` 4.1 auf Debian 13 (2 vCPU) treibt den Release-Build auf einem Desktop-Windows-PC übers LAN
(`perf.toml`-App: keine Auth, kein Skript, RAM-only-Store mit 5.000 Dokumenten — Listenseiten
≈ 2,5 KB). 10 s pro Lauf, 100 % 2xx-Antworten. Sofern nicht anders angegeben, nutzt wrk 32
Keep-Alive-Verbindungen — genau das, was Browser, HTTP-SDKs und Reverse-Proxies in Produktion tun:

| Szenario | RPS | Latenz (Ø) | Datendurchsatz |
|---|---|---|---|
| GET einzelnes Dokument | **8.565** | 3,7 ms | 2,1 MB/s |
| GET Liste, 20 Docs/Seite (~2,5 KB) | **8.105** | 3,9 ms | 20,3 MB/s ≈ 160 Mbit/s |
| GET Liste, gzip | **7.910** | 4,0 ms | 6,3 MB/s |
| POST — Anlegen | **8.346** | 3,8 ms | 2,8 MB/s |
| PUT — komplettes Ersetzen | **8.107** | 3,9 ms | 2,2 MB/s |
| PATCH — teilweise Aktualisierung | **8.241** | 3,9 ms | 2,3 MB/s |
| GET Liste — **eine frische TCP-Verbindung pro Request** (64 Verbindungen) | **995** | 21,7 ms | 2,5 MB/s |

Ehrlich gelesen:

* **Die ~8,5k-Grenze ist der beschäftigte Desktop-Host — nicht die Engine, nicht das Netzwerk.**
  Alle Varianten konvergieren unabhängig von der Payloadgröße, eine Verdopplung auf 64 Verbindungen
  ändert nichts (8.442 RPS), und die schwerste Zeile bewegt ~160 Mbit/s von 1.000 Mbit/s. Die Engine
  selbst hat deutlich mehr Reserve (Loopback-Tabelle unten); auf stiller, dedizierter Hardware wird
  das nächste echte Limit der Uplink: ~45k RPS unkomprimiert, ~150k RPS gezippt bei 2,5-KB-Listenseiten
  auf 1 GbE.
* **Die letzte Zeile ist der Anti-Benchmark — und sie bleibt drin.** Mit `Connection: close` zahlt
  jeder Request einen kompletten TCP-Handshake samt Abbau — ~8,5× langsamer. Das ist die ehrliche
  Antwort auf „was, wenn jeder Client neu aufbaut?“ — und genau deshalb zitieren wir nie nur
  Keep-Alive-Zahlen. Was nie das Problem war: RAM. Speicher skaliert mit *gleichzeitig offenen*
  Verbindungen (einige MB bei 32–64 Sockets; selbst 50.000 offene Verbindungen ≈ 0,5–2,5 GB), nicht
  mit Requests pro Sekunde.
* **Selbst nachmessen** (5.000 Docs mit dem mitgelieferten `loadtest`-Binary seeden, wie in
  `perf.toml` dokumentiert, dann von einer zweiten Kiste lasten):

  ```bash
  steadfast perf.toml 0.0.0.0:8081
  wrk -t2 -c32 -d10s http://<server>:8081/perf_app/items
  wrk -t2 -c64 -d10s -H 'Connection: close' http://<server>:8081/perf_app/items
  ```

### Motor-Reserve: Generator und Server auf einer Maschine (Loopback)

Keine NIC, keine LAN-Latenz, kein Cross-Traffic — eine Obergrenze dafür, was ein einzelner Prozess
aufnimmt, keine Deployment-Zahl. Release-Build, 32 Keep-Alive-Verbindungen, 5.000 Dokumente im RAM:

| HTTP-Szenario (siehe `perf.toml`, `loadtest`) | RPS | p50 | p99 |
|---|---|---|---|
| Einfache Liste `?limit=20` (Fast Path) | **49.613** | 610 µs | 1,40 ms |
| Indizierter Gleichheitsfilter `?grp=g2` | **32.391** | 949 µs | 1,95 ms |
| POST (geskriptet, ohne Persistenz) | **48.314** | 615 µs | 1,61 ms |
| POST mit aktivierter WAL-Persistenz | ~21.800 | — | ~2,8 ms |
| Range-Scan über 5.000 Docs | 6.894 | 4,46 ms | 9,87 ms |
| Vollständige Sortierung | 6.452 | 4,70 ms | 10,71 ms |
| Index-Präfilter + Range + Sortierung | 13.905 | 2,20 ms | 5,03 ms |

Store-Microbenchmarks (`bench_tiering`, 200k Docs, Hot-Cap 50k):

| Operation | Ergebnis |
|---|---|
| Insert-Durchsatz | ~495.000/s (p50 1 µs, p99 6 µs) |
| Hot GET | p50 < 1 µs, p99 1 µs |
| Cold GET (aus WAL/Snapshot von Platte) | p50 102 µs, p99 158 µs |
| Indizierte Gleichheitsliste vs. linearer Scan | 21 ms vs. 66 ms (3,2×) |

Crash-getestet: kill -9 mitten im Schreibvorgang, Neustart spielt Snapshot + WAL-Segmente zurück und
stellt jedes Dokument wieder her — auch ausgelagerte (fetch-on-miss) — mit CRC32-gesicherten
Segmenten und Toleranz gegenüber abgerissener Segmentenden.

## Quickstart — die ganze Idee in zwei Boxen

Deine komplette API (inklusive Business-Logik) ist Konfiguration:

<table>
<tr>
<th width="50%"><code>apps.toml</code> — das komplette Backend</th>
<th width="50%">Das ist bereits eine live-API</th>
</tr>
<tr>
<td>

```toml
[apps.todo_app]
api_key_secret = "${TODO_APP_SECRET}"

  [apps.todo_app.endpoints.tasks_get]
  path = "/tasks"
  method = "GET"

  [apps.todo_app.endpoints.tasks_create]
  path = "/tasks"
  method = "POST"
  auth_required = true

  # Sandboxierte Business-Logik (20k Ops / 5-ms-Deadline):
  business_logic = """
  fn on_request(payload, user) {
      if user.role != "premium" && payload.is_priority == true {
          throw "Only premium users may create priority tasks!";
      }
      payload.created_by = user.id;
      payload.status = "open";
      return payload;
  }
  """
```

</td>
<td>

```bash
# Anlegen (Skript läuft, setzt created_by/status)
curl -X POST localhost:8080/todo_app/tasks \
  -H "x-api-key: $TODO_APP_SECRET" \
  -H "x-user-id: user_1" \
  -H "x-user-role: premium" \
  -H "content-type: application/json" \
  -d '{"title": "First task", "is_priority": true}'

# → 201 Created + Location-Header

# Liste (offen, geseitet, filterbar, sortierbar)
curl 'localhost:8080/todo_app/tasks?status=open&limit=10'

# Item-CRUD
curl localhost:8080/todo_app/tasks/<id>
curl -X PATCH localhost:8080/todo_app/tasks/<id> \
  -H "x-api-key: $TODO_APP_SECRET" \
  -H "content-type: application/json" \
  -d '{"status": "done"}'
curl -X DELETE localhost:8080/todo_app/tasks/<id> \
  -H "x-api-key: $TODO_APP_SECRET"
```

</td>
</tr>
</table>

Ergänze `--data-dir data`, und die Engine wird persistent (WAL + Snapshots, übersteht Abstürze und
Neustarts). Jeder `[apps.<id>]`-Abschnitt ist ein vollständig isolierter Tenant.

## Warum

Kleine und mittlere Backends brauchen selten einen Microservice-Zoo — sie brauchen einen schnellen,
ehrlichen Prozess, der Daten sicher hält und nie ausfällt. Steadfast ist der Gegenentwurf zu
„dreh einfach 5 Container hoch“: eine einzige Binärdatei, eine Konfigurationsdatei, In-Memory-Tempo
mit dauerhafter Haltbarkeit auf Disk — und eine Trust-Boundary, die ein Gateway davor annimmt (wo
Auth, Rate-Limiting und TLS hingehören).

* **Config-getriebene Endpunkte** — Routen, Auth-Flags, Paging, Filter-Allowlists und sandboxierte
  [Rhai](https://rhai.rs)-Hooks werden deklariert, vorkompiliert und beim Start validiert (fail-fast).
* **Deklarative Schema-Validierung** — eine optionale `[schema]`-Sektion an Mutationen (`required`,
  Feld-`types` — inklusive `"date"` und RFC-3339-`"datetime"` —, strikte Unknown-Field-Policy) wird
  beim Start zu simplen Hash-Lookups vorkompiliert und im Hot Path erzwungen, bevor irgendein Skript
  läuft oder ein Write-Lock genommen wird; Verstöße liefern ein strukturiertes
  `400 validation_failed` mit sämtlichen Befunden. PATCH prüft die Typen nur der übermittelten
  Felder und verlangt nie `required`-Felder.
* **Schemalose JSON-Dokumente**, geteilt als `Arc<Value>` — Lese-Pfade kommen ohne Kopien aus.
* **Persistenz ab Werk**: jede Mutation geht in eine CRC32-gesicherte WAL (Backpressure statt
  Verlust), Snapshots rotieren atomar, Replay ist crash-tolerant.
* **Tiering jenseits des RAMs**: `--max-docs N` deckelt Hot-Dokumente pro Kollektion; kalte werden
  beim Zugriff aus WAL/Snapshot geholt und befördert. `total` und Paging bleiben exakt.
* **Durch Audit gehärtet** — siehe [SECURITY_AUDIT_V2.md](SECURITY_AUDIT_V2.md): constant-time
  API-Key-Vergleich, create-if-absent-POST (409), atomares PATCH, Zurückweisung doppelter Header,
  optionale Gateway-Provenienz (`X-Internal-Auth`), 1-MiB-Body-Limit, Auth vor 404, generische
  Fehlermeldungen. Pro-App-CORS (Preflight, Origin-Allowlist, Credential-Regeln) und
  gzip-Kompression für große JSON-Antworten. 164 Tests.

## `apps.toml`-Referenz

| Feld | Ebene | Bedeutung |
|---|---|---|
| `api_key_secret` | App | Secret für `X-API-Key` (erforderlich, sobald irgendein Endpunkt `auth_required = true` setzt). Min. 16 Zeichen; `${ENV_VAR}`-Indirektion mit fail-fast-Auflösung |
| `cors.allowed_origins` | App | Exakte Browser-Origins (case-insensitive) oder exakt `["*"]`. **Ohne `[cors]`-Sektion sendet die Engine keine CORS-Header** — Browser-Frontends sehen dann CORS-Fehler |
| `cors.allowed_methods` | App | Standard: alle unterstützten Methoden (`GET, POST, PUT, PATCH, DELETE`) |
| `cors.allowed_headers` | App | Standard: `content-type`, `x-api-key`, `x-user-id`, `x-user-role` (exakt die Header, die die Engine liest) |
| `cors.exposed_headers` | App | Response-Header, die Browser-JS via `Access-Control-Expose-Headers` lesen darf. Standard: `["location"]` (der 201-Header) |
| `cors.allow_credentials` | App | Standard `false`; `true` verlangt explizite Origins — `*` wird beim Start abgelehnt (Browser lehnen `*` neben Credentials ab) |
| `cors.max_age_secs` | App | Optionale Preflight-Cachezeit, 1..=86400 |
| `endpoints.<name>.path` | Endpunkt | Kollektions-Pfad, genau ein Segment (`/tasks`) |
| `endpoints.<name>.method` | Endpunkt | `GET`, `POST`, `PUT`, `PATCH` oder `DELETE` |
| `endpoints.<name>.auth_required` | Endpunkt | Standard `false`; `true` → 401 ohne gültigen `X-API-Key` |
| `endpoints.<name>.paging_default` | Endpunkt | Standardseitengröße für Listen-GETs (1..=100, Standard 20) |
| `endpoints.<name>.filter_fields` | Endpunkt | Optionale Allowlist filterbarer/sortierbarer Felder — Security-Allowlist **und** Index-Schalter |
| `endpoints.<name>.business_logic` | Endpunkt | Rhai-Skript mit Hook `fn on_request(payload, user)`; läuft vor dem Storage bei POST/PUT/PATCH; `throw` → 422 |
| `endpoints.<name>.schema` | Endpunkt | Optionale Validierung für POST/PUT/PATCH. `required = [...]` (erzwungen bei POST/PUT; PATCH ist partiell), `allow_unknown_fields` (Standard `false` — nicht deklarierte Felder werden abgelehnt), `schema.types.<field> = "string" \| "number" \| "boolean" \| "object" \| "array" \| "null" \| "date" (strikt `YYYY-MM-DD`, inkl. Schaltjahre) \| "datetime" (RFC 3339 — Zeitzone `Z`/`±HH:MM` ist Pflicht)`. Ungültige Typ-Strings oder Feldnamen brechen den Start ab |

CORS wird pro App in Middleware erzwungen: Preflights (`OPTIONS` +
`Access-Control-Request-Method`) werden nach Prüfung von Origin, Methode und Headern mit 204
beantwortet (keine Auth, kein Storage); echte Requests von unerlaubten Origins enden mit
`403 cors_rejected` — ein Browser-Aufruf kann also nie seine Seiteneffekte ausführen, nur um dann
an der Antwort gehindert zu werden. Requests ohne `Origin`-Header (curl, Gateways,
Server-to-Server) und `/health` sind nicht betroffen. Jede echte Antwort trägt außerdem
`Access-Control-Expose-Headers`, damit Browser-Code Engine-Header wie den 201-`Location` lesen
kann; Preflights enthalten ihn bewusst nicht (Fetch-Spec).

**Antwort-Kompression ist standardmäßig aktiv**: JSON-Antworten ≥ 1 KiB werden gzipped, wenn der
Client `Accept-Encoding: gzip` (oder `*`) sendet, mit `Vary: Accept-Encoding` für
Cache-Korrektheit. Clients ohne diesen Header — curl-Skripte, Gateways, Server-to-Server —
erhalten die identische, unkomprimierte Antwort. `--no-compression` deaktiviert die Funktion
komplett.

**Observability**: jeder Request wird als genau eine `info`-Zeile geloggt — Methode, Pfad, Status,
Dauer in µs und `request_id` — und jede Antwort trägt diesen `X-Request-Id`-Header (eine frische
UUID v4, oder die eigene `X-Request-Id` des Gateways, wenn vorhanden; druckbar und ≤ 128 Zeichen).
Zitiere die ID aus einer Fehlerantwort und greppe ins Log: sie landet auf der exakten Zeile. 4xx
loggen mit `debug`, 5xx mit `warn`; expose `x-request-id` über `cors.exposed_headers`, damit
Browser-Code ihn lesen kann.

### CRUD-Semantik

* `GET /<app>/<coll>` — Liste mit Paging, Gleichheits-/Bereichsfiltern, Sortierung.
* `GET /<app>/<coll>/{id}` — Item oder 404.
* `POST /<app>/<coll>` — Schema-Check → Skript → Engine setzt fehlende `id` (UUID v4) →
  `201` + `Location`. Vorhandene ID → `409 already_exists` (strenges create-if-absent, Bestand
  unangetastet).
* `PUT /<app>/<coll>/{id}` — komplettes Ersetzen, `id` wird aus dem Pfad erzwungen.
* `PATCH /<app>/<coll>/{id}` — shallow merge + Skript, atomar unter dem Write-Lock der Kollektion
  (keine Lost Updates; ein Skript-`throw` committet nichts).
* `DELETE /<app>/<coll>/{id}` — `204`.

Listen-Queries: reservierte Parameter sind `page`, `limit`, `sort`, `order`. `field=value` ist ein
Gleichheitsfilter; `field_min/max` (inklusive) und `field_gt/lt` (exklusive) sind Bereichsfilter.
Feldnamen müssen `[A-Za-z0-9_]{1,64}` entsprechen — alles andere ist ein 400 an der HTTP-Kante.
**Es gibt keine Abfragesprache, also gibt es nichts hineinzuinjizieren**: Werte werden nur
verglichen (`value_matches`/`value_in_range`), nie interpretiert. Max. 16 Filter, 256 Bytes pro
Wert, `limit` gedeckelt auf 100. `HEAD` verhält sich wie GET (Header, kein Body).

Statuscodes: 404 unbekannte App/Item · 401 fehlender/ungültiger Key (auch für unbekannte Pfade von
Apps mit Secret — kein Enumeration-Oracle) · 400 fehlerhaftes JSON/Query oder doppelte
Identity-Header · 400 `validation_failed` mit sortierten `error.details`, wenn eine Payload ihr
deklariertes Schema verfehlt · 405 (+ `Allow`) nicht konfigurierte Methode · 413 Body > 1 MiB ·
422 Skript-Ablehnung · 500 Sandbox-Limits (generische Meldung, Details im Log).

User-Metadaten für Skripte kommen aus `X-User-Id` / `X-User-Role` (Standard `anonymous` / `user`).
Setze `ENGINE_GATEWAY_SECRET`, und diese Header zählen nur, wenn der Request die
Gateway-Provenienz per `X-Internal-Auth` nachweist — direkte Clients können keine Rollen fälschen.

## Persistenz & Tiering in 60 Sekunden

* `--data-dir <dir>` aktiviert WAL + Snapshots; `--snapshot-interval` (Standard 60 s) und
  `--wal-max-segment-mb` (Standard 256) steuern Rotation/Kompaktion. Atomare
  tmp→fsync→rename-Snapshots; Segmente werden erst nach einem erfolgreichen Snapshot gelöscht.
* Schreibvorgänge landen in einem begrenzten Kanal (65.536 Ops): eine volle Platte erzeugt
  Backpressure, nie stillen Verlust. Replay-Reihenfolge: zuerst Snapshot, dann Segmente;
  abgerissene Segmentenden werden toleriert, CRC-Fehler stoppen exakt diese Datei.
* Ein zweiter Prozess auf demselben Datenverzeichnis bricht schnell ab (advisory lock file).
* `--max-docs N`: LRU-artige Eviction nach jeder WAL-Rotation hält Kollektionen bei ~95 % der
  Kapazität; kalte Dokumente bleiben gelistet (exaktes `total`) und werden beim Zugriff geholt.

## Sicherheitsmodell

Steadfast ist eine **Engine hinter deinem Gateway**. Sie besitzt App-Secrets, Storage, Sandboxing
und Haltbarkeit; dein Gateway besitzt Benutzer, Sessions, Rate-Limits und TLS. Der Vertrag:

1. Das Gateway MUSS `X-API-Key`, `X-User-*`, `X-Internal-Auth` strippen und neu setzen (ersetzen,
   nie anhängen — doppelte Header werden mit 400 abgelehnt).
2. Beschränke den Netzwerkzugriff auf das Gateway; optional `ENGINE_GATEWAY_SECRET` setzen, um die
   Header-Provenienz im Code zu erzwingen.
3. Startup-Warnungen decken die klassischen Fußfallen ab: Schreib-Endpunkte ohne
   `auth_required`, Non-Loopback-Binds, unbegrenztes `--max-docs`.

Bekannte, dokumentierte Grenzen: noch kein Audit-Trail (Phase 3), Rate-Limiting gehört ins
Gateway. Der vollständige Verifikations-Pfad jeder Findung und jedes Fixes lebt in
[SECURITY_AUDIT_V2.md](SECURITY_AUDIT_V2.md); Schwachstellenmeldungen: [SECURITY.md](SECURITY.md).

## Architektur

| Crate | Zweck |
|---|---|
| `steadfast-core` | `apps.toml`-Parsing/-Validierung, Rhai-AST-Vorkompilierung + Sandbox (ohne HTTP) |
| `steadfast-storage` | In-Memory-Store (DashMap, dualer Index, `Arc<Value>`), WAL-/Snapshot-Persistenz, Tiering, Sekundärindizes |
| `steadfast-server` | Axum-Hot-Path, Auth, Binary `steadfast` (plus `loadtest`-Lastgenerator) |

Geplante Phase 3: Distributed Mode (gRPC-Contracts, Redis/Dragonfly-Shared-Memory-Layer,
Rate-Limiting, Audit-Trail, HMAC-gesicherte Segmente).

## Lizenz

Dual-lizenziert unter [MIT](LICENSE-MIT) oder [Apache-2.0](LICENSE-APACHE) — nimm, was dir passt.
