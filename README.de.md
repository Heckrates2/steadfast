# Steadfast

[English](README.md) · **Deutsch**

**Die Always-on-REST-Engine in Rust. Deine API ist eine TOML-Datei.**

[![CI](https://github.com/Heckrates2/steadfast/actions/workflows/ci.yml/badge.svg)](https://github.com/Heckrates2/steadfast/actions/workflows/ci.yml)
[![Lizenz: MIT oder Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#lizenz)

Steadfast macht aus einer einzigen Konfigurationsdatei voll isolierte, gehärtete CRUD-REST-APIs —
kein Endpunkt-Code, keine Migrationen, kein Boilerplate. Wenn PocketBase ein Geschwister hätte, das
eine reine *Engine* wäre (config-getrieben, mit **optionaler, eingebauter Benutzer-Auth pro App** —
JWT-Logins, Refresh-Rotation, Rollen — plus Gateway-Vertrauensmodell für Maschinenzugriff),
entworfen in-memory-first mit WAL-Persistenz und sandboxed Scripting — dann sähe es so aus.

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

### Auth-Overhead: dieselbe Liste, einmal öffentlich, einmal `auth_mode = "jwt"`

`perf-auth.toml` (zwei identische 5.000-Doc-Kollektionen, eine öffentlich, eine JWT-geschützt;
Release-Build, Loopback, 32 Keep-Alive-Verbindungen — Reproduktion wie in der Datei beschrieben):

| Szenario | RPS | p50 | p99 |
|---|---|---|---|
| GET-Liste ohne Auth | **44.121–45.097** | 0,67 ms | 1,6 ms |
| GET-Liste mit JWT (`Authorization: Bearer`) | **40.455–40.634** | 0,74 ms | 1,8 ms |
| Indizierter Gleichheitsfilter ohne Auth | 40.850 | 0,73 ms | 1,9 ms |
| Indizierter Gleichheitsfilter mit JWT | 43.323 | 0,69 ms | 1,7 ms |
| POST (RAM-only) mit JWT | 40.741 | 0,74 ms | 1,8 ms |
| Einzelner Login (Argon2id + Token-Ausstellung) | — | ~28 ms | — |

Ehrlich gelesen: Die JWT-Verifizierung plus der frische Benutzer-Lookup pro Request kosten
grob **8–10 % Durchsatz / ~60–80 µs p50** auf Listen-Lesezugriffen. Das Lauf-zu-Lauf-Rauschen
dieses Hosts liegt bei ±5 % (das Filter-Paar flippte sogar — der „schnellere" JWT-Lauf ist der
beschäftigte Desktop, nicht das Token). Logins sind Argon2-gebunden (~28 ms pro Login) und per
Design gedrosselt — sie sind ein Korrektheits-, kein Durchsatzpfad.

Crash-getestet: kill -9 mitten im Schreibvorgang, Neustart spielt Snapshot + WAL-Segmente zurück und
stellt jedes Dokument wieder her — auch ausgelagerte (fetch-on-miss) — mit CRC32-gesicherten
Segmenten und Toleranz gegenüber abgerissener Segmentenden.

## Quickstart — die ganze Idee in zwei Boxen

Deine komplette API (inklusive Business-Logik und Benutzer-Auth) ist Konfiguration:

<table>
<tr>
<th width="50%"><code>apps.toml</code> — das komplette Backend</th>
<th width="50%">Das ist bereits eine live-API</th>
</tr>
<tr>
<td>

```toml
[apps.muster_app]

  # Benutzer-Auth pro App: /muster_app/_auth/* (login,
  # refresh, logout, register, Admin-User-Verwaltung)
  [apps.muster_app.auth]
  enabled = true
  jwt_secret = "${MUSTER_JWT_SECRET}"   # min. 32 Zeichen
  admin_email = "admin@example.com"
  admin_password = "${MUSTER_ADMIN_PASSWORD}"

  [apps.muster_app.endpoints.notes_get]
  path = "/notes"
  method = "GET"          # oeffentliches Lesen

  [apps.muster_app.endpoints.notes_create]
  path = "/notes"
  method = "POST"
  auth_mode = "jwt"       # Nutzer loggen sich ein,
  roles = ["user", "admin"]  # Skripte sehen user.id/role

  # Sandboxierte Business-Logik (20k Ops / 5-ms-Deadline):
  business_logic = """
  fn on_request(payload, user) {
      payload.created_by = user.id;
      payload.status = "offen";
      return payload;
  }
  """
```

</td>
<td>

```bash
# Login → Access-Token (15 min) + rotierender Refresh-Token
curl -X POST localhost:8080/muster_app/_auth/login \
  -H "content-type: application/json" \
  -d '{"email": "admin@example.com",
       "password": "…"}'
# → {"access_token": "eyJ…", "refresh_token": "…", …}

# Anlegen (Skript läuft, created_by aus JWT-Claims)
curl -X POST localhost:8080/muster_app/notes \
  -H "authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -d '{"title": "Erste Notiz"}'
# → 201 Created + Location-Header

# Liste (offen, geseitet, filterbar, sortierbar)
curl 'localhost:8080/muster_app/notes?status=offen&limit=10'

# Refresh-Token rotieren (das alte wird Single-Use-
# Evidence; Wiederverwendung sperrt ALLE Tokens des Nutzers)
curl -X POST localhost:8080/muster_app/_auth/refresh \
  -d '{"refresh_token": "…"}'

# Maschinen-Endpunkte behalten den API-Key parallel:
curl -X POST localhost:8080/muster_app/imports \
  -H "x-api-key: $MUSTER_APP_SECRET" \
  -d '{"row": 1}'
```

</td>
</tr>
</table>

Apps ohne `[auth]`-Sektion bleiben exakt beim API-Key-/Gateway-Modell — die Auth kostet sie
nichts. Ergänze `--data-dir data`, und die Engine wird persistent (WAL + Snapshots, übersteht
Abstürze und Neustarts). Jeder `[apps.<id>]`-Abschnitt ist ein vollständig isolierter Tenant —
inklusive seines Benutzerverzeichnisses.

## Warum

Kleine und mittlere Backends brauchen selten einen Microservice-Zoo — sie brauchen einen schnellen,
ehrlichen Prozess, der Daten sicher hält und nie ausfällt. Steadfast ist der Gegenentwurf zu
„dreh einfach 5 Container hoch“: eine einzige Binärdatei, eine Konfigurationsdatei, In-Memory-Tempo
mit dauerhafter Haltbarkeit auf Disk — und Auth, die du pro App wählst: eingebaute
Benutzerverwaltung (JWT, Rollen, Sperren, gedrosselte Logins) oder eine schlanke
Gateway-Trust-Boundary für Maschinendatenverkehr (wohin TLS und Edge-Rate-Limiting gehören).

* **Config-getriebene Endpunkte** — Routen, Auth-Modi, Paging, Filter-Allowlists und sandboxierte
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
  gzip-Kompression für große JSON-Antworten. Optionale Benutzer-Auth pro App (Argon2id, JWT,
  rotierende Refresh-Tokens, Sperren, gedrosselte Logins). 228 Tests.

## `apps.toml`-Referenz

| Feld | Ebene | Bedeutung |
|---|---|---|
| `api_key_secret` | App | Secret für `X-API-Key` (erforderlich, sobald irgendein Endpunkt `auth_mode = "api_key"` bzw. `auth_required = true` setzt). Min. 16 Zeichen; `${ENV_VAR}`-Indirektion mit fail-fast-Auflösung |
| `auth.enabled` | App | `true` aktiviert die Benutzer-Auth der App (`/{app}/_auth/*`-Endpunkte, `auth_mode = "jwt"` auf Endpunkten). Ohne `[auth]`-Sektion bleibt die App beim API-Key-/Gateway-Modell — null Overhead |
| `auth.jwt_secret` | App | HS256-Signatur-Secret für Access-Tokens, min. 32 Zeichen, `${ENV_VAR}`-Indirektion (Pflicht bei `enabled = true`) |
| `auth.access_token_secs` / `auth.refresh_token_secs` | App | Token-Lebenszeiten (Defaults 15 min / 30 Tage; Refresh-Tokens rotieren bei jeder Nutzung) |
| `auth.registration_open` | App | Default `false` — dann legen nur Admins Benutzer über `POST /_auth/users` an |
| `auth.allowed_origins` | App | Exakte Origins, die den Cookie-Modus nutzen dürfen (CSRF-Origin-Check, kein `*`); Rückfall: konkrete `cors.allowed_origins`. Fehlt = nur Bearer-Modus |
| `auth.admin_email` + `auth.admin_password` | App | Bootstrap-Admin, wird beim Start angelegt, falls die E-Mail fehlt (Passwort muss die Policy erfüllen) |
| `auth.password_policy.*` | App | Vollständig konfigurierbare Passwort-Regeln: `min_length` (Default 10), `max_length` (Default 128, Hartdeckel 1024), `require_lowercase`, `require_uppercase`, `require_digits`, `require_special` (Defaults alle `true`) |
| `auth.rate_limit.*` | App | Token-Bucket je Client-IP auf den Auth-Endpunkten: `login_per_min` (10), `register_per_min` (5), `refresh_per_min` (30) |
| `cors.allowed_origins` | App | Exakte Browser-Origins (case-insensitive) oder exakt `["*"]`. **Ohne `[cors]`-Sektion sendet die Engine keine CORS-Header** — Browser-Frontends sehen dann CORS-Fehler |
| `cors.allowed_methods` | App | Standard: alle unterstützten Methoden (`GET, POST, PUT, PATCH, DELETE`) |
| `cors.allowed_headers` | App | Standard: `authorization`, `content-type`, `x-api-key`, `x-user-id`, `x-user-role` (exakt die Header, die die Engine liest) |
| `cors.exposed_headers` | App | Response-Header, die Browser-JS via `Access-Control-Expose-Headers` lesen darf. Standard: `["location"]` (der 201-Header) |
| `cors.allow_credentials` | App | Standard `false`; `true` verlangt explizite Origins — `*` wird beim Start abgelehnt (Browser lehnen `*` neben Credentials ab) |
| `cors.max_age_secs` | App | Optionale Preflight-Cachezeit, 1..=86400 |
| `endpoints.<name>.path` | Endpunkt | Kollektions-Pfad, genau ein Segment (`/tasks`) |
| `endpoints.<name>.method` | Endpunkt | `GET`, `POST`, `PUT`, `PATCH` oder `DELETE` |
| `endpoints.<name>.auth_mode` | Endpunkt | `"api_key"` (klassisch `X-API-Key`; `auth_required = true` bleibt die Kurzform) oder `"jwt"` (erfordert aktives `[auth]`; prüft `Authorization: Bearer` und liest `user.id`/`user.role` frisch aus dem Benutzer-Dokument). Kein `auth_mode` = öffentlicher Endpunkt |
| `endpoints.<name>.roles` | Endpunkt | Optionale Rollen-Allowlist (nur mit `auth_mode = "jwt"`): die *aktuelle* Rolle des Benutzers muss passen, sonst 403. Fehlt = jeder authentifizierte Benutzer der App |
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

### Benutzer-Auth pro App (`[auth]`, `/_auth/*`)

Mit `auth.enabled = true` bekommt eine App ein eigenes Benutzerverzeichnis und Endpunkte unter
`/{app_id}/_auth/`:

| Endpunkt | Zweck |
|---|---|
| `POST /_auth/login` | `{email, password, use_cookie?}` → Access-Token (JWT, HS256, `iss = steadfast:<app>`) + Refresh-Token (Body oder `HttpOnly`+`Secure`+`SameSite=Strict`-Cookie auf `/{app}/_auth` im Cookie-Modus). Uniforme 401 `invalid_credentials` bei unbekannter E-Mail / falschem Passwort / gesperrtem / deaktiviertem Konto — inklusive Argon2-Dummy-Lauf für identische Antwortzeiten |
| `POST /_auth/refresh` | Single-Use-Rotation (atomar unter dem Kollektions-Write-Lock). Wiederverwendung eines rotierten Tokens sperrt **alle** Refresh-Tokens des Benutzers (Diebstahl-Alarm) und liefert 401. Cookie-Refresh verlangt eine erlaubte `Origin` (CSRF) |
| `POST /_auth/logout` | Widerruft den vorgelegten Refresh-Token, löscht das Cookie (idempotent) |
| `POST /_auth/register` | Selbstregistrierung, nur bei `registration_open = true`; Policy-Verstöße liefern 400 mit den verletzten Regeln |
| `GET /_auth/me` | Eigenes Profil aus verifizierten Claims (frisch gegen den Store geprüft) |
| `GET/POST /_auth/users`, `PATCH /_auth/users/{id}` | Admin-Verwaltung (Rollen-Änderung und Deaktivierung greifen sofort; Deaktivierung sperrt zusätzlich alle Refresh-Tokens) |

Sicherheitseigenschaften: **Argon2id**-Passwort-Hashing (Salt pro Benutzer, OWASP-Parameter),
**vollständig konfigurierbare Passwort-Policy** (Länge + Zeichenklassen, jede Regel ein TOML-Schalter),
**Konto-Sperre** (10 fehlgeschlagene Logins → exponentielle Sperre 15 min → 24-h-Deckel),
**Rate-Limiting** je Client-IP (Token-Bucket, 429 + `Retry-After`), **Tenant-Isolation**
(Benutzer, Tokens und Secrets kreuzen nie Apps — getrennte JWT-Secrets *und* Issuer-Claims),
Security-Header (`Cache-Control: no-store`, `X-Content-Type-Options`, `Referrer-Policy`) und
Audit-Logzeilen für Logins, Sperren und Rotations-Alarme. Benutzer und Refresh-Token-Hashes
(SHA-256, nie der Token selbst) liegen als gewöhnliche Dokumente im WAL-persistenten Store der
App; ein Hintergrund-Sweeper entfernt abgelaufene Tokens nach 7 Tagen Evidence-Frist.

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

Steadfast unterstützt zwei Vertrauensmodelle, **pro App** in der `apps.toml` gewählt:

1. **Eingebaute Benutzer-Auth pro App** (`[auth]` mit `enabled = true`): Die Engine besitzt
   Benutzer, Argon2id-Hashing, JWT-Access-Tokens, rotierende Refresh-Tokens, Rollen, Sperren
   und Rate-Limiting der Auth-Endpunkte (siehe oben). Endpunkte optieren per
   `auth_mode = "jwt"` ein, optional per `roles` beschränkt. Maschinen-Endpunkte behalten
   `auth_mode = "api_key"` parallel.
2. **Gateway-Vertrauensmodell** (keine `[auth]`-Sektion): der klassische Vertrag — die Engine
   besitzt App-Secrets, Storage, Sandboxing und Haltbarkeit; dein Gateway besitzt Benutzer,
   Sessions und TLS. Das Gateway MUSS `X-API-Key`, `X-User-*`, `X-Internal-Auth` strippen und
   neu setzen (ersetzen, nie anhängen — doppelte Header werden mit 400 abgelehnt); optional
   `ENGINE_GATEWAY_SECRET` setzen, um die Header-Provenienz im Code zu erzwingen, und den
   Netzwerkzugriff auf das Gateway beschränken. Startup-Warnungen decken die klassischen
   Fußfallen ab: Schreib-Endpunkte ohne jede Auth, Non-Loopback-Binds, unbegrenztes
   `--max-docs`.

Bekannte, dokumentierte Grenzen: kein Audit-Trail jenseits strukturierter Logzeilen (Phase 3),
Rate-Limiting der *Daten*-Endpunkte gehört weiterhin ins Gateway (die `/_auth`-Endpunkte haben
ein eigenes). Der vollständige Verifikations-Pfad jeder Findung und jedes Fixes lebt in
[SECURITY_AUDIT_V2.md](SECURITY_AUDIT_V2.md); Schwachstellenmeldungen: [SECURITY.md](SECURITY.md).

## Architektur

| Crate | Zweck |
|---|---|
| `steadfast-core` | `apps.toml`-Parsing/-Validierung (inkl. `[auth]`, `password_policy`), Rhai-AST-Vorkompilierung + Sandbox (ohne HTTP) |
| `steadfast-storage` | In-Memory-Store (DashMap, dualer Index, `Arc<Value>`), WAL-/Snapshot-Persistenz, Tiering, Sekundärindizes |
| `steadfast-auth` | Benutzer-Auth pro App: Argon2id, JWT + Refresh-Rotation mit Wiederverwendungs-Erkennung, Sperren, Rate-Limiting, `/_auth`-Endpunkte |
| `steadfast-server` | Axum-Hot-Path, Auth-Dispatch, Binary `steadfast` (plus `loadtest`-Lastgenerator) |

Geplante Phase 3: Distributed Mode (gRPC-Contracts, Redis/Dragonfly-Shared-Memory-Layer,
Rate-Limiting, Audit-Trail, HMAC-gesicherte Segmente).

## Lizenz

Dual-lizenziert unter [MIT](LICENSE-MIT) oder [Apache-2.0](LICENSE-APACHE) — nimm, was dir passt.
