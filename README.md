# Steadfast

**English** · [Deutsch](README.de.md)

**The always-on REST engine in Rust. Your API is a TOML file.**

[![CI](https://github.com/Heckrates2/steadfast/actions/workflows/ci.yml/badge.svg)](https://github.com/Heckrates2/steadfast/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

Steadfast turns a single configuration file into fully isolated, hardened CRUD REST APIs —
no endpoint code, no migrations, no boilerplate. If PocketBase had a sibling that is a pure
*engine* (config-driven, with **optional built-in per-app user auth** — JWT logins, refresh
rotation, roles — and a gateway-trust mode for machine access), designed in-memory-first with
WAL persistence and sandboxed scripting, it would look like this.

```bash
cargo install --git https://github.com/Heckrates2/steadfast --locked
steadfast apps.toml 127.0.0.1:8080   # your API is live
```

## Benchmarks

Two views, published together on purpose: what a **real client on a real network** sees,
and what the engine absorbs once the network is out of the picture. The unflattering run
is in the table, not in a footnote.

### Realistic: second machine, real LAN, real TCP/IP

`wrk` 4.1 on Debian 13 (2 vCPU) drives the release build on a desktop Windows PC across
the LAN (`perf.toml` app: no auth, no script, RAM-only store seeded with 5,000 documents —
list pages ≈ 2.5 KB). 10 s per run, 100% 2xx responses. Unless noted, wrk reuses 32
keep-alive connections — exactly what browsers, HTTP SDKs and reverse proxies do in
production:

| Scenario | RPS | avg latency | wire load |
|---|---|---|---|
| GET single document | **8,565** | 3.7 ms | 2.1 MB/s |
| GET list, 20 docs/page (~2.5 KB) | **8,105** | 3.9 ms | 20.3 MB/s ≈ 160 Mbit/s |
| GET list, gzipped | **7,910** | 4.0 ms | 6.3 MB/s |
| POST — create | **8,346** | 3.8 ms | 2.8 MB/s |
| PUT — full replace | **8,107** | 3.9 ms | 2.2 MB/s |
| PATCH — partial update | **8,241** | 3.9 ms | 2.3 MB/s |
| GET list — **a fresh TCP connection for every request** (64 conns) | **995** | 21.7 ms | 2.5 MB/s |

Reading these honestly:

* **The ~8.5k ceiling is the busy desktop host — not the engine, not the network.** All
  variants converge regardless of payload size, doubling the connections to 64 changes
  nothing (8,442 RPS), and the heaviest row moves ~160 Mbit/s of a 1,000 Mbit/s link. The
  engine itself has far more headroom (loopback table below); on quiet, dedicated hardware
  the next real ceiling is the uplink: ~45k RPS uncompressed, ~150k RPS gzipped at 2.5 KB
  list pages on 1 GbE.
* **The last row is the anti-benchmark, and it stays.** With `Connection: close`, every
  request pays a full TCP handshake plus teardown — ~8.5× slower. That is the honest answer
  to "what if every client connects fresh?", which is exactly why we won't quote keep-alive
  numbers alone. Note what was never the problem: RAM. Memory scales with *concurrently
  open* connections (a few MB at 32–64 sockets; even 50,000 open connections ≈ 0.5–2.5 GB),
  not with requests per second.
* **Reproduce it** (seed 5,000 docs with the bundled `loadtest` binary as documented in
  `perf.toml`, then load-test from a second box):

  ```bash
  steadfast perf.toml 0.0.0.0:8081
  wrk -t2 -c32 -d10s http://<server>:8081/perf_app/items
  wrk -t2 -c64 -d10s -H 'Connection: close' http://<server>:8081/perf_app/items
  ```

### Engine headroom: generator and server on one machine (loopback)

No NIC, no LAN latency, no cross-traffic — an upper bound on what a single process
absorbs, not a deployment number. Release build, 32 keep-alive connections, 5,000
documents in RAM:

| HTTP scenario (see `perf.toml`, `loadtest`) | RPS | p50 | p99 |
|---|---|---|---|
| Plain list `?limit=20` (fast path) | **49,613** | 610 µs | 1.40 ms |
| Indexed equality filter `?grp=g2` | **32,391** | 949 µs | 1.95 ms |
| POST (scripted, no persistence) | **48,314** | 615 µs | 1.61 ms |
| POST with WAL persistence enabled | ~21,800 | — | ~2.8 ms |
| Range scan over 5,000 docs | 6,894 | 4.46 ms | 9.87 ms |
| Full sort | 6,452 | 4.70 ms | 10.71 ms |
| Index prefilter + range + sort | 13,905 | 2.20 ms | 5.03 ms |

Store-level microbenchmarks (`bench_tiering`, 200k docs, hot cap 50k):

| Operation | Result |
|---|---|
| Insert throughput | ~495,000/s (p50 1 µs, p99 6 µs) |
| Hot GET | p50 < 1 µs, p99 1 µs |
| Cold GET (fetch from WAL/snapshot on disk) | p50 102 µs, p99 158 µs |
| Indexed equality list vs. linear scan | 21 ms vs. 66 ms (3.2×) |

### Auth overhead: the same list, once public, once `auth_mode = "jwt"`

`perf-auth.toml` (two identical 5,000-doc collections, one public, one JWT-gated; release
build, loopback, 32 keep-alive connections — reproduce as documented in the file):

| Scenario | RPS | p50 | p99 |
|---|---|---|---|
| GET list, no auth | **44,121–45,097** | 0.67 ms | 1.6 ms |
| GET list, JWT (`Authorization: Bearer`) | **40,455–40,634** | 0.74 ms | 1.8 ms |
| Indexed equality filter, no auth | 40,850 | 0.73 ms | 1.9 ms |
| Indexed equality filter + JWT | 43,323 | 0.69 ms | 1.7 ms |
| POST (RAM-only) + JWT | 40,741 | 0.74 ms | 1.8 ms |
| Single login (Argon2id verify + token issue) | — | ~28 ms | — |

Reading these honestly: JWT verification plus the fresh per-request user lookup costs
roughly **8–10 % throughput / ~60–80 µs p50** on list reads. Run-to-run noise on this host
is ±5 % (the filter pair even flipped — the "faster" JWT run is the busy desktop, not the
token). Logins are Argon2-bound (~28 ms each) and rate-limited by design; they are a
correctness path, not a throughput path.

Crash-tested: kill -9 mid-write, restart replays snapshot + WAL segments and restores every
document, including tiered-out ones (fetch-on-miss), with CRC32-checked segments and torn-tail
tolerance.

## Quickstart — the whole idea in two boxes

Your entire API (including business logic and user auth) is configuration:

<table>
<tr>
<th width="50%"><code>apps.toml</code> — the whole backend</th>
<th width="50%">That's already a live API</th>
</tr>
<tr>
<td>

```toml
[apps.muster_app]

  # Per-app user auth: /muster_app/_auth/* (login,
  # refresh, logout, register, admin user management)
  [apps.muster_app.auth]
  enabled = true
  jwt_secret = "${MUSTER_JWT_SECRET}"   # min 32 chars
  admin_email = "admin@example.com"
  admin_password = "${MUSTER_ADMIN_PASSWORD}"

  [apps.muster_app.endpoints.notes_get]
  path = "/notes"
  method = "GET"          # public read

  [apps.muster_app.endpoints.notes_create]
  path = "/notes"
  method = "POST"
  auth_mode = "jwt"       # users log in, scripts see
  roles = ["user", "admin"]  # user.id / user.role claims

  # Sandboxed business logic (20k ops / 5 ms deadline):
  business_logic = """
  fn on_request(payload, user) {
      payload.created_by = user.id;
      payload.status = "open";
      return payload;
  }
  """
```

</td>
<td>

```bash
# Login → access token (15 min) + rotating refresh token
curl -X POST localhost:8080/muster_app/_auth/login \
  -H "content-type: application/json" \
  -d '{"email": "admin@example.com",
       "password": "…"}'
# → {"access_token": "eyJ…", "refresh_token": "…", …}

# Create (script runs, sets created_by from JWT claims)
curl -X POST localhost:8080/muster_app/notes \
  -H "authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -d '{"title": "First note"}'
# → 201 Created + Location header

# List (open, paged, filterable, sortable)
curl 'localhost:8080/muster_app/notes?status=open&limit=10'

# Rotate the refresh token (old one becomes single-use
# evidence; replay revokes ALL of the user's tokens)
curl -X POST localhost:8080/muster_app/_auth/refresh \
  -d '{"refresh_token": "…"}'

# Machine endpoints keep the classic API key in parallel:
curl -X POST localhost:8080/muster_app/imports \
  -H "x-api-key: $MUSTER_APP_SECRET" \
  -d '{"row": 1}'
```

</td>
</tr>
</table>

Apps without an `[auth]` section stay exactly on the API-key/gateway model — the auth module
costs them nothing. Add `--data-dir data` and the engine becomes persistent (WAL + snapshots,
survives crashes and restarts). Every `[apps.<id>]` section is a fully isolated tenant,
including its user directory.

## Why

Small and mid-sized backends rarely need a microservice zoo — they need one fast, honest
process that holds data safely and never falls over. Steadfast is the counter-proposal to
"just spin up 5 containers": a single binary, one config file, in-memory speed with
disk-backed durability — and auth you choose per app: built-in user management (JWT, roles,
lockout, rate-limited logins) or a lean gateway-trust boundary for machine traffic (where
TLS and edge rate limiting belong).

* **Config-driven endpoints** — routes, auth modes, paging, filter allowlists and sandboxed
  [Rhai](https://rhai.rs) hooks are declared, precompiled and validated at startup (fail-fast).
* **Declarative schema validation** — an optional per-endpoint `[schema]` section on
  mutations (`required`, field `types` — including `"date"` and RFC 3339 `"datetime"` —,
  strict unknown-field policy) is precompiled at startup into plain hash lookups and
  enforced in the hot path before any script runs or a write lock is taken; violations
  return a structured `400 validation_failed` with every finding. PATCH checks types on
  the submitted fields but never demands `required` ones.
* **Schemaless JSON documents**, shared as `Arc<Value>` — read paths work without copies.
* **Persistence ready**: every mutation goes to a CRC32-secured WAL (backpressure instead
  of loss), snapshots rotate atomically, replay is crash-tolerant.
* **Tiering beyond RAM**: `--max-docs N` caps hot documents per collection; cold ones are
  fetched from WAL/snapshot on access and promoted. `total` and paging stay exact.
* **Hardened by audit** — see [SECURITY_AUDIT_V2.md](SECURITY_AUDIT_V2.md): constant-time
  API-key compare, create-if-absent POST (409), atomic PATCH, duplicate-header rejection,
  optional gateway provenance (`X-Internal-Auth`), 1 MiB body limit, auth before 404,
  generic error messages. Per-app CORS (preflight, origin allowlist, credential rules) and
  gzip compression for large JSON responses. Optional per-app user auth (Argon2id, JWT,
  rotating refresh tokens, lockout, rate-limited logins). 228 tests.

## `apps.toml` reference

| Field | Level | Meaning |
|---|---|---|
| `api_key_secret` | App | Secret for `X-API-Key` (required once any endpoint sets `auth_mode = "api_key"` / `auth_required = true`). Min. 16 chars; `${ENV_VAR}` indirection with fail-fast resolution |
| `auth.enabled` | App | `true` activates the per-app user auth (`/{app}/_auth/*` endpoints, `auth_mode = "jwt"` on endpoints). Without an `[auth]` section the app stays on the API-key/gateway model — zero overhead |
| `auth.jwt_secret` | App | HS256 signing secret for access tokens, min. 32 chars, `${ENV_VAR}` indirection (required when `enabled = true`) |
| `auth.access_token_secs` / `auth.refresh_token_secs` | App | Token lifetimes (defaults 15 min / 30 days; refresh tokens rotate on every use) |
| `auth.registration_open` | App | Default `false` — then only admins create users via `POST /_auth/users` |
| `auth.allowed_origins` | App | Exact origins allowed to use the cookie mode (CSRF origin check, no `*`); fallback: concrete `cors.allowed_origins`. Absent = Bearer-only |
| `auth.admin_email` + `auth.admin_password` | App | Bootstrap admin, created at startup if the email is missing (password must satisfy the policy) |
| `auth.password_policy.*` | App | Fully configurable password rules: `min_length` (default 10), `max_length` (default 128, hard cap 1024), `require_lowercase`, `require_uppercase`, `require_digits`, `require_special` (default all `true`) |
| `auth.rate_limit.*` | App | Token bucket per client IP on the auth endpoints: `login_per_min` (10), `register_per_min` (5), `refresh_per_min` (30) |
| `cors.allowed_origins` | App | Exact browser origins (case-insensitive) or exactly `["*"]`. **Without a `[cors]` section the engine sends no CORS headers** — browser frontends will see CORS errors |
| `cors.allowed_methods` | App | Default: all supported methods (`GET, POST, PUT, PATCH, DELETE`) |
| `cors.allowed_headers` | App | Default: `authorization`, `content-type`, `x-api-key`, `x-user-id`, `x-user-role` (exactly the headers the engine reads) |
| `cors.exposed_headers` | App | Response headers browser JS may read via `Access-Control-Expose-Headers`. Default: `["location"]` (the 201 header) |
| `cors.allow_credentials` | App | Default `false`; `true` requires explicit origins — `*` is rejected at startup (browsers refuse `*` alongside credentials) |
| `cors.max_age_secs` | App | Optional preflight cache time, 1..=86400 |
| `endpoints.<name>.path` | Endpoint | Collection path, exactly one segment (`/tasks`) |
| `endpoints.<name>.method` | Endpoint | `GET`, `POST`, `PUT`, `PATCH` or `DELETE` |
| `endpoints.<name>.auth_mode` | Endpoint | `"api_key"` (classic `X-API-Key`; `auth_required = true` remains the shorthand) or `"jwt"` (requires enabled `[auth]`; verifies `Authorization: Bearer` and reads `user.id`/`user.role` fresh from the user document). No `auth_mode` = public endpoint |
| `endpoints.<name>.roles` | Endpoint | Optional role allowlist (only with `auth_mode = "jwt"`): the user's *current* role must match, else 403. Absent = every authenticated user of the app |
| `endpoints.<name>.paging_default` | Endpoint | Default page size for list GETs (1..=100, default 20) |
| `endpoints.<name>.filter_fields` | Endpoint | Optional allowlist of filterable/sortable fields — security allowlist **and** index switch |
| `endpoints.<name>.business_logic` | Endpoint | Rhai script with hook `fn on_request(payload, user)`; runs before storage on POST/PUT/PATCH; `throw` → 422 |
| `endpoints.<name>.schema` | Endpoint | Optional validation for POST/PUT/PATCH. `required = [...]` (enforced on POST/PUT; PATCH is partial), `allow_unknown_fields` (default `false` — reject undeclared fields), `schema.types.<field> = "string" \| "number" \| "boolean" \| "object" \| "array" \| "null" \| "date" (strict `YYYY-MM-DD`, leap years included) \| "datetime" (RFC 3339 — timezone `Z`/`±HH:MM` required). Invalid type strings or field names abort startup |

CORS is enforced per app in middleware: preflights (`OPTIONS` + `Access-Control-Request-Method`)
are answered with 204 (no auth, no storage touched) after checking origin, method and headers;
actual requests from a disallowed origin are rejected with `403 cors_rejected` — so a browser
call can never run its side effect only for the response to be blocked. Requests without an
`Origin` header (curl, gateways, server-to-server) and `/health` are unaffected. Every actual
response also carries `Access-Control-Expose-Headers` so browser code can read engine headers
such as the 201 `Location`; preflights intentionally don't include it (Fetch spec).

**Response compression is on by default**: JSON responses ≥ 1 KiB are gzipped when the client
sends `Accept-Encoding: gzip` (or `*`), with `Vary: Accept-Encoding` for cache correctness.
Clients without that header — curl scripts, gateways, server-to-server calls — receive the
identical, uncompressed response. `--no-compression` disables the feature entirely.

**Observability**: every request is logged as exactly one `info` line — method, path, status,
elapsed µs and `request_id` — and every response carries that `X-Request-Id` header (a fresh
UUID v4, or the gateway's own `X-Request-Id` when present, printable and ≤ 128 chars). Cite
the ID from an error response and grep the log: it lands on the exact line. 4xx log at
`debug`, 5xx at `warn`; expose `x-request-id` via `cors.exposed_headers` so browser code
can read it.

### CRUD semantics

* `GET /<app>/<coll>` — list with paging, equality/range filters, sorting.
* `GET /<app>/<coll>/{id}` — item or 404.
* `POST /<app>/<coll>` — schema check → script → engine sets missing `id` (UUID v4) →
  `201` + `Location`. Existing id → `409 already_exists` (strict create-if-absent, stock
  untouched).
* `PUT /<app>/<coll>/{id}` — full replace, `id` forced from path.
* `PATCH /<app>/<coll>/{id}` — shallow merge + script, atomic under the collection's write
  lock (no lost updates; a script `throw` commits nothing).
* `DELETE /<app>/<coll>/{id}` — `204`.

List queries: reserved params are `page`, `limit`, `sort`, `order`. `field=value` is an
equality filter; `field_min/max` (inclusive) and `field_gt/lt` (exclusive) are range filters.
Field names must match `[A-Za-z0-9_]{1,64}` — everything else is a 400 at the HTTP edge.
**There is no query language, so there is nothing to inject into**: values are only compared
(`value_matches`/`value_in_range`), never interpreted. Max. 16 filters, 256 bytes per value,
`limit` capped at 100. `HEAD` behaves like GET (headers, no body).

Status codes: 404 unknown app/item · 401 missing/invalid key (also for unknown paths of
apps with a secret — no enumeration oracle) · 400 bad JSON/query or duplicate identity
headers · 400 `validation_failed` with sorted `error.details` when a payload misses its
declared schema · 405 (+ `Allow`) unconfigured method · 413 body > 1 MiB · 422 script
rejection · 500 sandbox limits (generic message, details in the log).

User metadata for scripts comes from `X-User-Id` / `X-User-Role` (defaults `anonymous` /
`user`). Set `ENGINE_GATEWAY_SECRET` and these headers only count when the request proves
gateway provenance via `X-Internal-Auth` — direct clients cannot spoof roles.

### Per-app user auth (`[auth]`, `/_auth/*`)

With `auth.enabled = true` an app gets its own user directory and endpoints under
`/{app_id}/_auth/`:

| Endpoint | Purpose |
|---|---|
| `POST /_auth/login` | `{email, password, use_cookie?}` → access token (JWT, HS256, `iss = steadfast:<app>`) + refresh token (body, or `HttpOnly`+`Secure`+`SameSite=Strict` cookie scoped to `/{app}/_auth` in cookie mode). Uniform 401 `invalid_credentials` for unknown email / wrong password / locked / disabled accounts — with an Argon2 dummy run for timing parity |
| `POST /_auth/refresh` | Single-use rotation (atomic under the collection write lock). Replaying a rotated token revokes **all** of the user's refresh tokens (theft alarm) and returns 401. Cookie-based refresh requires an allowed `Origin` (CSRF) |
| `POST /_auth/logout` | Revokes the presented refresh token, clears the cookie (idempotent) |
| `POST /_auth/register` | Self-registration, only when `registration_open = true`; policy violations return 400 with the violated rules |
| `GET /_auth/me` | Own profile from verified claims (re-checked against the store) |
| `GET/POST /_auth/users`, `PATCH /_auth/users/{id}` | Admin user management (role changes and deactivation take effect immediately, deactivation also revokes all refresh tokens) |

Security properties: **Argon2id** password hashing (per-user salt, OWASP parameters),
**configurable password policy** (length + character classes, every rule a TOML switch),
**account lockout** (10 failed logins → exponential lock 15 min → 24 h cap), **rate limiting**
per client IP (token bucket, 429 + `Retry-After`), **tenant isolation** (users, tokens and
secrets never cross apps — separate JWT secrets *and* issuer claims), security headers
(`Cache-Control: no-store`, `X-Content-Type-Options`, `Referrer-Policy`) and audit log lines
for logins, lockouts and rotation alarms. Users and refresh-token hashes (SHA-256, never the
token itself) live as ordinary documents in the app's WAL-persisted store; a background
sweeper removes expired tokens after a 7-day evidence window.

## Persistence & tiering in 60 seconds

* `--data-dir <dir>` enables WAL + snapshots; `--snapshot-interval` (default 60 s) and
  `--wal-max-segment-mb` (default 256) drive rotation/compaction. Atomic tmp→fsync→rename
  snapshots; segments are only deleted after a successful snapshot.
* Writes are queued to a bounded channel (65,536 ops): a full disk causes backpressure,
  never silent loss. Replay order: snapshot first, then segments; torn tails are tolerated,
  CRC errors stop exactly that file.
* A second process on the same data dir fails fast (advisory lock file).
* `--max-docs N`: LRU-style eviction after each WAL rotation keeps collections within ~95%
  of the cap; cold documents stay listed (exact `total`) and are fetched on access.

## Security model

Steadfast supports two trust models, chosen **per app** in `apps.toml`:

1. **Built-in per-app user auth** (`[auth]` with `enabled = true`): the engine owns users,
   Argon2id password hashing, JWT access tokens, rotating refresh tokens, roles, lockout and
   rate limiting for the auth endpoints (see above). Endpoints opt in via
   `auth_mode = "jwt"`, optionally restricted by `roles`. Machine endpoints keep
   `auth_mode = "api_key"` in parallel.
2. **Gateway-trust mode** (no `[auth]` section): the classic contract — the engine owns app
   secrets, storage, sandboxing and durability; your gateway owns users, sessions and TLS.
   The gateway MUST strip and re-set `X-API-Key`, `X-User-*`, `X-Internal-Auth` (replace,
   never append — duplicate headers are rejected with 400); optionally set
   `ENGINE_GATEWAY_SECRET` to enforce header provenance in code, and restrict network access
   to the gateway. Startup warnings cover the classic footguns: write endpoints without any
   auth, non-loopback binds, unlimited `--max-docs`.

Known, documented limits: no audit trail beyond structured log lines (Phase 3), rate limiting
for the *data* endpoints still belongs to the gateway (the `/_auth` endpoints carry their own).
The full verification trail of every finding and fix lives in
[SECURITY_AUDIT_V2.md](SECURITY_AUDIT_V2.md); vulnerability reports: [SECURITY.md](SECURITY.md).

## Architecture

| Crate | Purpose |
|---|---|
| `steadfast-core` | `apps.toml` parsing/validation (incl. `[auth]`, `password_policy`), Rhai AST precompile + sandbox (HTTP-free) |
| `steadfast-storage` | In-memory store (DashMap, dual index, `Arc<Value>`), WAL/snapshot persistence, tiering, secondary indexes |
| `steadfast-auth` | Per-app user auth: Argon2id, JWT + refresh rotation with reuse detection, lockout, rate limiting, `/_auth` endpoints |
| `steadfast-server` | Axum hot path, auth dispatch, binary `steadfast` (plus `loadtest` load generator) |

Planned Phase 3: distributed mode (gRPC contracts, Redis/Dragonfly shared memory layer,
rate limiting, audit trail, HMAC-secured segments).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) — pick either.
