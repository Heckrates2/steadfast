# Steadfast Security-Policy

## Unterstützte Versionen

Security-Fixes landen im `main`-Branch; es gibt (noch) keine versionierten
Releases. Halte den Checkout aktuell.

## Melden einer Schwachstelle

**Bitte erstelle KEIN öffentliches GitHub-Issue für Sicherheitslücken.**

Melde Schwachstellen stattdessen vertraulich:

1. **Bevorzugt:** GitHub → Security → "Report a vulnerability" (private
   Vulnerability-Reporting des Repos).
2. **Alternativ:** E-Mail an die in den Repository-Metadaten hinterlegte
   Security-Adresse mit dem Betreff `[security] <Kurzbeschreibung>`.

Bitte liefere mit: betroffene Komponente (`steadfast-server`, `steadfast-core`,
`steadfast-storage`), Reproduktionsschritte oder PoC, eingesetzte Konfiguration
(`apps.toml`, Startargumente, `ENGINE_GATEWAY_SECRET` aktiv?) und deine
Einschätzung der Auswirkungen.

## Umgang mit Meldungen

- Bestätigung des Erhalts innerhalb von **7 Tagen**.
- Bewertung und Kommunikationstermin werden individuell vereinbart; als
   Richtwert gilt **90 Tage** bis zur Veröffentlichung (koordinated
   disclosure).
- Credits auf Wunsch in der Release-/Commit-Notiz.

## Scope

Die Engine unterstützt zwei Vertrauensmodelle pro App (siehe README „Security-Modell"):
**eingebaute Benutzer-Auth** (`[apps.<id>.auth]`: Login, JWT, Refresh-Rotation, Rollen,
Lockout, Rate-Limiting der `/_auth`-Endpunkte) und das klassische **Gateway-Modell**
(Engine hinter einem Gateway; User-Auth, Edge-Rate-Limiting und TLS beim Betreiber).
Gemeldet werden sollte alles, was die Engine selbst betrifft — etwa Sandbox-Escapes (Rhai),
Auth-Bypass (`X-API-Key` oder JWT/Refresh-Logik in `steadfast-auth`), Header-Spoofing
(`X-User-*`, `X-Internal-Auth`), Passwort-/Token-Handling (Argon2id, Rotation, Reuse-
Detection), Datenkorruption (WAL/Snapshot) oder Injection in Filter/Sortierung.

Außer Scope: Fehlkonfigurationen ohne Code-Verantwortung (z. B. fehlende
Netzwerk-Isolation des Engine-Ports, im Klartext committe Secrets, fehlende
Gateway-Rate-Limits auf Daten-Endpunkten) — dafür dokumentiert das Security-Modell die
Betreiber-Verantwortung.

## Bekannte bewusste Grenzen

Diese Punkte sind dokumentiert und bewusst (siehe Audit-Report):

- Kein Audit-Trail jenseits strukturierter Logzeilen (Phase 3).
- Ohne gesetztes `ENGINE_GATEWAY_SECRET` werden `X-User-*`-Header
  unverifiziert honoring (Gateway-Vertrauensmodell) — gilt nur für Apps
  ohne aktive `[auth]`-Sektion; bei `auth_mode = "jwt"` stammt die Identität
  aus verifizierten Token-Claims.
- Rate-Limiting/Timeouts der Daten-Endpunkte liegen beim Gateway (die
  `/_auth`-Endpunkte haben ein eigenes Token-Bucket-Rate-Limit je Client-IP).
